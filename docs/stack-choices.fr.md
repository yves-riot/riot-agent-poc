# Choix de la stack

_English version: [stack-choices.md](stack-choices.md)._

Pourquoi l'agent est un daemon Rust, avec le moteur TypeScript de l'extension sur un QuickJS
embarqué (en attendant un moteur Rust), et des apps natives par OS (Swift sur macOS, C# plus tard
sur Windows).

## Contraintes

- **Mêmes résultats que l'extension navigateur.** Un texte anonymisé d'une façon quand on le colle
  dans Chrome et d'une autre quand on le colle dans ChatGPT Desktop, c'est un bug produit.
- **Léger.** L'agent tourne en permanence sur chaque Mac et PC géré : peu de RAM, pas de CPU au
  repos.
- **Installé et autorisé entièrement par MDM**, sans action de l'utilisateur.
- **macOS d'abord, Windows ensuite**, sans réécrire le cœur.
- **Le socle du futur agent MDM de Riot** : un daemon privilégié qui parle au serveur.

## Architecture

```
Riot.app (Swift : barre de menus, HUD, garde presse-papier et glisser-déposer)   UI et hooks OS, par OS
      │  socket Unix, JSON ligne par ligne (core/riot-ipc)
riot-daemon (Rust, root)                                        commun à tous les OS
      ├─ riot-detect : QuickJS qui exécute @tryriot/sonar-detection
      ├─ extraction native du texte des fichiers (txt, csv, docx, xlsx, pdf)
      └─ policy, mémoire des tokens, synchro parrot, file des rapports
      ▲  même socket (scanFile avec un délai maximal)
RiotES.systemextension (Swift : Endpoint Security)               blocage des fichiers, par OS
```

Toutes les décisions et toute la logique sont dans le daemon. Les apps sont de simples clients :
elles affichent ce qu'il dit et s'accrochent à ce que seul l'OS permet d'intercepter.

## Rust pour le daemon

- **Un seul daemon pour les deux OS** : un LaunchDaemon sur macOS, un service sur Windows, avec le
  même code et le même protocole. Seuls l'UI et les hooks changent d'un OS à l'autre.
- **Il tourne en root et lit des fichiers non fiables** (pdf, docx, xlsx). La sûreté mémoire
  compte là.
- **Petit et silencieux** : 16 Mo (`phys_footprint`), 0 % de CPU au repos.
- **Bon outillage pour le reste** : `rquickjs` pour héberger le moteur, `pdf-extract` + `lopdf`
  pour le texte des pdf (100 % Rust, pas les 5 Mo de pdfium), `tokio` pour le socket et la synchro
  avec le serveur.

### Pourquoi pas Go, C++ ou un autre langage

Ce qui tranche, c'est le moteur Rust probable (voir plus bas) : un seul code, natif dans le daemon
et en WASM dans l'extension. Le WASM produit par Rust est petit, sans runtime, et compilé par
l'outillage standard.

- **Go** aurait été un choix défendable pour le daemon seul : sûr pour la mémoire, simple, courant
  pour les agents. Ce qui joue contre lui ici : son WASM embarque le runtime Go et le
  GC (plusieurs Mo, TinyGo est plus petit mais ne gère qu'une partie du langage),
  embarquer QuickJS passe par cgo (compilation plus pénible, un coût à chaque appel), et le
  GC ajoute de la mémoire par rapport aux 16 Mo actuels.
- **C++** : pas de sûreté mémoire, dans un daemon root qui lit des fichiers non fiables, la source
  classique de failles exploitables. Outillage plus lourd entre macOS, Windows et WASM
  (dépendances, Emscripten). Son seul vrai atout, appeler directement les API C (QuickJS,
  Endpoint Security, Win32), Rust l'a aussi.
- **Swift partout** : parfait sur macOS, encore immature sur Windows. La phase 2 demanderait un
  autre daemon.
- **C#/.NET partout** : runtime plus lourd sur macOS, et WASM lourd.
- **Zig** : écosystème trop jeune pour un agent déployé sur des flottes entières.

Ce que coûte Rust : un apprentissage plus long, des compilations plus lentes, moins de
développeurs qui le connaissent que Go. Si le moteur ne devait jamais tourner en WASM, Go serait
un concurrent sérieux pour le daemon.

## Détection : le moteur de l'extension sur QuickJS aujourd'hui, Rust ensuite

### Aujourd'hui : le moteur TypeScript sur QuickJS

- **Parité garantie.** Le daemon exécute lui-même `@tryriot/sonar-detection` :
  mêmes détecteurs, mêmes tokens (`[EMAIL_1]`), mêmes corrections de faux positifs. Le corpus de
  conformance de l'extension passe à 236/236 sur QuickJS.
- **Rien à porter pour commencer** : `compromise` (noms de personnes) et `libphonenumber-js`
  tournent tels quels.
- **Une seule base de règles, une seule équipe** : un changement de détecteur part dans
  l'extension et dans l'agent à la fois.
- **Le risque était la vitesse** (QuickJS n'a pas de JIT). Mesuré : collage de 1 Ko en 20 ms, de
  64 Ko en 330 ms ; un fichier texte de 1 Mio en 3,3 s. Du code peu coûteux sur V8 peut être lent
  ici : découper une chaîne la copie sur QuickJS (le découpage de fin de texte du détecteur de
  téléphones faisait monter un scan de 1 Mio à 12,3 s, jusqu'à sa correction dans le code de
  l'extension).
- Non réutilisés : pdf.js (workers, lourd, lent sans JIT ; le texte des pdf est extrait en
  natif), ainsi que l'interception DOM et l'UI Vue de l'extension.

### Ensuite, probablement : un seul moteur Rust, en WASM dans l'extension

Le moteur sera probablement porté en Rust, puis importé par l'extension en WASM. Une seule
implémentation partout : native dans le daemon (pas de runtime JS, pas d'écart de performance
entre V8 et QuickJS, un langage de moins à déboguer), en WASM dans le navigateur.

- **La frontière existe déjà** : le daemon appelle le moteur via une API Rust
  (`riot_detect::Engine` : `redact`, `detokenize`, `detect`, `scan_path`). Remplacer QuickJS par
  du code Rust ne change rien pour les apps, l'extension ES ou le protocole.
- **Le corpus sert de garde-fou** : les mêmes cas de conformance (236 aujourd'hui) doivent passer
  sur le moteur Rust, en natif et en WASM, avant qu'il remplace le moteur TypeScript.
- **À résoudre pendant le portage** : les noms de personnes (`compromise` n'a pas d'équivalent en
  Rust : porter ses heuristiques, ou un petit modèle NER, au prix de RAM en plus) et les téléphones
  (la crate `phonenumber` ne donne pas exactement les mêmes résultats que `libphonenumber-js` ; le
  corpus montre les écarts).
- **Le texte des pdf** est déjà extrait en Rust dans le daemon ; l'extension garde pdf.js ou
  passe au même extracteur en WASM.

## Des apps natives par OS, quelle que soit l'évolution de l'UI

L'UI reste native, même si elle s'enrichit. Les apps par OS :

- **macOS : Swift** (SwiftUI et AppKit). L'extension Endpoint Security doit de toute façon être
  une system extension. Mesuré : app 21 Mo, `Riot.app` 9,8 Mo.
- **Windows (phase 2) : C#**, avec WinUI 3 ou WPF pour l'UI et un minifilter pour les fichiers,
  sur le même daemon et le même protocole.

### Natif plutôt que web

- **Mémoire et processus.** Un seul processus, 21 Mo. Une webview est un moteur de navigateur
  avec ses propres processus : la première version de l'app, en Tauri (shell Rust, webview
  système), dépassait 100 Mo de RAM répartis sur 4 sous-processus ; Electron embarque en plus un
  Chromium entier par app.
- **Le garde, c'est du comportement d'OS, pas des pages.** Un HUD qui ne prend jamais le focus à
  l'app IA (`NSPanel` non activant), les promesses du presse-papier, le presse-papier du
  glisser-déposer, la barre de menus, les frappes envoyées à l'app au premier plan. Une UI web a
  quand même besoin de code natif pour tout ça, plus un pont entre les deux : deux technos pour
  une seule fonctionnalité.
- **Immédiat.** Le HUD doit apparaître au moment où l'utilisateur colle ; il n'y a pas de webview
  à lancer ou à réveiller.
- **L'apparence et le comportement de l'OS**, sans effort : contrôles système, mode sombre,
  polices, navigation au clavier, VoiceOver, mises en page de droite à gauche, menus système.
- **Moins de surface d'attaque** pour un agent présent sur chaque machine gérée : pas de moteur
  qui exécute du HTML et du JS à côté d'un daemon root, pas de runtime web à maintenir à jour
  (WebView2 se met à jour à son propre rythme sur Windows).
- **Un seul binaire signé** à notariser et à déployer par MDM, sans runtime embarqué.
- **Le web reste possible si besoin** : une fenêtre native peut accueillir une webview
  (`WKWebView`, WebView2 sur Windows) pour un écran, créée à son ouverture et qui parle au daemon
  via l'app native. Passer plus tard un écran en web ne change pas le reste de l'app.

Ce que ça coûte : l'UI est écrite pour chaque OS (Swift, puis C#), et les composants Vue de
l'extension (`sonar-ui`) ne sont pas réutilisés. Ses textes, si : l'app charge les fichiers de
traduction de l'extension, donc les deux produits disent exactement la même chose.

## Apps ↔ daemon : du JSON sur un socket, pas des bindings générés

Le plan prévoyait un binding UniFFI de Rust vers Swift. Les apps parlent plutôt directement le
protocole JSON du daemon (`DaemonClient.swift`) : le binding n'aurait fait qu'envelopper ce
socket, toute la logique est dans le daemon, et un client C# est tout aussi petit. `riotctl` est
un client de plus sur le même socket ([riotctl.md](riotctl.md)).

## Le coût

- **Trois langages** (Rust, Swift, puis C#) au lieu d'un ; tant que le moteur Rust n'est pas là,
  le débogage passe aussi par le JS.
- **Les performances du moteur sont à surveiller** tant qu'il tourne sur QuickJS : un code gratuit
  sur V8 peut y devenir quadratique. Le bench
  (`cargo run -p riot-detect --release --example bench`) sert de contrôle.

## À revoir si

- QuickJS devient trop lent pour le délai d'Endpoint Security sur les gros fichiers avant
  l'arrivée du moteur Rust : porter d'abord les détecteurs les plus coûteux, ou passer à
  JavaScriptCore (fourni par le système, avec JIT) sur macOS.
