import Foundation

/// Strings. Guard and popup texts come from the extension's own locale files
/// (`@tryriot/sonar-ui/src/locales/{lang}.json`, copied into the app by build-app.sh), so both
/// products say exactly the same thing. vue-i18n conventions apply: `{name}` placeholders and
/// `singular | plural` forms. Agent-only texts live in `native` below.
final class L10n {
    static let shared = L10n()

    let language: String
    private var table: [String: String] = [:]
    private var fallback: [String: String] = [:]

    init(language: String? = nil, localesDirectory: URL? = L10n.defaultDirectory()) {
        let preferred = language ?? Locale.preferredLanguages.first.map { String($0.prefix(2)) } ?? "en"
        self.language = ["fr", "en"].contains(preferred) ? preferred : "en"
        if let dir = localesDirectory {
            table = L10n.load(dir.appendingPathComponent("\(self.language).json"))
            fallback = L10n.load(dir.appendingPathComponent("en.json"))
        }
    }

    static func defaultDirectory() -> URL? {
        if let env = ProcessInfo.processInfo.environment["RIOT_LOCALES_DIR"] { return URL(fileURLWithPath: env) }
        return Bundle.main.resourceURL?.appendingPathComponent("locales")
    }

    private static func load(_ url: URL) -> [String: String] {
        guard let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) else { return [:] }
        var flat: [String: String] = [:]
        func walk(_ value: Any, _ prefix: String) {
            if let dict = value as? [String: Any] {
                for (k, v) in dict { walk(v, prefix.isEmpty ? k : "\(prefix).\(k)") }
            } else if let s = value as? String {
                flat[prefix] = s
            }
        }
        walk(object, "")
        return flat
    }

    /// `t("popup.redactions.title", count: 3, ["count": "3"])`
    func t(_ key: String, count: Int? = nil, _ params: [String: String] = [:]) -> String {
        var s = table[key] ?? fallback[key] ?? L10n.native[language]?[key] ?? L10n.native["en"]?[key] ?? key
        if let count {
            let forms = s.components(separatedBy: " | ")
            if forms.count == 2 { s = count == 1 ? forms[0] : forms[1] }
            if forms.count == 3 { s = count == 0 ? forms[0] : (count == 1 ? forms[1] : forms[2]) }
        }
        for (k, v) in params { s = s.replacingOccurrences(of: "{\(k)}", with: v) }
        return s
    }

    /// Agent-only strings (no browser equivalent).
    static let native: [String: [String: String]] = [
        "fr": [
            "agent.notConfigured.title": "Configuration manquante",
            "agent.notConfigured.body": "Le profil de configuration Riot n'est pas installé sur ce Mac. Contacte ton équipe IT.",
            "agent.reconnect.title": "Compte non reconnu",
            "agent.reconnect.body": "Ce Mac n'est rattaché à aucun employé. Contacte ton équipe IT.",
            "agent.daemon.down.title": "Service Riot arrêté",
            "agent.daemon.down.body": "La protection est suspendue : le service Riot ne répond pas.",
            "agent.standby.body": "{botName} est installé sur ce Mac pour protéger les données sensibles dans les applis d'IA. Ton équipe cybersécurité ne l'a pas encore activé pour toi.",
            "agent.protectedApps": "Applis protégées",
            "agent.notInstalled": "non installée",
            "agent.recent": "Activité récente",
            "agent.recent.textRedacted": "Copier-coller anonymisé",
            "agent.recent.fileBlocked": "Fichier bloqué",
            "agent.recent.fileAllowedByUser": "Fichier envoyé quand même",
            "agent.recent.originalPasted": "Collé sans anonymisation",
            "agent.pasteboard.title": "Accès au presse-papier",
            "agent.pasteboard.denied": "Refusé : {botName} ne peut pas vérifier tes copier-coller. Autorise-le dans Réglages > Confidentialité et sécurité > Coller depuis d'autres apps.",
            "agent.pasteboard.ask": "macOS te demandera l'autorisation. Choisis « Toujours autoriser » pour que {botName} protège tes copier-coller.",
            "agent.pasteboard.open": "Ouvrir les Réglages",
            "agent.text.pasteOriginalHint": "Le texte original est dans le presse-papier : annule le collage (⌘Z) puis colle à nouveau (⌘V).",
            "agent.text.pasteOriginalUnseenHint": "Le texte original est dans le presse-papier : colle-le (⌘V). Si tu avais déjà collé la version anonymisée, annule-la d'abord (⌘Z).",
            "agent.file.bypassGranted": "C'est noté. Tu peux renvoyer le fichier dans {app} (pendant 60 secondes).",
            "agent.quit": "Quitter",
            "agent.status.daemon": "Service",
            "agent.status.connected": "connecté",
            "agent.status.disconnected": "déconnecté",
        ],
        "en": [
            "agent.notConfigured.title": "Configuration missing",
            "agent.notConfigured.body": "The Riot configuration profile is not installed on this Mac. Contact your IT team.",
            "agent.reconnect.title": "Account not recognized",
            "agent.reconnect.body": "This Mac is not linked to an employee. Contact your IT team.",
            "agent.daemon.down.title": "Riot service stopped",
            "agent.daemon.down.body": "Protection is paused: the Riot service is not responding.",
            "agent.standby.body": "{botName} is installed on this Mac to protect sensitive data in AI apps. Your security team hasn't enabled it for you yet.",
            "agent.protectedApps": "Protected apps",
            "agent.notInstalled": "not installed",
            "agent.recent": "Recent activity",
            "agent.recent.textRedacted": "Paste redacted",
            "agent.recent.fileBlocked": "File blocked",
            "agent.recent.fileAllowedByUser": "File sent anyway",
            "agent.recent.originalPasted": "Pasted without redaction",
            "agent.pasteboard.title": "Clipboard access",
            "agent.pasteboard.denied": "Denied: {botName} can't check your pastes. Allow it in Settings > Privacy & Security > Paste from Other Apps.",
            "agent.pasteboard.ask": "macOS will ask for permission. Choose “Always Allow” so {botName} can protect your pastes.",
            "agent.pasteboard.open": "Open Settings",
            "agent.text.pasteOriginalHint": "The original text is on the clipboard: undo the paste (⌘Z), then paste again (⌘V).",
            "agent.text.pasteOriginalUnseenHint": "The original text is on the clipboard: paste it (⌘V). If you already pasted the redacted version, undo it first (⌘Z).",
            "agent.file.bypassGranted": "Noted. You can send the file again in {app} (for 60 seconds).",
            "agent.quit": "Quit",
            "agent.status.daemon": "Service",
            "agent.status.connected": "connected",
            "agent.status.disconnected": "disconnected",
        ],
    ]
}

extension TypeCount {
    /// The engine reports labels as i18n keys (`redaction.flag.iban`).
    var localizedLabel: String { L10n.shared.t(label) }
}
