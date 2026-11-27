using System.Globalization;
using System.Text.Json;

namespace Riot.Agent;

/// <summary>
/// Strings. Guard and popup texts come from the extension's own locale files
/// (<c>@tryriot/sonar-ui/src/locales/{lang}.json</c>, copied next to the app at build), so both
/// products say exactly the same thing. vue-i18n conventions apply: <c>{name}</c> placeholders
/// and <c>singular | plural</c> forms. Agent-only texts live in <see cref="Native"/>.
/// </summary>
public sealed class L10n
{
    public static L10n Shared { get; set; } = new();

    public string Language { get; }
    private readonly Dictionary<string, string> table;
    private readonly Dictionary<string, string> fallback;

    public L10n(string? language = null, string? localesDirectory = null)
    {
        var preferred = language ?? CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        Language = preferred is "fr" or "en" ? preferred : "en";
        var dir = localesDirectory ?? DefaultDirectory();
        table = Load(Path.Combine(dir, $"{Language}.json"));
        fallback = Load(Path.Combine(dir, "en.json"));
    }

    /// <summary><c>RIOT_LOCALES_DIR</c>, or <c>locales</c> next to the app.</summary>
    public static string DefaultDirectory() =>
        Environment.GetEnvironmentVariable("RIOT_LOCALES_DIR") is { Length: > 0 } dir ? dir : Path.Combine(AppContext.BaseDirectory, "locales");

    private static Dictionary<string, string> Load(string path)
    {
        var flat = new Dictionary<string, string>();
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(path));
            Walk(document.RootElement, "");
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            // no locale file: native strings and keys only
        }
        return flat;

        void Walk(JsonElement value, string prefix)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in value.EnumerateObject())
                    Walk(property.Value, prefix.Length == 0 ? property.Name : $"{prefix}.{property.Name}");
            }
            else if (value.ValueKind == JsonValueKind.String)
            {
                flat[prefix] = value.GetString()!;
            }
        }
    }

    /// <summary><c>T("popup.redactions.title", 3, ("count", "3"))</c></summary>
    public string T(string key, int? count = null, params (string Name, string Value)[] parameters)
    {
        var s = table.GetValueOrDefault(key) ?? fallback.GetValueOrDefault(key)
            ?? Native.GetValueOrDefault(Language)?.GetValueOrDefault(key) ?? Native["en"].GetValueOrDefault(key) ?? key;
        if (count is { } n)
        {
            var forms = s.Split(" | ");
            if (forms.Length == 2) s = n == 1 ? forms[0] : forms[1];
            if (forms.Length == 3) s = n == 0 ? forms[0] : n == 1 ? forms[1] : forms[2];
        }
        foreach (var (name, value) in parameters) s = s.Replace("{" + name + "}", value);
        return s;
    }

    public string T(string key, params (string Name, string Value)[] parameters) => T(key, null, parameters);

    /// <summary>The engine reports labels as i18n keys (<c>redaction.flag.iban</c>).</summary>
    public string Label(TypeCount type) => T(type.Label);

    /// <summary>Agent-only strings (no browser equivalent), as on macOS for this PC.</summary>
    public static readonly IReadOnlyDictionary<string, Dictionary<string, string>> Native = new Dictionary<string, Dictionary<string, string>>
    {
        ["fr"] = new()
        {
            ["agent.notConfigured.title"] = "Configuration manquante",
            ["agent.notConfigured.body"] = "La configuration Riot n'est pas installée sur ce PC. Contacte ton équipe IT.",
            ["agent.reconnect.title"] = "Compte non reconnu",
            ["agent.reconnect.body"] = "Ce PC n'est rattaché à aucun employé. Contacte ton équipe IT.",
            ["agent.daemon.down.title"] = "Service Riot arrêté",
            ["agent.daemon.down.body"] = "La protection est suspendue : le service Riot ne répond pas.",
            ["agent.standby.body"] = "{botName} est installé sur ce PC pour protéger les données sensibles dans les applis d'IA. Ton équipe cybersécurité ne l'a pas encore activé pour toi.",
            ["agent.protectedApps"] = "Applis protégées",
            ["agent.notInstalled"] = "non installée",
            ["agent.recent"] = "Activité récente",
            ["agent.recent.textRedacted"] = "Copier-coller anonymisé",
            ["agent.recent.fileBlocked"] = "Fichier bloqué",
            ["agent.recent.fileAllowedByUser"] = "Fichier envoyé quand même",
            ["agent.recent.originalPasted"] = "Collé sans anonymisation",
            ["agent.text.pasteOriginalHint"] = "Le texte original est dans le presse-papier : annule le collage (Ctrl+Z) puis colle à nouveau (Ctrl+V).",
            ["agent.text.pasteOriginalUnseenHint"] = "Le texte original est dans le presse-papier : colle-le (Ctrl+V). Si tu avais déjà collé la version anonymisée, annule-la d'abord (Ctrl+Z).",
            ["agent.file.bypassGranted"] = "C'est noté. Tu peux renvoyer le fichier dans {app} (pendant 60 secondes).",
            ["agent.quit"] = "Quitter",
            ["agent.dev"] = "développement",
        },
        ["en"] = new()
        {
            ["agent.notConfigured.title"] = "Configuration missing",
            ["agent.notConfigured.body"] = "The Riot configuration is not installed on this PC. Contact your IT team.",
            ["agent.reconnect.title"] = "Account not recognized",
            ["agent.reconnect.body"] = "This PC is not linked to an employee. Contact your IT team.",
            ["agent.daemon.down.title"] = "Riot service stopped",
            ["agent.daemon.down.body"] = "Protection is paused: the Riot service is not responding.",
            ["agent.standby.body"] = "{botName} is installed on this PC to protect sensitive data in AI apps. Your security team hasn't enabled it for you yet.",
            ["agent.protectedApps"] = "Protected apps",
            ["agent.notInstalled"] = "not installed",
            ["agent.recent"] = "Recent activity",
            ["agent.recent.textRedacted"] = "Paste redacted",
            ["agent.recent.fileBlocked"] = "File blocked",
            ["agent.recent.fileAllowedByUser"] = "File sent anyway",
            ["agent.recent.originalPasted"] = "Pasted without redaction",
            ["agent.text.pasteOriginalHint"] = "The original text is on the clipboard: undo the paste (Ctrl+Z), then paste again (Ctrl+V).",
            ["agent.text.pasteOriginalUnseenHint"] = "The original text is on the clipboard: paste it (Ctrl+V). If you already pasted the redacted version, undo it first (Ctrl+Z).",
            ["agent.file.bypassGranted"] = "Noted. You can send the file again in {app} (for 60 seconds).",
            ["agent.quit"] = "Quit",
            ["agent.dev"] = "development",
        },
    };
}
