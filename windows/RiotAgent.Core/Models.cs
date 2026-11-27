namespace Riot.Agent;

// Mirrors of core/riot-ipc. Keys are camelCase on the wire: System.Text.Json's web defaults
// read them into these records as is.

public sealed record TypeCount(string Flag, string Label, int Count);

/// <summary>A protected app. <c>BundleId</c> is the policy's app id: on Windows, the package
/// family name (<c>Claude_pzs8sxrjxfjjc</c>), or the lower-case executable file name of an app
/// that is not packaged.</summary>
public sealed record TargetApp(string ServiceId, string DisplayName, string BundleId, bool Installed);

public sealed record RecentEvent(string EventId, string At, string Kind, string AppName, IReadOnlyList<TypeCount> Types);

/// <summary>The popup's state, tagged by <c>Kind</c>: <c>loading</c>, <c>notConfigured</c>,
/// <c>standby</c>, <c>signedIn</c> (with <c>Name</c>, <c>Redactions</c>), <c>reconnect</c>,
/// <c>error</c> (with <c>Message</c>).</summary>
public sealed record PopupView(string Kind, string? Name = null, int? Redactions = null, string? Message = null)
{
    /// <summary>The clipboard guard applies: an active policy, with or without an employee.</summary>
    public bool IsActive => Kind is "signedIn" or "reconnect";
}

public sealed record PopupState(
    PopupView View,
    string BotName,
    string? BotIconUrl,
    string? Company,
    string? PortalUrl,
    bool AllowBypass,
    IReadOnlyList<TargetApp> ProtectedApps,
    IReadOnlyList<RecentEvent> RecentEvents)
{
    public static readonly PopupState Placeholder = new(new PopupView("loading"), "Albert", null, null, null, false, [], []);
}

/// <summary><c>Action</c>: <c>redacted</c> (with <c>Text</c>), <c>clean</c>, <c>skipped</c>,
/// <c>error</c>.</summary>
public sealed record RedactTextResult(string Action, string? Text, IReadOnlyList<TypeCount> Types, string? EventId, bool AllowBypass);

public sealed record ReportPasteResult(string PasteId);

public sealed record DetokenizeResult(string Text, int Replaced);

public sealed record FileBlocked(string EventId, string FileName, string BundleId, string AppName, IReadOnlyList<TypeCount> Types, bool AllowBypass);

/// <summary>Pushed by the daemon on a subscribed connection.</summary>
public abstract record DaemonEvent
{
    public sealed record StateChanged : DaemonEvent;
    public sealed record Blocked(FileBlocked File) : DaemonEvent;
}
