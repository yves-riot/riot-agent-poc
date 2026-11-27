using System.IO;
using System.Text.Json;
using System.Windows.Threading;

namespace Riot.Agent.App;

/// <summary>App state: the daemon connection, what the popup shows, and the wiring between the
/// clipboard guard, pushed daemon events and the HUD. Lives on the UI thread.</summary>
internal sealed class AppModel : IGuardBackend
{
    private static readonly string SettingsPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot", "agent.json");
    private readonly Dispatcher dispatcher = Dispatcher.CurrentDispatcher;
    private DaemonClient? client;
    private DispatcherTimer? retry;
    private string popupMode = LoadPopupMode();

    public AppModel(Func<AppModel, ClipboardGuard> guard, bool development)
    {
        Development = development;
        Clipboard = guard(this);
        Hud = new Hud(this);
    }

    public ClipboardGuard Clipboard { get; }
    public Hud Hud { get; }
    /// <summary>Not the installed copy: says so, to tell it from an installed agent next to it.</summary>
    public bool Development { get; }
    public PopupState Popup { get; private set; } = PopupState.Placeholder;
    public bool Connected { get; private set; }
    public event Action? Changed;

    /// <summary><c>full</c> | <c>lite</c>, as the extension's <c>pasteGuard:popupMode</c>.</summary>
    public string PopupMode
    {
        get => popupMode;
        set
        {
            popupMode = value;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
                File.WriteAllText(SettingsPath, JsonSerializer.Serialize(new { popupMode = value }));
            }
            catch (IOException)
            {
                // kept for this session
            }
        }
    }

    private static string LoadPopupMode()
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            return document.RootElement.GetProperty("popupMode").GetString() == "lite" ? "lite" : "full";
        }
        catch (Exception)
        {
            return "full";
        }
    }

    public void Start()
    {
        Clipboard.Pasted += (result, appId) => Hud.ShowText(result, AppName(appId));
        _ = Connect();
    }

    // ---------- connection ----------

    private async Task Connect()
    {
        try
        {
            var connected = await DaemonClient.Connect(
                e => dispatcher.InvokeAsync(() => Handle(e)),
                () => dispatcher.InvokeAsync(Disconnected));
            client = connected;
            Connected = true;
            Changed?.Invoke();
            await connected.Call("subscribe");
            await Refresh();
        }
        catch (Exception)
        {
            Disconnected();
        }
    }

    private void Disconnected()
    {
        var closing = client;
        client = null;
        closing?.Dispose(); // its close callback comes back here: the retry is already planned
        Connected = false;
        Clipboard.Targets = new HashSet<string>(); // no daemon, no decisions: leave the clipboard alone
        Changed?.Invoke();
        if (retry is not null) return;
        retry = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        retry.Tick += (_, _) =>
        {
            retry?.Stop();
            retry = null;
            if (client is null) _ = Connect();
        };
        retry.Start();
    }

    private void Handle(DaemonEvent daemonEvent)
    {
        if (daemonEvent is DaemonEvent.Blocked blocked) Hud.ShowFile(blocked.File);
        _ = Refresh();
    }

    public async Task Refresh()
    {
        if (client is not { } current) return;
        try
        {
            Popup = await current.Call<PopupState>("popupState");
        }
        catch (DaemonException)
        {
            return;
        }
        Clipboard.Targets = Popup.View.IsActive
            ? Popup.ProtectedApps.Select(a => a.BundleId).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>();
        Changed?.Invoke();
    }

    /// <summary>Sample state for <see cref="Snapshot"/>.</summary>
    public void Preview(PopupState state)
    {
        Popup = state;
        Connected = true;
        Changed?.Invoke();
    }

    public string AppName(string appId) =>
        Popup.ProtectedApps.FirstOrDefault(a => string.Equals(a.BundleId, appId, StringComparison.OrdinalIgnoreCase))?.DisplayName ?? appId;

    private DaemonClient Client => client ?? throw new DaemonException("closed", "not connected");

    // ---------- IGuardBackend ----------

    public Task<RedactTextResult> RedactText(string text, string appId) =>
        Client.Call<RedactTextResult>("redactText", new { text, bundleId = appId });

    public async Task<string> ReportPaste(string eventId) =>
        (await Client.Call<ReportPasteResult>("reportPaste", new { eventId })).PasteId;

    public Task<DetokenizeResult> Detokenize(string text, string appId) =>
        Client.Call<DetokenizeResult>("detokenize", new { text, bundleId = appId });

    public Task ReportOverride(string pasteId) => Client.Call("reportOverride", new { pasteId });

    public async Task<bool> GrantFileBypass(string eventId)
    {
        try
        {
            await Client.Call("grantFileBypass", new { eventId });
            return true;
        }
        catch (DaemonException)
        {
            return false;
        }
    }
}
