using System.IO;
using System.Windows;
using Riot.Agent.App.Win32;

namespace Riot.Agent.App;

/// <summary>
/// RiotAgent.exe: the notification icon, the clipboard guard and the HUD, for the signed-in
/// user; the daemon (the RiotAgent service) takes every decision. One per session and per daemon:
/// a development copy runs next to an installed one.
/// <para><c>RIOT_SOCKET</c> names the daemon's pipe; <c>RIOT_DEBUG=1</c> logs events and timings
/// (never content) to <c>%LOCALAPPDATA%\Riot\agent-debug.log</c>.</para>
/// </summary>
internal static class Program
{
    [STAThread]
    private static int Main()
    {
        // A backslash would make the name a path (a malformed RIOT_SOCKET), which throws.
        using var instance = new Mutex(true, $@"Local\Riot.Agent.{DaemonClient.PipeName.Replace('\\', '_')}", out var first);
        if (!first) return 0;

        var app = new App();
        app.InitializeComponent();
        var parts = new List<IDisposable>();
        app.Startup += (_, _) => parts.AddRange(Start());
        app.Exit += (_, _) => parts.ForEach(p => p.Dispose());
        return app.Run();
    }

    private static IEnumerable<IDisposable> Start()
    {
        var log = Log();
        var window = new MessageWindow();
        var clipboard = new Win32Clipboard(window) { Log = log };
        if (SelfTest.ReportPath is { } report)
        {
            _ = SelfTest.Run(clipboard, report);
            return [clipboard, window];
        }
        var keyboard = new KeyboardState(window);
        var foreground = new Foreground();
        var tray = new TrayIcon(window);
        var ownApp = Path.GetFileName(Environment.ProcessPath)?.ToLowerInvariant();
        var development = !IsInstalledCopy();

        var model = new AppModel(backend => new ClipboardGuard(clipboard, backend, keyboard, new Keystrokes()) { OwnAppId = ownApp, Log = log }, development);
        var popup = new TrayPopup(model);
        clipboard.Changed += model.Clipboard.ClipboardChanged;
        foreground.Changed += model.Clipboard.Activated;
        tray.Clicked += popup.Toggle;
        void UpdateIcon()
        {
            var name = development ? $"Riot ({L10n.Shared.T("agent.dev")})" : "Riot";
            tray.Update(model.Connected, development, model.Connected ? name : $"{name} — {L10n.Shared.T("agent.daemon.down.title")}");
        }
        model.Changed += UpdateIcon;
        UpdateIcon();
        if (Snapshot.Directory is { } snapshots)
        {
            _ = Snapshot.Run(model, popup, snapshots);
            return [tray, foreground, clipboard, window];
        }
        model.Start();
        model.Clipboard.Activated(Foreground.Current);
        return [tray, foreground, clipboard, window];
    }

    /// <summary>Installed under Program Files; anything else is a development copy.</summary>
    private static bool IsInstalledCopy()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return Environment.ProcessPath?.StartsWith(programFiles + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) == true;
    }

    private static Action<string>? Log()
    {
        if (Environment.GetEnvironmentVariable("RIOT_DEBUG") != "1") return null;
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot", "agent-debug.log");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        return line =>
        {
            try
            {
                File.AppendAllText(path, $"{DateTime.Now:HH:mm:ss.fff} {line}{Environment.NewLine}");
            }
            catch (IOException)
            {
                // diagnostics only
            }
        };
    }
}
