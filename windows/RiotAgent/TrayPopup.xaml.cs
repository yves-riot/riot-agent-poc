using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Riot.Agent.App.Win32;

namespace Riot.Agent.App;

/// <summary>The popup of the notification icon: the extension's toolbar popup
/// (entrypoints/popup/App.vue) plus what only the agent knows (protected apps, recent activity).
/// It closes when it loses the focus, as a flyout does.</summary>
internal sealed partial class TrayPopup
{
    private readonly AppModel model;
    private (int X, int Y) anchor;

    public TrayPopup(AppModel model)
    {
        this.model = model;
        InitializeComponent();
        Deactivated += (_, _) => Hide();
        SizeChanged += (_, _) => Place();
        model.Changed += () =>
        {
            if (IsVisible) Rebuild();
        };
    }

    /// <summary>Opens next to the notification icon at (<paramref name="x"/>, <paramref name="y"/>),
    /// or closes if open.</summary>
    public void Toggle(int x, int y)
    {
        if (IsVisible)
        {
            Hide();
            return;
        }
        anchor = (x, y);
        Rebuild();
        Show();
        Activate();
        Place();
        _ = model.Refresh();
    }

    /// <summary>Above the taskbar, at the right edge of the screen the icon is on.</summary>
    private void Place()
    {
        if (!IsVisible) return;
        var (work, scale) = Screens.MonitorAt(anchor.X, anchor.Y);
        var (width, height) = ((int)Math.Round(ActualWidth * scale), (int)Math.Round(ActualHeight * scale));
        var margin = (int)Math.Round(12 * scale);
        var y = anchor.Y < work.Top ? work.Top + margin : work.Bottom - height - margin; // taskbar at the top
        Screens.MoveTo(this, work.Right - width - margin, Math.Max(work.Top, y));
    }

    private void Rebuild()
    {
        var l = L10n.Shared;
        var popup = model.Popup;
        var bot = popup.BotName;
        var status = model.Connected ? Status(popup) : new StatusView(Brushes.IndianRed, l.T("agent.daemon.down.title"), l.T("agent.daemon.down.body"));
        DataContext = new TrayPopupView(
            new HeaderView(popup.BotIconUrl, model.Development ? $"{bot} ({l.T("agent.dev")})" : bot,
                popup.Company is { } company ? l.T("popup.subtitle", ("company", company)) : l.T("popup.subtitleNoCompany"), 40),
            status,
            status is null ? l.T("Loading…") : null,
            popup.View is { Kind: "signedIn", Redactions: { } count }
                ? new InfoView(l.T("popup.redactions.title", count, ("count", $"{count}")), l.T("popup.redactions.body", ("botName", bot)))
                : null,
            new InfoView(l.T("privacy.title", ("botName", bot)), l.T("privacy.body")),
            l.T("agent.protectedApps"),
            // The same service may list several apps (macOS and Windows): one line per name.
            popup.ProtectedApps.DistinctBy(a => a.DisplayName).Select(a => new AppRow(a.DisplayName, a.Installed)).ToList(),
            l.T("agent.recent"),
            popup.RecentEvents.Take(4).Select(e => new RecentRow(l.T($"agent.recent.{e.Kind}"), e.AppName, string.Join(", ", e.Types.Take(2).Select(l.Label)))).ToList(),
            model.PopupMode == "full",
            l.T("popup.showFullPopup"),
            l.T("agent.quit"));
    }

    private static StatusView? Status(PopupState popup)
    {
        var l = L10n.Shared;
        return popup.View.Kind switch
        {
            "notConfigured" => new(Brushes.Orange, l.T("agent.notConfigured.title"), l.T("agent.notConfigured.body")),
            "standby" => new(Brushes.Gray, l.T("popup.standby.title"), l.T("agent.standby.body", ("botName", popup.BotName))),
            "signedIn" => new(Brushes.SeaGreen, l.T("popup.signedIn.title"), l.T("popup.signedIn.body", ("name", popup.View.Name ?? ""))),
            "reconnect" => new(Brushes.Orange, l.T("agent.reconnect.title"), l.T("agent.reconnect.body")),
            "error" => new(Brushes.IndianRed, l.T("popup.unexpectedError"), null),
            _ => null,
        };
    }

    private void FullPopup_Click(object sender, RoutedEventArgs e) =>
        model.PopupMode = ((CheckBox)sender).IsChecked == true ? "full" : "lite";

    private void Quit_Click(object sender, RoutedEventArgs e) => Application.Current.Shutdown();
}

/// <summary>The popup's content, laid out by TrayPopup.xaml. <c>Status</c> null: still loading.</summary>
public sealed record TrayPopupView(
    HeaderView Header,
    StatusView? Status,
    string? Loading,
    InfoView? Redactions,
    InfoView Privacy,
    string ProtectedAppsTitle,
    IReadOnlyList<AppRow> ProtectedApps,
    string RecentTitle,
    IReadOnlyList<RecentRow> Recent,
    bool FullPopup,
    string FullPopupLabel,
    string QuitLabel);

public sealed record StatusView(Brush Dot, string Title, string? Body);

public sealed record InfoView(string Title, string Body);

public sealed record AppRow(string Name, bool Installed);

public sealed record RecentRow(string What, string App, string Types);
