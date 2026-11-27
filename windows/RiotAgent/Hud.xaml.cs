using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using Riot.Agent.App.Win32;
using static Riot.Agent.App.Win32.Native;

namespace Riot.Agent.App;

/// <summary>The in-the-moment cards, the counterpart of the extension's in-page guard popup
/// (346 px wide, top right). The window never takes the focus (<c>WS_EX_NOACTIVATE</c>): the AI
/// app keeps it, so clicking a card is not leaving the app, and Ctrl+Z/Ctrl+V still reach it.</summary>
internal sealed partial class Hud
{
    public abstract record Card
    {
        public sealed record Text(RedactTextResult Result, string App) : Card;
        public sealed record TextConfirm(RedactTextResult Result, string App) : Card;
        /// <summary>After "paste without redaction", when the original could only go on the
        /// clipboard. <c>SeenPaste</c>: a redacted paste was seen, to undo before pasting again.</summary>
        public sealed record SteppedAside(bool SeenPaste) : Card;
        public sealed record File(FileBlocked Blocked) : Card;
        public sealed record FileConfirm(FileBlocked Blocked) : Card;
        public sealed record FileGranted(string App) : Card;
    }

    private readonly AppModel model;
    private DispatcherTimer? dismissTimer;

    public Hud(AppModel model)
    {
        this.model = model;
        InitializeComponent();
        SizeChanged += (_, _) => Place();
    }

    public Card? Current { get; private set; }
    /// <summary>A card was shown, or the HUD closed (null).</summary>
    public event Action<Card?>? CardChanged;

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        var hwnd = new WindowInteropHelper(this).Handle;
        var style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE).ToInt64();
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new IntPtr(style | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST));
        HwndSource.FromHwnd(hwnd)?.AddHook((IntPtr _, int msg, IntPtr _, IntPtr _, ref bool handled) =>
        {
            if (msg != WM_MOUSEACTIVATE) return IntPtr.Zero;
            handled = true;
            return new IntPtr(MA_NOACTIVATE);
        });
    }

    public void ShowText(RedactTextResult result, string app) =>
        Show(new Card.Text(result, app), model.PopupMode == "lite" ? TimeSpan.FromSeconds(6) : null);

    public void ShowFile(FileBlocked blocked) => Show(new Card.File(blocked), null);

    public void Dismiss()
    {
        dismissTimer?.Stop();
        Current = null;
        Hide();
        CardChanged?.Invoke(null);
    }

    public void Show(Card card, TimeSpan? autoDismiss)
    {
        Current = card;
        DataContext = View(card);
        CardChanged?.Invoke(card);
        if (!IsVisible) Show();
        Place();
        dismissTimer?.Stop();
        if (autoDismiss is { } delay)
        {
            dismissTimer = new DispatcherTimer { Interval = delay };
            dismissTimer.Tick += (_, _) => Dismiss();
            dismissTimer.Start();
        }
    }

    /// <summary>Top right of the screen the pointer is on, as on macOS.</summary>
    private void Place()
    {
        if (!IsVisible) return;
        var (work, scale) = Screens.MonitorAtCursor();
        var width = (int)Math.Round(ActualWidth * scale);
        Screens.MoveTo(this, work.Right - width, work.Top);
    }

    private HudCardView View(Card card)
    {
        var l = L10n.Shared;
        var popup = model.Popup;
        var (bot, workspace) = (popup.BotName, popup.Company ?? "");
        HeaderView Header(string title, string? subtitle) => new(popup.BotIconUrl, title, subtitle);

        return card switch
        {
            Card.Text(var result, var app) when model.PopupMode == "lite" => new(
                Header(l.T("redactionGuard.lite.title", ("botName", bot)), l.T("redactionGuard.lite.subtitleService", ("service", app))))
            {
                Link = new(l.T("redactionGuard.lite.viewDetails"), () =>
                {
                    model.PopupMode = "full";
                    Show(new Card.Text(result, app), null);
                }),
                Close = new(l.T("redactionGuard.lite.close"), Dismiss),
            },
            Card.Text(var result, var app) => new(
                Header(l.T("redactionGuard.text.intercepted.title", ("botName", bot)), l.T("redactionGuard.text.intercepted.subtitle")))
            {
                Intro = l.T("redactionGuard.text.intercepted.intro", ("service", app), ("workspace", workspace)),
                Findings = FindingsView.Of(result.Types),
                Link = result.AllowBypass ? new(l.T("redactionGuard.text.intercepted.pasteAnyway"), () => Show(new Card.TextConfirm(result, app), null)) : null,
                Primary = new(l.T("redactionGuard.text.intercepted.dismiss"), Dismiss),
            },
            Card.TextConfirm(var result, var app) => new(Header(l.T("redactionGuard.text.confirm.title"), null))
            {
                Warning = new(l.T("redactionGuard.text.confirm.boxTitle"), l.T("redactionGuard.text.confirm.warning", ("service", app))),
                Secondary = new(l.T("redactionGuard.text.confirm.cancel"), () => Show(new Card.Text(result, app), null)),
                Primary = new(l.T("redactionGuard.text.confirm.submit"), PasteOriginal),
            },
            // The keys could not be sent (or the user typed, or no paste was seen): the original
            // is only on the clipboard, the user swaps it in themselves.
            Card.SteppedAside(var seen) => new(
                Header(l.T("redactionGuard.steppedAside.title"), l.T(seen ? "agent.text.pasteOriginalHint" : "agent.text.pasteOriginalUnseenHint")))
            {
                Close = new(l.T("redactionGuard.steppedAside.close"), Dismiss),
            },
            Card.File(var blocked) => new(Header(l.T("redactionGuard.file.intercepted.title", 1, ("botName", bot)), blocked.FileName))
            {
                Intro = l.T("redactionGuard.file.intercepted.intro", ("service", blocked.AppName), ("workspace", workspace)),
                Findings = blocked.Types.Count == 0 ? null : FindingsView.Of(blocked.Types),
                Note = blocked.Types.Count == 0 ? l.T("redactionGuard.error.processing.body", 1) : null,
                Link = blocked.AllowBypass ? new(l.T("redactionGuard.file.intercepted.sendOriginal"), () => Show(new Card.FileConfirm(blocked), null)) : null,
                Primary = new(l.T("redactionGuard.file.intercepted.dismiss"), Dismiss),
            },
            Card.FileConfirm(var blocked) => new(Header(l.T("redactionGuard.file.confirm.title", 1), blocked.FileName))
            {
                Warning = new(l.T("redactionGuard.file.confirm.boxTitle"), l.T("redactionGuard.file.confirm.warning", 1, ("service", blocked.AppName))),
                Secondary = new(l.T("redactionGuard.file.confirm.cancel"), () => Show(new Card.File(blocked), null)),
                Primary = new(l.T("redactionGuard.file.confirm.submit"), () => _ = SendFileAnyway(blocked)),
            },
            Card.FileGranted(var app) => new(Header(l.T("agent.file.bypassGranted", ("app", app)), null))
            {
                Close = new(l.T("redactionGuard.steppedAside.close"), Dismiss),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(card)),
        };
    }

    private void PasteOriginal()
    {
        switch (model.Clipboard.PasteOriginal())
        {
            case OriginalOutcome.Pasted:
                Dismiss(); // pasted in place: the field shows it, nothing to add
                break;
            case OriginalOutcome.OnClipboardUnseen:
                Show(new Card.SteppedAside(SeenPaste: false), TimeSpan.FromSeconds(8));
                break;
            default:
                Show(new Card.SteppedAside(SeenPaste: true), TimeSpan.FromSeconds(8));
                break;
        }
    }

    private async Task SendFileAnyway(FileBlocked blocked)
    {
        if (await model.GrantFileBypass(blocked.EventId)) Show(new Card.FileGranted(blocked.AppName), TimeSpan.FromSeconds(8));
        else Dismiss();
    }
}

/// <summary>One HUD card, laid out by Hud.xaml: whatever is null is not shown.</summary>
public sealed record HudCardView(HeaderView Header)
{
    public string? Intro { get; init; }
    public FindingsView? Findings { get; init; }
    /// <summary>Plain text where findings would be (a file that could not be read).</summary>
    public string? Note { get; init; }
    public WarningView? Warning { get; init; }
    /// <summary>On the left: a link, or a button.</summary>
    public ActionView? Link { get; init; }
    public ActionView? Secondary { get; init; }
    /// <summary>On the right: the accent button, or a plain one.</summary>
    public ActionView? Primary { get; init; }
    public ActionView? Close { get; init; }
}
