using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Riot.Agent.App;

/// <summary>Development aid: <c>RIOT_SNAPSHOT_DIR=&lt;dir&gt; RiotAgent.exe</c> draws every HUD card
/// and the popup, with sample data, into PNG files in that folder, then quits. For reviewing the
/// cards without staging each case.</summary>
internal static class Snapshot
{
    public static string? Directory => Environment.GetEnvironmentVariable("RIOT_SNAPSHOT_DIR") is { Length: > 0 } dir ? dir : null;

    public static async Task Run(AppModel model, TrayPopup popup, string dir)
    {
        System.IO.Directory.CreateDirectory(dir);
        IReadOnlyList<TypeCount> types =
        [
            new("iban", "redaction.flag.iban", 1), new("email", "redaction.flag.email", 2),
            new("phone", "redaction.flag.phone", 1), new("person_name", "redaction.flag.person_name", 1), new("api_key", "redaction.flag.api_key", 1),
        ];
        var result = new RedactTextResult("redacted", "[IBAN_1]", types, "ev", true);
        var file = new FileBlocked("ev", "Relevé bancaire.pdf", "Claude_pzs8sxrjxfjjc", "Claude", types.Take(2).ToList(), true);
        model.Preview(new PopupState(new PopupView("signedIn", "Camille Martin", 12), "Albert", null, "Acme", null, true,
            [new("anthropic", "Claude", "Claude_pzs8sxrjxfjjc", true), new("openai", "ChatGPT", "OpenAI.Codex_2p2nqsd0c76g0", false)],
            [new("1", "", "textRedacted", "Claude", types.Take(2).ToList()), new("2", "", "fileBlocked", "ChatGPT", types.Take(1).ToList())]));

        Hud.Card[] cards =
        [
            new Hud.Card.Text(result, "Claude"), new Hud.Card.TextConfirm(result, "Claude"), new Hud.Card.SteppedAside(true),
            new Hud.Card.File(file), new Hud.Card.FileConfirm(file), new Hud.Card.FileGranted("Claude"),
        ];
        foreach (var card in cards)
        {
            model.Hud.Show(card, null);
            await Save(model.Hud, Path.Combine(dir, $"hud-{card.GetType().Name}.png"));
        }
        model.PopupMode = "lite";
        model.Hud.Show(new Hud.Card.Text(result, "Claude"), null);
        await Save(model.Hud, Path.Combine(dir, "hud-TextLite.png"));
        model.PopupMode = "full";
        model.Hud.Dismiss();

        popup.Toggle(int.MaxValue / 2, int.MaxValue / 2);
        await Save(popup, Path.Combine(dir, "popup.png"));
        popup.Hide();
        Application.Current.Shutdown();
    }

    private static async Task Save(Window window, string path)
    {
        await Dispatcher.CurrentDispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        var scale = VisualTreeHelper.GetDpi(window);
        var bitmap = new RenderTargetBitmap((int)Math.Ceiling(window.ActualWidth * scale.DpiScaleX),
            (int)Math.Ceiling(window.ActualHeight * scale.DpiScaleY), scale.PixelsPerInchX, scale.PixelsPerInchY, PixelFormats.Pbgra32);
        bitmap.Render(window);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        await using var stream = File.Create(path);
        encoder.Save(stream);
    }
}
