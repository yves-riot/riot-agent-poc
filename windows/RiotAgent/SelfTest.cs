using System.Diagnostics;
using System.IO;
using System.Windows;
using Riot.Agent.App.Win32;

namespace Riot.Agent.App;

/// <summary>Development aid: <c>RIOT_SELFTEST=&lt;report file&gt; RiotAgent.exe</c> checks what the
/// unit tests cannot, the real clipboard: a promise is rendered once, when another process reads
/// it; Windows keeps the rendered text; our render is not a change of content; history markers
/// are there. The user's clipboard is put back at the end.</summary>
internal static class SelfTest
{
    public static string? ReportPath => Environment.GetEnvironmentVariable("RIOT_SELFTEST") is { Length: > 0 } path ? path : null;

    public static async Task Run(Win32Clipboard clipboard, string reportPath)
    {
        var report = new List<string>();
        var failed = 0;
        void Check(bool ok, string what)
        {
            report.Add($"{(ok ? "ok  " : "FAIL")} {what}");
            if (!ok) failed++;
        }
        var changes = 0;
        clipboard.Changed += () => changes++;
        var saved = clipboard.Snapshot();
        try
        {
            clipboard.WriteTexts(new Dictionary<string, string> { [ClipboardFormats.PlainText] = "selftest original" });
            Check(clipboard.PlainText() == "selftest original", "plain text written and read back");

            var provided = 0;
            clipboard.WritePromisedText(ClipboardGuard.PromiseMarkers, () =>
            {
                provided++;
                return "selftest redacted";
            });
            var armed = clipboard.ChangeCount;
            Check(clipboard.HasFormat(ClipboardGuard.Marker), "our marker is on the clipboard");
            Check(clipboard.HasFormat("CanIncludeInClipboardHistory"), "the clipboard history marker is on the clipboard");
            Check(clipboard.HasFormat(ClipboardFormats.PlainText), "the promised text is announced");
            Check(provided == 0, "nothing rendered before a read");

            await Settle();
            var changesBefore = changes;
            var read = await ReadFromAnotherProcess();
            Check(read == "selftest redacted", $"another process reads the promised text (got \"{read}\")");
            Check(provided == 1, $"rendered once for that read (renders: {provided})");
            Check(clipboard.ChangeCount == armed, $"our render is not a change of content (count {armed} -> {clipboard.ChangeCount})");
            await Settle();
            report.Add($"     change notifications during the read: {changes - changesBefore}");

            var again = await ReadFromAnotherProcess();
            Check(again == "selftest redacted" && provided == 1, $"a second read gets the kept text without a render (renders: {provided})");

            clipboard.WritePromisedText(ClipboardGuard.PromiseMarkers, () =>
            {
                provided++;
                return "selftest re-armed";
            });
            var rearmed = await ReadFromAnotherProcess();
            Check(rearmed == "selftest re-armed" && provided == 2, $"a re-armed promise is rendered again (renders: {provided})");

            var ansi = await ReadFromAnotherProcess("[Console]::OutputEncoding=[Text.Encoding]::UTF8; Add-Type -AssemblyName System.Windows.Forms; [Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::Text)");
            Check(ansi == "selftest re-armed", $"a CF_TEXT reader gets the same text, converted by Windows (got \"{ansi}\")");
        }
        catch (Exception e)
        {
            Check(false, $"exception: {e.GetType().Name}: {e.Message}");
        }
        finally
        {
            clipboard.Restore(saved, marker: null);
            report.Add($"     the user's clipboard put back ({saved.Count} formats)");
        }
        report.Add(failed == 0 ? "PASSED" : $"FAILED ({failed})");
        await File.WriteAllLinesAsync(reportPath, report);
        Application.Current.Shutdown(failed == 0 ? 0 : 1);
    }

    /// <summary>Lets the message loop run: renders and notifications are messages.</summary>
    private static Task Settle() => Task.Delay(150);

    /// <summary>Waits without blocking the UI thread: the render request comes through its messages.</summary>
    private static async Task<string> ReadFromAnotherProcess(string script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw")
    {
        var start = new ProcessStartInfo("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script])
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
        };
        using var process = Process.Start(start)!;
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        return output.TrimEnd('\r', '\n');
    }
}
