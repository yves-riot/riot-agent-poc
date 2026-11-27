namespace Riot.Agent;

/// <summary>One representation on the clipboard, as the clipboard holds it.</summary>
public sealed record ClipboardItem(string Format, byte[] Data);

/// <summary>Format names, as <c>RegisterClipboardFormat</c> knows them; standard formats by
/// their <c>CF_</c> name.</summary>
public static class ClipboardFormats
{
    public const string PlainText = "CF_UNICODETEXT";
    public const string Html = "HTML Format";
    public const string Rtf = "Rich Text Format";
}

/// <summary>What the guard needs from the clipboard (an interface so tests can drive it).</summary>
public interface IClipboard
{
    /// <summary>Changes with every write by another app; our own reads and renders leave it as
    /// it is.</summary>
    long ChangeCount { get; }
    string? PlainText();
    bool HasFormat(string format);
    /// <summary>Every representation, to put back exactly what the user copied.</summary>
    IReadOnlyList<ClipboardItem> Snapshot();
    void Restore(IReadOnlyList<ClipboardItem> snapshot, string? marker);
    /// <summary>The representations among <paramref name="formats"/>, as text (HTML without
    /// its header).</summary>
    IReadOnlyDictionary<string, string> Texts(IEnumerable<string> formats);
    void WriteTexts(IReadOnlyDictionary<string, string> texts);
    /// <summary>Writes <paramref name="markers"/> as real data and the plain text as a promise
    /// (delayed rendering): <paramref name="provide"/> runs on the UI thread when an app
    /// actually reads the text, i.e. when it pastes.</summary>
    void WritePromisedText(IReadOnlyList<string> markers, Func<string> provide);
}

public interface IKeyboardState
{
    /// <summary>Ctrl is down right now (Ctrl+V).</summary>
    bool ShortcutKeyHeld { get; }
    /// <summary>Time since the last key event, anywhere.</summary>
    TimeSpan SinceKeyDown { get; }
}

public interface IKeystrokes
{
    /// <summary>Sends Ctrl+Z then Ctrl+V to the foreground app. False, with nothing sent, when
    /// it cannot.</summary>
    bool UndoThenPaste();
}

/// <summary>What the guard asks the daemon.</summary>
public interface IGuardBackend
{
    Task<RedactTextResult> RedactText(string text, string appId);
    Task<string> ReportPaste(string eventId);
    Task<DetokenizeResult> Detokenize(string text, string appId);
    Task ReportOverride(string pasteId);
}

/// <summary>What "paste the original" could do.</summary>
public enum OriginalOutcome
{
    /// <summary>Nothing to put back (the clipboard changed, or bypass is not allowed).</summary>
    Unavailable,
    /// <summary>The original is on the clipboard: the user undoes and pastes again.</summary>
    OnClipboard,
    /// <summary>The original is on the clipboard, but no paste of ours was seen (the HUD showed
    /// at an eager reader's read): the user pastes it, undoing first if they already had.</summary>
    OnClipboardUnseen,
    /// <summary>The redacted paste was undone and the original pasted in its place.</summary>
    Pasted,
}

/// <summary>
/// The clipboard side of the agent, the Windows counterpart of the macOS ClipboardGuard (same
/// rules, same tests):
/// <list type="bullet">
/// <item>Content is read only when a protected AI app is in the foreground: when it is activated,
/// or when the clipboard changes while it is. Elsewhere the guard never looks.</item>
/// <item>Sensitive text is redacted ahead of time, then put back on the clipboard as a promise
/// (delayed rendering): Windows asks us for the text only when an app reads it, whatever the
/// paste gesture. That read is the paste: the HUD shows and the daemon reports then. The original
/// is kept in memory only.</item>
/// <item>A read 150 ms or more after the promise was written is a paste; an earlier one is a
/// clipboard monitor or a sync reacting to our write.</item>
/// <item>Windows keeps what it rendered: the promise is written again after each read, so every
/// paste is seen. A re-armed promise counts a read as a paste only while Ctrl is held (Ctrl+V).</item>
/// <item>An early read of the first promise means an eager reader (a VM sharing its clipboard):
/// the paste to come will be served from its copy, unseen. The HUD shows at that read; not
/// re-armed.</item>
/// <item>Leaving the app puts the original back; text copied out of the app gets its tokens
/// swapped back to the real values, in plain text, HTML and RTF.</item>
/// </list>
/// All of it runs on the UI thread; steps that call the daemon are serialized.
/// </summary>
public sealed class ClipboardGuard
{
    /// <summary>Our own writes carry this format, so the next change is recognised as ours.</summary>
    public const string Marker = "Riot.Agent.Redacted";
    /// <summary>Our promises also carry the formats Windows' clipboard history, cloud clipboard and
    /// clipboard monitors honour: they skip the text without reading it.</summary>
    public static readonly IReadOnlyList<string> PromiseMarkers =
        [Marker, "ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"];
    /// <summary>Restored on a copy out of the app; other formats are dropped, they could still
    /// hold the tokens.</summary>
    public static readonly IReadOnlyList<string> TextFormats = [ClipboardFormats.PlainText, ClipboardFormats.Html, ClipboardFormats.Rtf];
    /// <summary>Readers this soon after our write are reacting to the write, not pasting.</summary>
    public static readonly TimeSpan EarlyRead = TimeSpan.FromMilliseconds(150);
    /// <summary>A key pressed later than this after the paste means the user typed: Ctrl+Z would
    /// undo their typing, not the paste.</summary>
    public static readonly TimeSpan TypedAfterPaste = TimeSpan.FromSeconds(1);

    public sealed class Swap(string appId, IReadOnlyList<ClipboardItem> original, string originalText, RedactTextResult result, string redacted)
    {
        public string AppId { get; } = appId;
        public IReadOnlyList<ClipboardItem> Original { get; } = original;
        public string OriginalText { get; } = originalText;
        public RedactTextResult Result { get; } = result;
        public string Redacted { get; } = redacted;
        /// <summary>The change count of our promise on the clipboard.</summary>
        public long ChangeCount { get; set; }
        public DateTimeOffset ArmedAt { get; set; }
        /// <summary>Pasted at least once: later promises are re-arms.</summary>
        public bool Pasted { get; set; }
        /// <summary>Silent re-arms left after reads that were not pastes (bounds a loop with an
        /// app that reads on every clipboard change).</summary>
        public int SilentRearms { get; set; } = 1;
        /// <summary>The report of the last paste, for "paste the original".</summary>
        public Task<string?>? LastPaste { get; set; }
        public DateTimeOffset? LastPasteAt { get; set; }
    }

    private readonly IClipboard clipboard;
    private readonly IGuardBackend backend;
    private readonly IKeyboardState keyboard;
    private readonly IKeystrokes keys;
    private readonly Func<DateTimeOffset> now;
    private readonly TimeSpan rearmDelay;

    private long lastSeen;
    /// <summary>The clipboard changed while a protected app was in the foreground.</summary>
    private bool copiedInside;
    private Task inFlight = Task.CompletedTask;
    /// <summary>Re-arming empties the clipboard. Done at once, it can land while the reading app
    /// is still receiving the data, and that paste then gets nothing.</summary>
    private Task pendingRearm = Task.CompletedTask;

    public ClipboardGuard(IClipboard clipboard, IGuardBackend backend, IKeyboardState keyboard, IKeystrokes keys,
        Func<DateTimeOffset>? now = null, TimeSpan? rearmDelay = null)
    {
        this.clipboard = clipboard;
        this.backend = backend;
        this.keyboard = keyboard;
        this.keys = keys;
        this.now = now ?? (() => DateTimeOffset.Now);
        this.rearmDelay = rearmDelay ?? TimeSpan.FromMilliseconds(500);
        lastSeen = clipboard.ChangeCount;
    }

    /// <summary>The protected apps' ids, case-insensitive.</summary>
    public IReadOnlySet<string> Targets { get; set; } = new HashSet<string>();
    /// <summary>This app: its popup taking the foreground is not leaving the AI app.</summary>
    public string? OwnAppId { get; set; }
    /// <summary>A paste of redacted text into a protected app: show the HUD.</summary>
    public event Action<RedactTextResult, string>? Pasted;
    /// <summary>Events and timings only, never clipboard content.</summary>
    public Action<string>? Log { get; set; }

    public string? Foreground { get; private set; }
    public Swap? Current { get; private set; }

    private bool IsTarget(string? appId) => appId is not null && Targets.Contains(appId);
    private static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private bool IsTargetForeground => IsTarget(Foreground);

    // ---------- events ----------

    public void Activated(string? appId)
    {
        if (appId is not null && Same(appId, OwnAppId)) return;
        var previous = Foreground;
        if (Same(appId, previous)) return;
        Log?.Invoke($"activate {appId ?? "-"}");
        // A copy made just before switching, not handled yet, belongs to the app being left:
        // without this, Ctrl+C then Alt+Tab would skip its detokenization.
        NoteClipboardChange();
        Foreground = appId;
        Enqueue(async () =>
        {
            if (IsTarget(previous)) await Leave(previous!);
            if (IsTarget(appId)) await Inspect(appId!);
        });
    }

    public void ClipboardChanged()
    {
        if (!NoteClipboardChange() || Foreground is not { } appId) return;
        // New content while the AI app is in the foreground: an answer copied out, or a background copy.
        Enqueue(() => Inspect(appId));
    }

    /// <summary>Records a clipboard change. True when it is new content (not ours) while a
    /// protected app is in the foreground.</summary>
    private bool NoteClipboardChange()
    {
        var count = clipboard.ChangeCount;
        if (count == lastSeen) return false;
        lastSeen = count;
        if (!IsTargetForeground) return false;
        if (clipboard.HasFormat(Marker)) return false;
        if (Current is { } swap && clipboard.PlainText() == swap.Redacted)
        {
            // A clipboard sync writing our text back: still ours, with the original to restore.
            Log?.Invoke("echo of the redacted text adopted");
            swap.ChangeCount = count;
            return false;
        }
        copiedInside = true;
        Current = null;
        return true;
    }

    /// <summary>Runs <paramref name="step"/> after the steps before it, never within the caller:
    /// an event handler returns before its step runs (a leave must not beat a "paste the
    /// original" clicked in the meantime).</summary>
    private void Enqueue(Func<Task> step)
    {
        var previous = inFlight;
        inFlight = Run();

        async Task Run()
        {
            await Task.Yield();
            await previous;
            try
            {
                await step();
            }
            catch (Exception e)
            {
                Log?.Invoke($"step failed: {e.GetType().Name}");
            }
        }
    }

    /// <summary>Until no step and no re-arm is pending (a step may enqueue another one).</summary>
    public async Task WaitIdle()
    {
        while (true)
        {
            var (step, rearm) = (inFlight, pendingRearm);
            await step;
            await rearm;
            if (step == inFlight && rearm == pendingRearm) return;
        }
    }

    // ---------- steps ----------

    private async Task Inspect(string appId)
    {
        if (clipboard.HasFormat(Marker) || clipboard.PlainText() is not { Length: > 0 } text) return;
        var countAtRead = clipboard.ChangeCount;
        var original = clipboard.Snapshot();
        RedactTextResult result;
        try
        {
            result = await backend.RedactText(text, appId);
        }
        catch (Exception)
        {
            return; // no daemon, no decision: the clipboard is left as it is
        }
        Log?.Invoke($"inspect {result.Action}");
        // The user copied something else meanwhile, or left the app: that newer state wins.
        if (result.Action != "redacted" || result.Text is not { } redacted
            || clipboard.ChangeCount != countAtRead || !Same(Foreground, appId)) return;
        Current = new Swap(appId, original, text, result, redacted) { ArmedAt = now() };
        Arm();
    }

    /// <summary>Puts (back) the promise of the redacted text on the clipboard.</summary>
    private void Arm()
    {
        if (Current is not { } swap) return;
        var (redacted, original) = (swap.Redacted, swap.OriginalText);
        clipboard.WritePromisedText(PromiseMarkers, () => Provide(redacted, original));
        swap.ChangeCount = clipboard.ChangeCount;
        swap.ArmedAt = now();
        lastSeen = swap.ChangeCount;
    }

    /// <summary>An app reads our promise. Answer at once (it is waiting), decide what the read
    /// was after.</summary>
    private string Provide(string redacted, string original)
    {
        // Safety net, should the read beat the leave step: a non-protected app gets the original.
        if (Foreground is { } reader && !IsTarget(reader)) return original;
        var (count, readAt, held) = (clipboard.ChangeCount, now(), keyboard.ShortcutKeyHeld);
        Enqueue(() =>
        {
            ClassifyRead(count, readAt, held);
            return Task.CompletedTask;
        });
        return redacted;
    }

    private void ClassifyRead(long changeCount, DateTimeOffset readAt, bool shortcutHeld)
    {
        if (Current is not { } swap || swap.ChangeCount != changeCount || !Same(Foreground, swap.AppId)
            || clipboard.ChangeCount != changeCount) return;
        var sinceArm = readAt - swap.ArmedAt;
        var early = sinceArm < EarlyRead;
        if (early && !swap.Pasted)
        {
            Log?.Invoke($"read {sinceArm.TotalMilliseconds:F0} ms after arm: eager reader, shown now");
            Report(swap);
            Pasted?.Invoke(swap.Result, swap.AppId);
            return;
        }
        var pasted = !early && (!swap.Pasted || shortcutHeld);
        Log?.Invoke($"read {sinceArm.TotalMilliseconds:F0} ms after arm, ctrl={shortcutHeld}, rearm={swap.Pasted}: {(pasted ? "paste" : "not a paste")}");
        if (pasted)
        {
            Report(swap);
            swap.Pasted = true;
            swap.LastPasteAt = readAt;
            swap.SilentRearms = 1;
            Pasted?.Invoke(swap.Result, swap.AppId);
            ScheduleRearm(changeCount); // Windows keeps what it rendered: re-arm to see the next paste
        }
        else if (swap.SilentRearms > 0)
        {
            swap.SilentRearms -= 1;
            ScheduleRearm(changeCount);
        }
    }

    private void Report(Swap swap)
    {
        if (swap.Result.EventId is not { } eventId) return;
        swap.LastPaste = ReportPaste();

        async Task<string?> ReportPaste()
        {
            try
            {
                return await backend.ReportPaste(eventId);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

    /// <summary>Re-arms once the reading app has its data, if our promise is still the
    /// clipboard. A paste within the delay gets the kept text, without a HUD of its own.</summary>
    private void ScheduleRearm(long changeCount)
    {
        pendingRearm = Rearm();

        async Task Rearm()
        {
            if (rearmDelay > TimeSpan.Zero) await Task.Delay(rearmDelay);
            else await Task.Yield();
            // A promise put back or replaced meanwhile has another change count: nothing to cancel.
            if (Current is not { } swap || swap.ChangeCount != changeCount
                || clipboard.ChangeCount != changeCount || !Same(Foreground, swap.AppId)) return;
            Arm();
        }
    }

    private async Task Leave(string appId)
    {
        try
        {
            if (Current is { } swap && Same(swap.AppId, appId))
            {
                Current = null;
                if (clipboard.ChangeCount == swap.ChangeCount)
                {
                    // Still our redacted text: give the user their original back.
                    clipboard.Restore(swap.Original, marker: null);
                    lastSeen = clipboard.ChangeCount;
                }
            }
            if (copiedInside) await RestoreValues(appId);
        }
        finally
        {
            copiedInside = false;
        }
    }

    /// <summary>An answer copied inside the app may carry tokens: hand out the real values, in
    /// each text format with its own escaping, so a paste into Outlook or Word keeps the
    /// formatting.</summary>
    private async Task RestoreValues(string appId)
    {
        var texts = clipboard.Texts(TextFormats);
        var tokens = texts.Values.SelectMany(Tokens.In).ToHashSet();
        if (tokens.Count == 0) return;
        var countAtRead = clipboard.ChangeCount;
        var values = new Dictionary<string, string>();
        foreach (var token in tokens)
        {
            try
            {
                var result = await backend.Detokenize(token, appId);
                if (result.Replaced > 0) values[token] = result.Text;
            }
            catch (Exception)
            {
                // left as a token
            }
        }
        if (values.Count == 0 || clipboard.ChangeCount != countAtRead) return;
        var restored = texts.ToDictionary(t => t.Key, t => Tokens.Replace(t.Value, values, Escape(t.Key)));
        clipboard.WriteTexts(restored);
        lastSeen = clipboard.ChangeCount;
        Log?.Invoke($"copy out: {values.Count} token(s) restored in {restored.Count} format(s)");
    }

    private static Func<string, string> Escape(string format) => format switch
    {
        ClipboardFormats.Html => Tokens.EscapeHtml,
        ClipboardFormats.Rtf => Tokens.EscapeRtf,
        _ => s => s,
    };

    /// <summary>"Paste without redaction", after the user confirmed: the original goes back on
    /// the clipboard for this app, and the last paste is re-reported as not redacted. Then, if
    /// the app is still in the foreground (the HUD does not take focus) and the user has not
    /// typed since the paste, Ctrl+Z undoes the redacted paste and Ctrl+V pastes the original.</summary>
    public OriginalOutcome PasteOriginal()
    {
        if (Current is not { } swap || !swap.Result.AllowBypass || clipboard.ChangeCount != swap.ChangeCount)
            return OriginalOutcome.Unavailable;
        Current = null;
        clipboard.Restore(swap.Original, Marker); // marked: not inspected again
        lastSeen = clipboard.ChangeCount;
        if (swap.LastPaste is { } lastPaste) _ = Override(lastPaste);
        if (swap.LastPasteAt is not { } pastedAt) return OriginalOutcome.OnClipboardUnseen;
        if (!Same(Foreground, swap.AppId)) return OriginalOutcome.OnClipboard;
        if ((now() - pastedAt) - keyboard.SinceKeyDown >= TypedAfterPaste)
        {
            Log?.Invoke("original on the clipboard: typed after the paste");
            return OriginalOutcome.OnClipboard;
        }
        if (!keys.UndoThenPaste())
        {
            Log?.Invoke("original on the clipboard: keys could not be sent");
            return OriginalOutcome.OnClipboard;
        }
        Log?.Invoke("original pasted over the redacted paste");
        return OriginalOutcome.Pasted;

        async Task Override(Task<string?> report)
        {
            try
            {
                if (await report is { } pasteId) await backend.ReportOverride(pasteId);
            }
            catch (Exception)
            {
                // the redacted report stands
            }
        }
    }
}
