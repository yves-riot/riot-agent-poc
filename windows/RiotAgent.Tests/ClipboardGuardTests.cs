using System.Text;
using Xunit;
using static Riot.Agent.ClipboardFormats;

namespace Riot.Agent.Tests;

/// <summary>Stands in for the Windows clipboard. Like delayed rendering, the promise is resolved
/// once and the answer kept.</summary>
internal sealed class FakeClipboard : IClipboard
{
    public long ChangeCount { get; private set; } = 1;
    public Dictionary<string, string> Item { get; private set; } = [];
    private Func<string>? promise;
    /// <summary>Content reads.</summary>
    public int ContentReads { get; private set; }

    public void Copy(string text, bool rich = false)
    {
        var item = new Dictionary<string, string> { [ClipboardFormats.PlainText] = text };
        if (rich) item[Rtf] = $@"{{\rtf1 {text}}}";
        Copy(item);
    }

    public void Copy(Dictionary<string, string> item)
    {
        Item = item;
        promise = null;
        ChangeCount++;
    }

    /// <summary>Another app reads the text, e.g. to paste it.</summary>
    public string? SimulateRead()
    {
        if (promise is { } provide)
        {
            promise = null;
            Item[ClipboardFormats.PlainText] = provide();
        }
        return Text(ClipboardFormats.PlainText);
    }

    public string? Text(string format) => Item.GetValueOrDefault(format);
    public bool IsPromised => promise is not null;

    public string? PlainText()
    {
        ContentReads++;
        return SimulateRead();
    }

    public bool HasFormat(string format) => Item.ContainsKey(format);

    public IReadOnlyList<ClipboardItem> Snapshot()
    {
        ContentReads++;
        return Item.Select(i => new ClipboardItem(i.Key, Encoding.UTF8.GetBytes(i.Value))).ToList();
    }

    public void Restore(IReadOnlyList<ClipboardItem> snapshot, string? marker)
    {
        Item = snapshot.ToDictionary(i => i.Format, i => Encoding.UTF8.GetString(i.Data));
        if (marker is not null && Item.Count > 0) Item[marker] = "";
        promise = null;
        ChangeCount++;
    }

    public IReadOnlyDictionary<string, string> Texts(IEnumerable<string> formats)
    {
        ContentReads++;
        return formats.Where(Item.ContainsKey).ToDictionary(f => f, f => Item[f]);
    }

    public void WriteTexts(IReadOnlyDictionary<string, string> texts) => Copy(texts.ToDictionary());

    public void WritePromisedText(IReadOnlyList<string> markers, Func<string> provide)
    {
        Item = markers.ToDictionary(m => m, _ => "");
        promise = provide;
        ChangeCount++;
    }
}

internal sealed class FakeKeyboard : IKeyboardState
{
    public bool ShortcutKeyHeld { get; set; }
    public TimeSpan SinceKeyDown { get; set; } = TimeSpan.FromSeconds(1000);
}

internal sealed class FakeKeystrokes : IKeystrokes
{
    public bool Allowed { get; set; } = true;
    public int Sent { get; private set; }

    public bool UndoThenPaste()
    {
        if (Allowed) Sent++;
        return Allowed;
    }
}

/// <summary>Stands in for the daemon: redacts one IBAN, remembers the tokens.</summary>
internal sealed class FakeBackend : IGuardBackend
{
    public const string Iban = "FR76 3000 6000 0112 3456 7890 189";
    public static readonly Dictionary<string, string> Vault = new() { ["[IBAN_1]"] = Iban, ["[NAME_1]"] = "Zoé <Dupont> & {Cie}" };
    public int RedactCalls { get; private set; }
    public List<string> Pastes { get; } = [];
    public List<string> Overrides { get; } = [];
    public Action? OnRedact { get; set; }

    public Task<RedactTextResult> RedactText(string text, string appId)
    {
        RedactCalls++;
        OnRedact?.Invoke();
        if (!text.Contains(Iban)) return Task.FromResult(new RedactTextResult("clean", null, [], null, true));
        return Task.FromResult(new RedactTextResult("redacted", text.Replace(Iban, "[IBAN_1]"),
            [new TypeCount("iban", "redaction.flag.iban", 1)], "ev-1", true));
    }

    public Task<string> ReportPaste(string eventId)
    {
        Pastes.Add(eventId);
        return Task.FromResult($"paste-{Pastes.Count}");
    }

    public Task<DetokenizeResult> Detokenize(string text, string appId)
    {
        var out_ = Vault.Aggregate(text, (t, v) => t.Replace(v.Key, v.Value));
        return Task.FromResult(new DetokenizeResult(out_, out_ == text ? 0 : 1));
    }

    public Task ReportOverride(string pasteId)
    {
        Overrides.Add(pasteId);
        return Task.CompletedTask;
    }
}

public sealed class ClipboardGuardTests
{
    private const string ChatGpt = "chatgpt.exe";
    private const string Claude = "claude.exe";
    private const string Own = "riotagent.exe";
    private readonly FakeClipboard pb = new();
    private readonly FakeBackend backend = new();
    private readonly FakeKeyboard keyboard = new();
    private readonly FakeKeystrokes keys = new();
    private DateTimeOffset clock = DateTimeOffset.FromUnixTimeSeconds(1_000_000);
    private ClipboardGuard guardian;
    private int pastedEvents;

    public ClipboardGuardTests() => guardian = MakeGuard(TimeSpan.Zero);

    private ClipboardGuard MakeGuard(TimeSpan rearmDelay)
    {
        var made = new ClipboardGuard(pb, backend, keyboard, keys, () => clock, rearmDelay)
        {
            Targets = new HashSet<string>([ChatGpt, Claude], StringComparer.OrdinalIgnoreCase),
            OwnAppId = Own,
        };
        made.Pasted += (_, _) => pastedEvents++;
        return made;
    }

    private string? Text() => pb.Text(PlainText);

    /// <summary>An app reads <paramref name="after"/> from now, Ctrl held or not.</summary>
    private async Task<string?> Read(double after, bool ctrl)
    {
        clock = clock.AddSeconds(after);
        keyboard.ShortcutKeyHeld = ctrl;
        var read = pb.SimulateRead();
        await guardian.WaitIdle();
        return read;
    }

    /// <summary>A Ctrl+V a moment later.</summary>
    private Task<string?> Paste() => Read(2, ctrl: true);

    private async Task CopyIbanAndActivate(string app = ChatGpt)
    {
        pb.Copy($"Mon IBAN {FakeBackend.Iban}", rich: true);
        guardian.Activated(app);
        await guardian.WaitIdle();
    }

    private static Task Settle() => Task.Delay(20);

    // ---------- paste detection ----------

    [Fact]
    public void ActivationAloneShowsNothingButPromisesTheRedactedText() => SingleThread.Run(async () =>
    {
        guardian.Activated("outlook.exe");
        pb.Copy($"Mon IBAN {FakeBackend.Iban}", rich: true);
        guardian.ClipboardChanged();
        await guardian.WaitIdle();
        Assert.Equal(0, pb.ContentReads); // never reads while a non-protected app is in front

        guardian.Activated(ChatGpt);
        await guardian.WaitIdle();
        Assert.True(pb.IsPromised);
        Assert.True(pb.HasFormat(ClipboardGuard.Marker));
        Assert.True(pb.HasFormat("CanIncludeInClipboardHistory")); // Win+V history skips it
        Assert.Null(pb.Text(Rtf)); // rich formats would leak the value
        Assert.Equal(0, pastedEvents);
        Assert.Empty(backend.Pastes);

        // Our own write is not inspected again.
        guardian.ClipboardChanged();
        await guardian.WaitIdle();
        Assert.Equal(1, backend.RedactCalls);
    });

    [Fact]
    public void EachPasteShowsTheHudAndIsReported() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        Assert.Equal("Mon IBAN [IBAN_1]", await Paste());
        Assert.Equal(1, pastedEvents);
        await Settle();
        Assert.Equal(["ev-1"], backend.Pastes);
        Assert.True(pb.IsPromised); // re-armed for the next paste

        Assert.Equal("Mon IBAN [IBAN_1]", await Paste());
        Assert.Equal(2, pastedEvents);
        await Settle();
        Assert.Equal(["ev-1", "ev-1"], backend.Pastes);
    });

    [Fact]
    public void TheFirstPasteNeedsNoShortcutKey() => SingleThread.Run(async () =>
    {
        // Edit > Paste or the context menu: no Ctrl, the read still comes well after our write.
        await CopyIbanAndActivate(Claude);
        await Read(0.3, ctrl: false);
        Assert.Equal(1, pastedEvents);
    });

    [Fact]
    public void AnEagerReaderShowsTheHudAtOnce() => SingleThread.Run(async () =>
    {
        // A VM sharing its clipboard reads each write within 100 ms: the paste to come is
        // served from its copy, unseen.
        await CopyIbanAndActivate(Claude);
        Assert.Equal("Mon IBAN [IBAN_1]", await Read(0.07, ctrl: false));
        Assert.Equal(1, pastedEvents);
        await Settle();
        Assert.Equal(["ev-1"], backend.Pastes);
        Assert.False(pb.IsPromised); // not re-armed: the reader would spend it again

        await Paste(); // from the kept text
        Assert.Equal(1, pastedEvents);
        Assert.Equal(["ev-1"], backend.Pastes);
    });

    [Fact]
    public void TheEagerReadersEchoIsStillOurs() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate(Claude);
        await Read(0.07, ctrl: false);
        pb.Copy("Mon IBAN [IBAN_1]"); // the VM writes it back, unmarked
        guardian.ClipboardChanged();
        await guardian.WaitIdle();
        Assert.Equal(1, backend.RedactCalls);
        Assert.NotNull(guardian.Current);
        Assert.False(pb.IsPromised);

        guardian.Activated("notepad.exe");
        await guardian.WaitIdle();
        Assert.Equal($"Mon IBAN {FakeBackend.Iban}", Text());
        Assert.NotNull(pb.Text(Rtf)); // the original, not a detokenized echo
    });

    [Fact]
    public void PasteOriginalAfterAnEagerReaderSendsNoKeys() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate(Claude);
        await Read(0.07, ctrl: false);
        pb.Copy("Mon IBAN [IBAN_1]"); // echo
        guardian.ClipboardChanged();
        await guardian.WaitIdle();
        clock = clock.AddSeconds(3);
        Assert.Equal(OriginalOutcome.OnClipboardUnseen, guardian.PasteOriginal());
        Assert.Equal(0, keys.Sent); // no paste seen: Ctrl+Z could undo something else
        Assert.Equal($"Mon IBAN {FakeBackend.Iban}", Text());
        await Settle();
        Assert.Equal(["paste-1"], backend.Overrides);
    });

    [Fact]
    public void AReadOfTheReArmedPromiseWithoutCtrlIsNotAPaste() => SingleThread.Run(async () =>
    {
        // After a paste, a clipboard monitor reads each re-armed promise: no HUD loop.
        await CopyIbanAndActivate();
        await Paste();
        await Read(0.6, ctrl: false);
        Assert.Equal(1, pastedEvents);
    });

    [Fact]
    public void PastesReadLateAreStillPastes() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate(Claude);
        await Read(1.2, ctrl: true);
        await Read(1.7, ctrl: true);
        Assert.Equal(2, pastedEvents);
    });

    [Fact]
    public void AReadOnceTheAppIsLeftGetsTheOriginal() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        // The paste in Notepad beats the queued restore: the promise still answers.
        guardian.Activated("notepad.exe");
        Assert.Equal($"Mon IBAN {FakeBackend.Iban}", pb.SimulateRead());
        await guardian.WaitIdle();
        Assert.Equal(0, pastedEvents);
    });

    // ---------- leaving, copy out ----------

    [Fact]
    public void LeavingTheAppRestoresTheOriginal() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        guardian.Activated("notepad.exe");
        await guardian.WaitIdle();
        Assert.Equal($"Mon IBAN {FakeBackend.Iban}", Text());
        Assert.NotNull(pb.Text(Rtf)); // exactly what the user copied
        Assert.False(pb.HasFormat(ClipboardGuard.Marker));
    });

    [Fact]
    public void AnAnswerCopiedInsideTheAppIsDetokenizedOnLeaving() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        pb.Copy("Virement prêt vers [IBAN_1].");
        guardian.ClipboardChanged();
        await guardian.WaitIdle();
        guardian.Activated("outlook.exe");
        await guardian.WaitIdle();
        Assert.Equal($"Virement prêt vers {FakeBackend.Iban}.", Text());
    });

    [Fact]
    public void ACopyFollowedAtOnceByASwitchIsDetokenized() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        pb.Copy("Virement prêt vers [IBAN_1].");
        // Ctrl+C then Alt+Tab before the change notification is handled.
        guardian.Activated("outlook.exe");
        await guardian.WaitIdle();
        Assert.Equal($"Virement prêt vers {FakeBackend.Iban}.", Text());
    });

    [Fact]
    public void ARichCopyIsRestoredInEveryFormat() => SingleThread.Run(async () =>
    {
        guardian.Activated(Claude);
        await guardian.WaitIdle();
        // Claude's copy: markdown escapes in the plain text, HTML and RTF alongside.
        pb.Copy(new Dictionary<string, string>
        {
            [PlainText] = @"Pour \[NAME\_1\] : [IBAN_1]",
            [Html] = "<p>Pour [NAME_1] : <b>[IBAN_1]</b></p>",
            [Rtf] = @"{\rtf1 Pour [NAME_1] : [IBAN_1]}",
            ["Chromium Web Custom MIME Data Format"] = "[IBAN_1]",
        });
        guardian.Activated("outlook.exe");
        await guardian.WaitIdle();
        Assert.Equal($"Pour Zoé <Dupont> & {{Cie}} : {FakeBackend.Iban}", Text());
        Assert.Equal($"<p>Pour Zoé &lt;Dupont&gt; &amp; {{Cie}} : <b>{FakeBackend.Iban}</b></p>", pb.Text(Html));
        Assert.Equal(@"{\rtf1 Pour Zo\u233? <Dupont> & \{Cie\} : " + FakeBackend.Iban + "}", pb.Text(Rtf));
        Assert.False(pb.HasFormat("Chromium Web Custom MIME Data Format")); // could still hold the tokens
    });

    // ---------- races, bypass ----------

    [Fact]
    public void CleanTextIsLeftAlone() => SingleThread.Run(async () =>
    {
        pb.Copy("Bonjour, peux-tu résumer ce texte ?");
        var before = pb.ChangeCount;
        guardian.Activated(ChatGpt);
        await guardian.WaitIdle();
        Assert.Equal(before, pb.ChangeCount);
        Assert.False(pb.IsPromised);
    });

    [Fact]
    public void ANewerCopyWinsOverAnInFlightRedaction() => SingleThread.Run(async () =>
    {
        pb.Copy($"Mon IBAN {FakeBackend.Iban}");
        backend.OnRedact = () => pb.Copy("autre chose"); // the user copies again meanwhile
        guardian.Activated(ChatGpt);
        await guardian.WaitIdle();
        Assert.Equal("autre chose", Text());
        Assert.False(pb.IsPromised);
    });

    [Fact]
    public void PasteOriginalPutsItBackAndOverridesTheLastPaste() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        await Paste();
        clock = clock.AddSeconds(5); // reading the HUD, clicking through the confirmation
        Assert.Equal(OriginalOutcome.Pasted, guardian.PasteOriginal());
        Assert.Equal(1, keys.Sent); // Ctrl+Z then Ctrl+V over the redacted paste
        Assert.Equal($"Mon IBAN {FakeBackend.Iban}", Text());
        guardian.ClipboardChanged();
        await guardian.WaitIdle();
        Assert.Equal(1, backend.RedactCalls); // the original the user chose is not redacted again
        await Settle();
        Assert.Equal(["paste-1"], backend.Overrides);
    });

    [Fact]
    public void PasteOriginalLeavesItOnTheClipboardIfTheUserTypedSinceThePaste() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        await Paste();
        clock = clock.AddSeconds(5);
        keyboard.SinceKeyDown = TimeSpan.FromSeconds(2); // a key 3 s after the paste: Ctrl+Z would undo it
        Assert.Equal(OriginalOutcome.OnClipboard, guardian.PasteOriginal());
        Assert.Equal(0, keys.Sent);
        Assert.Equal($"Mon IBAN {FakeBackend.Iban}", Text());
    });

    [Fact]
    public void PasteOriginalWhenKeysCannotBeSentLeavesItOnTheClipboard() => SingleThread.Run(async () =>
    {
        keys.Allowed = false; // e.g. the AI app runs elevated
        await CopyIbanAndActivate();
        await Paste();
        keyboard.SinceKeyDown = TimeSpan.FromSeconds(0.5); // the Ctrl+V itself
        Assert.Equal(OriginalOutcome.OnClipboard, guardian.PasteOriginal());
        Assert.Equal($"Mon IBAN {FakeBackend.Iban}", Text());
    });

    [Fact]
    public void PasteOriginalSendsNoKeysToAnotherApp() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        await Paste();
        guardian.Activated("notepad.exe"); // the leave step has not run yet
        Assert.Equal(OriginalOutcome.OnClipboard, guardian.PasteOriginal());
        Assert.Equal(0, keys.Sent); // Ctrl+Z in Notepad would undo something else
    });

    [Fact]
    public void TheReArmWaitsUntilTheReadingAppHasItsData() => SingleThread.Run(async () =>
    {
        guardian = MakeGuard(TimeSpan.FromMilliseconds(200));
        await CopyIbanAndActivate();
        clock = clock.AddSeconds(2);
        keyboard.ShortcutKeyHeld = true;
        Assert.Equal("Mon IBAN [IBAN_1]", pb.SimulateRead());
        await Task.Delay(50);
        Assert.Equal(1, pastedEvents); // the HUD does not wait
        Assert.False(pb.IsPromised); // emptying the clipboard now could empty the paste in progress
        Assert.Equal("Mon IBAN [IBAN_1]", Text());
        await guardian.WaitIdle();
        Assert.True(pb.IsPromised);
    });

    [Fact]
    public void ACopyDuringTheReArmDelayIsKept() => SingleThread.Run(async () =>
    {
        guardian = MakeGuard(TimeSpan.FromMilliseconds(200));
        await CopyIbanAndActivate();
        clock = clock.AddSeconds(2);
        keyboard.ShortcutKeyHeld = true;
        pb.SimulateRead(); // a paste: re-arm pending
        await Task.Delay(50);
        pb.Copy("autre chose"); // the user copies something else meanwhile
        await guardian.WaitIdle();
        Assert.Equal("autre chose", Text());
        Assert.False(pb.IsPromised);
    });

    [Fact]
    public void OwnPopupTakingFocusIsNotLeavingTheApp() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate();
        guardian.Activated(Own);
        await guardian.WaitIdle();
        Assert.Equal(ChatGpt, guardian.Foreground);
        Assert.True(pb.IsPromised);
        Assert.Equal("Mon IBAN [IBAN_1]", await Paste());
    });

    [Fact]
    public void AppIdsAreCaseInsensitive() => SingleThread.Run(async () =>
    {
        await CopyIbanAndActivate("Claude.EXE");
        Assert.True(pb.IsPromised);
    });
}

public sealed class FormatTests
{
    [Fact]
    public void Escaping()
    {
        Assert.Equal("a&lt;b&gt;&amp;&quot;c&quot;", Tokens.EscapeHtml("a<b>&\"c\""));
        Assert.Equal(@"a\{b\}\\c\u233?\u-10179?\u-8704?", Tokens.EscapeRtf("a{b}\\cé\U0001F600"));
        Assert.Equal(["[EMAIL_1]", "[API_KEY_2]"], Tokens.In(@"[EMAIL_1], \[API\_KEY\_2\] et [x_1]"));
    }

    [Fact]
    public void HtmlFormatOffsetsFollowTheText()
    {
        var html = "<html><body><!--StartFragment--><b>Zoé</b><!--EndFragment--></body></html>";
        var data = CfHtml.Encode(html);
        Assert.Equal(html, CfHtml.Decode(data));
        var text = Encoding.UTF8.GetString(data);
        int Field(string name) => int.Parse(text[(text.IndexOf(name) + name.Length)..].Split('\r')[0]);
        var fragment = Encoding.UTF8.GetString(data, Field("StartFragment:"), Field("EndFragment:") - Field("StartFragment:"));
        Assert.Equal("<b>Zoé</b>", fragment);
        Assert.Equal(data.Length, Field("EndHTML:"));
        // A fragment without markers is wrapped.
        Assert.Contains("<!--StartFragment-->x<!--EndFragment-->", CfHtml.Decode(CfHtml.Encode("x")));
    }

    [Fact]
    public void StringsComeFromTheExtensionThenTheAgent()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"riot-l10n-{Environment.ProcessId}");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "fr.json"), """{"popup":{"redactions":{"title":"Aucune | {count} donnée | {count} données"}}}""");
        File.WriteAllText(Path.Combine(dir, "en.json"), """{"only":{"en":"English"}}""");
        var l = new L10n("fr", dir);
        Assert.Equal("3 données", l.T("popup.redactions.title", 3, ("count", "3")));
        Assert.Equal("Aucune", l.T("popup.redactions.title", 0));
        Assert.Equal("English", l.T("only.en"));
        Assert.Equal("Quitter", l.T("agent.quit"));
        Assert.Equal("missing.key", l.T("missing.key"));
        Assert.Equal("en", new L10n("de", dir).Language);
    }
}
