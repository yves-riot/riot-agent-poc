using System.Runtime.InteropServices;
using System.Text;
using static Riot.Agent.App.Win32.Native;

namespace Riot.Agent.App.Win32;

/// <summary>
/// The Windows clipboard for the guard. Change notifications come from
/// <c>AddClipboardFormatListener</c>; the redacted text is a delayed render
/// (<c>SetClipboardData(CF_UNICODETEXT, NULL)</c>): Windows sends <c>WM_RENDERFORMAT</c> to our
/// window when an app reads it, and keeps what we render.
/// </summary>
internal sealed class Win32Clipboard : IClipboard, IDisposable
{
    /// <summary>Handles that are not global memory (GDI objects, owner display): not copied.</summary>
    private static readonly HashSet<uint> NotMemory = [2, 3, 9, 14, 0x80, 0x82, 0x83, 0x8E];
    private readonly MessageWindow window;
    private Func<string>? promise;
    /// <summary>Sequence numbers our own renders produced, each mapped to the one before: a render
    /// is not a change of content.</summary>
    private readonly Dictionary<uint, uint> renderAliases = [];

    public Win32Clipboard(MessageWindow window)
    {
        this.window = window;
        window.AddHook(Hook);
        AddClipboardFormatListener(window.Handle);
    }

    /// <summary>The clipboard changed (another app's write, or ours).</summary>
    public event Action? Changed;
    /// <summary>Diagnostics: format ids and timings, never content.</summary>
    public Action<string>? Log { get; set; }

    public long ChangeCount
    {
        get
        {
            var seq = GetClipboardSequenceNumber();
            return renderAliases.TryGetValue(seq, out var before) ? before : seq;
        }
    }

    private IntPtr Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        switch (msg)
        {
            case WM_CLIPBOARDUPDATE:
                Changed?.Invoke();
                break;
            case WM_RENDERFORMAT:
                // An app reads our promise: the clipboard is open by the reader, write only.
                Render((uint)wParam);
                handled = true;
                break;
            case WM_RENDERALLFORMATS:
                // We are going away while owning a promise: leave its text behind.
                if (Open())
                {
                    try
                    {
                        if (GetClipboardOwner() == window.Handle) Render(CF_UNICODETEXT);
                    }
                    finally
                    {
                        CloseClipboard();
                    }
                }
                handled = true;
                break;
            case WM_DESTROYCLIPBOARD:
                promise = null; // emptied by someone else: nothing of ours left to render
                break;
        }
        return IntPtr.Zero;
    }

    private void Render(uint format)
    {
        if (format != CF_UNICODETEXT || promise is not { } provide) return;
        var before = GetClipboardSequenceNumber();
        var text = provide();
        SetData(CF_UNICODETEXT, Encoding.Unicode.GetBytes(text + "\0"));
        var after = GetClipboardSequenceNumber();
        if (after != before) renderAliases[after] = renderAliases.GetValueOrDefault(before, before);
        Log?.Invoke($"rendered (seq {before} -> {after})");
    }

    public string? PlainText() => Texts([ClipboardFormats.PlainText]).GetValueOrDefault(ClipboardFormats.PlainText);

    public bool HasFormat(string format) => IsClipboardFormatAvailable(Id(format));

    public IReadOnlyList<ClipboardItem> Snapshot()
    {
        var items = new List<ClipboardItem>();
        if (!Open()) return items;
        try
        {
            for (var format = EnumClipboardFormats(0); format != 0; format = EnumClipboardFormats(format))
            {
                if (NotMemory.Contains(format) || format is >= 0x200 and < 0x400) continue;
                if (Read(format) is { } data) items.Add(new ClipboardItem(Name(format), data));
            }
        }
        finally
        {
            CloseClipboard();
        }
        return items;
    }

    public void Restore(IReadOnlyList<ClipboardItem> snapshot, string? marker) => Write(() =>
    {
        foreach (var item in snapshot) SetData(Id(item.Format), item.Data);
        if (marker is not null) SetData(Id(marker), new byte[4]);
    });

    public IReadOnlyDictionary<string, string> Texts(IEnumerable<string> formats)
    {
        var texts = new Dictionary<string, string>();
        if (!Open()) return texts;
        try
        {
            foreach (var format in formats)
            {
                if (IsClipboardFormatAvailable(Id(format)) && Read(Id(format)) is { } data) texts[format] = Decode(format, data);
            }
        }
        finally
        {
            CloseClipboard();
        }
        return texts;
    }

    public void WriteTexts(IReadOnlyDictionary<string, string> texts) => Write(() =>
    {
        foreach (var (format, text) in texts) SetData(Id(format), Encode(format, text));
    });

    public void WritePromisedText(IReadOnlyList<string> markers, Func<string> provide) => Write(() =>
    {
        // DWORD 0: "no" for CanIncludeInClipboardHistory and CanUploadToCloudClipboard; the
        // other markers only need to be present.
        foreach (var marker in markers) SetData(Id(marker), new byte[4]);
        SetClipboardData(CF_UNICODETEXT, IntPtr.Zero);
        promise = provide;
    });

    /// <summary>Empties the clipboard (we become its owner) and writes.</summary>
    private void Write(Action write)
    {
        if (!Open())
        {
            Log?.Invoke("clipboard busy: write skipped");
            return;
        }
        try
        {
            EmptyClipboard();
            promise = null;
            renderAliases.Clear();
            write();
        }
        finally
        {
            CloseClipboard();
        }
    }

    /// <summary>Another app may hold the clipboard for a moment.</summary>
    private bool Open()
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            if (OpenClipboard(window.Handle)) return true;
            Thread.Sleep(10);
        }
        return false;
    }

    private static byte[]? Read(uint format)
    {
        var handle = GetClipboardData(format);
        if (handle == IntPtr.Zero) return null;
        var size = (int)GlobalSize(handle);
        var pointer = GlobalLock(handle);
        if (pointer == IntPtr.Zero) return null;
        try
        {
            var data = new byte[size];
            Marshal.Copy(pointer, data, 0, size);
            return data;
        }
        finally
        {
            GlobalUnlock(handle);
        }
    }

    /// <summary>The clipboard owns the memory once <c>SetClipboardData</c> succeeds.</summary>
    private static void SetData(uint format, byte[] data)
    {
        var handle = GlobalAlloc(GMEM_MOVEABLE, (UIntPtr)Math.Max(data.Length, 1));
        if (handle == IntPtr.Zero) return;
        var pointer = GlobalLock(handle);
        if (pointer == IntPtr.Zero)
        {
            GlobalFree(handle);
            return;
        }
        Marshal.Copy(data, 0, pointer, data.Length);
        GlobalUnlock(handle);
        if (SetClipboardData(format, handle) == IntPtr.Zero) GlobalFree(handle);
    }

    private static uint Id(string format) => format switch
    {
        ClipboardFormats.PlainText => CF_UNICODETEXT,
        _ when format.StartsWith('#') => uint.Parse(format.AsSpan(1)),
        _ => RegisterClipboardFormatW(format),
    };

    private static string Name(uint format)
    {
        if (format == CF_UNICODETEXT) return ClipboardFormats.PlainText;
        if (format < 0xC000) return $"#{format}";
        var name = new char[256];
        var length = GetClipboardFormatNameW(format, name, name.Length);
        return length > 0 ? new string(name, 0, length) : $"#{format}";
    }

    private static string DecodeUnicode(byte[] data) => Encoding.Unicode.GetString(data).Split('\0')[0];

    private static string Decode(string format, byte[] data) => format switch
    {
        ClipboardFormats.PlainText => DecodeUnicode(data),
        ClipboardFormats.Html => CfHtml.Decode(data),
        _ => Encoding.Latin1.GetString(data).TrimEnd('\0'), // RTF is 7-bit
    };

    private static byte[] Encode(string format, string text) => format switch
    {
        ClipboardFormats.PlainText => Encoding.Unicode.GetBytes(text + "\0"),
        ClipboardFormats.Html => [.. CfHtml.Encode(text), 0],
        _ => Encoding.Latin1.GetBytes(text + "\0"),
    };

    public void Dispose() => RemoveClipboardFormatListener(window.Handle);
}
