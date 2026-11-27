using static Riot.Agent.App.Win32.Native;

namespace Riot.Agent.App.Win32;

/// <summary>Which app is in the foreground, from <c>EVENT_SYSTEM_FOREGROUND</c>: the counterpart
/// of NSWorkspace's activation notifications. An app is known by its package family name
/// (<c>Claude_pzs8sxrjxfjjc</c>), which ends with a hash of its publisher, so another program
/// cannot pass for it; an app that is not packaged, by its executable's file name.</summary>
internal sealed class Foreground : IDisposable
{
    private readonly WinEventProc callback; // kept alive: Windows calls it
    private readonly IntPtr hook;

    public Foreground()
    {
        callback = (_, _, hwnd, _, _, _, _) => Changed?.Invoke(AppId(hwnd));
        hook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, IntPtr.Zero, callback, 0, 0, WINEVENT_OUTOFCONTEXT);
    }

    /// <summary>On the UI thread (out-of-context hooks are delivered to the hooking thread).</summary>
    public event Action<string?>? Changed;

    public static string? Current => AppId(GetForegroundWindow());

    public static string? AppId(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return null;
        GetWindowThreadProcessId(hwnd, out var pid);
        return pid == 0 ? null : ProcessAppId(pid);
    }

    /// <summary>The process's package family name, else the lower-case file name of its
    /// executable; null if it cannot be opened.</summary>
    public static string? ProcessAppId(uint pid)
    {
        var process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            var family = new char[256]; // PACKAGE_FAMILY_NAME_MAX_LENGTH + 1 fits
            var length = (uint)family.Length;
            if (GetPackageFamilyName(process, ref length, family) == 0 && length > 0) return new string(family, 0, (int)length - 1);
            var path = new char[1024];
            var size = (uint)path.Length;
            return QueryFullProcessImageNameW(process, 0, path, ref size)
                ? System.IO.Path.GetFileName(new string(path, 0, (int)size)).ToLowerInvariant()
                : null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    public void Dispose() => UnhookWinEvent(hook);
}

/// <summary>Ctrl's state now, and when a key was last pressed anywhere. The time comes from raw
/// keyboard input delivered to our hidden window (<c>RIDEV_INPUTSINK</c>), only while
/// <see cref="Listening"/>: from a paste, as long as its card is open, the one time the guard
/// needs to know whether the user typed since. Only the arrival time is kept, never which key.</summary>
internal sealed class KeyboardState : IKeyboardState
{
    private readonly MessageWindow window;
    private long lastKeyTicks = Environment.TickCount64 - 3_600_000;
    private bool listening;

    public KeyboardState(MessageWindow window)
    {
        this.window = window;
        window.AddHook((IntPtr _, int msg, IntPtr _, IntPtr _, ref bool _) =>
        {
            if (msg == WM_INPUT) lastKeyTicks = Environment.TickCount64; // DefWindowProc frees the input
            return IntPtr.Zero;
        });
    }

    public bool Listening
    {
        get => listening;
        set
        {
            if (value == listening) return;
            // Removing takes no target window.
            var keyboard = new RAWINPUTDEVICE
            {
                UsagePage = 0x01, Usage = 0x06,
                Flags = value ? RIDEV_INPUTSINK : RIDEV_REMOVE,
                Target = value ? window.Handle : IntPtr.Zero,
            };
            if (RegisterRawInputDevices([keyboard], 1, (uint)System.Runtime.InteropServices.Marshal.SizeOf<RAWINPUTDEVICE>())) listening = value;
        }
    }

    public bool ShortcutKeyHeld => (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;

    public TimeSpan SinceKeyDown => TimeSpan.FromMilliseconds(Environment.TickCount64 - lastKeyTicks);
}

/// <summary>Ctrl+Z then Ctrl+V into the foreground app, for "paste without redaction". Letter
/// keys follow the keyboard layout (VK_Z is the key that types Z on AZERTY too), as shortcuts do.
/// Windows drops input sent to an app running elevated: the user then undoes and pastes.</summary>
internal sealed class Keystrokes : IKeystrokes
{
    private const ushort VK_Z = 0x5A, VK_V = 0x56;

    public bool UndoThenPaste()
    {
        INPUT Key(ushort vk, bool up) => new()
        {
            Type = INPUT_KEYBOARD,
            Union = new InputUnion { Keyboard = new KEYBDINPUT { Vk = vk, Flags = up ? KEYEVENTF_KEYUP : 0 } },
        };
        INPUT[] inputs =
        [
            Key(VK_CONTROL, false), Key(VK_Z, false), Key(VK_Z, true), Key(VK_CONTROL, true),
            Key(VK_CONTROL, false), Key(VK_V, false), Key(VK_V, true), Key(VK_CONTROL, true),
        ];
        return SendInput((uint)inputs.Length, inputs, System.Runtime.InteropServices.Marshal.SizeOf<INPUT>()) == inputs.Length;
    }
}
