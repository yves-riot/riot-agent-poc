using static Riot.Agent.App.Win32.Native;

namespace Riot.Agent.App.Win32;

/// <summary>Which app is in the foreground, by executable file name (<c>claude.exe</c>), from
/// <c>EVENT_SYSTEM_FOREGROUND</c>: the counterpart of NSWorkspace's activation notifications.</summary>
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
        return pid == 0 ? null : ExecutableName(pid);
    }

    /// <summary>Lower-case file name of the process's executable; null if it cannot be opened.</summary>
    public static string? ExecutableName(uint pid)
    {
        var process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
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
/// keyboard input delivered to our hidden window (<c>RIDEV_INPUTSINK</c>); only the arrival time
/// is kept, never which key: the guard needs to know whether the user typed since a paste.</summary>
internal sealed class KeyboardState : IKeyboardState
{
    private long lastKeyTicks = Environment.TickCount64 - 3_600_000;

    public KeyboardState(MessageWindow window)
    {
        var keyboard = new RAWINPUTDEVICE { UsagePage = 0x01, Usage = 0x06, Flags = RIDEV_INPUTSINK, Target = window.Handle };
        RegisterRawInputDevices([keyboard], 1, (uint)System.Runtime.InteropServices.Marshal.SizeOf<RAWINPUTDEVICE>());
        window.AddHook((IntPtr _, int msg, IntPtr _, IntPtr _, ref bool _) =>
        {
            if (msg == WM_INPUT) lastKeyTicks = Environment.TickCount64; // DefWindowProc frees the input
            return IntPtr.Zero;
        });
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
