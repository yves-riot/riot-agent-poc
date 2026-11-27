using System.Windows.Interop;

namespace Riot.Agent.App.Win32;

/// <summary>A hidden message-only window on the UI thread: the clipboard's owner (its delayed
/// renders arrive here), the clipboard listener, the raw keyboard sink and the notification
/// icon's callback.</summary>
internal sealed class MessageWindow : IDisposable
{
    private static readonly IntPtr HWND_MESSAGE = new(-3);
    private readonly HwndSource source;
    private readonly List<HwndSourceHook> hooks = [];

    public MessageWindow()
    {
        source = new HwndSource(new HwndSourceParameters("RiotAgent") { ParentWindow = HWND_MESSAGE, Width = 0, Height = 0 });
        source.AddHook(Dispatch);
    }

    public IntPtr Handle => source.Handle;

    /// <summary>Hooks run in order until one handles the message.</summary>
    public void AddHook(HwndSourceHook hook) => hooks.Add(hook);

    private IntPtr Dispatch(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        foreach (var hook in hooks)
        {
            var result = hook(hwnd, msg, wParam, lParam, ref handled);
            if (handled) return result;
        }
        return IntPtr.Zero;
    }

    public void Dispose() => source.Dispose();
}
