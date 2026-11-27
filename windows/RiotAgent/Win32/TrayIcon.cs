using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using static Riot.Agent.App.Win32.Native;

namespace Riot.Agent.App.Win32;

/// <summary>The icon in the notification area (the menu bar extra's counterpart): a shield,
/// hollow when the service is not reachable, with an orange dot on a development copy. A click
/// or the context menu key opens the popup.</summary>
internal sealed class TrayIcon : IDisposable
{
    private const uint CallbackMessage = WM_APP + 1;
    private readonly MessageWindow window;
    private readonly uint taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
    private IntPtr icon;
    private string tip = "Riot";
    private bool added;

    public TrayIcon(MessageWindow window)
    {
        this.window = window;
        window.AddHook(Hook);
    }

    /// <summary>Clicked: where, in screen pixels.</summary>
    public event Action<int, int>? Clicked;

    public void Update(bool connected, bool development, string tooltip)
    {
        var previous = icon;
        icon = Draw(connected, development);
        tip = tooltip.Length > 127 ? tooltip[..127] : tooltip;
        Apply(added ? NIM_MODIFY : NIM_ADD);
        if (previous != IntPtr.Zero) DestroyIcon(previous);
    }

    private void Apply(uint message)
    {
        var data = Data();
        data.Flags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        data.CallbackMessage = CallbackMessage;
        data.Icon = icon;
        data.Tip = tip;
        if (!Shell_NotifyIconW(message, ref data)) return;
        if (message == NIM_ADD)
        {
            added = true;
            data.TimeoutOrVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, ref data);
        }
    }

    private NOTIFYICONDATAW Data() => new()
    {
        Size = Marshal.SizeOf<NOTIFYICONDATAW>(),
        Window = window.Handle,
        Id = 1,
        Tip = "",
        Info = "",
        InfoTitle = "",
    };

    private IntPtr Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == CallbackMessage)
        {
            // NOTIFYICON_VERSION_4: the event in lParam's low word, the anchor point in wParam.
            var notification = (int)(lParam.ToInt64() & 0xFFFF);
            if (notification is NIN_SELECT or NIN_KEYSELECT or WM_CONTEXTMENU)
            {
                var anchor = wParam.ToInt64();
                Clicked?.Invoke((short)(anchor & 0xFFFF), (short)((anchor >> 16) & 0xFFFF));
            }
            handled = true;
        }
        else if (msg == taskbarCreated && taskbarCreated != 0)
        {
            added = false; // Explorer restarted: the icon is gone, add it again
            Apply(NIM_ADD);
        }
        return IntPtr.Zero;
    }

    /// <summary>A 32 px shield drawn with WPF, handed to Windows as a PNG icon resource.</summary>
    private static IntPtr Draw(bool connected, bool development)
    {
        var dark = Screens.TaskbarIsDark();
        var ink = dark ? Colors.White : Color.FromRgb(0x1F, 0x1F, 0x1F);
        var shield = Geometry.Parse("M16,2 L28,6.5 L28,15 C28,22.5 22.8,27.8 16,30 C9.2,27.8 4,22.5 4,15 L4,6.5 Z");
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            if (connected)
            {
                dc.DrawGeometry(new SolidColorBrush(ink), null, shield);
                var check = Geometry.Parse("M10.5,16 L14.5,20 L21.5,12");
                dc.DrawGeometry(null, new Pen(new SolidColorBrush(dark ? Color.FromRgb(0x1F, 0x1F, 0x1F) : Colors.White), 2.6)
                { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round }, check);
            }
            else
            {
                dc.DrawGeometry(null, new Pen(new SolidColorBrush(ink), 2.4), shield);
                dc.DrawLine(new Pen(new SolidColorBrush(ink), 2.4) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round },
                    new Point(7, 7), new Point(25, 25));
            }
            if (development) dc.DrawEllipse(new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)), null, new Point(25.5, 25.5), 6, 6);
        }
        var bitmap = new RenderTargetBitmap(32, 32, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var png = new MemoryStream();
        encoder.Save(png);
        var bytes = png.ToArray();
        return CreateIconFromResourceEx(bytes, (uint)bytes.Length, true, 0x00030000, 32, 32, 0);
    }

    public void Dispose()
    {
        if (added)
        {
            var data = Data();
            Shell_NotifyIconW(NIM_DELETE, ref data);
        }
        if (icon != IntPtr.Zero) DestroyIcon(icon);
    }
}

internal static class Screens
{
    /// <summary>The taskbar follows the system theme, not the apps' one.</summary>
    public static bool TaskbarIsDark()
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("SystemUsesLightTheme") is not int light || light == 0;
    }

    /// <summary>The work area (screen pixels) and scale of the monitor under the point.</summary>
    public static (RECT Work, double Scale) MonitorAt(int x, int y)
    {
        var monitor = MonitorFromPoint(new POINT { X = x, Y = y }, MONITOR_DEFAULTTONEAREST);
        var info = new MONITORINFO { Size = Marshal.SizeOf<MONITORINFO>() };
        GetMonitorInfoW(monitor, ref info);
        var scale = GetDpiForMonitor(monitor, 0, out var dpi, out _) == 0 ? dpi / 96.0 : 1.0;
        return (info.Work, scale);
    }

    public static (RECT Work, double Scale) MonitorAtCursor()
    {
        GetCursorPos(out var point);
        return MonitorAt(point.X, point.Y);
    }

    /// <summary>Places a window by its top-left corner in screen pixels, without activating it.</summary>
    public static void MoveTo(Window window, int x, int y)
    {
        var hwnd = new System.Windows.Interop.WindowInteropHelper(window).Handle;
        SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
    }
}
