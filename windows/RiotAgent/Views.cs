using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Riot.Agent.App;

// What the HUD and the popup show, as plain data with the strings already translated; App.xaml,
// Hud.xaml and TrayPopup.xaml lay it out.

/// <summary>The bot's picture, a title and an optional subtitle.</summary>
public sealed record HeaderView(string? AvatarUrl, string Title, string? Subtitle, double Size = 32)
{
    /// <summary>The bot's picture (https only), drawn over the shield once loaded.</summary>
    public ImageSource? Image { get; } = Load(AvatarUrl, Size);
    public Thickness ShieldMargin => new(Size * 0.25);

    private static BitmapImage? Load(string? url, double size)
    {
        if (url is null || !Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps) return null;
        try
        {
            var image = new BitmapImage();
            image.BeginInit();
            image.UriSource = uri;
            image.DecodePixelWidth = (int)(size * 2);
            image.EndInit();
            return image;
        }
        catch (Exception)
        {
            return null;
        }
    }
}

public sealed record FindingRow(string Label, string? Count);

public sealed record FindingsView(IReadOnlyList<FindingRow> Rows, string? More)
{
    /// <summary>At most four types, then "and N more", as the extension lists them.</summary>
    public static FindingsView Of(IReadOnlyList<TypeCount> types)
    {
        var l = L10n.Shared;
        var rows = types.Take(4).Select(t => new FindingRow(l.Label(t), t.Count > 1 ? $"×{t.Count}" : null)).ToList();
        var more = types.Count > 4 ? l.T("redactionGuard.findings.more", types.Count - 4, ("count", $"{types.Count - 4}")) : null;
        return new FindingsView(rows, more);
    }
}

public sealed record WarningView(string Title, string Body);

/// <summary>A button or a link.</summary>
public sealed record ActionView(string Text, ICommand Command)
{
    public ActionView(string text, Action run) : this(text, new Command(run))
    {
    }
}

public sealed class Command(Action run) : ICommand
{
    public event EventHandler? CanExecuteChanged
    {
        add { }
        remove { }
    }

    public bool CanExecute(object? parameter) => true;

    public void Execute(object? parameter) => run();
}

/// <summary>Collapsed for null, an empty string, an empty list or false; visible otherwise.</summary>
public sealed class VisibleWhenSet : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        null or "" or false => Visibility.Collapsed,
        ICollection { Count: 0 } => Visibility.Collapsed,
        _ => Visibility.Visible,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
