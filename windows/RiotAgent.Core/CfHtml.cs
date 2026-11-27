using System.Globalization;
using System.Text;

namespace Riot.Agent;

/// <summary>The Windows clipboard's <c>HTML Format</c>: UTF-8 HTML behind a header of byte
/// offsets (<c>StartHTML</c>, <c>StartFragment</c>…). Replacing text changes the lengths, so a
/// restored copy gets a new header rather than a patched one.</summary>
public static class CfHtml
{
    private const string StartMarker = "<!--StartFragment-->";
    private const string EndMarker = "<!--EndFragment-->";

    /// <summary>The HTML document, without the header.</summary>
    public static string Decode(byte[] data)
    {
        var text = Encoding.UTF8.GetString(data).TrimEnd('\0');
        var start = Offset(text, "StartHTML:");
        if (start is { } bytes && bytes >= 0 && bytes <= data.Length)
        {
            return Encoding.UTF8.GetString(data, bytes, data.Length - bytes).TrimEnd('\0');
        }
        var html = text.IndexOf('<');
        return html >= 0 ? text[html..] : text;
    }

    /// <summary>A header for <paramref name="html"/>; its fragment is between the
    /// <c>StartFragment</c>/<c>EndFragment</c> comments, or the whole document without them.</summary>
    public static byte[] Encode(string html)
    {
        if (!html.Contains(StartMarker, StringComparison.Ordinal))
        {
            html = "<html><body>" + StartMarker + html + EndMarker + "</body></html>";
        }
        const string template = "Version:0.9\r\nStartHTML:{0:D10}\r\nEndHTML:{1:D10}\r\nStartFragment:{2:D10}\r\nEndFragment:{3:D10}\r\n";
        var headerLength = string.Format(CultureInfo.InvariantCulture, template, 0, 0, 0, 0).Length;
        var body = Encoding.UTF8.GetBytes(html);
        int ByteOffset(string marker, bool after)
        {
            var index = html.IndexOf(marker, StringComparison.Ordinal);
            if (index < 0) return after ? body.Length : 0;
            return Encoding.UTF8.GetByteCount(html.AsSpan(0, after ? index + marker.Length : index));
        }
        var header = string.Format(CultureInfo.InvariantCulture, template,
            headerLength, headerLength + body.Length,
            headerLength + ByteOffset(StartMarker, after: true), headerLength + ByteOffset(EndMarker, after: false));
        return [.. Encoding.ASCII.GetBytes(header), .. body];
    }

    private static int? Offset(string text, string key)
    {
        var at = text.IndexOf(key, StringComparison.Ordinal);
        if (at < 0) return null;
        var digits = new string(text[(at + key.Length)..].TakeWhile(char.IsAsciiDigit).ToArray());
        return int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;
    }
}
