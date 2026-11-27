using System.Text;
using System.Text.RegularExpressions;

namespace Riot.Agent;

/// <summary>The engine's tokens (<c>[IBAN_1]</c>, <c>[API_KEY_2]</c>) in copied text, and the
/// escaping each clipboard format needs when the real values are put back.</summary>
public static partial class Tokens
{
    /// <summary>Also as a markdown copy escapes them (<c>\[IBAN\_1\]</c>).</summary>
    [GeneratedRegex(@"\\?\[([A-Z][A-Z0-9]*(?:\\?_[A-Z][A-Z0-9]*)*\\?_\d+)\\?\]")]
    private static partial Regex Pattern();

    /// <summary>The canonical tokens in <paramref name="text"/> (markdown escapes removed).</summary>
    public static IEnumerable<string> In(string text) =>
        Pattern().Matches(text).Select(m => "[" + m.Groups[1].Value.Replace("\\", "") + "]");

    public static string Replace(string text, IReadOnlyDictionary<string, string> values, Func<string, string> escape) =>
        Pattern().Replace(text, m =>
            values.TryGetValue("[" + m.Groups[1].Value.Replace("\\", "") + "]", out var value) ? escape(value) : m.Value);

    public static string EscapeHtml(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

    /// <summary>RTF is 7-bit: its control characters escaped, non-ASCII as <c>\uN?</c> (UTF-16,
    /// signed).</summary>
    public static string EscapeRtf(string s)
    {
        var out_ = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c is '\\' or '{' or '}') out_.Append('\\').Append(c);
            else if (c < 0x80) out_.Append(c);
            else out_.Append(@"\u").Append((short)c).Append('?');
        }
        return out_.ToString();
    }
}
