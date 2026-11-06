using System.Globalization;
using System.Text.RegularExpressions;

namespace Bauplan.Core.Policy;

/// <summary>
/// Accepted risks, one per line in <c>.bauplan-ignore</c>:
/// <code>
/// azurerm_storage_account.public_assets   AZ-STG-001   reason="static website, public by design"
/// module.legacy.*                         *            reason="migration ticket OPS-412" expires=2027-03-31
/// azurerm_mssql_database.reporting        DESTROY      reason="rebuilt nightly from the warehouse"
/// </code>
/// The address may use * (any characters). DESTROY accepts a delete or replace. Every entry needs a reason;
/// an expired entry stops suppressing.
/// </summary>
public sealed partial class IgnoreList
{
    public static IgnoreList Empty { get; } = new([], []);

    private IgnoreList(IReadOnlyList<Entry> entries, IReadOnlyList<string> warnings)
    {
        Entries = entries;
        Warnings = warnings;
    }

    public IReadOnlyList<Entry> Entries { get; }
    public IReadOnlyList<string> Warnings { get; }

    public sealed record Entry(string Address, string Rule, string Reason, DateOnly? Expires)
    {
        internal Regex Pattern { get; } = new("^" + Regex.Escape(Address).Replace("\\*", ".*", StringComparison.Ordinal) + "$", RegexOptions.CultureInvariant);
    }

    [GeneratedRegex(@"^(?<addr>\S+)\s+(?<rule>\S+)(?<rest>.*)$")]
    private static partial Regex LinePattern();

    [GeneratedRegex(@"reason=""(?<r>[^""]*)""|expires=(?<e>\S+)")]
    private static partial Regex Attributes();

    public static IgnoreList Parse(string text, DateOnly? today = null)
    {
        var now = today ?? DateOnly.FromDateTime(DateTime.UtcNow);
        var entries = new List<Entry>();
        var warnings = new List<string>();
        var lines = text.Split('\n');
        for (var n = 0; n < lines.Length; n++)
        {
            var raw = lines[n].Trim();
            if (raw.Length == 0 || raw.StartsWith('#')) continue;
            var m = LinePattern().Match(raw);
            if (!m.Success)
            {
                warnings.Add($".bauplan-ignore line {n + 1}: expected <address> <rule id|DESTROY|*> reason=\"...\"");
                continue;
            }
            string? reason = null;
            DateOnly? expires = null;
            foreach (Match a in Attributes().Matches(m.Groups["rest"].Value))
            {
                if (a.Groups["r"].Success) reason = a.Groups["r"].Value.Trim();
                else if (DateOnly.TryParseExact(a.Groups["e"].Value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)) expires = d;
                else warnings.Add($".bauplan-ignore line {n + 1}: expires must be yyyy-MM-dd");
            }
            var address = m.Groups["addr"].Value;
            if (string.IsNullOrEmpty(reason))
            {
                warnings.Add($".bauplan-ignore line {n + 1}: entry for {address} has no reason=\"...\" and is not applied");
                continue;
            }
            if (expires is { } e && e < now)
            {
                warnings.Add($".bauplan-ignore line {n + 1}: entry for {address} expired on {e:yyyy-MM-dd}, it counts again");
                continue;
            }
            entries.Add(new Entry(address, m.Groups["rule"].Value, reason, expires));
        }
        return new IgnoreList(entries, warnings);
    }

    public Entry? Match(string address, string ruleId) =>
        Entries.FirstOrDefault(e => (e.Rule == "*" && ruleId != "DESTROY" || e.Rule.Equals(ruleId, StringComparison.OrdinalIgnoreCase))
                                    && e.Pattern.IsMatch(address));
}
