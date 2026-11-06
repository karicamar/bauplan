using System.Text.RegularExpressions;

namespace Bauplan.Core.Analysis;

/// <summary>
/// Finds the <c>resource "type" "name"</c> block of an address in the .tf files, so SARIF results and
/// pull request annotations point at the code, not at the plan JSON.
/// </summary>
public sealed partial class SourceLocator
{
    private readonly Dictionary<string, List<SourceLocation>> blocks = new(StringComparer.Ordinal);

    [GeneratedRegex(@"^\s*resource\s+""(?<type>[\w-]+)""\s+""(?<name>[\w-]+)""", RegexOptions.Multiline)]
    private static partial Regex ResourceBlock();

    public SourceLocator(string root, string? relativeTo = null)
    {
        if (!Directory.Exists(root)) return;
        var baseDir = relativeTo ?? root;
        foreach (var file in Directory.EnumerateFiles(root, "*.tf", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            if (file.Replace('\\', '/').Contains("/.terraform/", StringComparison.Ordinal)) continue;
            var text = File.ReadAllText(file);
            var relative = Path.GetRelativePath(baseDir, file).Replace('\\', '/');
            foreach (Match m in ResourceBlock().Matches(text))
            {
                var key = $"{m.Groups["type"].Value}.{m.Groups["name"].Value}";
                var line = text.AsSpan(0, m.Groups["type"].Index).Count('\n') + 1;
                if (!blocks.TryGetValue(key, out var list)) blocks[key] = list = [];
                list.Add(new SourceLocation(relative, line));
            }
        }
    }

    public int Count => blocks.Values.Sum(l => l.Count);

    /// <summary>module.app.azurerm_x.y["k"] → the block azurerm_x.y. With the same name in several modules, the first match wins.</summary>
    public SourceLocation? Find(string address)
    {
        var parts = Plan.Configuration.StripIndex(address).Split('.');
        if (parts.Length < 2) return null;
        var key = $"{parts[^2]}.{parts[^1]}";
        if (!blocks.TryGetValue(key, out var list)) return null;
        if (list.Count == 1 || parts.Length == 2) return list[0];
        // Prefer a file under modules/<name>/ for module.<name>.x.y
        var module = parts.Length >= 4 ? parts[^3] : null;
        return list.FirstOrDefault(l => module is not null && ("/" + l.File).Contains($"/{module}/", StringComparison.Ordinal)) ?? list[0];
    }

    public void Annotate(AnalysisResult result)
    {
        foreach (var f in result.Findings) f.Source = Find(f.Address);
        foreach (var d in result.Destructive) d.Source = Find(d.Address);
    }
}
