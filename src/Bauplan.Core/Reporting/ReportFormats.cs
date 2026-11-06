using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Bauplan.Core.Analysis;
using Bauplan.Core.Rules;

namespace Bauplan.Core.Reporting;

public static class ReportFormats
{
    public const string ToolVersion = "1.0.0";
    public const string InformationUri = "https://github.com/karicamar/bauplan";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string ToJson(AnalysisResult r) => JsonSerializer.Serialize(new
    {
        tool = "Bauplan",
        version = ToolVersion,
        terraformVersion = r.TerraformVersion,
        plan = r.Summary,
        worst = r.Worst,
        destructive = r.Destructive,
        findings = r.Findings,
        resolved = r.Resolved,
        warnings = r.Warnings,
    }, Json);

    /// <summary>A pull request comment: what this change destroys, what it introduces, what it fixes.</summary>
    public static string ToMarkdown(AnalysisResult r)
    {
        var sb = new StringBuilder();
        var destroy = r.ActiveDestructive.Where(d => d.Severity > Severity.Info).ToList();
        var newOnes = r.ActiveFindings.Where(f => f.Status == FindingStatus.New).ToList();
        var existing = r.ActiveFindings.Where(f => f.Status == FindingStatus.Existing).ToList();

        sb.AppendLine("## Bauplan: Terraform plan review").AppendLine();
        sb.AppendLine($"**Plan:** {r.Summary}.").AppendLine();

        if (destroy.Count == 0 && newOnes.Count == 0)
            sb.AppendLine("✅ This plan destroys no data and introduces no new security findings.").AppendLine();

        if (destroy.Count > 0)
        {
            sb.AppendLine("### 💥 Destroys").AppendLine();
            sb.AppendLine("| | Resource | What happens |").AppendLine("|---|---|---|");
            foreach (var d in destroy)
                sb.AppendLine($"| {Icon(d.Severity)} | `{d.Address}`{Where(d.Source)} | {Escape(d.Message)} |");
            sb.AppendLine();
        }

        if (newOnes.Count > 0)
        {
            sb.AppendLine($"### 🆕 Introduced by this plan ({newOnes.Count})").AppendLine();
            Table(sb, newOnes);
        }

        if (r.Resolved.Count > 0)
        {
            sb.AppendLine($"### ✅ Fixed by this plan ({r.Resolved.Count})").AppendLine();
            foreach (var x in r.Resolved)
                sb.AppendLine($"- `{x.RuleId}` `{x.Address}`: {Escape(x.Message)}");
            sb.AppendLine();
        }

        if (existing.Count > 0)
        {
            sb.AppendLine("<details>").AppendLine($"<summary>Already present before this plan ({existing.Count})</summary>").AppendLine();
            Table(sb, existing);
            sb.AppendLine("</details>").AppendLine();
        }

        var accepted = r.Findings.Count(f => f.Suppressed) + r.Destructive.Count(d => d.Suppressed);
        if (accepted > 0)
            sb.AppendLine($"Accepted in `.bauplan-ignore`: {accepted}.").AppendLine();
        foreach (var w in r.Warnings)
            sb.AppendLine($"- ⚠️ {w}");
        return sb.ToString();
    }

    private static void Table(StringBuilder sb, IEnumerable<Finding> findings)
    {
        sb.AppendLine("| Severity | Rule | Resource | Finding | Fix |").AppendLine("|---|---|---|---|---|");
        foreach (var f in findings)
            sb.AppendLine($"| {Icon(f.Severity)} {f.Severity} | `{f.RuleId}` | `{f.Address}`{Where(f.Source)} | {Escape(f.Message)} | {Escape(f.Fix ?? "")} |");
        sb.AppendLine();
    }

    private static string Where(SourceLocation? s) => s is null ? "" : $"<br><sub>{s.File}:{s.Line}</sub>";

    private static string Icon(Severity s) => s switch
    {
        Severity.Critical => "🟣",
        Severity.High => "🔴",
        Severity.Medium => "🟠",
        Severity.Low => "🟡",
        _ => "⚪",
    };

    private static string Escape(string s) => s.Replace("|", "\\|").Replace("\n", " ");

    /// <summary>
    /// SARIF 2.1.0. Results point at the .tf file of the resource when it was found (otherwise at the plan file),
    /// so GitHub shows them as annotations on the changed code.
    /// </summary>
    public static string ToSarif(AnalysisResult r, string planPath)
    {
        var usedRules = r.Findings.Select(f => f.RuleId).ToHashSet();
        var rules = RuleCatalog.All.Where(x => usedRules.Contains(x.Id)).Select(x => (x.Id, Name: x.Title, x.Severity, Help: $"{x.Why} Fix: {x.Fix}", Tags: new[] { "security", "terraform", "azure", x.Category })).ToList();
        if (r.Destructive.Any(d => d.Severity > Severity.Info))
            rules.Add(("DESTROY", "Plan destroys a resource that holds data", Severity.Critical,
                "Deleting or replacing a database, storage account, key vault or resource group loses its data. Check that this is intended and that a backup exists, or add lifecycle { prevent_destroy = true }.",
                ["terraform", "data-loss"]));

        var results = new JsonArray();
        foreach (var f in r.Findings)
            results.Add(Result(f.RuleId, rules.FindIndex(x => x.Id == f.RuleId), f.Severity, $"{f.Address}: {f.Message} ({(f.Status == FindingStatus.New ? "new in this plan" : "existing")})",
                f.Source, planPath, f.Address + "|" + f.RuleId + "|" + f.Attribute, f.Suppressed ? f.SuppressedBecause : null));
        foreach (var d in r.Destructive.Where(d => d.Severity > Severity.Info))
            results.Add(Result("DESTROY", rules.FindIndex(x => x.Id == "DESTROY"), d.Severity, $"{d.Address} {d.Message}", d.Source, planPath, d.Address + "|DESTROY", d.Suppressed ? d.SuppressedBecause : null));

        var sarif = new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray(new JsonObject
            {
                ["tool"] = new JsonObject
                {
                    ["driver"] = new JsonObject
                    {
                        ["name"] = "Bauplan",
                        ["version"] = ToolVersion,
                        ["informationUri"] = InformationUri,
                        ["rules"] = new JsonArray(rules.Select(x => (JsonNode)new JsonObject
                        {
                            ["id"] = x.Id,
                            ["shortDescription"] = new JsonObject { ["text"] = x.Name },
                            ["help"] = new JsonObject { ["text"] = x.Help },
                            ["properties"] = new JsonObject
                            {
                                ["security-severity"] = x.Severity switch { Severity.Critical => "9.5", Severity.High => "8.0", Severity.Medium => "5.5", Severity.Low => "3.0", _ => "1.0" },
                                ["tags"] = new JsonArray(x.Tags.Select(t => (JsonNode)JsonValue.Create(t)!).ToArray()),
                            },
                        }).ToArray()),
                    },
                },
                ["results"] = results,
            }),
        };
        return sarif.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    private static JsonObject Result(string ruleId, int ruleIndex, Severity severity, string message, SourceLocation? source, string planPath, string fingerprint, string? suppressedBecause)
    {
        var result = new JsonObject
        {
            ["ruleId"] = ruleId,
            ["ruleIndex"] = ruleIndex,
            ["level"] = severity switch { Severity.Critical or Severity.High => "error", Severity.Medium => "warning", _ => "note" },
            ["message"] = new JsonObject { ["text"] = message },
            ["locations"] = new JsonArray(new JsonObject
            {
                ["physicalLocation"] = new JsonObject
                {
                    ["artifactLocation"] = new JsonObject { ["uri"] = source?.File ?? planPath },
                    ["region"] = new JsonObject { ["startLine"] = source?.Line ?? 1 },
                },
            }),
            ["partialFingerprints"] = new JsonObject { ["resourceRule/v1"] = fingerprint },
        };
        if (suppressedBecause is not null)
            result["suppressions"] = new JsonArray(new JsonObject { ["kind"] = "external", ["justification"] = suppressedBecause });
        return result;
    }
}
