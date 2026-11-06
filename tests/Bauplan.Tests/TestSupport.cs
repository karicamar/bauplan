using System.Text.Json.Nodes;
using Bauplan.Core.Analysis;
using Bauplan.Core.Plan;
using Bauplan.Core.Policy;
using Bauplan.Core.Rules;

namespace Bauplan.Tests;

internal static class T
{
    public static ResourceState State(string type, string json, string? unknown = null, string? name = "x") =>
        new($"{type}.{name}", type, (JsonObject)JsonNode.Parse(json)!, unknown is null ? null : (JsonObject)JsonNode.Parse(unknown)!);

    public static RuleContext Context(string? configurationResources = null) =>
        new(TerraformPlan.Parse(PlanJson("[]", configurationResources)));

    public static List<Issue> Evaluate(Rule rule, string type, string json, RuleContext? context = null, string? unknown = null) =>
        rule.Evaluate(State(type, json, unknown), context ?? Context()).ToList();

    /// <summary>A minimal plan document with the given resource_changes and configuration resources (JSON arrays).</summary>
    public static string PlanJson(string resourceChanges, string? configurationResources = null) => $$"""
        {
          "format_version": "1.2",
          "terraform_version": "1.9.8",
          "resource_changes": {{resourceChanges}},
          "configuration": { "root_module": { "resources": {{configurationResources ?? "[]"}} } }
        }
        """;

    /// <summary>One resource_changes entry.</summary>
    public static string Change(string type, string name, string actions, string? before, string? after, string extra = "") => $$"""
        {
          "address": "{{type}}.{{name}}", "mode": "managed", "type": "{{type}}", "name": "{{name}}",
          "provider_name": "registry.terraform.io/hashicorp/azurerm",
          "change": { "actions": {{actions}}, "before": {{before ?? "null"}}, "after": {{after ?? "null"}}, "after_unknown": {} {{extra}} }
        }
        """;

    public static AnalysisResult Analyze(string resourceChanges, string? config = null, IgnoreList? ignore = null) =>
        new Analyzer().Analyze(TerraformPlan.Parse(PlanJson(resourceChanges, config)), ignore);

    public static string SamplesDir
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "samples")))
                dir = dir.Parent;
            return Path.Combine(dir?.FullName ?? throw new DirectoryNotFoundException("samples"), "samples");
        }
    }

    public static AnalysisResult Sample(string name, IgnoreList? ignore = null)
    {
        var folder = Path.Combine(SamplesDir, name);
        var result = new Analyzer().Analyze(TerraformPlan.Parse(File.ReadAllText(Path.Combine(folder, "plan.json"))), ignore);
        new SourceLocator(folder, SamplesDir).Annotate(result);
        return result;
    }
}
