using Bauplan.Core.Plan;
using Bauplan.Core.Policy;
using Bauplan.Core.Rules;

namespace Bauplan.Core.Analysis;

/// <summary>Whether this plan causes a finding or it was there before.</summary>
public enum FindingStatus
{
    /// <summary>Introduced by this plan: a new resource, or an update that makes it worse.</summary>
    New,

    /// <summary>Already true before the plan (unchanged resource, or an update that keeps the problem).</summary>
    Existing,
}

public sealed record Finding
{
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required string Category { get; init; }
    public required string Address { get; init; }
    public required string ResourceType { get; init; }
    public required string Message { get; init; }
    public required string Attribute { get; init; }
    public required FindingStatus Status { get; init; }
    public required ChangeAction Action { get; init; }
    public string? Benchmark { get; init; }
    public string? Fix { get; init; }
    public SourceLocation? Source { get; set; }
    public bool Suppressed { get; init; }
    public string? SuppressedBecause { get; init; }
}

/// <summary>A delete or replace that destroys something.</summary>
public sealed record DestructiveChange
{
    public required string Address { get; init; }
    public required string ResourceType { get; init; }
    public required ChangeAction Action { get; init; }
    public required Severity Severity { get; init; }
    public required string Message { get; init; }
    public IReadOnlyList<string> ReplacePaths { get; init; } = [];
    public bool Stateful { get; init; }
    public SourceLocation? Source { get; set; }
    public bool Suppressed { get; init; }
    public string? SuppressedBecause { get; init; }
}

public sealed record Resolved(string RuleId, string Address, string Message);

public sealed record SourceLocation(string File, int Line);

public sealed record PlanSummary(int Create, int Update, int Replace, int Delete, int NoOp)
{
    public override string ToString() =>
        // Same counting as Terraform's own summary: a replace is one add and one destroy
        $"{Create + Replace} to add, {Update} to change, {Delete + Replace} to destroy" + (Replace > 0 ? $" ({Replace} replaced)" : "");
}

public sealed class AnalysisResult
{
    public required string? TerraformVersion { get; init; }
    public required PlanSummary Summary { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required IReadOnlyList<DestructiveChange> Destructive { get; init; }
    public required IReadOnlyList<Resolved> Resolved { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }

    public IEnumerable<Finding> ActiveFindings => Findings.Where(f => !f.Suppressed);
    public IEnumerable<DestructiveChange> ActiveDestructive => Destructive.Where(d => !d.Suppressed);

    /// <summary>
    /// Fails when a finding or destructive change reaches the threshold. With <paramref name="newOnly"/> (pull requests)
    /// existing findings do not fail, so a team can adopt Bauplan without fixing everything first. Destruction always counts.
    /// </summary>
    public bool Fails(Severity threshold, bool newOnly = false) =>
        ActiveFindings.Any(f => f.Severity >= threshold && (!newOnly || f.Status == FindingStatus.New))
        || ActiveDestructive.Any(d => d.Severity >= threshold);

    public Severity? Worst => ActiveFindings.Select(f => (Severity?)f.Severity).Concat(ActiveDestructive.Select(d => (Severity?)d.Severity)).Max();
}

public sealed class Analyzer
{
    // Resources that hold data or keys: destroying them loses it (a new one is empty)
    internal static readonly HashSet<string> Stateful = new(StringComparer.Ordinal)
    {
        "azurerm_mssql_server", "azurerm_mssql_database", "azurerm_mssql_managed_instance", "azurerm_sql_server", "azurerm_sql_database",
        "azurerm_postgresql_flexible_server", "azurerm_postgresql_flexible_server_database", "azurerm_postgresql_server", "azurerm_postgresql_database",
        "azurerm_mysql_flexible_server", "azurerm_mysql_flexible_database", "azurerm_cosmosdb_account", "azurerm_cosmosdb_sql_database",
        "azurerm_cosmosdb_sql_container", "azurerm_redis_cache", "azurerm_storage_account", "azurerm_storage_container", "azurerm_storage_share",
        "azurerm_key_vault", "azurerm_key_vault_key", "azurerm_key_vault_secret", "azurerm_managed_disk", "azurerm_recovery_services_vault",
        "azurerm_data_protection_backup_vault", "azurerm_log_analytics_workspace", "azurerm_container_registry", "azurerm_dns_zone",
        "azurerm_private_dns_zone", "azurerm_eventhub_namespace", "azurerm_servicebus_namespace", "azurerm_search_service",
    };

    private readonly IReadOnlyList<Rule> rules;

    public Analyzer(IReadOnlyList<Rule>? rules = null) => this.rules = rules ?? RuleCatalog.All;

    public AnalysisResult Analyze(TerraformPlan plan, IgnoreList? ignore = null)
    {
        ignore ??= IgnoreList.Empty;
        var context = new RuleContext(plan);
        var findings = new List<Finding>();
        var resolved = new List<Resolved>();
        var destructive = new List<DestructiveChange>();
        var warnings = new List<string>(ignore.Warnings);

        foreach (var change in plan.Changes.Where(c => c.IsManaged))
        {
            foreach (var rule in rules.Where(r => r.Types.Contains(change.Type)))
            {
                var before = change.Before is { } b && change.Action is not ChangeAction.Create
                    ? rule.Evaluate(new ResourceState(change.Address, change.Type, b), context).ToList() : [];
                var after = change.After is { } a && change.Action is not ChangeAction.Delete
                    ? rule.Evaluate(new ResourceState(change.Address, change.Type, a, change.AfterUnknown), context).ToList() : [];

                var beforeKeys = before.Select(i => (i.Attribute, i.Key)).ToHashSet();
                foreach (var issue in after)
                {
                    var status = change.Action is ChangeAction.NoOp || beforeKeys.Contains((issue.Attribute, issue.Key))
                        ? FindingStatus.Existing : FindingStatus.New;
                    var suppressed = ignore.Match(change.Address, rule.Id);
                    findings.Add(new Finding
                    {
                        RuleId = rule.Id,
                        Title = rule.Title,
                        Severity = issue.SeverityOverride ?? rule.Severity,
                        Category = rule.Category,
                        Address = change.Address,
                        ResourceType = change.Type,
                        Message = issue.Message,
                        Attribute = issue.Attribute,
                        Status = status,
                        Action = change.Action,
                        Benchmark = rule.Benchmark,
                        Fix = rule.Fix,
                        Suppressed = suppressed is not null,
                        SuppressedBecause = suppressed?.Reason,
                    });
                }

                var afterKeys = after.Select(i => (i.Attribute, i.Key)).ToHashSet();
                foreach (var issue in before.Where(i => !afterKeys.Contains((i.Attribute, i.Key))))
                    resolved.Add(new Resolved(rule.Id, change.Address, issue.Message));
            }

            if (Destruction(change) is { } d)
            {
                var suppressed = ignore.Match(change.Address, "DESTROY");
                destructive.Add(d with { Suppressed = suppressed is not null, SuppressedBecause = suppressed?.Reason });
            }
        }

        if (plan.Changes.Count == 0)
            warnings.Add("The plan has no resource_changes. Was it created with terraform show -json <planfile>?");

        return new AnalysisResult
        {
            TerraformVersion = plan.TerraformVersion,
            Summary = Summarize(plan),
            Findings = findings.OrderByDescending(f => f.Status == FindingStatus.New).ThenByDescending(f => f.Severity).ThenBy(f => f.Address, StringComparer.Ordinal).ToList(),
            Destructive = destructive.OrderByDescending(d => d.Severity).ThenBy(d => d.Address, StringComparer.Ordinal).ToList(),
            Resolved = resolved,
            Warnings = warnings,
        };
    }

    internal static DestructiveChange? Destruction(ResourceChange c)
    {
        if (c.Action is not (ChangeAction.Delete or ChangeAction.Replace)) return null;
        var stateful = Stateful.Contains(c.Type);
        var because = c.ReplacePaths.Count > 0 ? $" because {string.Join(", ", c.ReplacePaths)} changed" : "";

        string message;
        Severity severity;
        if (c.Type == "azurerm_resource_group" && c.Action == ChangeAction.Delete)
        {
            (severity, message) = (Severity.Critical, "deletes the resource group and EVERYTHING in it, including resources not managed by this Terraform code");
        }
        else if (stateful && c.Action == ChangeAction.Replace)
        {
            severity = Severity.Critical;
            message = $"replaces a resource that holds data{because}: the new one starts empty"
                      + (c.CreateBeforeDestroy ? " (created before the old one is destroyed)" : "");
        }
        else if (stateful)
        {
            (severity, message) = (Severity.Critical, "deletes a resource that holds data");
        }
        else if (c.Action == ChangeAction.Replace)
        {
            severity = c.Type == "azurerm_resource_group" ? Severity.Critical : Severity.Info;
            message = c.Type == "azurerm_resource_group"
                ? $"replaces the resource group{because}: everything in it is destroyed"
                : $"is replaced{because}" + (c.CreateBeforeDestroy ? "" : ": brief outage while it is recreated");
        }
        else
        {
            (severity, message) = (Severity.Info, "is deleted");
        }

        return new DestructiveChange
        {
            Address = c.Address,
            ResourceType = c.Type,
            Action = c.Action,
            Severity = severity,
            Message = message,
            ReplacePaths = c.ReplacePaths,
            Stateful = stateful,
        };
    }

    private static PlanSummary Summarize(TerraformPlan plan)
    {
        var managed = plan.Changes.Where(c => c.IsManaged).ToList();
        return new PlanSummary(
            managed.Count(c => c.Action == ChangeAction.Create),
            managed.Count(c => c.Action == ChangeAction.Update),
            managed.Count(c => c.Action == ChangeAction.Replace),
            managed.Count(c => c.Action == ChangeAction.Delete),
            managed.Count(c => c.Action == ChangeAction.NoOp));
    }
}
