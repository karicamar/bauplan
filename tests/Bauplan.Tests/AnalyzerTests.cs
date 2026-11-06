using System.Text.Json;
using Bauplan.Core.Analysis;
using Bauplan.Core.Plan;
using Bauplan.Core.Policy;
using Bauplan.Core.Reporting;
using Bauplan.Core.Rules;

namespace Bauplan.Tests;

public class AnalyzerTests
{
    private const string OpenKv = """{ "purge_protection_enabled": false, "network_acls": [{ "default_action": "Deny" }] }""";
    private const string SafeKv = """{ "purge_protection_enabled": true, "network_acls": [{ "default_action": "Deny" }] }""";

    [Fact]
    public void CreateIsNew()
    {
        var r = T.Analyze($"[{T.Change("azurerm_key_vault", "kv", "[\"create\"]", null, OpenKv)}]");
        var f = Assert.Single(r.Findings, f => f.RuleId == "AZ-KV-001");
        Assert.Equal(FindingStatus.New, f.Status);
        Assert.Equal(ChangeAction.Create, f.Action);
    }

    [Fact]
    public void UnchangedResourceIsExisting()
    {
        var r = T.Analyze($"[{T.Change("azurerm_key_vault", "kv", "[\"no-op\"]", OpenKv, OpenKv)}]");
        Assert.Equal(FindingStatus.Existing, Assert.Single(r.Findings, f => f.RuleId == "AZ-KV-001").Status);
    }

    [Fact]
    public void UpdateThatBreaksSomethingIsNew()
    {
        var r = T.Analyze($"[{T.Change("azurerm_key_vault", "kv", "[\"update\"]", SafeKv, OpenKv)}]");
        Assert.Equal(FindingStatus.New, Assert.Single(r.Findings, f => f.RuleId == "AZ-KV-001").Status);
    }

    [Fact]
    public void UpdateThatFixesSomethingIsResolved()
    {
        var r = T.Analyze($"[{T.Change("azurerm_key_vault", "kv", "[\"update\"]", OpenKv, SafeKv)}]");
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "AZ-KV-001");
        Assert.Contains(r.Resolved, x => x.RuleId == "AZ-KV-001" && x.Address == "azurerm_key_vault.kv");
    }

    [Fact]
    public void NewNsgRuleInAnExistingGroup()
    {
        const string before = """{ "security_rule": [{ "name": "ssh-old", "direction": "Inbound", "access": "Allow", "destination_port_range": "22", "source_address_prefix": "*" }] }""";
        const string after = """
            { "security_rule": [
              { "name": "ssh-old", "direction": "Inbound", "access": "Allow", "destination_port_range": "22", "source_address_prefix": "*" },
              { "name": "rdp-new", "direction": "Inbound", "access": "Allow", "destination_port_range": "3389", "source_address_prefix": "*" } ] }
            """;
        var r = T.Analyze($"[{T.Change("azurerm_network_security_group", "nsg", "[\"update\"]", before, after)}]");
        Assert.Equal(FindingStatus.Existing, r.Findings.Single(f => f.Message.Contains("ssh-old")).Status);
        Assert.Equal(FindingStatus.New, r.Findings.Single(f => f.Message.Contains("rdp-new")).Status);
    }

    [Fact]
    public void DeletedResourceResolvesItsFindings()
    {
        var r = T.Analyze($"[{T.Change("azurerm_key_vault", "kv", "[\"delete\"]", OpenKv, null)}]");
        Assert.Empty(r.Findings);
        Assert.Contains(r.Resolved, x => x.RuleId == "AZ-KV-001");
        Assert.Equal(Severity.Critical, Assert.Single(r.Destructive).Severity); // but deleting a key vault loses keys
    }

    [Theory]
    [InlineData("azurerm_mssql_database", "[\"delete\",\"create\"]", Severity.Critical, "the new one starts empty")]
    [InlineData("azurerm_storage_account", "[\"delete\"]", Severity.Critical, "holds data")]
    [InlineData("azurerm_resource_group", "[\"delete\"]", Severity.Critical, "EVERYTHING in it")]
    [InlineData("azurerm_resource_group", "[\"delete\",\"create\"]", Severity.Critical, "everything in it is destroyed")]
    [InlineData("azurerm_network_security_group", "[\"delete\",\"create\"]", Severity.Info, "brief outage")]
    [InlineData("azurerm_network_security_group", "[\"create\",\"delete\"]", Severity.Info, "is replaced")]
    [InlineData("azurerm_role_assignment", "[\"delete\"]", Severity.Info, "is deleted")]
    public void Destruction(string type, string actions, Severity severity, string text)
    {
        var d = Assert.Single(T.Analyze($"[{T.Change(type, "x", actions, "{}", actions.Contains("create") ? "{}" : null)}]").Destructive);
        Assert.Equal(severity, d.Severity);
        Assert.Contains(text, d.Message);
    }

    [Fact]
    public void ReplaceExplainsWhichAttributeForcesIt()
    {
        var d = Assert.Single(T.Analyze($"[{T.Change("azurerm_mssql_server", "s", "[\"delete\",\"create\"]", "{}", "{}", ", \"replace_paths\": [[\"name\"]]")}]").Destructive);
        Assert.Contains("because name changed", d.Message);
        Assert.True(d.Stateful);
    }

    [Fact]
    public void CreateBeforeDestroyIsMentioned()
    {
        var d = Assert.Single(T.Analyze($"[{T.Change("azurerm_storage_account", "s", "[\"create\",\"delete\"]", "{}", "{}")}]").Destructive);
        Assert.Contains("created before the old one is destroyed", d.Message);
    }

    [Fact]
    public void NewOnlyIgnoresExistingFindingsButNotDestruction()
    {
        var existing = T.Analyze($"[{T.Change("azurerm_mssql_server", "s", "[\"no-op\"]", "{}", "{}")}]");
        Assert.True(existing.Fails(Severity.Medium));
        Assert.False(existing.Fails(Severity.Medium, newOnly: true));

        var destroy = T.Analyze($"[{T.Change("azurerm_mssql_database", "d", "[\"delete\"]", "{}", null)}]");
        Assert.True(destroy.Fails(Severity.High, newOnly: true));
    }

    [Fact]
    public void Summary()
    {
        var r = T.Analyze($"""
            [{T.Change("azurerm_resource_group", "a", "[\"create\"]", null, "{}")},
             {T.Change("azurerm_resource_group", "b", "[\"update\"]", "{}", "{}")},
             {T.Change("azurerm_resource_group", "c", "[\"delete\",\"create\"]", "{}", "{}")},
             {T.Change("azurerm_resource_group", "d", "[\"delete\"]", "{}", null)},
             {T.Change("azurerm_resource_group", "e", "[\"no-op\"]", "{}", "{}")}]
            """);
        Assert.Equal(new PlanSummary(1, 1, 1, 1, 1), r.Summary);
        Assert.Equal("2 to add, 1 to change, 2 to destroy (1 replaced)", r.Summary.ToString());
    }

    [Fact]
    public void EmptyPlanWarns() => Assert.Contains("no resource_changes", Assert.Single(T.Analyze("[]").Warnings));
}

public class IgnoreListTests
{
    private static readonly DateOnly Today = new(2026, 11, 7);

    [Fact]
    public void SuppressesByAddressAndRule()
    {
        var ignore = IgnoreList.Parse("""
            azurerm_key_vault.kv   AZ-KV-001   reason="legacy vault, replaced in Q1"
            module.legacy.*        *           reason="migration" expires=2027-03-31
            """, Today);
        Assert.Empty(ignore.Warnings);
        Assert.NotNull(ignore.Match("azurerm_key_vault.kv", "AZ-KV-001"));
        Assert.Null(ignore.Match("azurerm_key_vault.kv", "AZ-KV-002"));
        Assert.NotNull(ignore.Match("module.legacy.azurerm_storage_account.s", "AZ-STG-001"));
        Assert.Null(ignore.Match("module.legacy.azurerm_storage_account.s", "DESTROY")); // * does not accept data loss
    }

    [Fact]
    public void DestroyMustBeAcceptedExplicitly()
    {
        var ignore = IgnoreList.Parse("azurerm_mssql_database.reporting DESTROY reason=\"rebuilt nightly\"", Today);
        var r = T.Analyze($"[{T.Change("azurerm_mssql_database", "reporting", "[\"delete\"]", "{}", null)}]", ignore: ignore);
        Assert.True(Assert.Single(r.Destructive).Suppressed);
        Assert.False(r.Fails(Severity.Low));
    }

    [Fact]
    public void SuppressedFindingsDoNotFail()
    {
        var ignore = IgnoreList.Parse("azurerm_key_vault.kv * reason=\"accepted\"", Today);
        var r = T.Analyze($"[{T.Change("azurerm_key_vault", "kv", "[\"create\"]", null, "{}")}]", ignore: ignore);
        Assert.All(r.Findings, f => Assert.True(f.Suppressed));
        Assert.False(r.Fails(Severity.Low));
        Assert.Null(r.Worst);
    }

    [Fact]
    public void NoReasonOrExpired()
    {
        var ignore = IgnoreList.Parse("""
            azurerm_key_vault.a  AZ-KV-001
            azurerm_key_vault.b  AZ-KV-001  reason="until the audit" expires=2026-10-01
            azurerm_key_vault.c  AZ-KV-001  reason="x" expires=01.01.2027
            justoneword
            """, Today);
        Assert.Single(ignore.Entries); // c is kept (bad date reported, no expiry)
        Assert.Equal(4, ignore.Warnings.Count);
        Assert.Contains(ignore.Warnings, w => w.Contains("no reason"));
        Assert.Contains(ignore.Warnings, w => w.Contains("expired on 2026-10-01"));
    }
}

public class SourceLocatorTests
{
    [Fact]
    public void FindsBlocksWithLineNumbers()
    {
        var dir = Path.Combine(Path.GetTempPath(), "bauplan-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(dir, "modules", "app"));
        try
        {
            File.WriteAllText(Path.Combine(dir, "main.tf"), "\n\n# comment\n\nresource \"azurerm_key_vault\" \"main\" {\n}\n");
            File.WriteAllText(Path.Combine(dir, "modules", "app", "kv.tf"), "resource \"azurerm_key_vault\" \"main\" {\n}\n");
            var locator = new SourceLocator(dir);
            Assert.Equal(2, locator.Count);
            Assert.Equal(new SourceLocation("main.tf", 5), locator.Find("azurerm_key_vault.main"));
            Assert.Equal(new SourceLocation("modules/app/kv.tf", 1), locator.Find("module.app.azurerm_key_vault.main"));
            Assert.Equal(new SourceLocation("main.tf", 5), locator.Find("azurerm_key_vault.main[\"eu\"]"));
            Assert.Null(locator.Find("azurerm_key_vault.other"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void MissingFolderFindsNothing() => Assert.Equal(0, new SourceLocator(Path.Combine(Path.GetTempPath(), "nope-" + Guid.NewGuid())).Count);
}

public class SampleTests
{
    [Fact]
    public void RiskyPullRequest()
    {
        var r = T.Sample("risky-pr");
        var newIds = r.Findings.Where(f => f.Status == FindingStatus.New).Select(f => f.RuleId).ToHashSet();
        Assert.Superset(new HashSet<string> { "AZ-NET-001", "AZ-NET-002", "AZ-STG-001", "AZ-TLS-001", "AZ-TLS-002", "AZ-SEC-001", "AZ-SEC-002", "AZ-IAM-001" }, newIds);
        // The SQL server was already like this: reported, but as existing
        Assert.All(r.Findings.Where(f => f.Address == "azurerm_mssql_server.main"), f => Assert.Equal(FindingStatus.Existing, f.Status));
        // The PR also fixes the key vault, and it has a diagnostic setting
        Assert.Equal(["AZ-KV-001", "AZ-KV-002"], r.Resolved.Select(x => x.RuleId).Order());
        Assert.DoesNotContain(r.Findings, f => f.Address == "azurerm_key_vault.main");
        Assert.Empty(r.Destructive);
        Assert.True(r.Fails(Severity.High, newOnly: true));
        Assert.Equal(Severity.Critical, r.Worst);
        // Source locations point at the .tf code
        Assert.Equal(new SourceLocation("risky-pr/main.tf", 86), r.Findings.Single(f => f.RuleId == "AZ-NET-002").Source);
    }

    [Fact]
    public void RenameDatabase()
    {
        var r = T.Sample("rename-database");
        Assert.Empty(r.Findings);
        var critical = r.Destructive.Where(d => d.Severity == Severity.Critical).Select(d => d.Address).ToList();
        Assert.Equal(["azurerm_mssql_database.orders", "azurerm_mssql_server.main", "azurerm_resource_group.test"], critical);
        Assert.Contains("because name changed", r.Destructive.Single(d => d.Address == "azurerm_mssql_server.main").Message);
        Assert.Null(r.Destructive.Single(d => d.Address == "azurerm_resource_group.test").Source); // removed from the code
        Assert.Equal("4 to add, 0 to change, 5 to destroy (4 replaced)", r.Summary.ToString());
    }

    [Fact]
    public void HardenedIsClean()
    {
        var r = T.Sample("hardened");
        Assert.Empty(r.Findings);
        Assert.Empty(r.Destructive);
        Assert.False(r.Fails(Severity.Low));
    }
}

public class ReportTests
{
    // Secrets that are in the sample plan and must never appear in a report
    private static readonly string[] Secrets = ["Winter2026!", "not-a-real-key-0123456789", "from-a-variable"];

    [Theory]
    [InlineData("json")]
    [InlineData("markdown")]
    [InlineData("sarif")]
    public void ReportsNeverContainSecretValues(string format)
    {
        var r = T.Sample("risky-pr");
        var text = format switch { "json" => ReportFormats.ToJson(r), "markdown" => ReportFormats.ToMarkdown(r), _ => ReportFormats.ToSarif(r, "risky-pr/plan.json") };
        foreach (var s in Secrets) Assert.DoesNotContain(s, text);
    }

    [Fact]
    public void MarkdownForPullRequests()
    {
        var md = ReportFormats.ToMarkdown(T.Sample("risky-pr"));
        Assert.Contains("**Plan:** 5 to add, 3 to change, 0 to destroy.", md);
        Assert.Contains("### 🆕 Introduced by this plan (12)", md);
        Assert.Contains("### ✅ Fixed by this plan (2)", md);
        Assert.Contains("<summary>Already present before this plan (3)</summary>", md);
        Assert.Contains("<sub>risky-pr/main.tf:86</sub>", md);

        var destroy = ReportFormats.ToMarkdown(T.Sample("rename-database"));
        Assert.Contains("### 💥 Destroys", destroy);
        Assert.Contains("`azurerm_mssql_database.orders`", destroy);
        Assert.DoesNotContain("`azurerm_network_security_group.db`", destroy); // info-level replacements are left out of the comment

        Assert.Contains("destroys no data and introduces no new security findings", ReportFormats.ToMarkdown(T.Sample("hardened")));
    }

    [Fact]
    public void SarifPointsAtTerraformCode()
    {
        using var doc = JsonDocument.Parse(ReportFormats.ToSarif(T.Sample("rename-database"), "rename-database/plan.json"));
        var run = doc.RootElement.GetProperty("runs")[0];
        var rules = run.GetProperty("tool").GetProperty("driver").GetProperty("rules").EnumerateArray().Select(x => x.GetProperty("id").GetString()).ToList();
        Assert.Equal(["DESTROY"], rules);
        var results = run.GetProperty("results").EnumerateArray().ToList();
        Assert.Equal(3, results.Count);
        string Uri(JsonElement res) => res.GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString()!;
        Assert.Contains(results, x => Uri(x) == "rename-database/main.tf");
        Assert.Contains(results, x => Uri(x) == "rename-database/plan.json"); // the deleted resource group has no code any more
        Assert.All(results, x => Assert.Equal("error", x.GetProperty("level").GetString()));
    }

    [Fact]
    public void SarifRuleIndexesMatch()
    {
        using var doc = JsonDocument.Parse(ReportFormats.ToSarif(T.Sample("risky-pr"), "risky-pr/plan.json"));
        var run = doc.RootElement.GetProperty("runs")[0];
        var rules = run.GetProperty("tool").GetProperty("driver").GetProperty("rules").EnumerateArray().ToList();
        foreach (var res in run.GetProperty("results").EnumerateArray())
            Assert.Equal(res.GetProperty("ruleId").GetString(), rules[res.GetProperty("ruleIndex").GetInt32()].GetProperty("id").GetString());
    }

    [Fact]
    public void JsonHasEverything()
    {
        using var doc = JsonDocument.Parse(ReportFormats.ToJson(T.Sample("risky-pr")));
        Assert.Equal("critical", doc.RootElement.GetProperty("worst").GetString());
        Assert.Equal(5, doc.RootElement.GetProperty("plan").GetProperty("create").GetInt32());
        Assert.Equal(15, doc.RootElement.GetProperty("findings").GetArrayLength());
        Assert.Equal("new", doc.RootElement.GetProperty("findings")[0].GetProperty("status").GetString());
    }
}
