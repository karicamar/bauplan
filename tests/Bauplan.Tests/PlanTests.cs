using Bauplan.Core.Plan;

namespace Bauplan.Tests;

public class PlanParsingTests
{
    [Theory]
    [InlineData("[\"no-op\"]", ChangeAction.NoOp)]
    [InlineData("[\"create\"]", ChangeAction.Create)]
    [InlineData("[\"update\"]", ChangeAction.Update)]
    [InlineData("[\"delete\"]", ChangeAction.Delete)]
    [InlineData("[\"delete\",\"create\"]", ChangeAction.Replace)]
    [InlineData("[\"create\",\"delete\"]", ChangeAction.Replace)]
    [InlineData("[\"read\"]", ChangeAction.Read)]
    public void Actions(string actions, ChangeAction expected)
    {
        var plan = TerraformPlan.Parse(T.PlanJson($"[{T.Change("azurerm_resource_group", "a", actions, "{}", "{}")}]"));
        Assert.Equal(expected, plan.Changes.Single().Action);
    }

    [Fact]
    public void CreateBeforeDestroyAndReplacePaths()
    {
        var json = T.PlanJson($"[{T.Change("azurerm_mssql_server", "main", "[\"create\",\"delete\"]", "{}", "{}", ", \"replace_paths\": [[\"name\"], [\"site_config\", 0, \"name\"]]")}]");
        var c = TerraformPlan.Parse(json).Changes.Single();
        Assert.True(c.CreateBeforeDestroy);
        Assert.Equal(["name", "site_config.0.name"], c.ReplacePaths);
    }

    [Fact]
    public void UnknownActionsAreRejected() =>
        Assert.Throws<InvalidDataException>(() => TerraformPlan.Parse(T.PlanJson($"[{T.Change("x", "a", "[\"explode\"]", "{}", "{}")}]")));

    [Theory]
    [InlineData("not json", "Not valid JSON")]
    [InlineData("[1,2]", "not an object")]
    [InlineData("{\"resource_changes\": []}", "format_version is missing")]
    [InlineData("{\"format_version\": \"2.0\", \"resource_changes\": []}", "Unsupported plan format_version 2.0")]
    [InlineData("{\"format_version\": \"1.0\", \"values\": {}}", "state file")]
    public void InvalidInput(string json, string message) =>
        Assert.Contains(message, Assert.Throws<InvalidDataException>(() => TerraformPlan.Parse(json)).Message);

    [Fact]
    public void DataSourcesAreNotManaged()
    {
        var json = T.PlanJson("""[{ "address": "data.azurerm_subscription.current", "mode": "data", "type": "azurerm_subscription", "name": "current", "change": { "actions": ["read"], "before": null, "after": {} } }]""");
        Assert.False(TerraformPlan.Parse(json).Changes.Single().IsManaged);
    }

    [Fact]
    public void ParsesTheSamples()
    {
        foreach (var dir in Directory.GetDirectories(T.SamplesDir))
        {
            var plan = TerraformPlan.Parse(File.ReadAllText(Path.Combine(dir, "plan.json")));
            Assert.Equal("1.2", plan.FormatVersion);
            Assert.NotEmpty(plan.Changes);
        }
    }
}

public class ConfigurationTests
{
    private const string Resources = """
        [
          { "address": "azurerm_role_assignment.a", "type": "azurerm_role_assignment", "name": "a",
            "expressions": { "scope": { "references": ["data.azurerm_subscription.current.id", "data.azurerm_subscription.current"] } } },
          { "address": "azurerm_key_vault_secret.literal", "type": "azurerm_key_vault_secret", "name": "literal",
            "expressions": { "value": { "constant_value": "hunter2" } } },
          { "address": "azurerm_key_vault_secret.sensitive", "type": "azurerm_key_vault_secret", "name": "sensitive",
            "expressions": { "value": {} } },
          { "address": "azurerm_key_vault_secret.generated", "type": "azurerm_key_vault_secret", "name": "generated",
            "expressions": { "value": { "references": ["random_password.db.result", "random_password.db"] } } },
          { "address": "azurerm_monitor_diagnostic_setting.kv", "type": "azurerm_monitor_diagnostic_setting", "name": "kv",
            "expressions": { "target_resource_id": { "references": ["azurerm_key_vault.main.id", "azurerm_key_vault.main"] } } }
        ]
        """;

    private static Configuration Config() => T.Context(Resources).Configuration;

    [Fact]
    public void References() =>
        Assert.Contains("data.azurerm_subscription.current.id", Config().References("azurerm_role_assignment.a", "scope"));

    [Theory]
    [InlineData("azurerm_key_vault_secret.literal", true)]
    [InlineData("azurerm_key_vault_secret.sensitive", true)]   // Terraform omits constant_value for sensitive literals
    [InlineData("azurerm_key_vault_secret.generated", false)]
    [InlineData("azurerm_key_vault_secret.missing", false)]
    public void Literals(string address, bool literal) => Assert.Equal(literal, Config().IsLiteral(address, "value"));

    [Fact]
    public void ReferencedByIgnoresIndexes()
    {
        Assert.Single(Config().ReferencedBy("azurerm_monitor_diagnostic_setting", "target_resource_id", "azurerm_key_vault.main"));
        Assert.Single(Config().ReferencedBy("azurerm_monitor_diagnostic_setting", "target_resource_id", "azurerm_key_vault.main[\"eu\"]"));
        Assert.Empty(Config().ReferencedBy("azurerm_monitor_diagnostic_setting", "target_resource_id", "azurerm_key_vault.main2"));
    }

    [Fact]
    public void ModuleResourcesGetTheirPrefix()
    {
        var json = """
            { "format_version": "1.2", "resource_changes": [],
              "configuration": { "root_module": { "module_calls": { "app": { "module": { "resources": [
                { "address": "azurerm_key_vault_secret.s", "expressions": { "value": { "constant_value": "x" } } } ] } } } } } }
            """;
        var config = TerraformPlan.Parse(json).Configuration;
        Assert.True(config.IsLiteral("module.app.azurerm_key_vault_secret.s", "value"));
        Assert.True(config.IsLiteral("module.app[0].azurerm_key_vault_secret.s", "value"));
        Assert.False(config.IsLiteral("azurerm_key_vault_secret.s", "value"));
    }
}

public class ResourceStateTests
{
    [Fact]
    public void NestedBlocksStepIntoFirstElement()
    {
        var s = T.State("azurerm_linux_web_app", """{ "site_config": [{ "ftps_state": "Disabled", "minimum_tls_version": "1.2" }] }""");
        Assert.Equal("Disabled", s.String("site_config.ftps_state"));
        Assert.True(s.HasBlock("site_config"));
        Assert.False(s.HasBlock("auth_settings"));
    }

    [Fact]
    public void DefaultsApplyWhenNotSet()
    {
        var s = T.State("azurerm_storage_account", """{ "https_traffic_only_enabled": null }""");
        Assert.True(s.Bool("https_traffic_only_enabled", true));
        Assert.False(s.Bool("missing", false));
    }

    [Fact]
    public void UnknownValues()
    {
        var s = T.State("azurerm_role_assignment", """{ "scope": null }""", """{ "scope": true, "id": true }""");
        Assert.True(s.IsUnknown("scope"));
        Assert.False(s.IsUnknown("role_definition_name"));
    }

    [Fact]
    public void BlocksAndNumbers()
    {
        var s = T.State("azurerm_network_security_group", """{ "security_rule": [{ "name": "a", "priority": 100 }, { "name": "b", "priority": "200" }] }""");
        var blocks = s.Blocks("security_rule");
        Assert.Equal(["a", "b"], blocks.Select(b => b.String("name")));
        Assert.Equal([100, 200], blocks.Select(b => b.Int("priority") ?? 0));
        Assert.Equal("azurerm_network_security_group.x.security_rule[1]", blocks[1].Address);
    }

    [Fact]
    public void StringsFromListOrSingle()
    {
        var s = T.State("x", """{ "list": ["a", "b"], "one": "c" }""");
        Assert.Equal(["a", "b"], s.Strings("list"));
        Assert.Equal(["c"], s.Strings("one"));
        Assert.Empty(s.Strings("none"));
    }
}
