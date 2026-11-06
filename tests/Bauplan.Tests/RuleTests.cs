using Bauplan.Core.Rules;

namespace Bauplan.Tests;

public class NetworkRuleTests
{
    private static string Nsg(string port, string source, string direction = "Inbound", string access = "Allow", string? ports = null) => $$"""
        { "security_rule": [{ "name": "r1", "direction": "{{direction}}", "access": "{{access}}", "destination_port_range": "{{port}}",
          "destination_port_ranges": {{ports ?? "[]"}}, "source_address_prefix": "{{source}}", "source_address_prefixes": [] }] }
        """;

    [Theory]
    [InlineData("3389", "*", Severity.Critical, "RDP 3389")]
    [InlineData("22", "Internet", Severity.Critical, "SSH 22")]
    [InlineData("20-25", "0.0.0.0/0", Severity.Critical, "SSH 22")]   // range covers 22 and Telnet 23
    [InlineData("1433", "Any", Severity.High, "SQL Server 1433")]
    [InlineData("5432", "*", Severity.High, "PostgreSQL 5432")]
    public void ExposedPorts(string port, string source, Severity severity, string text)
    {
        var issue = Assert.Single(T.Evaluate(new NsgOpenToInternetRule(), "azurerm_network_security_group", Nsg(port, source)));
        Assert.Equal(severity, issue.SeverityOverride ?? Severity.Critical);
        Assert.Contains(text, issue.Message);
        Assert.Equal("r1", issue.Key);
    }

    [Fact]
    public void AllPorts()
    {
        var issue = Assert.Single(T.Evaluate(new NsgOpenToInternetRule(), "azurerm_network_security_group", Nsg("*", "*")));
        Assert.Contains("ALL ports", issue.Message);
    }

    [Fact]
    public void PortListsCount() =>
        Assert.Single(T.Evaluate(new NsgOpenToInternetRule(), "azurerm_network_security_group", Nsg("", "*", ports: "[\"443\", \"3389\"]")));

    [Theory]
    [InlineData("443", "*")]                         // HTTPS for everyone is normal
    [InlineData("3389", "10.0.0.0/8")]               // internal source
    [InlineData("3389", "*", "Outbound")]
    [InlineData("3389", "*", "Inbound", "Deny")]
    public void NotFlagged(string port, string source, string direction = "Inbound", string access = "Allow") =>
        Assert.Empty(T.Evaluate(new NsgOpenToInternetRule(), "azurerm_network_security_group", Nsg(port, source, direction, access)));

    [Fact]
    public void StandaloneRuleResource()
    {
        var json = """{ "name": "ssh", "direction": "Inbound", "access": "Allow", "destination_port_range": "22", "source_address_prefix": "*" }""";
        var issue = Assert.Single(T.Evaluate(new NsgOpenToInternetRule(), "azurerm_network_security_rule", json));
        Assert.Equal("source_address_prefix", issue.Attribute);
    }

    [Theory]
    [InlineData("22", 22, true)]
    [InlineData("20-30", 22, true)]
    [InlineData("23-30", 22, false)]
    [InlineData("*", 1, true)]
    [InlineData("abc", 22, false)]
    public void PortRanges(string range, int port, bool covered) => Assert.Equal(covered, NsgOpenToInternetRule.Covers(range, port));

    [Theory]
    [InlineData("0.0.0.0", "255.255.255.255", Severity.Critical, "all 4.3 billion")]
    [InlineData("10.0.0.0", "10.255.255.255", Severity.Critical, "16.8 million")]
    [InlineData("203.0.0.0", "203.0.255.255", Severity.High, "65,536")]
    [InlineData("0.0.0.0", "0.0.0.0", Severity.Medium, "Allow Azure services")]
    public void DatabaseFirewall(string start, string end, Severity severity, string text)
    {
        var issue = Assert.Single(T.Evaluate(new DatabaseFirewallOpenRule(), "azurerm_mssql_firewall_rule", $$"""{ "start_ip_address": "{{start}}", "end_ip_address": "{{end}}" }"""));
        Assert.Equal(severity, issue.SeverityOverride ?? Severity.Critical);
        Assert.Contains(text, issue.Message);
    }

    [Fact]
    public void SmallFirewallRangeIsFine() =>
        Assert.Empty(T.Evaluate(new DatabaseFirewallOpenRule(), "azurerm_mssql_firewall_rule", """{ "start_ip_address": "203.0.113.10", "end_ip_address": "203.0.113.20" }"""));

    [Fact]
    public void RedisFirewallUsesOtherAttributeNames() =>
        Assert.Single(T.Evaluate(new DatabaseFirewallOpenRule(), "azurerm_redis_firewall_rule", """{ "start_ip": "0.0.0.0", "end_ip": "255.255.255.255" }"""));
}

public class StorageRuleTests
{
    [Fact]
    public void PublicBlobDefaultIsTrue() =>
        Assert.Single(T.Evaluate(new StoragePublicBlobRule(), "azurerm_storage_account", "{}"));

    [Fact]
    public void PublicBlobExplicitlyOff() =>
        Assert.Empty(T.Evaluate(new StoragePublicBlobRule(), "azurerm_storage_account", """{ "allow_nested_items_to_be_public": false }"""));

    [Fact]
    public void PublicBlobUnknownIsNotJudged() =>
        Assert.Empty(T.Evaluate(new StoragePublicBlobRule(), "azurerm_storage_account", "{}", unknown: """{ "allow_nested_items_to_be_public": true }"""));

    [Theory]
    [InlineData("blob", true)]
    [InlineData("container", true)]
    [InlineData("private", false)]
    public void ContainerAccess(string access, bool flagged) =>
        Assert.Equal(flagged, T.Evaluate(new StoragePublicBlobRule(), "azurerm_storage_container", $$"""{ "container_access_type": "{{access}}" }""").Count == 1);

    [Fact]
    public void NetworkRulesDeny() =>
        Assert.Empty(T.Evaluate(new StorageNetworkRule(), "azurerm_storage_account", """{ "network_rules": [{ "default_action": "Deny" }] }"""));

    [Fact]
    public void NoNetworkRules() =>
        Assert.Single(T.Evaluate(new StorageNetworkRule(), "azurerm_storage_account", """{ "network_rules": [] }"""));

    [Fact]
    public void PrivateStorageNeedsNoRules() =>
        Assert.Empty(T.Evaluate(new StorageNetworkRule(), "azurerm_storage_account", """{ "public_network_access_enabled": false }"""));

    [Fact]
    public void SeparateNetworkRulesResource()
    {
        var context = T.Context("""
            [{ "address": "azurerm_storage_account_network_rules.r", "expressions": { "storage_account_id": { "references": ["azurerm_storage_account.x.id", "azurerm_storage_account.x"] } } }]
            """);
        Assert.Empty(T.Evaluate(new StorageNetworkRule(), "azurerm_storage_account", "{}", context));
    }

    [Fact]
    public void SharedKey()
    {
        Assert.Single(T.Evaluate(new StorageSharedKeyRule(), "azurerm_storage_account", "{}"));
        Assert.Empty(T.Evaluate(new StorageSharedKeyRule(), "azurerm_storage_account", """{ "shared_access_key_enabled": false }"""));
    }
}

public class EncryptionRuleTests
{
    [Theory]
    [InlineData("azurerm_storage_account", """{ "min_tls_version": "TLS1_0" }""", true)]
    [InlineData("azurerm_storage_account", """{ "min_tls_version": "TLS1_2" }""", false)]
    [InlineData("azurerm_mssql_server", """{ "minimum_tls_version": "1.1" }""", true)]
    [InlineData("azurerm_mssql_server", """{ "minimum_tls_version": "1.2" }""", false)]
    [InlineData("azurerm_linux_web_app", """{ "site_config": [{ "minimum_tls_version": "1.0" }] }""", true)]
    [InlineData("azurerm_redis_cache", """{ "minimum_tls_version": "1.2" }""", false)]
    public void Tls(string type, string json, bool flagged) => Assert.Equal(flagged, T.Evaluate(new TlsMinimumRule(), type, json).Count == 1);

    [Theory]
    [InlineData("azurerm_linux_web_app", "{}", true)]   // https_only defaults to false
    [InlineData("azurerm_linux_web_app", """{ "https_only": true }""", false)]
    [InlineData("azurerm_storage_account", """{ "https_traffic_only_enabled": false }""", true)]
    [InlineData("azurerm_storage_account", """{ "enable_https_traffic_only": false }""", true)]  // azurerm 3.x name
    [InlineData("azurerm_storage_account", "{}", false)]
    [InlineData("azurerm_redis_cache", """{ "non_ssl_port_enabled": true }""", true)]
    [InlineData("azurerm_redis_cache", """{ "enable_non_ssl_port": false }""", false)]
    public void HttpsOnly(string type, string json, bool flagged) => Assert.Equal(flagged, T.Evaluate(new HttpsOnlyRule(), type, json).Count == 1);

    [Fact]
    public void AppServiceFtpAndDebugging()
    {
        var issues = T.Evaluate(new AppServiceHardeningRule(), "azurerm_windows_web_app", """{ "site_config": [{ "ftps_state": "AllAllowed", "remote_debugging_enabled": true }] }""");
        Assert.Equal(["ftp", "debug"], issues.Select(i => i.Key));
        Assert.Empty(T.Evaluate(new AppServiceHardeningRule(), "azurerm_windows_web_app", """{ "site_config": [{ "ftps_state": "FtpsOnly" }] }"""));
    }
}

public class SecretRuleTests
{
    [Fact]
    public void LiteralSecretSettingsAreFlaggedWithoutTheirValue()
    {
        var json = """
            { "app_settings": { "Db__Password": "Winter2026!", "API_KEY": "abc", "Storage__ConnectionString": "@Microsoft.KeyVault(SecretUri=https://kv/secrets/s/)",
              "ASPNETCORE_ENVIRONMENT": "Production", "Jwt__Secret": "" } }
            """;
        var issues = T.Evaluate(new PlaintextAppSecretRule(), "azurerm_linux_web_app", json);
        Assert.Equal(["Db__Password", "API_KEY"], issues.Select(i => i.Key));
        Assert.All(issues, i => Assert.DoesNotContain("Winter2026!", i.Message));
        Assert.Contains("11 characters", issues[0].Message);
    }

    [Fact]
    public void UnknownSettingIsNotJudged() =>
        Assert.Empty(T.Evaluate(new PlaintextAppSecretRule(), "azurerm_linux_web_app", """{ "app_settings": { "Db__Password": "x" } }""", unknown: """{ "app_settings": { "Db__Password": true } }"""));

    [Fact]
    public void ConnectionStringBlocks()
    {
        var json = """
            { "connection_string": [
                { "name": "Orders", "type": "SQLAzure", "value": "Server=tcp:sql;Database=orders;User ID=app;Password=x;" },
                { "name": "Cache", "type": "Custom", "value": "@Microsoft.KeyVault(SecretUri=https://kv/secrets/c/)" },
                { "name": "Search", "type": "Custom", "value": "https://search.example" } ] }
            """;
        Assert.Equal("cs:Orders", Assert.Single(T.Evaluate(new PlaintextAppSecretRule(), "azurerm_linux_web_app", json)).Key);
    }

    [Theory]
    [InlineData("DB_PASSWORD", true)]
    [InlineData("ClientSecret", true)]
    [InlineData("Storage__AccountKey", true)]
    [InlineData("GITHUB_TOKEN", true)]
    [InlineData("WEBSITE_RUN_FROM_PACKAGE", false)]
    [InlineData("Logging__LogLevel", false)]
    public void SecretNames(string name, bool secret) => Assert.Equal(secret, PlaintextAppSecretRule.SecretName().IsMatch(name));

    [Fact]
    public void HardcodedKeyVaultSecret()
    {
        var context = T.Context("""[{ "address": "azurerm_key_vault_secret.x", "expressions": { "value": { "constant_value": "s3cret" } } }]""");
        var issue = Assert.Single(T.Evaluate(new HardcodedSecretRule(), "azurerm_key_vault_secret", """{ "value": "s3cret" }""", context));
        Assert.DoesNotContain("s3cret", issue.Message);
    }

    [Fact]
    public void PasswordFromVariableIsFine()
    {
        var context = T.Context("""[{ "address": "azurerm_mssql_server.x", "expressions": { "administrator_login_password": { "references": ["var.sql_password"] } } }]""");
        Assert.Empty(T.Evaluate(new HardcodedSecretRule(), "azurerm_mssql_server", "{}", context));
    }
}

public class KeyVaultAndDatabaseRuleTests
{
    [Fact]
    public void PurgeProtection()
    {
        Assert.Single(T.Evaluate(new KeyVaultPurgeProtectionRule(), "azurerm_key_vault", "{}"));
        Assert.Empty(T.Evaluate(new KeyVaultPurgeProtectionRule(), "azurerm_key_vault", """{ "purge_protection_enabled": true }"""));
    }

    [Theory]
    [InlineData("""{ "network_acls": [] }""", true)]
    [InlineData("""{ "network_acls": [{ "default_action": "Deny" }] }""", false)]
    [InlineData("""{ "public_network_access_enabled": false }""", false)]
    public void KeyVaultNetwork(string json, bool flagged) => Assert.Equal(flagged, T.Evaluate(new KeyVaultNetworkRule(), "azurerm_key_vault", json).Count == 1);

    [Fact]
    public void SqlEntraAdmin()
    {
        Assert.Equal("azuread_administrator", Assert.Single(T.Evaluate(new SqlEntraAuthRule(), "azurerm_mssql_server", """{ "azuread_administrator": [] }""")).Attribute);
        var partial = Assert.Single(T.Evaluate(new SqlEntraAuthRule(), "azurerm_mssql_server", """{ "azuread_administrator": [{ "azuread_authentication_only": false }] }"""));
        Assert.Equal(Severity.Low, partial.SeverityOverride);
        Assert.Empty(T.Evaluate(new SqlEntraAuthRule(), "azurerm_mssql_server", """{ "azuread_administrator": [{ "azuread_authentication_only": true }] }"""));
    }

    [Theory]
    [InlineData("azurerm_mssql_server", "{}", true)]  // defaults to public
    [InlineData("azurerm_mssql_server", """{ "public_network_access_enabled": false }""", false)]
    [InlineData("azurerm_postgresql_flexible_server", "{}", false)] // only explicit true counts
    [InlineData("azurerm_postgresql_flexible_server", """{ "public_network_access_enabled": true }""", true)]
    [InlineData("azurerm_cosmosdb_account", """{ "ip_range_filter": ["203.0.113.0/24"] }""", false)]
    public void PublicDatabase(string type, string json, bool flagged) => Assert.Equal(flagged, T.Evaluate(new PublicDatabaseRule(), type, json).Count == 1);

    [Fact]
    public void DiagnosticsFoundThroughConfiguration()
    {
        var withDiag = T.Context("""[{ "address": "azurerm_monitor_diagnostic_setting.d", "expressions": { "target_resource_id": { "references": ["azurerm_key_vault.x.id", "azurerm_key_vault.x"] } } }]""");
        Assert.Empty(T.Evaluate(new MissingDiagnosticsRule(), "azurerm_key_vault", "{}", withDiag));
        Assert.Single(T.Evaluate(new MissingDiagnosticsRule(), "azurerm_key_vault", "{}"));
    }

    [Fact]
    public void SqlAuditingPolicyCountsAsLogging()
    {
        var context = T.Context("""[{ "address": "azurerm_mssql_server_extended_auditing_policy.a", "expressions": { "server_id": { "references": ["azurerm_mssql_server.x.id"] } } }]""");
        Assert.Empty(T.Evaluate(new MissingDiagnosticsRule(), "azurerm_mssql_server", "{}", context));
    }
}

public class IdentityRuleTests
{
    [Theory]
    [InlineData("Owner", "/subscriptions/0000", "subscription")]
    [InlineData("Contributor", "/subscriptions/0000/", "subscription")]
    [InlineData("User Access Administrator", "/providers/Microsoft.Management/managementGroups/root-mg", "management group")]
    public void PrivilegedAtWideScope(string role, string scope, string level)
    {
        var issue = Assert.Single(T.Evaluate(new PrivilegedRoleAssignmentRule(), "azurerm_role_assignment", $$"""{ "role_definition_name": "{{role}}", "scope": "{{scope}}" }"""));
        Assert.Contains($"at {level} scope", issue.Message);
    }

    [Fact]
    public void OwnerOnAResourceGroupIsMedium()
    {
        var issue = Assert.Single(T.Evaluate(new PrivilegedRoleAssignmentRule(), "azurerm_role_assignment", """{ "role_definition_name": "Owner", "scope": "/subscriptions/0000/resourceGroups/rg" }"""));
        Assert.Equal(Severity.Medium, issue.SeverityOverride);
    }

    [Theory]
    [InlineData("Contributor", "/subscriptions/0000/resourceGroups/rg")]
    [InlineData("Reader", "/subscriptions/0000")]
    [InlineData("Storage Blob Data Contributor", "/subscriptions/0000")]
    public void NotFlagged(string role, string scope) =>
        Assert.Empty(T.Evaluate(new PrivilegedRoleAssignmentRule(), "azurerm_role_assignment", $$"""{ "role_definition_name": "{{role}}", "scope": "{{scope}}" }"""));

    [Fact]
    public void RoleById() =>
        Assert.Single(T.Evaluate(new PrivilegedRoleAssignmentRule(), "azurerm_role_assignment",
            """{ "role_definition_id": "/subscriptions/0000/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "scope": "/subscriptions/0000" }"""));

    [Fact]
    public void UnknownScopeResolvedThroughConfiguration()
    {
        var context = T.Context("""[{ "address": "azurerm_role_assignment.x", "expressions": { "scope": { "references": ["data.azurerm_subscription.current.id", "data.azurerm_subscription.current"] } } }]""");
        var issue = Assert.Single(T.Evaluate(new PrivilegedRoleAssignmentRule(), "azurerm_role_assignment", """{ "role_definition_name": "Contributor", "scope": null }""", context));
        Assert.Contains("subscription scope", issue.Message);
    }

    [Fact]
    public void Aks()
    {
        var issues = T.Evaluate(new AksHardeningRule(), "azurerm_kubernetes_cluster", """{ "role_based_access_control_enabled": false }""");
        Assert.Equal(["rbac", "api", "local"], issues.Select(i => i.Key));
        Assert.Empty(T.Evaluate(new AksHardeningRule(), "azurerm_kubernetes_cluster", """{ "private_cluster_enabled": true, "local_account_disabled": true }"""));
        Assert.Empty(T.Evaluate(new AksHardeningRule(), "azurerm_kubernetes_cluster",
            """{ "api_server_access_profile": [{ "authorized_ip_ranges": ["203.0.113.0/24"] }], "local_account_disabled": true }"""));
    }

    [Fact]
    public void VmPassword()
    {
        Assert.Single(T.Evaluate(new VmPasswordAuthRule(), "azurerm_linux_virtual_machine", """{ "disable_password_authentication": false }"""));
        Assert.Empty(T.Evaluate(new VmPasswordAuthRule(), "azurerm_linux_virtual_machine", "{}"));
    }

    [Fact]
    public void CatalogIsConsistent()
    {
        var ids = RuleCatalog.All.Select(r => r.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.All(RuleCatalog.All, r =>
        {
            Assert.Matches("^AZ-[A-Z]+-\\d{3}$", r.Id);
            Assert.NotEmpty(r.Types);
            Assert.All(r.Types, t => Assert.StartsWith("azurerm_", t));
            Assert.False(string.IsNullOrWhiteSpace(r.Why));
            Assert.False(string.IsNullOrWhiteSpace(r.Fix));
        });
        Assert.Equal(18, ids.Count);
    }
}
