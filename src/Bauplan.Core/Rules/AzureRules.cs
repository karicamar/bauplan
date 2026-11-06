using System.Net;
using System.Text.RegularExpressions;
using Bauplan.Core.Plan;

namespace Bauplan.Core.Rules;

// Attribute names follow the azurerm provider (3.x and 4.x). Where a provider default matters, the rule states it,
// because an attribute that is not set appears in the plan with its default value (or not at all).

public sealed class NsgOpenToInternetRule : Rule
{
    private static readonly HashSet<string> Internet = new(StringComparer.OrdinalIgnoreCase) { "*", "0.0.0.0", "0.0.0.0/0", "internet", "any", "::/0" };

    internal static readonly (int Port, string Service, Severity Severity)[] SensitivePorts =
    [
        (22, "SSH", Severity.Critical), (3389, "RDP", Severity.Critical), (5985, "WinRM", Severity.Critical), (5986, "WinRM", Severity.Critical),
        (23, "Telnet", Severity.Critical), (445, "SMB", Severity.Critical),
        (1433, "SQL Server", Severity.High), (3306, "MySQL", Severity.High), (5432, "PostgreSQL", Severity.High), (1521, "Oracle", Severity.High),
        (6379, "Redis", Severity.High), (27017, "MongoDB", Severity.High), (9200, "Elasticsearch", Severity.High), (2375, "Docker API", Severity.Critical),
    ];

    public override string Id => "AZ-NET-001";
    public override string Title => "Management or database port open to the Internet";
    public override Severity Severity => Severity.Critical;
    public override string Category => "network";
    public override string Benchmark => "MCSB NS-1";
    public override string Why => "SSH, RDP, WinRM and database ports reachable from any address are found by Internet-wide scanners within minutes and are a top initial access vector (brute force, exploits).";
    public override string Fix => "Restrict source_address_prefix to known ranges, or remove the rule and use Azure Bastion, a VPN or Just-in-Time VM access.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_network_security_group", "azurerm_network_security_rule" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        var rules = r.Type == "azurerm_network_security_rule" ? [r] : r.Blocks("security_rule");
        foreach (var rule in rules)
        {
            if (!"Inbound".Equals(rule.String("direction"), StringComparison.OrdinalIgnoreCase)) continue;
            if (!"Allow".Equals(rule.String("access"), StringComparison.OrdinalIgnoreCase)) continue;
            var sources = rule.Strings("source_address_prefixes").Append(rule.String("source_address_prefix") ?? "").Where(s => s.Length > 0).ToList();
            if (!sources.Any(Internet.Contains)) continue;

            var ranges = rule.Strings("destination_port_ranges").Append(rule.String("destination_port_range") ?? "").Where(s => s.Length > 0).ToList();
            var name = rule.String("name") ?? "(unnamed)";
            var prefix = r.Type == "azurerm_network_security_rule" ? "" : "security_rule.";
            if (ranges.Contains("*"))
            {
                yield return new Issue($"rule '{name}' allows ALL ports from the Internet ({string.Join(", ", sources)})", prefix + "destination_port_range", name);
                continue;
            }
            var exposed = SensitivePorts.Where(p => ranges.Any(range => Covers(range, p.Port))).ToList();
            if (exposed.Count == 0) continue;
            var worst = exposed.Max(p => p.Severity);
            var services = string.Join(", ", exposed.Select(p => $"{p.Service} {p.Port}").Distinct());
            yield return new Issue($"rule '{name}' allows {services} from the Internet ({string.Join(", ", sources)})", prefix + "source_address_prefix", name, worst);
        }
    }

    internal static bool Covers(string range, int port)
    {
        range = range.Trim();
        if (range == "*") return true;
        var dash = range.IndexOf('-');
        if (dash < 0) return int.TryParse(range, out var p) && p == port;
        return int.TryParse(range[..dash], out var lo) && int.TryParse(range[(dash + 1)..], out var hi) && port >= lo && port <= hi;
    }
}

public sealed class DatabaseFirewallOpenRule : Rule
{
    public override string Id => "AZ-NET-002";
    public override string Title => "Database firewall allows a huge address range";
    public override Severity Severity => Severity.Critical;
    public override string Category => "network";
    public override string Benchmark => "MCSB NS-2";
    public override string Why => "A firewall rule from 0.0.0.0 to 255.255.255.255 puts the database on the open Internet, protected by a password only. The special rule 0.0.0.0-0.0.0.0 (\"Allow Azure services\") opens it to every Azure customer, not just your own resources.";
    public override string Fix => "Use a private endpoint or VNet integration; otherwise allow only the exact outbound IPs of your applications.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string>
    {
        "azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule", "azurerm_postgresql_flexible_server_firewall_rule",
        "azurerm_mysql_flexible_server_firewall_rule", "azurerm_postgresql_firewall_rule", "azurerm_mariadb_firewall_rule", "azurerm_redis_firewall_rule",
    };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        var (startAttr, endAttr) = r.Type == "azurerm_redis_firewall_rule" ? ("start_ip", "end_ip") : ("start_ip_address", "end_ip_address");
        if (!IPAddress.TryParse(r.String(startAttr), out var start) || !IPAddress.TryParse(r.String(endAttr), out var end)) yield break;
        var size = (long)ToNumber(end) - ToNumber(start) + 1;

        if (start.Equals(IPAddress.Any) && end.Equals(IPAddress.Any))
            yield return new Issue("0.0.0.0-0.0.0.0 \"Allow Azure services\": any resource in any Azure tenant can connect", startAttr, "", Severity.Medium);
        else if (size >= 1L << 24)
            yield return new Issue($"allows {start}-{end} ({FormatSize(size)} addresses)", startAttr);
        else if (size >= 1L << 16)
            yield return new Issue($"allows {start}-{end} ({FormatSize(size)} addresses)", startAttr, "", Severity.High);
    }

    private static uint ToNumber(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b.Length == 4 ? (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) : 0;
    }

    private static string FormatSize(long n) => n switch
    {
        >= 1L << 32 => "all 4.3 billion",
        >= 1_000_000_000 => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{n / 1e9:0.#} billion"),
        >= 1_000_000 => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{n / 1e6:0.#} million"),
        _ => n.ToString("N0", System.Globalization.CultureInfo.InvariantCulture),
    };
}

public sealed class StoragePublicBlobRule : Rule
{
    public override string Id => "AZ-STG-001";
    public override string Title => "Storage account allows anonymous public blob access";
    public override Severity Severity => Severity.High;
    public override string Category => "data-protection";
    public override string Why => "With nested items allowed to be public, a single container set to 'blob' or 'container' access exposes its files to anyone with the URL, without any credential. Many cloud data leaks started this way.";
    public override string Fix => "Set allow_nested_items_to_be_public = false (azurerm 3.x defaults to true). Serve public files through a CDN or SAS tokens instead.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_storage_account", "azurerm_storage_container" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (r.Type == "azurerm_storage_container")
        {
            var access = r.String("container_access_type");
            if (access is "blob" or "container")
                yield return new Issue($"container_access_type = \"{access}\": files can be read anonymously", "container_access_type");
            yield break;
        }
        if (!r.IsUnknown("allow_nested_items_to_be_public") && r.Bool("allow_nested_items_to_be_public", defaultValue: true))
            yield return new Issue("allow_nested_items_to_be_public is true (or not set): containers can be made public", "allow_nested_items_to_be_public");
    }
}

public sealed class StorageNetworkRule : Rule
{
    public override string Id => "AZ-STG-002";
    public override string Title => "Storage account reachable from all networks";
    public override Severity Severity => Severity.Medium;
    public override string Category => "network";
    public override string Benchmark => "MCSB NS-2";
    public override string Why => "Without network rules a stolen access key or SAS token works from anywhere on the Internet.";
    public override string Fix => "Add network_rules { default_action = \"Deny\" } with your VNets/IPs, or set public_network_access_enabled = false and use a private endpoint.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_storage_account" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (!r.Bool("public_network_access_enabled", defaultValue: true)) yield break;
        if ("Deny".Equals(r.String("network_rules.default_action"), StringComparison.OrdinalIgnoreCase)) yield break;
        // Network rules can also be a separate resource that points to this account
        if (context.Configuration.ReferencedBy("azurerm_storage_account_network_rules", "storage_account_id", r.Address).Any()) yield break;
        yield return new Issue("public network access with no network_rules (default_action is Allow)", "network_rules");
    }
}

public sealed class StorageSharedKeyRule : Rule
{
    public override string Id => "AZ-STG-003";
    public override string Title => "Storage account accepts shared access keys";
    public override Severity Severity => Severity.Low;
    public override string Category => "identity";
    public override string Benchmark => "MCSB IM-1";
    public override string Why => "Account keys are full-access passwords that do not expire and cannot be scoped; every SAS token is derived from them. Entra ID authentication with RBAC can be audited and revoked per identity.";
    public override string Fix => "Set shared_access_key_enabled = false and use managed identities with roles like Storage Blob Data Reader.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_storage_account" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (r.Bool("shared_access_key_enabled", defaultValue: true))
            yield return new Issue("shared_access_key_enabled is true (or not set)", "shared_access_key_enabled");
    }
}

public sealed class TlsMinimumRule : Rule
{
    // type → (attribute, values that mean TLS 1.0 or 1.1)
    private static readonly Dictionary<string, string> Attributes = new()
    {
        ["azurerm_storage_account"] = "min_tls_version",
        ["azurerm_mssql_server"] = "minimum_tls_version",
        ["azurerm_redis_cache"] = "minimum_tls_version",
        ["azurerm_eventhub_namespace"] = "minimum_tls_version",
        ["azurerm_servicebus_namespace"] = "minimum_tls_version",
        ["azurerm_linux_web_app"] = "site_config.minimum_tls_version",
        ["azurerm_windows_web_app"] = "site_config.minimum_tls_version",
        ["azurerm_linux_function_app"] = "site_config.minimum_tls_version",
        ["azurerm_windows_function_app"] = "site_config.minimum_tls_version",
    };

    public override string Id => "AZ-TLS-001";
    public override string Title => "TLS 1.0 or 1.1 allowed";
    public override Severity Severity => Severity.High;
    public override string Category => "encryption";
    public override string Benchmark => "MCSB DP-3";
    public override string Why => "TLS 1.0 and 1.1 are deprecated (RFC 8996) and fail PCI DSS and BSI TR-02102-2 requirements. Azure is retiring them for its own services.";
    public override string Fix => "Set the minimum TLS version to 1.2 (TLS1_2 for storage accounts).";
    public override IReadOnlySet<string> Types { get; } = Attributes.Keys.ToHashSet();

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        var attr = Attributes[r.Type];
        var value = r.String(attr);
        if (value is "1.0" or "1.1" or "TLS1_0" or "TLS1_1")
            yield return new Issue($"{attr} = \"{value}\"", attr);
    }
}

public sealed class HttpsOnlyRule : Rule
{
    public override string Id => "AZ-TLS-002";
    public override string Title => "Unencrypted HTTP or non-TLS port enabled";
    public override Severity Severity => Severity.High;
    public override string Category => "encryption";
    public override string Benchmark => "MCSB DP-3";
    public override string Why => "Plain HTTP exposes session cookies, tokens and form data to anyone on the network path and allows content injection.";
    public override string Fix => "App Service: https_only = true (the provider default is false). Storage: https_traffic_only_enabled = true. Redis: disable the non-SSL port.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string>
    {
        "azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app",
        "azurerm_storage_account", "azurerm_redis_cache",
    };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        switch (r.Type)
        {
            case "azurerm_storage_account":
                // 4.x name first, then 3.x
                var https = r.Get("https_traffic_only_enabled") is not null ? r.Bool("https_traffic_only_enabled", true) : r.Bool("enable_https_traffic_only", true);
                if (!https) yield return new Issue("HTTPS-only traffic is disabled", r.Get("https_traffic_only_enabled") is not null ? "https_traffic_only_enabled" : "enable_https_traffic_only");
                break;
            case "azurerm_redis_cache":
                if (r.Bool("non_ssl_port_enabled", false) || r.Bool("enable_non_ssl_port", false))
                    yield return new Issue("the non-TLS port 6379 is enabled", r.Get("non_ssl_port_enabled") is not null ? "non_ssl_port_enabled" : "enable_non_ssl_port");
                break;
            default:
                if (!r.Bool("https_only", defaultValue: false))
                    yield return new Issue("https_only is false (or not set): the app answers on plain HTTP", "https_only");
                break;
        }
    }
}

public sealed class AppServiceHardeningRule : Rule
{
    public override string Id => "AZ-APP-001";
    public override string Title => "App Service: FTP or remote debugging enabled";
    public override Severity Severity => Severity.Medium;
    public override string Category => "network";
    public override string Benchmark => "MCSB PV-2";
    public override string Why => "Plain FTP sends deployment credentials unencrypted; remote debugging opens extra ports into the running app. Neither belongs in production.";
    public override string Fix => "site_config { ftps_state = \"Disabled\" (or \"FtpsOnly\"), remote_debugging_enabled = false }";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (r.String("site_config.ftps_state") is "AllAllowed")
            yield return new Issue("site_config.ftps_state = \"AllAllowed\": FTP without TLS", "site_config.ftps_state", "ftp");
        if (r.Bool("site_config.remote_debugging_enabled", false))
            yield return new Issue("site_config.remote_debugging_enabled = true", "site_config.remote_debugging_enabled", "debug");
    }
}

public sealed partial class PlaintextAppSecretRule : Rule
{
    [GeneratedRegex("(password|passwd|pwd|secret|api[_-]?key|apikey|token|connection[_-]?string|connstr|accountkey|account_key|sas|private[_-]?key|client[_-]?secret)", RegexOptions.IgnoreCase)]
    internal static partial Regex SecretName();

    public override string Id => "AZ-SEC-001";
    public override string Title => "Secret stored as plain app setting";
    public override Severity Severity => Severity.High;
    public override string Category => "secrets";
    public override string Benchmark => "MCSB IM-8";
    public override string Why => "App settings are readable by everyone with Reader-plus rights on the app (and in the Terraform state). A Key Vault reference keeps the secret in the vault, with access logs and rotation.";
    public override string Fix => "Store the secret in Key Vault and set the setting to @Microsoft.KeyVault(SecretUri=...), or use a managed identity so no secret is needed.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (r.Get("app_settings") is System.Text.Json.Nodes.JsonObject settings)
        {
            foreach (var (key, value) in settings)
            {
                if (!SecretName().IsMatch(key) || r.IsUnknown($"app_settings.{key}")) continue;
                var text = value?.ToString() ?? "";
                if (text.Length == 0 || IsReference(text)) continue;
                // Never print the value, only that there is one
                yield return new Issue($"app_settings.{key} holds a literal value ({text.Length} characters), not a Key Vault reference", $"app_settings.{key}", key);
            }
        }
        foreach (var cs in r.Blocks("connection_string"))
        {
            var text = cs.String("value") ?? "";
            if (text.Length == 0 || IsReference(text) || cs.IsUnknown("value")) continue;
            if (!text.Contains("password=", StringComparison.OrdinalIgnoreCase) && !text.Contains("accountkey=", StringComparison.OrdinalIgnoreCase) && !text.Contains("sharedaccesskey=", StringComparison.OrdinalIgnoreCase)) continue;
            var name = cs.String("name") ?? "?";
            yield return new Issue($"connection_string '{name}' contains a password or key", "connection_string", "cs:" + name);
        }
    }

    private static bool IsReference(string value) =>
        value.StartsWith("@Microsoft.KeyVault(", StringComparison.OrdinalIgnoreCase) || value.StartsWith("@Microsoft.AppConfiguration(", StringComparison.OrdinalIgnoreCase);
}

public sealed class HardcodedSecretRule : Rule
{
    private static readonly Dictionary<string, string> Attributes = new()
    {
        ["azurerm_key_vault_secret"] = "value",
        ["azurerm_mssql_server"] = "administrator_login_password",
        ["azurerm_postgresql_flexible_server"] = "administrator_password",
        ["azurerm_mysql_flexible_server"] = "administrator_password",
        ["azurerm_linux_virtual_machine"] = "admin_password",
        ["azurerm_windows_virtual_machine"] = "admin_password",
    };

    public override string Id => "AZ-SEC-002";
    public override string Title => "Password or secret hard-coded in Terraform";
    public override Severity Severity => Severity.High;
    public override string Category => "secrets";
    public override string Benchmark => "MCSB IM-8";
    public override string Why => "A literal secret in .tf code is in the Git history forever, visible to everyone with repository access.";
    public override string Fix => "Generate it (random_password), pass it in as a sensitive variable from the pipeline's secret store, or use Entra ID authentication instead of a password.";
    public override IReadOnlySet<string> Types { get; } = Attributes.Keys.ToHashSet();

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        var attr = Attributes[r.Type];
        if (context.Configuration.IsLiteral(r.Address, attr))
            yield return new Issue($"{attr} is a literal in the code", attr);
    }
}

public sealed class KeyVaultPurgeProtectionRule : Rule
{
    public override string Id => "AZ-KV-001";
    public override string Title => "Key Vault without purge protection";
    public override Severity Severity => Severity.Medium;
    public override string Category => "data-protection";
    public override string Benchmark => "MCSB DP-8";
    public override string Why => "Without purge protection an attacker (or a mistake) with enough rights can delete the vault and purge it at once: the keys that encrypt your data are gone for good. Ransomware groups do exactly this.";
    public override string Fix => "purge_protection_enabled = true (it cannot be turned off again, which is the point), soft_delete_retention_days = 90.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_key_vault" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (!r.Bool("purge_protection_enabled", defaultValue: false))
            yield return new Issue("purge_protection_enabled is false (or not set)", "purge_protection_enabled");
    }
}

public sealed class KeyVaultNetworkRule : Rule
{
    public override string Id => "AZ-KV-002";
    public override string Title => "Key Vault reachable from all networks";
    public override Severity Severity => Severity.Medium;
    public override string Category => "network";
    public override string Benchmark => "MCSB NS-2";
    public override string Why => "With a leaked token the vault's secrets can be read from anywhere. Network ACLs or a private endpoint add a second barrier.";
    public override string Fix => "network_acls { default_action = \"Deny\", bypass = \"AzureServices\" } plus your VNets, or public_network_access_enabled = false with a private endpoint.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_key_vault" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (!r.Bool("public_network_access_enabled", defaultValue: true)) yield break;
        if ("Deny".Equals(r.String("network_acls.default_action"), StringComparison.OrdinalIgnoreCase)) yield break;
        yield return new Issue("public network access without network_acls default_action = \"Deny\"", "network_acls");
    }
}

public sealed class SqlEntraAuthRule : Rule
{
    public override string Id => "AZ-SQL-001";
    public override string Title => "SQL Server without Entra ID administrator";
    public override Severity Severity => Severity.Medium;
    public override string Category => "identity";
    public override string Benchmark => "MCSB IM-1";
    public override string Why => "With only SQL logins there is one shared admin password, no MFA, and no central offboarding when someone leaves.";
    public override string Fix => "Add azuread_administrator { login_username, object_id, azuread_authentication_only = true } and use managed identities for applications.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_mssql_server" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (!r.HasBlock("azuread_administrator"))
            yield return new Issue("no azuread_administrator block: SQL authentication only", "azuread_administrator");
        else if (!r.Bool("azuread_administrator.azuread_authentication_only", false))
            yield return new Issue("Entra ID admin set, but SQL logins are still allowed (azuread_authentication_only = false)", "azuread_administrator.azuread_authentication_only", "", Severity.Low);
    }
}

public sealed class PublicDatabaseRule : Rule
{
    public override string Id => "AZ-SQL-002";
    public override string Title => "Database server with public network access";
    public override Severity Severity => Severity.Medium;
    public override string Category => "network";
    public override string Benchmark => "MCSB NS-2";
    public override string Why => "A public endpoint makes the firewall rules the only network barrier. Private endpoints keep database traffic inside your network.";
    public override string Fix => "public_network_access_enabled = false and a private endpoint (or VNet integration for flexible servers).";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_mssql_server", "azurerm_postgresql_flexible_server", "azurerm_mysql_flexible_server", "azurerm_cosmosdb_account" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        // mssql_server and cosmosdb default to true; for flexible servers only an explicit true counts
        var defaultPublic = r.Type is "azurerm_mssql_server" or "azurerm_cosmosdb_account";
        if (r.IsUnknown("public_network_access_enabled") || !r.Bool("public_network_access_enabled", defaultPublic)) yield break;
        if (r.Type == "azurerm_cosmosdb_account" && r.Strings("ip_range_filter").Count > 0) yield break;
        yield return new Issue("public_network_access_enabled is true", "public_network_access_enabled");
    }
}

public sealed partial class PrivilegedRoleAssignmentRule : Rule
{
    private static readonly HashSet<string> Privileged = new(StringComparer.OrdinalIgnoreCase)
    {
        "Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator",
    };

    // Role definition ids of the built-in roles, for role_definition_id instead of a name
    private static readonly Dictionary<string, string> BuiltInIds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["8e3af657-a8ff-443c-a75c-2fe8c4bcb635"] = "Owner",
        ["b24988ac-6180-42a0-ab88-20f7382dd24c"] = "Contributor",
        ["18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"] = "User Access Administrator",
    };

    [GeneratedRegex(@"^/subscriptions/[^/]+/?$", RegexOptions.IgnoreCase)]
    private static partial Regex SubscriptionScope();

    public override string Id => "AZ-IAM-001";
    public override string Title => "Privileged role assigned at subscription or management group scope";
    public override Severity Severity => Severity.High;
    public override string Category => "identity";
    public override string Benchmark => "MCSB PA-7";
    public override string Why => "Owner or Contributor on a whole subscription is far more than any application or pipeline needs; a leaked credential of that identity controls everything in it. Standing privileged access should go through PIM.";
    public override string Fix => "Assign the narrowest built-in role (e.g. Storage Blob Data Contributor) at resource group or resource scope; for people, use PIM eligible assignments.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_role_assignment" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        var role = r.String("role_definition_name");
        if (role is null && r.String("role_definition_id") is { } id)
            role = BuiltInIds.FirstOrDefault(b => id.EndsWith(b.Key, StringComparison.OrdinalIgnoreCase)).Value;
        if (role is null || !Privileged.Contains(role)) yield break;

        var scope = r.String("scope");
        string? level = null;
        if (scope is not null)
        {
            if (SubscriptionScope().IsMatch(scope)) level = "subscription";
            else if (scope.Contains("/providers/Microsoft.Management/managementGroups/", StringComparison.OrdinalIgnoreCase)) level = "management group";
            else if (scope == "/") level = "root";
        }
        else
        {
            // Unknown until apply: the code shows where it comes from (data.azurerm_subscription.current.id)
            var refs = context.Configuration.References(r.Address, "scope");
            if (refs.Any(x => x.StartsWith("data.azurerm_subscription", StringComparison.Ordinal) || x.StartsWith("azurerm_subscription", StringComparison.Ordinal))) level = "subscription";
            else if (refs.Any(x => x.Contains("azurerm_management_group", StringComparison.Ordinal))) level = "management group";
        }

        var who = r.String("principal_type") is { } type ? $" to a {type}" : "";
        if (level is not null)
            yield return new Issue($"'{role}'{who} at {level} scope", "scope", role);
        else if (role is "Owner" or "User Access Administrator")
            yield return new Issue($"'{role}'{who}: can grant access to others", "role_definition_name", role, Severity.Medium);
    }
}

public sealed class AksHardeningRule : Rule
{
    public override string Id => "AZ-AKS-001";
    public override string Title => "AKS cluster: RBAC off or API server open to the Internet";
    public override Severity Severity => Severity.High;
    public override string Category => "identity";
    public override string Benchmark => "MCSB PA-7";
    public override string Why => "Without Kubernetes RBAC every authenticated user is cluster admin. A public API server without authorized IP ranges can be attacked from anywhere.";
    public override string Fix => "role_based_access_control_enabled = true, azure_active_directory_role_based_access_control { azure_rbac_enabled = true }, local_account_disabled = true, and private_cluster_enabled = true or api_server_access_profile { authorized_ip_ranges = [...] }.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_kubernetes_cluster" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (!r.Bool("role_based_access_control_enabled", defaultValue: true))
            yield return new Issue("role_based_access_control_enabled = false", "role_based_access_control_enabled", "rbac");
        if (!r.Bool("private_cluster_enabled", false) && r.Strings("api_server_access_profile.authorized_ip_ranges").Count == 0)
            yield return new Issue("public API server without authorized_ip_ranges", "api_server_access_profile", "api", Severity.Medium);
        if (!r.Bool("local_account_disabled", false))
            yield return new Issue("local admin account enabled (local_account_disabled = false)", "local_account_disabled", "local", Severity.Low);
    }
}

public sealed class VmPasswordAuthRule : Rule
{
    public override string Id => "AZ-VM-001";
    public override string Title => "Linux VM allows password login";
    public override Severity Severity => Severity.Medium;
    public override string Category => "identity";
    public override string Benchmark => "MCSB IM-6";
    public override string Why => "Password SSH logins can be brute-forced; SSH keys (or Entra ID login) cannot.";
    public override string Fix => "disable_password_authentication = true with admin_ssh_key { ... }.";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_linux_virtual_machine", "azurerm_linux_virtual_machine_scale_set" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (!r.Bool("disable_password_authentication", defaultValue: true))
            yield return new Issue("disable_password_authentication = false", "disable_password_authentication");
    }
}

public sealed class MissingDiagnosticsRule : Rule
{
    public override string Id => "AZ-LOG-001";
    public override string Title => "No audit logging configured";
    public override Severity Severity => Severity.Low;
    public override string Category => "logging";
    public override string Benchmark => "MCSB LT-3";
    public override string Why => "Without diagnostic settings there is no record of who read a secret or queried the database: an incident cannot be investigated (and DORA Art. 10 and the BAIT expect exactly that).";
    public override string Fix => "Add azurerm_monitor_diagnostic_setting with target_resource_id = this resource, sending the audit categories to Log Analytics (for SQL also azurerm_mssql_server_extended_auditing_policy).";
    public override IReadOnlySet<string> Types { get; } = new HashSet<string> { "azurerm_key_vault", "azurerm_mssql_server" };

    public override IEnumerable<Issue> Evaluate(ResourceState r, RuleContext context)
    {
        if (context.Configuration.ReferencedBy("azurerm_monitor_diagnostic_setting", "target_resource_id", r.Address).Any()) yield break;
        if (r.Type == "azurerm_mssql_server" && context.Configuration.ReferencedBy("azurerm_mssql_server_extended_auditing_policy", "server_id", r.Address).Any()) yield break;
        yield return new Issue("no azurerm_monitor_diagnostic_setting targets this resource", "target_resource_id");
    }
}
