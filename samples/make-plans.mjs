// Writes the sample plan files (node samples/make-plans.mjs).
//
// A real azurerm plan needs an Azure subscription to run `terraform plan`, so these files are generated here
// in the documented `terraform show -json` format (format_version 1.2): resource_changes with before/after/after_unknown,
// replace_paths and action_reason, and the configuration section with expressions and references.
// Attributes the provider fills with defaults are included the way the provider reports them.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SUB = "/subscriptions/00000000-0000-0000-0000-000000000000";
const RG = `${SUB}/resourceGroups/rg-portal-prod`;

function change(type, name, actions, before, after, extra = {}) {
  const { unknown = {}, replacePaths, reason, sensitive = {} } = extra;
  const rc = {
    address: `${type}.${name}`,
    mode: "managed",
    type,
    name,
    provider_name: "registry.terraform.io/hashicorp/azurerm",
    change: {
      actions,
      before,
      after,
      after_unknown: unknown,
      before_sensitive: before ? sensitive : false,
      after_sensitive: after ? sensitive : false,
    },
  };
  if (replacePaths) rc.change.replace_paths = replacePaths;
  if (reason) rc.action_reason = reason;
  return rc;
}

const ref = (...refs) => ({ references: refs });
const constant = (v) => ({ constant_value: v });

function plan(changes, configResources) {
  return {
    format_version: "1.2",
    terraform_version: "1.9.8",
    planned_values: { root_module: { resources: [] } },
    resource_changes: changes,
    configuration: {
      provider_config: { azurerm: { name: "azurerm", full_name: "registry.terraform.io/hashicorp/azurerm", version_constraint: "~> 4.0" } },
      root_module: { resources: configResources },
    },
  };
}

const cfg = (type, name, expressions) => ({ address: `${type}.${name}`, mode: "managed", type, name, provider_config_key: "azurerm", expressions });

function nsgRule(name, priority, port, source) {
  return {
    name, priority, direction: "Inbound", access: "Allow", protocol: "Tcp", description: "",
    source_port_range: "*", source_port_ranges: [], destination_port_range: port, destination_port_ranges: [],
    source_address_prefix: source, source_address_prefixes: [], destination_address_prefix: "*", destination_address_prefixes: [],
    source_application_security_group_ids: [], destination_application_security_group_ids: [],
  };
}

function storage(name, overrides = {}) {
  return {
    name, resource_group_name: "rg-portal-prod", location: "germanywestcentral", account_kind: "StorageV2",
    account_tier: "Standard", account_replication_type: "GRS", access_tier: "Hot",
    allow_nested_items_to_be_public: true, https_traffic_only_enabled: true, min_tls_version: "TLS1_2",
    public_network_access_enabled: true, shared_access_key_enabled: true, infrastructure_encryption_enabled: false,
    network_rules: [], tags: null, ...overrides,
  };
}

function keyVault(overrides = {}) {
  return {
    name: "kv-portal-prod", location: "germanywestcentral", resource_group_name: "rg-portal-prod", sku_name: "standard",
    tenant_id: "11111111-1111-1111-1111-111111111111", enabled_for_deployment: false, enable_rbac_authorization: true,
    purge_protection_enabled: false, soft_delete_retention_days: 90, public_network_access_enabled: true,
    network_acls: [], id: `${RG}/providers/Microsoft.KeyVault/vaults/kv-portal-prod`, vault_uri: "https://kv-portal-prod.vault.azure.net/",
    ...overrides,
  };
}

function sqlServer(name, overrides = {}) {
  return {
    name, resource_group_name: "rg-portal-prod", location: "germanywestcentral", version: "12.0",
    administrator_login: "sqladmin", administrator_login_password: "from-a-variable", minimum_tls_version: "1.2",
    public_network_access_enabled: true, outbound_network_restriction_enabled: false, azuread_administrator: [],
    identity: [], id: `${RG}/providers/Microsoft.Sql/servers/${name}`, fully_qualified_domain_name: `${name}.database.windows.net`,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// 1. risky-pr: a feature PR against an existing environment
{
  const nsgBefore = {
    name: "nsg-portal-web", location: "germanywestcentral", resource_group_name: "rg-portal-prod",
    security_rule: [nsgRule("allow-https", 100, "443", "Internet")], id: `${RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-portal-web`,
  };
  const nsgAfter = { ...nsgBefore, security_rule: [nsgRule("allow-https", 100, "443", "Internet"), nsgRule("allow-rdp-migration", 200, "3389", "*")] };

  const firewallBefore = { name: "partner-test", server_id: `${RG}/providers/Microsoft.Sql/servers/sql-portal-prod`, start_ip_address: "203.0.113.10", end_ip_address: "203.0.113.10" };
  const firewallAfter = { ...firewallBefore, start_ip_address: "0.0.0.0", end_ip_address: "255.255.255.255" };

  const kvBefore = keyVault();
  const kvAfter = keyVault({ purge_protection_enabled: true, network_acls: [{ default_action: "Deny", bypass: "AzureServices", ip_rules: [], virtual_network_subnet_ids: [] }] });

  const sql = sqlServer("sql-portal-prod");

  const changes = [
    change("azurerm_resource_group", "app", ["no-op"],
      { name: "rg-portal-prod", location: "germanywestcentral", id: RG, tags: null },
      { name: "rg-portal-prod", location: "germanywestcentral", id: RG, tags: null }),
    change("azurerm_network_security_group", "web", ["update"], nsgBefore, nsgAfter),
    change("azurerm_storage_account", "exports", ["create"], null,
      storage("stportalexports", { min_tls_version: "TLS1_0" }),
      { unknown: { id: true, primary_access_key: true, primary_blob_endpoint: true, network_rules: true }, sensitive: { primary_access_key: true } }),
    change("azurerm_storage_container", "exports", ["create"], null,
      { name: "partner-exports", container_access_type: "blob", metadata: null },
      { unknown: { id: true, storage_account_id: true } }),
    change("azurerm_linux_web_app", "portal", ["create"], null,
      {
        name: "app-partner-portal", resource_group_name: "rg-portal-prod", location: "germanywestcentral",
        service_plan_id: `${RG}/providers/Microsoft.Web/serverFarms/asp-portal`, https_only: false, enabled: true,
        client_certificate_enabled: false, public_network_access_enabled: true,
        site_config: [{ always_on: true, ftps_state: "AllAllowed", http2_enabled: false, minimum_tls_version: "1.2", scm_minimum_tls_version: "1.2", remote_debugging_enabled: false }],
        app_settings: {
          ASPNETCORE_ENVIRONMENT: "Production",
          Db__Password: "Winter2026!",
          Storage__ConnectionString: "@Microsoft.KeyVault(SecretUri=https://kv-portal-prod.vault.azure.net/secrets/storage-cs/)",
        },
        connection_string: [],
      },
      { unknown: { id: true, default_hostname: true, outbound_ip_addresses: true }, sensitive: { app_settings: true } }),
    change("azurerm_mssql_server", "main", ["no-op"], sql, sql, { sensitive: { administrator_login_password: true } }),
    change("azurerm_mssql_firewall_rule", "partner", ["update"], firewallBefore, firewallAfter),
    change("azurerm_key_vault", "main", ["update"], kvBefore, kvAfter),
    change("azurerm_monitor_diagnostic_setting", "kv", ["no-op"],
      { name: "kv-audit", target_resource_id: kvBefore.id, log_analytics_workspace_id: `${RG}/providers/Microsoft.OperationalInsights/workspaces/log-portal` },
      { name: "kv-audit", target_resource_id: kvBefore.id, log_analytics_workspace_id: `${RG}/providers/Microsoft.OperationalInsights/workspaces/log-portal` }),
    change("azurerm_key_vault_secret", "partner_api", ["create"], null,
      { name: "partner-api-key", value: "not-a-real-key-0123456789", key_vault_id: kvBefore.id, content_type: null },
      { unknown: { id: true, version: true, versionless_id: true }, sensitive: { value: true } }),
    change("azurerm_role_assignment", "pipeline", ["create"], null,
      { scope: SUB, role_definition_name: "Contributor", principal_id: "22222222-2222-2222-2222-222222222222", principal_type: "ServicePrincipal" },
      { unknown: { id: true, name: true, role_definition_id: true } }),
  ];

  const config = [
    cfg("azurerm_mssql_server", "main", { administrator_login_password: ref("var.sql_admin_password"), name: constant("sql-portal-prod") }),
    cfg("azurerm_monitor_diagnostic_setting", "kv", { target_resource_id: ref("azurerm_key_vault.main.id", "azurerm_key_vault.main") }),
    cfg("azurerm_key_vault_secret", "partner_api", { value: constant("not-a-real-key-0123456789"), key_vault_id: ref("azurerm_key_vault.main.id", "azurerm_key_vault.main") }),
    cfg("azurerm_role_assignment", "pipeline", { scope: ref("data.azurerm_subscription.current.id", "data.azurerm_subscription.current"), role_definition_name: constant("Contributor") }),
    cfg("azurerm_storage_container", "exports", { storage_account_id: ref("azurerm_storage_account.exports.id", "azurerm_storage_account.exports") }),
  ];
  write("risky-pr", plan(changes, config));
}

// ---------------------------------------------------------------------------------------------------------------
// 2. rename-database: renaming forces replacement; a removed resource group is deleted
{
  const ORG = `${SUB}/resourceGroups/rg-orders-prod`;
  const aad = [{ login_username: "sql-admins", object_id: "33333333-3333-3333-3333-333333333333", tenant_id: "11111111-1111-1111-1111-111111111111", azuread_authentication_only: true }];
  const serverBefore = sqlServer("sqlordersprod", { resource_group_name: "rg-orders-prod", public_network_access_enabled: false, azuread_administrator: aad, id: `${ORG}/providers/Microsoft.Sql/servers/sqlordersprod` });
  const serverAfter = { ...serverBefore, name: "sql-orders-prod-gwc", id: null, fully_qualified_domain_name: null };
  const dbBefore = { name: "orders", server_id: serverBefore.id, sku_name: "S2", max_size_gb: 250, id: `${serverBefore.id}/databases/orders` };
  const nsgBefore = { name: "nsg-orders-db", location: "germanywestcentral", resource_group_name: "rg-orders-prod", security_rule: [], id: `${ORG}/providers/Microsoft.Network/networkSecurityGroups/nsg-orders-db` };

  const changes = [
    change("azurerm_resource_group", "app", ["no-op"], { name: "rg-orders-prod", location: "germanywestcentral", id: ORG }, { name: "rg-orders-prod", location: "germanywestcentral", id: ORG }),
    change("azurerm_mssql_server", "main", ["delete", "create"], serverBefore, serverAfter,
      { unknown: { id: true, fully_qualified_domain_name: true }, replacePaths: [["name"]], reason: "replace_because_cannot_update" }),
    change("azurerm_mssql_server_extended_auditing_policy", "main", ["delete", "create"],
      { server_id: serverBefore.id, log_monitoring_enabled: true }, { server_id: null, log_monitoring_enabled: true },
      { unknown: { server_id: true, id: true }, replacePaths: [["server_id"]], reason: "replace_because_cannot_update" }),
    change("azurerm_mssql_database", "orders", ["delete", "create"], dbBefore, { ...dbBefore, server_id: null, id: null },
      { unknown: { server_id: true, id: true }, replacePaths: [["server_id"]], reason: "replace_because_cannot_update" }),
    change("azurerm_network_security_group", "db", ["create", "delete"], nsgBefore, { ...nsgBefore, name: "nsg-orders-db-gwc", id: null },
      { unknown: { id: true }, replacePaths: [["name"]], reason: "replace_because_cannot_update" }),
    { ...change("azurerm_resource_group", "test", ["delete"], { name: "rg-orders-test", location: "germanywestcentral", id: `${SUB}/resourceGroups/rg-orders-test` }, null),
      action_reason: "delete_because_no_resource_config" },
  ];
  const config = [
    cfg("azurerm_mssql_server_extended_auditing_policy", "main", { server_id: ref("azurerm_mssql_server.main.id", "azurerm_mssql_server.main") }),
    cfg("azurerm_mssql_database", "orders", { server_id: ref("azurerm_mssql_server.main.id", "azurerm_mssql_server.main") }),
  ];
  write("rename-database", plan(changes, config));
}

// ---------------------------------------------------------------------------------------------------------------
// 3. hardened: everything configured well, all new
{
  const kv = keyVault({ purge_protection_enabled: true, network_acls: [{ default_action: "Deny", bypass: "AzureServices", ip_rules: [], virtual_network_subnet_ids: [] }], id: null, vault_uri: null });
  const changes = [
    change("azurerm_resource_group", "app", ["create"], null, { name: "rg-portal-prod", location: "germanywestcentral", tags: null }, { unknown: { id: true } }),
    change("azurerm_storage_account", "exports", ["create"], null,
      storage("stportalexports", { allow_nested_items_to_be_public: false, shared_access_key_enabled: false, network_rules: [{ default_action: "Deny", bypass: ["AzureServices"], ip_rules: [], virtual_network_subnet_ids: [] }] }),
      { unknown: { id: true, primary_blob_endpoint: true } }),
    change("azurerm_linux_web_app", "portal", ["create"], null,
      {
        name: "app-partner-portal", resource_group_name: "rg-portal-prod", location: "germanywestcentral", https_only: true, enabled: true,
        site_config: [{ always_on: true, ftps_state: "Disabled", http2_enabled: true, minimum_tls_version: "1.2", scm_minimum_tls_version: "1.2", remote_debugging_enabled: false }],
        app_settings: { Db__Password: "@Microsoft.KeyVault(SecretUri=https://kv-portal-prod.vault.azure.net/secrets/db-password/)" },
        connection_string: [],
      },
      { unknown: { id: true, service_plan_id: true, default_hostname: true }, sensitive: { app_settings: true } }),
    change("azurerm_key_vault", "main", ["create"], null, kv, { unknown: { id: true, vault_uri: true, tenant_id: true } }),
    change("azurerm_monitor_diagnostic_setting", "kv", ["create"], null, { name: "kv-audit", target_resource_id: null }, { unknown: { id: true, target_resource_id: true, log_analytics_workspace_id: true } }),
    change("azurerm_role_assignment", "pipeline", ["create"], null,
      { scope: null, role_definition_name: "Storage Blob Data Contributor", principal_id: "22222222-2222-2222-2222-222222222222", principal_type: "ServicePrincipal" },
      { unknown: { id: true, scope: true, role_definition_id: true } }),
  ];
  const config = [
    cfg("azurerm_monitor_diagnostic_setting", "kv", { target_resource_id: ref("azurerm_key_vault.main.id", "azurerm_key_vault.main") }),
    cfg("azurerm_role_assignment", "pipeline", { scope: ref("azurerm_storage_account.exports.id", "azurerm_storage_account.exports") }),
  ];
  write("hardened", plan(changes, config));
}

function write(folder, content) {
  const file = join(here, folder, "plan.json");
  writeFileSync(file, JSON.stringify(content, null, 2) + "\n");
  console.log(`wrote ${folder}/plan.json (${content.resource_changes.length} resource changes)`);
}
