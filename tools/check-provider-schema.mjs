// Contract test against the real azurerm provider: every attribute the rules read must exist in its schema.
// Usage (after terraform init in a folder that uses azurerm):
//   terraform providers schema -json > schema.json && node tools/check-provider-schema.mjs schema.json
// Keep the list in sync with src/Bauplan.Core/Rules/AzureRules.cs. CI runs it weekly against the latest 4.x provider,
// so a renamed attribute (like enable_https_traffic_only -> https_traffic_only_enabled in 4.0) fails the build.
import fs from "fs";
const s = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const res = Object.values(s.provider_schemas)[0].resource_schemas;
const checks = {
  azurerm_network_security_group: ["security_rule.direction","security_rule.access","security_rule.source_address_prefix","security_rule.source_address_prefixes","security_rule.destination_port_range","security_rule.destination_port_ranges","security_rule.name"],
  azurerm_network_security_rule: ["direction","access","source_address_prefix","source_address_prefixes","destination_port_range","destination_port_ranges","name"],
  azurerm_mssql_firewall_rule: ["start_ip_address","end_ip_address"],
  azurerm_postgresql_flexible_server_firewall_rule: ["start_ip_address","end_ip_address"],
  azurerm_mysql_flexible_server_firewall_rule: ["start_ip_address","end_ip_address"],
  azurerm_redis_firewall_rule: ["start_ip","end_ip"],
  azurerm_storage_account: ["allow_nested_items_to_be_public","min_tls_version","https_traffic_only_enabled","public_network_access_enabled","shared_access_key_enabled","network_rules.default_action"],
  azurerm_storage_container: ["container_access_type","storage_account_id"],
  azurerm_storage_account_network_rules: ["storage_account_id"],
  azurerm_mssql_server: ["minimum_tls_version","public_network_access_enabled","azuread_administrator.azuread_authentication_only","administrator_login_password"],
  azurerm_redis_cache: ["minimum_tls_version","non_ssl_port_enabled"],
  azurerm_eventhub_namespace: ["minimum_tls_version"],
  azurerm_servicebus_namespace: ["minimum_tls_version"],
  azurerm_linux_web_app: ["https_only","site_config.minimum_tls_version","site_config.ftps_state","site_config.remote_debugging_enabled","app_settings","connection_string.value","connection_string.name"],
  azurerm_windows_web_app: ["https_only","site_config.minimum_tls_version","site_config.ftps_state","site_config.remote_debugging_enabled","app_settings"],
  azurerm_linux_function_app: ["https_only","site_config.minimum_tls_version","site_config.ftps_state","app_settings"],
  azurerm_windows_function_app: ["https_only","site_config.minimum_tls_version","site_config.ftps_state","app_settings"],
  azurerm_key_vault_secret: ["value"],
  azurerm_postgresql_flexible_server: ["administrator_password","public_network_access_enabled"],
  azurerm_mysql_flexible_server: ["administrator_password","public_network_access_enabled"],
  azurerm_linux_virtual_machine: ["admin_password","disable_password_authentication"],
  azurerm_linux_virtual_machine_scale_set: ["disable_password_authentication"],
  azurerm_windows_virtual_machine: ["admin_password"],
  azurerm_key_vault: ["purge_protection_enabled","public_network_access_enabled","network_acls.default_action"],
  azurerm_cosmosdb_account: ["public_network_access_enabled","ip_range_filter"],
  azurerm_role_assignment: ["role_definition_name","role_definition_id","scope","principal_type"],
  azurerm_kubernetes_cluster: ["role_based_access_control_enabled","private_cluster_enabled","api_server_access_profile.authorized_ip_ranges","local_account_disabled"],
  azurerm_monitor_diagnostic_setting: ["target_resource_id"],
  azurerm_mssql_server_extended_auditing_policy: ["server_id"],
};
let bad = 0;
for (const [type, paths] of Object.entries(checks)) {
  const r = res[type];
  if (!r) { console.log("MISSING TYPE", type); bad++; continue; }
  for (const p of paths) {
    let block = r.block, ok = true;
    const parts = p.split(".");
    for (let i = 0; i < parts.length; i++) {
      const last = i === parts.length - 1;
      if (block.attributes?.[parts[i]] && last) { const a = block.attributes[parts[i]]; if (a.deprecated) console.log("deprecated", type, p); break; }
      if (block.block_types?.[parts[i]]) { block = block.block_types[parts[i]].block; if (last) break; continue; }
      if (block.attributes?.[parts[i]]?.type && !last) { break; } // object attribute (security_rule is attribute set of objects)
      ok = false; break;
    }
    if (!ok) { console.log("MISSING", type, p); bad++; }
  }
}
console.log(bad === 0 ? `all attributes exist (${Object.keys(checks).length} resource types)` : `${bad} problems`);
process.exit(bad === 0 ? 0 : 1);
