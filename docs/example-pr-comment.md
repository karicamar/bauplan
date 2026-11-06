## Bauplan: Terraform plan review

**Plan:** 5 to add, 3 to change, 0 to destroy.

### 🆕 Introduced by this plan (12)

| Severity | Rule | Resource | Finding | Fix |
|---|---|---|---|---|
| 🟣 Critical | `AZ-NET-002` | `azurerm_mssql_firewall_rule.partner`<br><sub>risky-pr/main.tf:86</sub> | allows 0.0.0.0-255.255.255.255 (all 4.3 billion addresses) | Use a private endpoint or VNet integration; otherwise allow only the exact outbound IPs of your applications. |
| 🟣 Critical | `AZ-NET-001` | `azurerm_network_security_group.web`<br><sub>risky-pr/main.tf:11</sub> | rule 'allow-rdp-migration' allows RDP 3389 from the Internet (*) | Restrict source_address_prefix to known ranges, or remove the rule and use Azure Bastion, a VPN or Just-in-Time VM access. |
| 🔴 High | `AZ-SEC-002` | `azurerm_key_vault_secret.partner_api`<br><sub>risky-pr/main.tf:120</sub> | value is a literal in the code | Generate it (random_password), pass it in as a sensitive variable from the pipeline's secret store, or use Entra ID authentication instead of a password. |
| 🔴 High | `AZ-TLS-002` | `azurerm_linux_web_app.portal`<br><sub>risky-pr/main.tf:59</sub> | https_only is false (or not set): the app answers on plain HTTP | App Service: https_only = true (the provider default is false). Storage: https_traffic_only_enabled = true. Redis: disable the non-SSL port. |
| 🔴 High | `AZ-SEC-001` | `azurerm_linux_web_app.portal`<br><sub>risky-pr/main.tf:59</sub> | app_settings.Db__Password holds a literal value (11 characters), not a Key Vault reference | Store the secret in Key Vault and set the setting to @Microsoft.KeyVault(SecretUri=...), or use a managed identity so no secret is needed. |
| 🔴 High | `AZ-IAM-001` | `azurerm_role_assignment.pipeline`<br><sub>risky-pr/main.tf:127</sub> | 'Contributor' to a ServicePrincipal at subscription scope | Assign the narrowest built-in role (e.g. Storage Blob Data Contributor) at resource group or resource scope; for people, use PIM eligible assignments. |
| 🔴 High | `AZ-STG-001` | `azurerm_storage_account.exports`<br><sub>risky-pr/main.tf:43</sub> | allow_nested_items_to_be_public is true (or not set): containers can be made public | Set allow_nested_items_to_be_public = false (azurerm 3.x defaults to true). Serve public files through a CDN or SAS tokens instead. |
| 🔴 High | `AZ-TLS-001` | `azurerm_storage_account.exports`<br><sub>risky-pr/main.tf:43</sub> | min_tls_version = "TLS1_0" | Set the minimum TLS version to 1.2 (TLS1_2 for storage accounts). |
| 🔴 High | `AZ-STG-001` | `azurerm_storage_container.exports`<br><sub>risky-pr/main.tf:52</sub> | container_access_type = "blob": files can be read anonymously | Set allow_nested_items_to_be_public = false (azurerm 3.x defaults to true). Serve public files through a CDN or SAS tokens instead. |
| 🟠 Medium | `AZ-APP-001` | `azurerm_linux_web_app.portal`<br><sub>risky-pr/main.tf:59</sub> | site_config.ftps_state = "AllAllowed": FTP without TLS | site_config { ftps_state = "Disabled" (or "FtpsOnly"), remote_debugging_enabled = false } |
| 🟠 Medium | `AZ-STG-002` | `azurerm_storage_account.exports`<br><sub>risky-pr/main.tf:43</sub> | public network access with no network_rules (default_action is Allow) | Add network_rules { default_action = "Deny" } with your VNets/IPs, or set public_network_access_enabled = false and use a private endpoint. |
| 🟡 Low | `AZ-STG-003` | `azurerm_storage_account.exports`<br><sub>risky-pr/main.tf:43</sub> | shared_access_key_enabled is true (or not set) | Set shared_access_key_enabled = false and use managed identities with roles like Storage Blob Data Reader. |

### ✅ Fixed by this plan (2)

- `AZ-KV-001` `azurerm_key_vault.main`: purge_protection_enabled is false (or not set)
- `AZ-KV-002` `azurerm_key_vault.main`: public network access without network_acls default_action = "Deny"

<details>
<summary>Already present before this plan (3)</summary>

| Severity | Rule | Resource | Finding | Fix |
|---|---|---|---|---|
| 🟠 Medium | `AZ-SQL-001` | `azurerm_mssql_server.main`<br><sub>risky-pr/main.tf:76</sub> | no azuread_administrator block: SQL authentication only | Add azuread_administrator { login_username, object_id, azuread_authentication_only = true } and use managed identities for applications. |
| 🟠 Medium | `AZ-SQL-002` | `azurerm_mssql_server.main`<br><sub>risky-pr/main.tf:76</sub> | public_network_access_enabled is true | public_network_access_enabled = false and a private endpoint (or VNet integration for flexible servers). |
| 🟡 Low | `AZ-LOG-001` | `azurerm_mssql_server.main`<br><sub>risky-pr/main.tf:76</sub> | no azurerm_monitor_diagnostic_setting targets this resource | Add azurerm_monitor_diagnostic_setting with target_resource_id = this resource, sending the audit categories to Log Analytics (for SQL also azurerm_mssql_server_extended_auditing_policy). |

</details>

