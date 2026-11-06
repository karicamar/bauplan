# Scenario: the same building blocks, configured the way Bauplan expects. The plan is clean.

resource "azurerm_resource_group" "app" {
  name     = "rg-portal-prod"
  location = "germanywestcentral"
}

resource "azurerm_storage_account" "exports" {
  name                            = "stportalexports"
  resource_group_name             = azurerm_resource_group.app.name
  location                        = azurerm_resource_group.app.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

resource "azurerm_linux_web_app" "portal" {
  name                = "app-partner-portal"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location
  service_plan_id     = var.service_plan_id
  https_only          = true

  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "Disabled"
  }

  app_settings = {
    "Db__Password" = "@Microsoft.KeyVault(SecretUri=https://kv-portal-prod.vault.azure.net/secrets/db-password/)"
  }
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-portal-prod"
  location                   = azurerm_resource_group.app.location
  resource_group_name        = azurerm_resource_group.app.name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = true
  soft_delete_retention_days = 90

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_monitor_diagnostic_setting" "kv" {
  name                       = "kv-audit"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = var.workspace_id

  enabled_log {
    category = "AuditEvent"
  }
}

resource "azurerm_role_assignment" "pipeline" {
  scope                = azurerm_storage_account.exports.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = var.pipeline_principal_id
  principal_type       = "ServicePrincipal"
}
