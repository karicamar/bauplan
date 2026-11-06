# Scenario: a pull request to an existing environment ("just add the export feature").
# plan.json is the `terraform show -json` output for this code against the existing state.

data "azurerm_subscription" "current" {}

resource "azurerm_resource_group" "app" {
  name     = "rg-portal-prod"
  location = "germanywestcentral"
}

resource "azurerm_network_security_group" "web" {
  name                = "nsg-portal-web"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name

  security_rule {
    name                       = "allow-https"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # NEW: "only for the migration weekend"
  security_rule {
    name                       = "allow-rdp-migration"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# NEW: storage for CSV exports to partners
resource "azurerm_storage_account" "exports" {
  name                     = "stportalexports"
  resource_group_name      = azurerm_resource_group.app.name
  location                 = azurerm_resource_group.app.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_0" # an old partner system
}

resource "azurerm_storage_container" "exports" {
  name                  = "partner-exports"
  storage_account_id    = azurerm_storage_account.exports.id
  container_access_type = "blob"
}

# NEW: partner portal
resource "azurerm_linux_web_app" "portal" {
  name                = "app-partner-portal"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location
  service_plan_id     = var.service_plan_id

  site_config {
    ftps_state = "AllAllowed"
  }

  app_settings = {
    "ASPNETCORE_ENVIRONMENT"    = "Production"
    "Db__Password"              = "Winter2026!"
    "Storage__ConnectionString" = "@Microsoft.KeyVault(SecretUri=https://kv-portal-prod.vault.azure.net/secrets/storage-cs/)"
  }
}

resource "azurerm_mssql_server" "main" {
  name                         = "sql-portal-prod"
  resource_group_name          = azurerm_resource_group.app.name
  location                     = azurerm_resource_group.app.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}

# CHANGED: was the office IP only. "Temporarily" opened for a partner test.
resource "azurerm_mssql_firewall_rule" "partner" {
  name             = "partner-test"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

# CHANGED: purge protection switched on, network ACLs added (this part of the PR is good)
resource "azurerm_key_vault" "main" {
  name                       = "kv-portal-prod"
  location                   = azurerm_resource_group.app.location
  resource_group_name        = azurerm_resource_group.app.name
  tenant_id                  = data.azurerm_subscription.current.tenant_id
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

# NEW: secret for the partner API
resource "azurerm_key_vault_secret" "partner_api" {
  name         = "partner-api-key"
  value        = "not-a-real-key-0123456789"
  key_vault_id = azurerm_key_vault.main.id
}

# NEW: let the deployment pipeline manage the portal
resource "azurerm_role_assignment" "pipeline" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"
  principal_id         = var.pipeline_principal_id
  principal_type       = "ServicePrincipal"
}
