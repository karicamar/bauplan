# Scenario: a "small cleanup". Rename the SQL server to the new naming convention and remove an old resource group.
# Renaming forces Terraform to destroy the server (and with it the database) and create empty new ones.

resource "azurerm_resource_group" "app" {
  name     = "rg-orders-prod"
  location = "germanywestcentral"
}

resource "azurerm_mssql_server" "main" {
  name                          = "sql-orders-prod-gwc" # was "sqlordersprod"
  resource_group_name           = azurerm_resource_group.app.name
  location                      = azurerm_resource_group.app.location
  version                       = "12.0"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false

  azuread_administrator {
    login_username              = "sql-admins"
    object_id                   = var.sql_admins_group_id
    azuread_authentication_only = true
  }
}

resource "azurerm_mssql_server_extended_auditing_policy" "main" {
  server_id              = azurerm_mssql_server.main.id
  log_monitoring_enabled = true
}

resource "azurerm_mssql_database" "orders" {
  name      = "orders"
  server_id = azurerm_mssql_server.main.id
  sku_name  = "S2"
}

resource "azurerm_network_security_group" "db" {
  name                = "nsg-orders-db-gwc" # renamed as well
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
}

# The resource group "rg-orders-test" was removed from the code. It still contains a VM someone created by hand.
