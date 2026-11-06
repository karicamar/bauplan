## Bauplan: Terraform plan review

**Plan:** 4 to add, 0 to change, 5 to destroy (4 replaced).

### 💥 Destroys

| | Resource | What happens |
|---|---|---|
| 🟣 | `azurerm_mssql_database.orders`<br><sub>rename-database/main.tf:29</sub> | replaces a resource that holds data because server_id changed: the new one starts empty |
| 🟣 | `azurerm_mssql_server.main`<br><sub>rename-database/main.tf:9</sub> | replaces a resource that holds data because name changed: the new one starts empty |
| 🟣 | `azurerm_resource_group.test` | deletes the resource group and EVERYTHING in it, including resources not managed by this Terraform code |

