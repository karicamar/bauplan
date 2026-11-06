variable "service_plan_id" { type = string }
variable "sql_admin_password" {
  type      = string
  sensitive = true
}
variable "workspace_id" { type = string }
variable "pipeline_principal_id" { type = string }
