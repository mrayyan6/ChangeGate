variable "region" {
  description = "AWS region for every resource in this stack."
  type        = string
  default     = "us-east-1"
}

variable "db_backup_window" {
  description = "Daily RDS backup window in UTC, format hh24:mi-hh24:mi. Must not overlap the maintenance window."
  type        = string
  default     = "03:00-03:30"
}
