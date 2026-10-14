locals {
  name_prefix = "fintech-prod"

  common_tags = {
    project     = "fintech-core"
    environment = "prod"
    owner       = "platform-team"
  }
}
