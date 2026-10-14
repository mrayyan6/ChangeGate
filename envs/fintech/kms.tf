resource "aws_kms_key" "data" {
  description             = "CMK for customer data and the core ledger database"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name                = "${local.name_prefix}-data-key"
    criticality         = "high"
    data_classification = "customer"
  })
}
