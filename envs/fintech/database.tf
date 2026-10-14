resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db"
  subnet_ids = [aws_subnet.data_a.id, aws_subnet.data_b.id]

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-db-subnets" })
}

resource "aws_db_instance" "main" {
  identifier     = "fintech-core-db"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = "db.t3.medium"

  allocated_storage = 50
  storage_type      = "gp3"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.data.arn

  db_name                     = "ledger"
  username                    = "ledger_admin"
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false

  backup_retention_period             = 7
  backup_window                       = var.db_backup_window
  maintenance_window                  = "sat:04:00-sat:04:30"
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "fintech-core-db-final"
  iam_database_authentication_enabled = false

  tags = merge(local.common_tags, {
    Name                = "fintech-core-db"
    criticality         = "high"
    data_classification = "customer"
  })
}
