# Customer data (PCI scope)

resource "aws_s3_bucket" "customer_data" {
  bucket = "${local.name_prefix}-customer-data"

  tags = merge(local.common_tags, {
    Name                = "${local.name_prefix}-customer-data"
    data_classification = "customer"
    criticality         = "high"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  bucket = aws_s3_bucket.customer_data.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = false
  }
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "customer_data" {
  bucket = aws_s3_bucket.customer_data.bucket

  versioning_configuration {
    status = "Enabled"
  }
}

# Audit logs (regulatory retention)

resource "aws_s3_bucket" "audit_log" {
  bucket = "${local.name_prefix}-audit-log"

  tags = merge(local.common_tags, {
    Name                = "${local.name_prefix}-audit-log"
    data_classification = "audit"
    criticality         = "high"
    retention_until     = "2033-12-31"
  })
}

resource "aws_s3_bucket_versioning" "audit_log" {
  bucket = aws_s3_bucket.audit_log.bucket

  versioning_configuration {
    status = "Enabled"
  }
}

# Archive of the 2023 audit trail. Read only, no longer written to, still under retention.
resource "aws_s3_bucket" "audit_log_2023" {
  bucket = "${local.name_prefix}-audit-log-2023"

  tags = merge(local.common_tags, {
    Name                = "${local.name_prefix}-audit-log-2023"
    data_classification = "audit"
    retention_until     = "2030-12-31"
  })
}

# Internal reports

resource "aws_s3_bucket" "reports" {
  bucket = "${local.name_prefix}-reports"

  tags = merge(local.common_tags, {
    Name                = "${local.name_prefix}-reports"
    data_classification = "internal"
  })
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Legacy buckets. Empty, decommissioning approved in CHG-0912.

resource "aws_s3_bucket" "legacy_exports" {
  bucket = "${local.name_prefix}-legacy-exports"

  tags = merge(local.common_tags, {
    Name                = "${local.name_prefix}-legacy-exports"
    data_classification = "none"
    legacy              = "true"
  })
}

resource "aws_s3_bucket" "legacy_tmp" {
  bucket = "${local.name_prefix}-legacy-tmp"

  tags = merge(local.common_tags, {
    Name                = "${local.name_prefix}-legacy-tmp"
    data_classification = "none"
    legacy              = "true"
  })
}
