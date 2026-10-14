resource "aws_iam_role" "app" {
  name                 = "${local.name_prefix}-app"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_policy" "app_s3_read" {
  name        = "${local.name_prefix}-app-s3-read"
  description = "Lets the app tier read generated reports"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadReports"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::fintech-prod-reports/*"]
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "app_s3_read" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_s3_read.arn
}

resource "aws_iam_role" "ci_deploy" {
  name                 = "${local.name_prefix}-ci-deploy"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}
