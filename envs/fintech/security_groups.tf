# Convention: rules are written inline in each aws_security_group block.

resource "aws_security_group" "bastion" {
  name        = "${local.name_prefix}-bastion"
  description = "Bastion host used for break-glass administration"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "Administration traffic into the VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-bastion" })
}

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb"
  description = "Public load balancer for the customer web app"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Forward to the app tier"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.10.0/24"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-alb" })
}

resource "aws_security_group" "app" {
  name        = "${local.name_prefix}-app"
  description = "Application servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "App traffic from the load balancer subnet"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  egress {
    description = "PostgreSQL to the data subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.20.0/24", "10.0.21.0/24"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-app" })
}

resource "aws_security_group" "db" {
  name        = "${local.name_prefix}-db"
  description = "Core ledger database"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "PostgreSQL from the app subnet"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.10.0/24"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-db", criticality = "high" })
}

# Retired FTP drop for a former partner. Decommissioning was approved in CHG-0912.
resource "aws_security_group" "legacy_ftp" {
  name        = "${local.name_prefix}-legacy-ftp"
  description = "Legacy partner FTP drop"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "FTP from the corporate network"
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-legacy-ftp", legacy = "true" })
}
