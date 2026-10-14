resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-vpc" })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-igw" })
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-public-a", tier = "public" })
}

resource "aws_subnet" "app_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "us-east-1a"

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-app-a", tier = "app" })
}

resource "aws_subnet" "data_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.20.0/24"
  availability_zone = "us-east-1a"

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-data-a", tier = "data" })
}

resource "aws_subnet" "data_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.21.0/24"
  availability_zone = "us-east-1b"

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-data-b", tier = "data" })
}

# Old batch subnet. Nothing runs here any more; decommissioning was approved in CHG-0912.
resource "aws_subnet" "legacy_batch" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.99.0/24"
  availability_zone = "us-east-1a"

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-legacy-batch", tier = "legacy", legacy = "true" })
}
