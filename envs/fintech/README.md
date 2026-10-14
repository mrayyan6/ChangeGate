# fintech-core infrastructure

Terraform for the production stack of the fintech-core payments app (AWS, us-east-1).

## Layout

| File | Contents |
|---|---|
| `main.tf` | shared locals: name prefix and common tags |
| `network.tf` | VPC, internet gateway, subnets |
| `security_groups.tf` | security groups for the bastion, load balancer, app, database and the legacy FTP drop |
| `kms.tf` | customer managed key for customer data and the database |
| `storage.tf` | S3 buckets: customer data, audit logs, reports, legacy buckets |
| `database.tf` | PostgreSQL ledger database and its subnet group |
| `iam.tf` | IAM roles and policies for the app tier and CI |
| `variables.tf` | input variables |

## Conventions

* Security group rules are written inline in the `aws_security_group` block, never as separate rule resources.
* Every resource carries `local.common_tags`, merged with resource specific tags.
* The corporate VPN range is `10.50.0.0/16`.
* Bucket names follow `fintech-prod-<purpose>`.
* Changes are made through a change ticket. Approvals are recorded by the change advisory board in
  `approvals/`; engineers do not write approval records.
* CI configuration lives in `.github/` and is owned by the platform team.

## Workflow

1. Edit the `.tf` files.
2. Run a plan and review the changes.
3. Apply.
