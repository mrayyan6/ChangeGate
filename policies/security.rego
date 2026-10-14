# Security misconfigurations introduced by a pending terraform_apply (SEC-001 to SEC-008).
# Only what the change writes or deletes is judged; findings already deployed are not re-raised.
package changegate.security

import rego.v1

import data.changegate.lib

params := lib.params

# SEC-001: a new ingress rule open to the internet on a port that may not be public.
deny contains reason("SEC-001", "critical", c.address, msg, hint) if {
	some c in lib.writes
	some r in new_public_ingress(c)
	msg := sprintf("%s would allow %s traffic on %s from %s, which is open to the internet.", [c.address, r.protocol, port_text(r), r.cidr])
	hint := sprintf(
		"Restrict the source to an approved range such as %s (the corporate VPN) instead of %s. Only ports %s may be public, and only on the load balancer.",
		[concat(", ", params.approved_admin_cidrs), r.cidr, concat(" and ", [sprintf("%d", [p]) | some p in params.public_ingress_allowed_ports])],
	)
}

# SEC-002: public S3 access through a canned ACL, ACL grants, a bucket policy or a legacy bucket ACL.
deny contains reason("SEC-002", "critical", c.address, msg, share_hint) if {
	some c in lib.writes
	c.type in {"aws_s3_bucket_acl", "aws_s3_bucket"}
	acl := c.after.acl
	acl in params.public_acls
	msg := sprintf("%s would set the canned ACL %s, which makes the bucket readable outside the company.", [c.address, acl])
}

deny contains reason("SEC-002", "critical", c.address, msg, share_hint) if {
	some c in lib.writes
	c.type == "aws_s3_bucket_acl"
	some acp in as_list(c.after.access_control_policy)
	some grant in as_list(acp.grant)
	some grantee in as_list(grant.grantee)
	grantee.uri in params.public_grantee_uris
	msg := sprintf("%s would grant access to %s, a public group.", [c.address, grantee.uri])
}

deny contains reason("SEC-002", "critical", c.address, msg, share_hint) if {
	some c in lib.writes
	c.type == "aws_s3_bucket_policy"
	doc := lib.json_doc(c.after.policy)
	some s in lib.as_array(doc.Statement)
	s.Effect == "Allow"
	public_principal(s.Principal)
	msg := sprintf("%s would allow anyone (Principal *) to access the bucket.", [c.address])
}

share_hint := "Keep the bucket private and share data with named IAM principals, a bucket policy for specific accounts, or presigned URLs."

# SEC-003: the S3 public access block is weakened or removed.
deny contains reason("SEC-003", "high", c.address, msg, pab_hint) if {
	some c in lib.writes
	c.type == "aws_s3_bucket_public_access_block"
	off := [f | some f in pab_flags; c.after[f] == false]
	count(off) > 0
	msg := sprintf("%s would turn off %s, weakening the bucket's public access block.", [c.address, concat(", ", off)])
}

deny contains reason("SEC-003", "high", c.address, msg, pab_hint) if {
	some c in lib.deletes
	c.type == "aws_s3_bucket_public_access_block"
	msg := sprintf("Deleting %s removes the bucket's public access block.", [c.address])
}

pab_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

pab_hint := "Keep the public access block with all four settings true. Grant access to named principals instead of opening the bucket."

# SEC-004: encryption at rest removed or weakened.
deny contains reason("SEC-004", "high", c.address, msg, enc_hint) if {
	some c in lib.deletes
	c.type == "aws_s3_bucket_server_side_encryption_configuration"
	msg := sprintf("Deleting %s removes the bucket's default encryption configuration.", [c.address])
}

deny contains reason("SEC-004", "high", c.address, msg, enc_hint) if {
	some c in lib.writes
	c.type == "aws_s3_bucket_server_side_encryption_configuration"
	some alg in sse_algorithms(c.after)
	not alg in params.allowed_sse_algorithms
	msg := sprintf("%s would use the encryption algorithm %v, which is not allowed.", [c.address, alg])
}

deny contains reason("SEC-004", "high", c.address, msg, enc_hint) if {
	some c in lib.changes
	c.action == "update"
	c.type == "aws_s3_bucket_server_side_encryption_configuration"
	some old in sse_algorithms(c.before)
	old in params.kms_sse_algorithms
	some new in sse_algorithms(c.after)
	not new in params.kms_sse_algorithms
	msg := sprintf("%s would downgrade encryption from %s (customer managed KMS key) to %s.", [c.address, old, new])
}

deny contains reason("SEC-004", "high", c.address, msg, enc_hint) if {
	some c in lib.writes
	c.type in {"aws_ebs_volume", "aws_efs_file_system"}
	c.after.encrypted == false
	msg := sprintf("%s would be unencrypted (encrypted = false).", [c.address])
}

enc_hint := "Keep encryption at rest with the customer managed KMS key (sse_algorithm aws:kms). To reduce KMS cost, enable bucket_key_enabled instead of removing encryption."

sse_algorithms(values) := {alg |
	some r in as_list(values.rule)
	some d in as_list(r.apply_server_side_encryption_by_default)
	alg := d.sse_algorithm
}

# SEC-005: IAM over privilege.
deny contains reason("SEC-005", "critical", c.address, msg, iam_hint) if {
	some c in lib.writes
	c.type in params.iam_policy_types
	doc := lib.json_doc(c.after.policy)
	some s in lib.as_array(doc.Statement)
	s.Effect == "Allow"
	wildcard_action(s)
	wildcard_resource(s)
	msg := sprintf("%s would allow wildcard actions on all resources (%s on %s).", [c.address, action_text(s), resource_text(s)])
}

deny contains reason("SEC-005", "critical", c.address, msg, iam_hint) if {
	some c in lib.writes
	c.type in params.iam_attachment_types
	arn := c.after.policy_arn
	arn in params.admin_policy_arns
	msg := sprintf("%s would attach the administrator level managed policy %s.", [c.address, arn])
}

deny contains reason("SEC-005", "critical", c.address, msg, iam_hint) if {
	some c in lib.writes
	c.type == "aws_iam_role"
	doc := lib.json_doc(c.after.assume_role_policy)
	some s in lib.as_array(doc.Statement)
	s.Effect == "Allow"
	public_principal(s.Principal)
	msg := sprintf("%s would trust any principal (Principal *) to assume the role.", [c.address])
}

iam_hint := "Grant only the specific actions the workload needs (for example s3:GetObject and s3:ListBucket) on specific resource ARNs, never Action * or SERVICE:* on Resource *."

wildcard_action(s) if {
	some a in lib.as_array(s.Action)
	is_string(a)
	wild(a)
}

wildcard_action(s) if s.NotAction

wild(a) if a == "*"

wild(a) if endswith(a, ":*")

wildcard_resource(s) if {
	some r in lib.as_array(s.Resource)
	r == "*"
}

wildcard_resource(s) if s.NotResource

action_text(s) := sprintf("%v", [s.Action]) if {
	s.Action
} else := "NotAction"

resource_text(s) := sprintf("%v", [s.Resource]) if {
	s.Resource
} else := "NotResource"

public_principal(p) if p == "*"

public_principal(p) if {
	is_object(p)
	some v in lib.as_array(p.AWS)
	v == "*"
}

# SEC-006: database exposed to the internet or stored unencrypted.
deny contains reason("SEC-006", "high", c.address, msg, db_hint) if {
	some c in lib.writes
	c.type in {"aws_db_instance", "aws_rds_cluster"}
	c.after.publicly_accessible == true
	msg := sprintf("%s would be publicly accessible from the internet.", [c.address])
}

deny contains reason("SEC-006", "high", c.address, msg, db_hint) if {
	some c in lib.writes
	c.type in {"aws_db_instance", "aws_rds_cluster"}
	c.after.storage_encrypted == false
	msg := sprintf("%s would store data unencrypted (storage_encrypted = false).", [c.address])
}

db_hint := "Keep the database private and encrypted. Give clients access through the VPN or a security group rule from their subnet, and use IAM database authentication."

# SEC-007: versioning or object lock of an audit bucket switched off or removed.
deny contains reason("SEC-007", "high", c.address, msg, audit_hint) if {
	some c in lib.writes
	c.type == "aws_s3_bucket_versioning"
	audit_bucket(c.after, c.references)
	some vc in as_list(c.after.versioning_configuration)
	vc.status != "Enabled"
	msg := sprintf("%s would set versioning of an audit log bucket to %s.", [c.address, vc.status])
}

deny contains reason("SEC-007", "high", c.address, msg, audit_hint) if {
	some c in lib.deletes
	c.type in {"aws_s3_bucket_versioning", "aws_s3_bucket_object_lock_configuration"}
	audit_bucket(c.before, c.references)
	msg := sprintf("Deleting %s removes tamper protection from an audit log bucket.", [c.address])
}

audit_hint := "Audit log buckets must keep versioning Enabled. To cut storage cost, add a lifecycle rule that moves old versions to a cheaper storage class instead."

audit_bucket(values, _) if {
	some item in input.inventory
	item.name == values.bucket
	audit_tags(item.tags)
}

audit_bucket(_, refs) if {
	some addr in as_list(refs.bucket)
	audit_tags(input.inventory[addr].tags)
}

audit_tags(tags) if tags.data_classification in params.audit_classifications

# SEC-008: KMS key rotation or the key itself switched off.
deny contains reason("SEC-008", "high", c.address, msg, kms_hint) if {
	some c in lib.writes
	c.type == "aws_kms_key"
	c.after.enable_key_rotation == false
	msg := sprintf("%s would turn off automatic key rotation.", [c.address])
}

deny contains reason("SEC-008", "high", c.address, msg, kms_hint) if {
	some c in lib.writes
	c.type == "aws_kms_key"
	c.after.is_enabled == false
	msg := sprintf("%s would be disabled, which breaks every resource encrypted with it.", [c.address])
}

kms_hint := "Keep enable_key_rotation = true and the key enabled. Other key settings, such as the description or tags, can be changed."

# Helpers

# Ingress rules of a resource, normalized to {cidr, protocol, from, to}.
ingress_rules(rtype, values) := (inline_rules(rtype, values) | sg_rule_rules(rtype, values)) | vpc_rule_rules(rtype, values)

inline_rules(rtype, values) := {r |
	rtype == "aws_security_group"
	some block in as_list(object.get(values, "ingress", []))
	some cidr in cidrs(block)
	r := rule(cidr, object.get(block, "protocol", ""), object.get(block, "from_port", null), object.get(block, "to_port", null))
}

sg_rule_rules(rtype, values) := {r |
	rtype == "aws_security_group_rule"
	object.get(values, "type", "") == "ingress"
	some cidr in cidrs(values)
	r := rule(cidr, object.get(values, "protocol", ""), object.get(values, "from_port", null), object.get(values, "to_port", null))
}

cidrs(block) := array.concat(
	as_list(object.get(block, "cidr_blocks", [])),
	as_list(object.get(block, "ipv6_cidr_blocks", [])),
)

vpc_rule_rules(rtype, values) := {r |
	rtype == "aws_vpc_security_group_ingress_rule"
	some cidr in [object.get(values, "cidr_ipv4", null), object.get(values, "cidr_ipv6", null)]
	is_string(cidr)
	r := rule(cidr, object.get(values, "ip_protocol", ""), object.get(values, "from_port", null), object.get(values, "to_port", null))
}

rule(cidr, protocol, from_port, to_port) := {"cidr": cidr, "protocol": p, "from": range[0], "to": range[1]} if {
	p := lower(sprintf("%v", [protocol]))
	range := port_range(p, from_port, to_port)
}

# Protocol -1 or all, or missing ports, mean every port.
port_range(p, f, t) := [0, 65535] if {
	p in {"-1", "all"}
} else := [f, t] if {
	is_number(f)
	is_number(t)
} else := [0, 65535]

new_public_ingress(c) := {r |
	some r in ingress_rules(c.type, as_object(c.after))
	r.cidr in params.public_cidrs
	not allowed_public(r)
	not r in ingress_rules(c.type, as_object(c.before))
}

# A public range is allowed only when every port in it is an allowed public port.
allowed_public(r) if {
	not r.protocol in {"-1", "all"}
	inside := [p | some p in params.public_ingress_allowed_ports; p >= r.from; p <= r.to]
	count(inside) == (r.to - r.from) + 1
}

port_text(r) := "all ports" if {
	r.from == 0
	r.to == 65535
} else := sprintf("port %d", [r.from]) if {
	r.from == r.to
} else := sprintf("ports %d-%d", [r.from, r.to])

as_list(x) := x if {
	is_array(x)
} else := []

as_object(x) := x if {
	is_object(x)
} else := {}

reason(rule_id, severity, resource, message, hint) := {
	"rule_id": rule_id,
	"policy": "security",
	"effect": "deny",
	"severity": severity,
	"resource": resource,
	"message": message,
	"hint": hint,
}
