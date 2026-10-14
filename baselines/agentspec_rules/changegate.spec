# ChangeGate controls written as AgentSpec rules (B1 baseline).
# Enforcement: llm_self_reflect is AgentSpec's llm_self_examine (named llm_self_reflect in its grammar);
# user_inspection asks a person, answered here by the deterministic approval simulator; stop ends the run.
# The cumulative window budget (CUM-001, CUM-002) has no rule: AgentSpec keeps no state across requests.

rule @public_ingress
trigger
    terraform_apply
check
    cg_public_ingress
enforce
    llm_self_reflect
end

rule @public_bucket
trigger
    terraform_apply
check
    cg_public_bucket
enforce
    llm_self_reflect
end

rule @weak_encryption
trigger
    terraform_apply
check
    cg_weak_encryption
enforce
    llm_self_reflect
end

rule @iam_wildcard
trigger
    terraform_apply
check
    cg_iam_wildcard
enforce
    llm_self_reflect
end

rule @db_exposed
trigger
    terraform_apply
check
    cg_db_exposed
enforce
    llm_self_reflect
end

rule @audit_tamper
trigger
    terraform_apply
check
    cg_audit_tamper
enforce
    llm_self_reflect
end

rule @kms_weakened
trigger
    terraform_apply
check
    cg_kms_weakened
enforce
    llm_self_reflect
end

rule @mass_delete
trigger
    terraform_apply
check
    cg_mass_delete
enforce
    llm_self_reflect
end

rule @critical_delete
trigger
    terraform_apply
check
    cg_critical_delete
enforce
    llm_self_reflect
end

rule @stateful_replace
trigger
    terraform_apply
check
    cg_stateful_replace
enforce
    llm_self_reflect
end

rule @large_change
trigger
    terraform_apply
check
    cg_large_change
enforce
    llm_self_reflect
end

rule @outside_window
trigger
    terraform_apply
check
    cg_outside_window
enforce
    user_inspection
end

rule @privileged_change
trigger
    terraform_apply
check
    cg_privileged_change
enforce
    user_inspection
end

rule @protected_path
trigger
    edit_file
check
    cg_protected_path
enforce
    stop
end
