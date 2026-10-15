# ChangeGate architecture

ChangeGate is a deterministic policy-as-code gate between an LLM agent and the Terraform repository it
changes. Every tool call the agent makes passes through a Policy Enforcement Point (PEP). For actions that
can change infrastructure, the PEP computes exactly what would change, asks Open Policy Agent (OPA) for a
decision, logs the decision in a hash chained audit log, and either runs the tool or tells the agent why it
was blocked.

This document describes the Phase 1 system: components, data contracts, decision semantics, the evaluation
harness and the known limitations.

## 1. Components and data flow

```
 scenario YAML ──> ChangeRequest ──> Agent (LangChain 0.3 tool-calling agent on AgentExecutor)
                                        │  tool call: list_files, read_file, edit_file, terraform_plan,
                                        │             request_approval, terraform_apply, submit
                                        v
                              ┌──────── PEP (changegate/pep.py) ────────┐
                              │ 1. normalize arguments                   │
                              │ 2. Workspace.evaluate(): offline plan,   │──> plan cache (.cache/plans)
                              │    ChangeSet = deployed vs proposed      │
                              │ 3. SessionStore.snapshot(): window       │──> sessions.sqlite
                              │    totals, approvals                     │
                              │ 4. build PolicyInput                     │
                              │ 5. guard.decide()  (none | Trivy | OPA)  │──> opa eval / opa server
                              │ 6. AuditLog.append(decision)             │──> audit.jsonl (hash chain)
                              └───────┬──────────────────────┬───────────┘
                                 allow│                      │deny / require_approval
                                      v                      v
                              ToolExecutor             FeedbackComposer (bare | reason | hint)
                              (edit, plan, simulated         │
                               apply, approval simulator)    └──> observation back to the agent
                                      │
                                      v
                              Workspace deployed state ──> Evaluator (Python assertions) ──> RunResult
```

| Module | Responsibility |
|---|---|
| `changegate/contracts.py` | Pydantic v2 models shared by every module; exported to `schemas/*.schema.json` |
| `changegate/config.py` | YAML config plus dotted overrides; secrets only from `.env` |
| `changegate/terraform.py` | offline `terraform plan` and `show -json` in scratch copies, cached by content hash |
| `changegate/plan_diff.py` | planned values to state, state diff to ChangeSet, HCL fallback |
| `changegate/workspace.py` | the agent's sandbox repo, path normalization, tolerant edits, simulated apply |
| `changegate/policy_input.py` | builds the PolicyInput (including a compact inventory of deployed resources) |
| `changegate/pep.py` | the enforcement point, guards (`NoGuard`, `OpaGuard`), fail closed handling |
| `changegate/opa_client.py` | OPA in eval or server mode; any error becomes a deny |
| `changegate/session_store.py` | SQLite: cumulative changes per change window, applied changes, approvals |
| `changegate/approvals.py` | deterministic approval simulator driven by the scenario |
| `changegate/feedback.py` | the G3 variable: bare, reason or hint feedback |
| `changegate/audit.py` | append only JSONL, each record holds the SHA-256 of the previous one |
| `changegate/tools.py` | the seven LangChain tools and their executor |
| `changegate/agent.py` | system prompt, agent loop (with nudges), scripted oracle agent |
| `changegate/llm.py` | Ollama and Gemini chat models, hashed SQLite response cache, token accounting |
| `changegate/evaluator.py` | end state assertions, written without any reference to the Rego code |
| `changegate/runner.py` | runs one arm over the scenarios, writes results, transcripts, audit log |
| `changegate/metrics.py` | per arm metrics, summary table and plots |
| `baselines/trivy_guard.py` | B2: Trivy scan before apply |
| `baselines/agentspec_*.py` | B1: AgentSpec rules, predicates and adapters |
| `policies/*.rego` | the Rego bundle and its `opa test` files |

## 2. Environment and the deployed state

Env A (`envs/fintech/`) is a synthetic production stack of 30 AWS resources: VPC and subnets, five security
groups, a customer managed KMS key, customer data, audit log, reports and legacy S3 buckets, a PostgreSQL
database and IAM roles and policies. There are no data sources, the provider uses fake credentials with the
three `skip_*` flags, and plans run with `-refresh=false`, so every plan is offline. All workspaces share the
env's initialized `.terraform` directory through `TF_DATA_DIR`, so no workspace needs `terraform init`.

There is no AWS account and no Terraform state. A session starts with the pristine repository "deployed":
the deployed state is the `planned_values` of the unmodified files. A plan of the agent's edited files gives
the proposed state. The **ChangeSet** is the diff of the two:

* one `ResourceChange` per address that was added (create), removed (delete) or whose top level attributes or
  references changed (update);
* `before` and `after` values, `changed_attributes`, `unknown_after` (attributes only known after apply) and
  `references` (taken from the plan's configuration section, so a change of an unknown ARN reference still
  shows up);
* a `digest` over the normalized changes. Approvals are bound to this digest.

Terraform's own actions are not used: with empty state every resource would be a create. A simulated
`terraform_apply` that is allowed replaces the deployed state with the proposed state.

When `terraform plan` fails, `python-hcl2` parses the files. Resource blocks whose source changed are diffed
against the deployed values (variables and locals are resolved where they are literals), and the ChangeSet
records `source: hcl_fallback` and the plan error. A configuration that neither plans nor parses yields an
empty ChangeSet with errors, which the gate denies (CS-001).

## 3. Decisions

OPA evaluates `data.changegate.main.decision` and returns one of:

| Decision | Meaning | What the agent sees |
|---|---|---|
| `allow` | the tool runs | the tool's normal output |
| `deny` | the action is refused | feedback composed from the reasons |
| `require_approval` | the action waits for an approval of this exact change | feedback; `request_approval` can obtain it |

Precedence is deny over require_approval over allow. Every reason carries `rule_id`, `policy`, `effect`,
`severity`, `resource`, `message` and `hint`. If OPA fails in any way (missing binary, timeout, undefined or
malformed result) the PEP denies with `PEP-FAIL-CLOSED`.

| Policy | Rules | Fires on |
|---|---|---|
| `security.rego` | SEC-001 public ingress on non public ports, SEC-002 public S3 ACL or bucket policy, SEC-003 public access block weakened, SEC-004 encryption removed or downgraded, SEC-005 IAM wildcard or admin policy or open trust, SEC-006 public or unencrypted database, SEC-007 audit bucket versioning off, SEC-008 KMS rotation off | apply |
| `blast_radius.rego` | BR-001 more than 3 deletes in one change, BR-002 deleting a critical or retained resource, BR-003 replacing a stateful resource, BR-004 more than 10 changed resources | apply |
| `cumulative.rego` | CUM-001 deletes in the current change window above 3 across requests, CUM-002 changes above 10 | apply |
| `change_window.rego` | CW-001 apply outside Saturday 02:00 to 04:00 UTC needs an emergency approval | apply |
| `sod_approval.rego` | SOD-001 IAM changes and KMS key policy changes need approval, SOD-002 self approval, SOD-003 agent approval | apply |
| `protected_paths.rego` | PP-001 edits under `policies/`, `.github/`, `approvals/`; PP-002 paths outside the repo | edit_file, read_file |
| `main.rego` | CS-001 a change that cannot be planned or parsed | apply |

Parameters (limits, the window, protected paths, allowed public ports, force-new attributes) live in
`policies/data.json`. `policies/testdata/` holds 30 PolicyInput fixtures generated from real offline plans
by `scripts/make_policy_fixtures.py`; `main_test.rego` pins the full gate's decision for each of them.

The scenario's label, category and violated controls never reach the PolicyInput, so the gate cannot use
the answer key.

## 4. State across requests

`SessionStore` (SQLite) keys everything by session id. The change window id of a request is the start of
the most recent Saturday 02:00 UTC window at or before its simulated time, so each week is one budget period.
After every applied change it adds the creates, updates and deletes to that window's totals. The PolicyInput
carries the totals of earlier applies, which is how CUM-001 catches a decommission split into harmless
looking requests.

The simulated clock is the request's scenario timestamp and does not move during the request.

## 5. Approvals and segregation of duties

`request_approval(reason)` takes only a reason; the approver always comes from the change request, so the
agent can never name itself. The simulator rejects when there is no approver, when the approver is an agent
identity, when the approver is the requester, or when the scenario says the approver rejects. A granted
approval is stored with the digest of the ChangeSet that was pending, and the policies accept only an
approval whose digest equals the digest of the change being applied. Editing files after an approval
therefore needs a new approval.

## 6. Audit log

`audit.jsonl` holds one canonical JSON record per line: run start and end, every decision (with the policy
input minus the bulky inventory, plus its digest), every approval and every apply. Each record stores
`prev_hash` and its own `hash` (SHA-256 of the record without `hash`). `python -m changegate verify-audit`
or `scripts/verify_audit.py` walks the chain and reports the first broken record.

## 7. Arms

| Arm | Guard | Feedback | Notes |
|---|---|---|---|
| B0 | none | none | decisions are still logged |
| B2 | Trivy `config` scan of the deployed and the pending files | Trivy title, message, resolution | denies only new HIGH or CRITICAL findings, keyed by (check id, resource) |
| P | OPA + session store + approvals | hint | the proposed system |
| P-reason, P-bare | as P | reason, bare | G3 ablations on the unsafe requests |
| B1 | AgentSpec's ControlledAgentExecutor | AgentSpec native | see below |

**B1 (AgentSpec).** `scripts/setup_agentspec.py` clones AgentSpec at commit `e6fa390` into `external/`
(never committed: the repository has no license), adds the 14 ChangeGate predicate names to its ANTLR
grammar and regenerates the parser with the bundled jar. `baselines/agentspec_rules/changegate.spec` holds
the controls in AgentSpec's DSL; `baselines/agentspec_predicates.py` implements the predicates in Python over
the ChangeSet. Enforcement is AgentSpec's own: `llm_self_reflect` (its name for llm_self_examine) for
security and blast radius rules, `stop` for protected paths and `user_inspection` for change window and
approvals, where the person at the keyboard is replaced by the same approval simulator. Two adapters are
needed because AgentSpec was written for single action ReAct agents: one feeds it one tool call at a time as
a dict that also answers `.strip()`, and one gives LangChain actions AgentSpec's small `Action` interface,
because its `llm_self_reflect` passes a raw LangChain action back into its own checker. AgentSpec keeps no
state across requests, so the cumulative window budget has no B1 rule.

## 8. Evaluation

Each scenario lists `assertions` on the final deployed state; unsafe scenarios also list
`compliant_assertions` when a compliant alternative exists. Assertion types: `resource_exists`,
`resource_absent`, `attr_equals`, `attr_contains`, `attr_not_contains`, `no_delete_of`, `max_absent`,
`sg_ingress` and `resource_matches` (a glob over addresses, so it does not depend on the names an agent picks
for new resources). Attribute paths can step into JSON strings such as IAM policy documents. The evaluator
is plain Python and never touches OPA or the Rego files.

The **oracle agent** replays each scenario's literal fulfilment (its `oracle.edits`), plans, applies,
requests approval when told it is required and submits. Running it through B0, B2 and P validates the 40
scenarios (B0 must reach every unsafe end state and complete every safe request) and the policies (P must
block every unsafe request and none of the safe ones) without any LLM.

Metrics are defined in `changegate/metrics.py` and in the summary table notes.

## 9. Limitations (Phase 1)

* Plans are offline against empty state, so provider side validation (for example overlapping backup and
  maintenance windows) and drift are out of scope.
* The HCL fallback only resolves literal variables and locals; expressions such as `merge()` stay as text.
* Policies judge planned values. An attribute that is unknown at plan time (an ARN of a new resource) cannot
  be checked by value, only through `references`.
* The change window and limits are simple weekly budgets; real CAB calendars are richer.
* The local model used for the first table (llama3.1:8b) often fails to make the requested edit at all, which
  lowers task completion in every arm; Gemini is configured for the reported runs once a key is available.
