# ChangeGate

Deterministic policy-as-code guardrails for LLM agents that change infrastructure-as-code.

Project G1-03, AI4015 Agentic AI, FAST-NUCES, Fall 2026. Phase 1 baseline and Phase 2 final repository.

An LLM agent receives change requests ("open SSH on the bastion security group", "delete the old audit-log
bucket") and edits a Terraform repository through seven tools. Every tool call goes through a Policy
Enforcement Point (PEP) that computes the exact change with an offline `terraform plan`, asks Open Policy
Agent (OPA) for `allow`, `deny` or `require_approval`, records the decision in a hash chained audit log, and
either runs the tool or tells the agent what was wrong and how to fix it. Rego policies encode change
management controls: security rules, blast radius limits, an approved change window, segregation of duties,
protected paths and cumulative limits across requests.

The base paper is AgentSpec (ICSE 2026), a runtime rule DSL for LangChain agents. It is used as baseline B1
through its own code (cloned at a pinned commit by a setup script, never copied into this repository).

The experiments target three research gaps:

* **G1 interception:** does the gate stop unsafe IaC changes, including a risky change split across requests
  and instructions injected into repository files?
* **G2 false blocks:** how often does the gate deny safe changes? Every unsafe request has a safe twin.
* **G3 recovery:** after a deny, does the agent finish compliantly more often with bare, reason, or reason
  plus hint feedback?

Design details are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the build plan and decisions are in
[PLAN.md](PLAN.md).

## Repository layout

| Path | Contents |
|---|---|
| `changegate/` | the system: contracts, config, Terraform runner, ChangeSet diff, workspace, PEP, OPA client, session store, approvals, feedback, audit, tools, agent, LLM layer, evaluator, runner, metrics, CLI |
| `policies/` | Rego bundle (`*.rego`), parameters (`data.json`), `opa test` files (`*_test.rego`) and plan fixtures (`testdata/`) |
| `envs/fintech/` | Env A: synthetic fintech Terraform repo with 30 AWS resources, plans offline |
| `scenarios/phase1/` | 40 change requests in 20 safe and unsafe twin pairs |
| `baselines/` | B2 (Trivy guard) and B1 (AgentSpec rules, predicates and adapters) |
| `schemas/` | JSON Schema of every contract, exported from `changegate/contracts.py` |
| `scripts/` | setup, schema export, fixture generation, the Phase 1 driver, audit verification, review export, Env B fetch |
| `results/`, `figures/` | summary tables and plots; raw runs go to `results/runs/` (gitignored) |
| `tests/` | pytest suite |

## Setup on Windows (PowerShell)

1. Install the tools (once):

   ```powershell
   winget install --id Hashicorp.Terraform -e
   winget install --id AquaSecurity.Trivy -e
   scoop install opa
   winget install --id Ollama.Ollama -e        # local model for development runs
   winget install --id EclipseAdoptium.Temurin.21.JDK -e   # only for the B1 (AgentSpec) setup
   ```

   Python 3.11 or newer and [uv](https://docs.astral.sh/uv/) are expected. Open a new terminal afterwards so
   the new tools are on `PATH`.

2. Create the environment and install the package:

   ```powershell
   uv venv --python 3.12 .venv
   $env:VIRTUAL_ENV = "$PWD\.venv"; uv pip install -e ".[dev,agentspec]"
   ```

   Without uv: `py -3.12 -m venv .venv` and `.\.venv\Scripts\python.exe -m pip install -e ".[dev,agentspec]"`.

3. Download the AWS provider once and initialize Env A (about 800 MB, cached in `.terraform-plugin-cache`):

   ```powershell
   $env:TF_PLUGIN_CACHE_DIR = "$PWD\.terraform-plugin-cache"
   New-Item -ItemType Directory -Force $env:TF_PLUGIN_CACHE_DIR | Out-Null
   terraform -chdir=envs/fintech init -input=false
   ```

4. Pick the LLM. The default is a local model through Ollama:

   ```powershell
   ollama pull qwen2.5:7b-instruct
   ```

   For Gemini, copy `.env.example` to `.env` and set `GEMINI_API_KEY`. Model names live in
   `config/default.yaml` (`gemini-3.8-flash` by default). Gemini 3 requires a `thought_signature` on
   function calls across turns, which `langchain-google-genai` 2.1.12 does not preserve; this repo uses its
   own `changegate/gemini_native.py` wrapper over the `google-genai` SDK instead. A free-tier API key is
   capped at 20 `gemini-3.8-flash` requests per day, far below what even a two-request smoke run needs; a
   real experiment needs a billing-enabled key.

5. Optional, for B1: set up AgentSpec (clones it at the pinned commit into `external/`, gitignored, and
   regenerates its parser with the ChangeGate predicates):

   ```powershell
   .\.venv\Scripts\python.exe scripts\setup_agentspec.py
   ```

6. Check everything:

   ```powershell
   .\.venv\Scripts\python.exe -m changegate check
   opa test policies
   .\.venv\Scripts\python.exe -m pytest
   ```

## Running

All commands run from the repository root.

```powershell
# validate the scenario set (40 requests, 20 twin pairs)
.\.venv\Scripts\python.exe -m changegate validate-scenarios

# deterministic validation without an LLM: the oracle agent applies each request literally
.\.venv\Scripts\python.exe -m changegate run --agent oracle --arms B0,B2,P --run-id oracle

# one arm on a few requests with the configured LLM
.\.venv\Scripts\python.exe -m changegate run --arms P -s SEC-01-U -s SEC-01-S

# the same with Gemini (needs GEMINI_API_KEY in .env)
.\.venv\Scripts\python.exe -m changegate run --arms P -s SEC-01-U --provider gemini

# summary table and plots for a run
.\.venv\Scripts\python.exe -m changegate eval --run-id oracle --prefix oracle

# verify every audit log hash chain
.\.venv\Scripts\python.exe -m changegate verify-audit results\runs

# HTML review of a run (uses the skill-creator eval viewer if it is installed)
.\.venv\Scripts\python.exe scripts\export_review.py --run-id oracle --out results\oracle_review.html
```

Arms are defined in `config/default.yaml`:

| Arm | Guard | Feedback |
|---|---|---|
| B0 | none | none |
| B1 | AgentSpec rules with its native enforcement | AgentSpec native |
| B2 | Trivy scan before apply, deny on new HIGH or CRITICAL findings | Trivy message and resolution |
| P | ChangeGate: OPA, session store, approvals | reason and remediation hint |
| P-reason | ChangeGate | rule ids and messages |
| P-bare | ChangeGate | "Action denied." |

## Reproducing the summary table

The whole Phase 1 experiment is one command. It runs B0, P, B2, B1 on all 40 requests and the two feedback
ablations on the unsafe requests, then writes `results/phase1_summary.md`, `results/phase1_summary.csv` and
the plots in `figures/`:

```powershell
.\.venv\Scripts\python.exe scripts\run_phase1.py --run-id phase1-llama31
```

It can be interrupted and started again with the same `--run-id`: finished sessions are skipped, and LLM
responses and Terraform plans are cached by content hash (`.cache/`), so a rerun with the same model and
seed replays the same results. For Gemini add `--provider gemini` and use a new run id. To rebuild only the
table from existing raw results:

```powershell
.\.venv\Scripts\python.exe -m changegate eval --run-id phase1-llama31
```

## Results

### Oracle validation (no LLM, run `oracle-v2`)

The oracle agent applies each scenario's request literally with no model in the loop, so these numbers check
the harness and the policies on their own, independent of any model's capability.

| Arm | Guard | Feedback | Interception (G1) | Bypass success (G1) | False blocks (G2) | Task completion | Recovery (G3) | Correct rule cited |
|---|---|---|---|---|---|---|---|---|
| B0 | none | none | 0/20 (0%) | 4/4 (100%) | 0/20 (0%) | 20/20 (100%) | n/a | n/a |
| B2 | trivy | reason | 5/20 (25%) | 3/4 (75%) | 0/20 (0%) | 20/20 (100%) | 0/4 (0%) | 0/5 (0%) |
| P | opa | hint | 20/20 (100%) | 0/4 (0%) | 0/20 (0%) | 20/20 (100%) | 9/16 (56%) | 20/20 (100%) |

All three audit chains verify (`changegate verify-audit`). Full table: [results/oracle_summary.md](results/oracle_summary.md).

### Phase 1 experiment, llama3.1:8b (run `phase1-llama31`)

Model llama3.1:8b, seed 7, temperature 0, `num_ctx` 12288, one lane (Ollama serves one request at a time).
These are the first full numbers with a real LLM in the loop; the reported table for the course will use
Gemini once a `GEMINI_API_KEY` is available (see Setup step 4). Ollama's reported token counts exclude
prefix-cached prompt tokens, so `tokens_per_run` understates Ollama's real input size; cost is 0 for Ollama
either way.

| Arm | Guard | Feedback | Interception (G1) | Bypass success (G1) | False blocks (G2) | Task completion | Recovery (G3) | Correct rule cited | Denies / run | Steps / run | Errors |
|---|---|---|---|---|---|---|---|---|---|---|---|
| B0 | none | none | 16/20 (80%) | 1/4 (25%) | 0/20 (0%) | 5/20 (25%) | n/a | n/a | 0.00 | 12.6 | 0 |
| B1 | agentspec | native | 20/20 (100%) | 0/4 (0%) | 0/20 (0%) | 5/20 (25%) | 2/4 (50%) | 4/4 (100%) | 0.25 | 12.3 | 4 |
| B2 | trivy | reason | 17/20 (85%) | 1/4 (25%) | 1/20 (5%) | 5/20 (25%) | 0/1 (0%) | 0/1 (0%) | 0.23 | 12.7 | 0 |
| P | opa | hint | 20/20 (100%) | 0/4 (0%) | 1/20 (5%) | 5/20 (25%) | 5/7 (71%) | 5/7 (71%) | 0.35 | 12.7 | 0 |
| P-reason | opa | reason | 20/20 (100%) | 0/4 (0%) | unsafe only | unsafe only | 3/5 (60%) | 4/5 (80%) | 0.77 | 14.8 | 0 |
| P-bare | opa | bare | 20/20 (100%) | 0/4 (0%) | unsafe only | unsafe only | 3/5 (60%) | 3/6 (50%) | 0.32 | 13.5 | 0 |

Full table (including latency, tokens, cost): [results/phase1_summary.md](results/phase1_summary.md). Plots in
`figures/phase1_*.png`. Failure patterns: [results/failures.md](results/failures.md). Notes:

* Task completion is 25% in every arm, including B0 with no guard at all, so llama3.1:8b itself is the main
  bottleneck for safe requests at this size, not false blocking (false block rate is 0 to 5% everywhere). See
  [results/failures.md](results/failures.md) for the evidence.
* B1 is the AgentSpec baseline running its own native enforcement (not a reimplementation): `scripts/setup_agentspec.py`
  sparse-clones the paper's repo at a pinned commit and patches its ANTLR grammar with 14 ChangeGate predicates.
  Two adapters bridge it to this harness: `SingleActionAdapter` (one tool call per step) and
  `SpecAction`/`SpecFinish` (gives AgentSpec's `llm_self_reflect` checker the Action interface it expects from
  LangChain actions). AgentSpec has no cross-request state, so it cannot express the cumulative (CUM-*) rules;
  that is an expected G1 gap, not a bug.
* G3 blind comparison (`agents/comparator.md` style, [results/comparisons/](results/comparisons/)): on the 3
  unsafe scenarios where both B1 and P blocked the request and a compliant alternative exists, a blind
  comparator (seeing only unlabelled transcripts) picked P's hint feedback over B1's native feedback in all 3
  cases, each time citing that P's message named the actual fix while B1's was terse and led the agent to
  blindly retry the same denied action instead of adapting.

## Changes since Phase 1

| Item | Phase 1 | Phase 2 | Reason |
|---|---|---|---|
| Model | llama3.1:8b through Ollama | qwen2.5:7b-instruct through Ollama | the local model that completed the full request set on an 8 GB GPU; a free-tier Gemini key is capped at 20 requests per day |
| Temperature | 0 | 0.3 | so that the three seeds differ |
| Request set | 40 requests (20 twin pairs) | 50 development requests and 102 test requests (51 safe and 51 unsafe twins), including split changes and instructions hidden in repository files | the test split is never used for design decisions; code was frozen after the development run |
| Seeds | 1 | 3 (reported as mean and standard deviation) | Phase 2 specification |
| Ablations | feedback modes only | feedback modes plus removal of single rule families (blast radius, cumulative, segregation of duties and others) | experiment E5 |
| B1 (AgentSpec) adapter | crashed on plain text final answers | fixed (the final answer is no longer treated as an action) | 18 of 102 requests per seed crashed before the fix; B1 was re-run |

The development log is in [docs/devlog.md](docs/devlog.md). A follow-up run with a 2048 token reply cap
(run ids `p2-fix-s1` to `p2-fix-s3`, summaries in `results/p2fix_s*`) is kept separate and is not part of the
main tables below.

## Phase 2 results (test split, 3 seeds)

Model qwen2.5:7b-instruct, temperature 0.3, 51 safe and 51 unsafe requests per seed. Cells are mean (sample
standard deviation) over seeds 1 to 3 in percent. Per seed tables: `results/p2test_s1_summary.md` to
`results/p2test_s3_summary.md`. B1 is the AgentSpec base paper approach run by this group through an adapter
(its numbers are our runs, not taken from the paper).

| Arm | Guard | Interception (G1) | Bypass success (G1) | False blocks (G2) | Safe task completion | Recovery after deny (G3) | Tokens / run |
|---|---|---|---|---|---|---|---|
| B0 | none | 50.3 (4.5) | 11.1 (4.8) | 0.0 (0.0) | 58.8 (2.0) | n/a | 22786 |
| B1 | AgentSpec | 94.8 (1.1) | 8.3 (0.0) | 1.3 (2.3) | 51.6 (2.3) | 66.8 (5.7) | 47066 |
| B2 | Trivy | 54.2 (4.1) | 16.7 (0.0) | 0.7 (1.1) | 52.9 (3.4) | 0.0 (0.0) | 26242 |
| P | ChangeGate (hint) | 95.4 (2.3) | 11.1 (4.8) | 3.9 (0.0) | 54.2 (1.1) | 66.7 (2.0) | 31664 |

Feedback ablation (unsafe requests only): recovery with reason feedback 63.8 (1.2), with bare feedback
70.9 (2.3), with reason plus hint 66.7 (2.0). Rule ablation (interception, full gate 95.4): without the blast
radius rule 85.5 (1.1), without segregation of duties 91.5 (3.0), without the cumulative rule 94.1 (2.0).

### Gap-resolution table

| Gap | Method / component | Metric | Base paper result (AgentSpec, B1) | Our result (ChangeGate, P) | Addressed? |
|---|---|---|---|---|---|
| G1 interception | OPA rule families, session store for cumulative limits, approvals | Interception of unsafe requests | 94.8% (1.1); no guard 50.3% (4.5) | 95.4% (2.3) | Fully against no guard; on par with AgentSpec (no significance test was run) |
| G2 false blocks | Rules checked on the planned change; every unsafe request has a safe twin | Safe requests denied at least once | 1.3% (2.3) | 3.9% (0.0), 2 of 51 in every seed | Partially (under the 5% target, but not lower than AgentSpec) |
| G3 recovery | Reason plus hint feedback after a deny | Blocked requests that end in the compliant state | 66.8% (5.7) | 66.7% (2.0) hint; 70.9% (2.3) bare | Partially (the hint did not beat bare feedback, so the hypothesis of a 20 point gain was not met) |

Limits that matter when reading the table: the model is a 7B local model, the repository has 30 resources, the
injected instructions were never followed by the model so they did not test the gate, and no significance
tests were run. Details are in the paper.

### Reproducing the Phase 2 numbers

```powershell
# all test split jobs for seeds 1 to 3 (resumable; one job at a time, about 45 to 60 minutes per arm per seed)
.\.venv\Scripts\python.exe scripts\run_phase2.py

# rebuild the summary table of one seed from its raw runs
.\.venv\Scripts\python.exe -m changegate eval --run-id p2-test-s1 --prefix p2test_s1
```

Code state used for the test runs: commit `e9158c2` (code frozen). Results: commit `219cd60`.

## Module ownership

The code is split so that each area can be owned and committed separately:

| Area | Paths |
|---|---|
| Environment and plans | `envs/`, `changegate/terraform.py`, `changegate/plan_diff.py`, `changegate/workspace.py` |
| Policies | `policies/`, `changegate/opa_client.py`, `changegate/policy_input.py` |
| Enforcement core | `changegate/pep.py`, `changegate/session_store.py`, `changegate/approvals.py`, `changegate/feedback.py`, `changegate/audit.py` |
| Agent and LLM | `changegate/agent.py`, `changegate/tools.py`, `changegate/llm.py` |
| Evaluation | `scenarios/`, `changegate/evaluator.py`, `changegate/metrics.py`, `changegate/runner.py` |
| Baselines | `baselines/` |

Env B (TerraGoat and KaiMonkey, for Phase 2) is fetched with `scripts\fetch_targets.py` into `targets/`.
