# ChangeGate running notes

Project state lives mainly in `HANDOFF.md` (read that first; it's the detailed source of truth for this
project, with environment facts, design decisions, gotchas and the ordered remaining-work list). This file is
a short pointer for continuity between sessions.

## Current state (2026-10-19)

Phase 1 is functionally complete with llama3.1:8b: all six arms (B0, B1, B2, P, P-reason, P-bare) ran end to
end, results are summarized and committed, the G3 blind comparison and failure analysis are written, README
and PLAN.md reflect real numbers. See `HANDOFF.md` section 11 for exactly what changed in the latest session
(a stalled 4-day-old experiment was resumed, a readiness-check bug that silently prevented the B1 baseline
from ever running was found and fixed, and the rest of the pipeline was run through to commits).

## Open items

* Gemini runs: blocked on the user adding `GEMINI_API_KEY` to `.env`. Once added, follow `HANDOFF.md` section 9
  step 9 (add prices to `config/default.yaml`, `llm-check`, then a fresh `run_phase1.py --provider gemini` run
  under a new run id, keeping the llama table under its own prefix).
* Final report_back to the user (what runs, commands, summary tables, what was skipped, module ownership) is
  still owed; `HANDOFF.md` section 9 step 10 and README.md now have everything needed to write it.
* Phase 2 (Env B TerraGoat/KaiMonkey, demo UI, OPA server mode, more seeds) is optional, only if asked.

## Working notes for this repo specifically

* Long experiment runs are launched detached via WMI (see `HANDOFF.md` section 7); check `ParentProcessId` in
  `Win32_Process` before assuming two listed processes are independent drivers racing each other.
* `scripts/run_phase1.py --resume` is safe to rerun after any interruption: finished sessions are skipped and
  LLM/plan caches make reruns cheap.
* Do not edit `changegate/*.py` (except `metrics.py`), `baselines/*`, `policies/*`, `config/default.yaml`,
  `envs/`, or `scenarios/` while a driver run is in progress; later arms start new processes and must run the
  same code as earlier arms in the same run.
