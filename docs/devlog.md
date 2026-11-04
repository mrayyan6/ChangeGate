# Devlog

## Phase 2 dev run (p2-dev-s1, seed 1, dev split, qwen2.5:7b-instruct)

* B0 and P finished 50/50 requests each, 0 errors. One request (SPLIT-06-U, P) first failed with an LLM read timeout and was re-run with --resume.
* P: interception 25/25, bypass 0/4, false blocks 0/25, task completion 11/25, recovery 5/7, correct rule 12/13.
* B0: interception 14/25, bypass 0/4, task completion 12/25.
* Harness review of every failed safe request: all are model failures (edit applied to the wrong security group or bucket, repeated identical edit after an "old text matches 2 places" message, "old text not found" loops, 20 step cap, partial multi-block deletes, wrong resource kind). B0 fails the same requests, so the guard is not the cause. No harness defect found, so no code change was made after the dev run.
* Code freeze: the commit that contains this file is the frozen state used for the test runs. Test runs: `python scripts/run_phase2.py`, run ids p2-test-s1..s3.
