from changegate.config import load_config
from changegate.contracts import PolicyDecision, Reason
from changegate.pep import OpaGuard


class FakeClient:
    def __init__(self, decision):
        self.decision = decision

    def evaluate(self, policy_input):
        return self.decision


def reason(rule, policy, effect):
    return Reason(rule_id=rule, policy=policy, effect=effect, severity="high", message="m", hint="h")


def test_ablated_policy_is_dropped_and_decision_recomputed():
    d = PolicyDecision(decision="deny", guard="opa", reasons=[reason("CUM-001", "cumulative", "deny")])
    out = OpaGuard(FakeClient(d), ablate=("cumulative",)).decide(None, None)
    assert out.decision == "allow" and out.reasons == []


def test_other_denies_survive_and_approval_remains():
    d = PolicyDecision(
        decision="deny", guard="opa", reasons=[reason("SOD-001", "sod_approval", "require_approval"), reason("SEC-001", "security", "deny")]
    )
    assert OpaGuard(FakeClient(d), ablate=("security",)).decide(None, None).decision == "require_approval"
    assert OpaGuard(FakeClient(d), ablate=("sod_approval",)).decide(None, None).decision == "deny"


def test_ablation_arms_load():
    cfg = load_config()
    assert cfg.arm("P-nocum").ablate == ["cumulative"]
    assert cfg.arm("P-nostore").no_session_store is True


def test_no_session_store_zeroes_window_totals():
    from changegate.contracts import SessionState, WindowTotals

    class Spy:
        seen = None

        def evaluate(self, policy_input):
            Spy.seen = policy_input.session.window_totals
            return PolicyDecision(decision="allow", guard="opa")

    class PI:
        session = SessionState(session_id="s", window_id="w", window_totals=WindowTotals(window_id="w", deletes=3))

        def model_copy(self, update):
            new = PI()
            new.session = update["session"]
            return new

    OpaGuard(Spy(), no_session_store=True).decide(PI(), None)
    assert Spy.seen.deletes == 0 and Spy.seen.window_id == "w"
