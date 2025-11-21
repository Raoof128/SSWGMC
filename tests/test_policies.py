from gateway.policy_engine import PolicyEngine


def test_policy_allows_known_user(tmp_path):
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text(
        """
users:
  alice:
    allowed_categories: [Business]
    blocked_categories: [Malware]
    allowed_destinations: [example.com]
    device_trust_required: false
"""
    )
    engine = PolicyEngine(policy_path)
    decision = engine.evaluate(
        token="token-alice", domain="example.com", categories={"Business"}, device_context={}
    )
    assert decision.allowed is True


def test_policy_blocks_category(tmp_path):
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text(
        """
users:
  alice:
    allowed_categories: [Business]
    blocked_categories: [Malware]
    allowed_destinations: [example.com]
    device_trust_required: false
"""
    )
    engine = PolicyEngine(policy_path)
    decision = engine.evaluate(
        token="token-alice", domain="example.com", categories={"Malware"}, device_context={}
    )
    assert decision.allowed is False
    assert any("category blocked" in reason for reason in decision.reasons)
