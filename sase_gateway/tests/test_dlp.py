from gateway.dlp_inspector import inspect_payload


def test_dlp_blocks_sensitive_numbers():
    result = inspect_payload("TFN 123 456 789")
    assert result.blocked is True
    assert "tfn" in result.findings
    assert result.action == "block"


def test_dlp_redacts_keywords():
    result = inspect_payload("customer salary details")
    assert result.blocked is False
    assert result.action == "redact"
    assert "sensitive_keyword" in result.findings
