from gateway.dns_filter import load_default_dns_filter


def test_malware_domain_blocked():
    dns_filter = load_default_dns_filter()
    assert dns_filter.is_blocked("malware.test") is True
    assert dns_filter.decision("example.com")["blocked"] is False
