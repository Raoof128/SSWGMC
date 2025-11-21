from gateway.proxy import SecureWebGateway


def test_proxy_blocks_malware_domain():
    gateway = SecureWebGateway()
    request = {
        "url": "http://malware.test/payload",
        "method": "GET",
        "token": "token-alice",
        "device": {"device_id": "endpoint", "healthy": True, "posture_score": 90},
    }
    result = gateway.process_request(request)
    assert result.allowed is False


def test_proxy_allows_safe_domain():
    gateway = SecureWebGateway()
    request = {
        "url": "http://example.com/docs",
        "method": "GET",
        "token": "token-alice",
        "device": {"device_id": "endpoint", "healthy": True, "posture_score": 90},
    }
    result = gateway.process_request(request)
    assert result.allowed is True


def test_proxy_blocks_unsupported_method():
    gateway = SecureWebGateway()
    request = {
        "url": "http://example.com/docs",
        "method": "TRACE",
        "token": "token-alice",
        "device": {"device_id": "endpoint", "healthy": True, "posture_score": 90},
    }
    result = gateway.process_request(request)
    assert result.allowed is False
    assert any("unsupported method" in reason for reason in result.log_record["reasons"])
