from fastapi.testclient import TestClient

from api.control_plane import app

client = TestClient(app)


def test_status_endpoint():
    response = client.get("/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"


def test_token_verify_failure():
    response = client.post("/token/verify", json={"token": "invalid"})
    assert response.status_code == 401


def test_register_user_updates_policy(tmp_path, monkeypatch):
    from api import admin

    custom_policy = tmp_path / "policies.yaml"
    monkeypatch.setattr(admin, "CONFIG_PATH", custom_policy)

    response = client.post("/user/register", json={"username": "carol", "token": "token-carol"})
    assert response.status_code == 200

    policies = admin.load_policies(custom_policy)
    assert policies["users"]["carol"]["device_trust_required"] is True
    assert policies["tokens"]["carol"] == "token-carol"


def test_get_logs_validates_limit():
    response = client.get("/logs", params={"limit": 0})
    assert response.status_code == 400
