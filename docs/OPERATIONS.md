# Operations & Runbook

## Local Development

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements-dev.txt
   ```
2. Run quality gates:
   ```bash
   ruff check .
   black --check .
   isort --check-only .
   mypy .
   pytest
   ```
3. Launch services locally:
   ```bash
   uvicorn api.control_plane:app --reload --port 8000
   python gateway/proxy.py
   streamlit run dashboard/app.py --server.port 8501
   ```

## Docker Compose

```bash
docker-compose up --build
```

- Proxy: `localhost:8888`
- Control plane: `localhost:8000`
- Dashboard: `localhost:8501`

## Configuration Management

- **Policies**: `config/policies.yaml` contains per-user rules, default policies, and token map.
- **Blocklists**: Add or remove domains in `config/blocklists/` and reload the proxy to apply.
- **Categories**: Extend `config/categories.json` with regex/keywords per category.
- **Logging**: Gateway and control plane logs are written to `streamlit_logs/gateway.log` by default.

## Observability

- Streamlit dashboard tails the normalized gateway log to display allowed/blocked activity, DLP hits, and CASB findings.
- The SIEM forwarder is file-based by default; replace `streamlit_logs/gateway.log` in `siem/log_forwarder.py` to push to external collectors.

## Security Considerations

- Tokens are stored in the policy file for demo purposes—rotate frequently and back with a real IdP for production.
- TLS inspection is metadata-only to avoid handling private keys and certificates.
- Device posture checks are mock implementations; integrate with EDR/MDM for real deployments.

## Troubleshooting

- Ensure the `streamlit_logs/` directory is writable when running inside containers.
- Use the `/status` endpoint to verify policy and log paths.
- Increase log verbosity by configuring the logging level in `logging_config.py`.
