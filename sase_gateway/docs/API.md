# Control Plane API

FastAPI surface for policy management, Zero Trust token checks, and retrieving normalized gateway logs.

## Endpoints

| Method & Path | Purpose | Request Model | Response |
| --- | --- | --- | --- |
| `POST /policy/update` | Replace the full policy document on disk. | `{ "policies": { ... } }` | `{ "status": "ok" }` |
| `GET /logs?limit=50` | Return normalized gateway logs from disk (fallback to in-memory buffer). | Query param `limit` (positive int). | `[{ ...log fields... }]` |
| `POST /user/register` | Register a new user and token, seeding default allow/block lists. | `{ "username": "carol", "token": "token-carol" }` | `{ "status": "registered", "user": "carol" }` |
| `POST /token/verify` | Validate a Zero Trust token. | `{ "token": "token-alice" }` | `{ "user": "alice", "status": "valid" }` or HTTP 401 |
| `GET /status` | Control plane health and configuration locations. | _None_ | `{ "status": "healthy", "policies_path": "...", "log_path": "..." }` |

### Notes
- Policy files are persisted to `config/policies.yaml` by default. The admin helpers ensure the directory exists.
- The logs endpoint enforces a positive `limit` to avoid accidental empty or negative slices.
- Token verification re-reads the policy token map when constructed to support runtime updates.

## Example Usage

```bash
# Verify a token
http POST :8000/token/verify token==token-alice

# Register a user and token
http POST :8000/user/register username==carol token==token-carol

# Push an updated policy document
http POST :8000/policy/update policies@config/policies.yaml

# Fetch recent normalized events
http GET :8000/logs limit==20
```
