# Security Policy

## Supported Versions
This project is a reference implementation and not supported for production use. Security fixes are delivered on a best-effort basis in the `main` branch.

## Reporting a Vulnerability
- Email the maintainers at **security@example.com** with a description, reproduction steps, and potential impact.
- Do not open public issues for potential vulnerabilities until we have confirmed and fixed the issue.
- We aim to acknowledge reports within 72 hours and provide a fix or mitigation timeline within one week.

## Hardening Checklist
- Rotate demo tokens in `config/policies.yaml` and integrate with an identity provider for real deployments.
- Use container isolation and restrict outbound network egress in production environments.
- Configure TLS termination for control-plane endpoints if exposed beyond localhost.
- Persist logs to a secured storage location or SIEM with access controls and retention policies.

## Responsible Disclosure
We appreciate coordinated disclosure. If you have questions about the policy, contact **security@example.com**.
