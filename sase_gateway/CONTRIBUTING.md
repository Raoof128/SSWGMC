# Contributing Guidelines

Thank you for your interest in improving the SASE / Secure Web Gateway mini-cloud. These guidelines keep the repository production-grade and easy to operate.

## Getting Started
- Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`.
- Install dependencies: `pip install -r requirements-dev.txt`.
- Familiarise yourself with the [architecture](docs/ARCHITECTURE.md) and [API](docs/API.md).

## Development Workflow
- Format and lint before pushing:
  ```bash
  ruff check .
  black --check .
  isort --check-only .
  mypy .
  pytest
  ```
- Keep changes small and focused. Squash noisy commits where appropriate.
- Use descriptive branches (e.g., `feature/dlp-tuning`, `chore/ci-hardening`).

## Code Quality
- Include type hints and docstrings for new functions, classes, and modules.
- Add or update tests alongside functional changes; prefer pytest fixtures for readability.
- Avoid hard-coded secrets; prefer configuration files or environment variables.
- Preserve backwards compatibility for public APIs or document breaking changes clearly.

## Pull Requests
- Provide a clear summary of motivation, approach, and testing performed.
- Link related issues and include screenshots for dashboard/UI updates when applicable.
- Ensure CI is green; the GitHub Actions workflow mirrors the local quality gates.

## Reporting Issues
- Describe the expected vs. observed behaviour, reproduction steps, and environment details.
- Highlight security-related concerns in the subject line for faster triage.

We appreciate contributions that improve security, clarity, performance, or developer experience. Thank you for helping keep the project production-ready.
