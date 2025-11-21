.PHONY: install dev-install lint format test

install:
	pip install -r requirements.txt

dev-install:
	pip install -r requirements-dev.txt

lint:
	ruff check .
	black --check .
	isort --check-only .
	mypy .

format:
	black .
	isort .

test:
	pytest
