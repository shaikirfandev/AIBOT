.PHONY: setup dev test lint security-test scan-demo clean

# Setup local development environment
setup:
	pip install -e ".[dev]"
	pip install -e packages/schemas
	pip install -e packages/scope-engine
	pip install -e packages/common
	pip install httpx
	@echo "Setup complete"

# Run API server in development mode
dev:
	cd apps/api && uvicorn app.main:app --reload --port 8000

# Run lab server
lab:
	cd apps/lab && uvicorn app:app --reload --port 8888

# Run all tests
test:
	PYTHONPATH=packages/schemas:packages/scope-engine:packages/common:services/llm-gateway:apps/api:$$PYTHONPATH \
		python -m pytest tests/unit/ -v --tb=short

# Run existing tests (original bbhunter)
test-legacy:
	python -m pytest tests/ -v --tb=short --ignore=tests/unit --ignore=tests/integration --ignore=tests/security --ignore=tests/regression --ignore=tests/e2e

# Lint
lint:
	ruff check .
	black --check .

# Format
format:
	black .
	ruff check --fix .

# Security tests
security-test:
	PYTHONPATH=packages/schemas:packages/scope-engine:packages/common:$$PYTHONPATH \
		python -m pytest tests/security/ -v --tb=short

# Demo scan against lab
scan-demo:
	@echo "Starting lab and running demo scan..."
	@echo "1. Start lab: make lab"
	@echo "2. Start API: make dev"
	@echo "3. Create program and scan via API"

# Docker dev environment
docker-dev:
	cd infrastructure/docker && docker-compose up --build

# Clean
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .ruff_cache dist build *.egg-info
