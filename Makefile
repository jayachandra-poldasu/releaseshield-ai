.PHONY: help install dev test lint run run-ui docker clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	pip install -r requirements.txt

dev: ## Install all dependencies (production + dev/test)
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test: ## Run test suite with coverage
	pytest tests/ -v --tb=short --cov=app --cov-report=term-missing

lint: ## Run linter
	ruff check app/ tests/

lint-fix: ## Run linter with auto-fix
	ruff check app/ tests/ --fix

run: ## Start the FastAPI backend server
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run-ui: ## Start the Streamlit UI
	streamlit run ui.py

docker: ## Build and run with Docker Compose
	docker-compose up --build

docker-down: ## Stop Docker Compose services
	docker-compose down

clean: ## Remove cache and compiled files
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov
