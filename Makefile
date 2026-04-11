# ============================================================================
# Sentinel3 - Makefile
# ============================================================================
# Quick commands for development and deployment
# ============================================================================

.PHONY: help install run test docker-build docker-up docker-down docker-logs clean

# Default target
help:
	@echo "🛡️  Sentinel3 - Available Commands"
	@echo "=================================="
	@echo ""
	@echo "Development:"
	@echo "  make install      Install dependencies"
	@echo "  make run          Run the monitor locally"
	@echo "  make test         Run tests"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-up    Start with Docker Compose"
	@echo "  make docker-down  Stop Docker containers"
	@echo "  make docker-logs  View container logs"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean        Remove cache and temp files"
	@echo "  make lint         Run linter"
	@echo ""

# --------------------------------------------------------------------------
# Development
# --------------------------------------------------------------------------

install:
	pip install -r requirements.txt

run:
	python monitor.py

test:
	pytest tests/ -v

lint:
	flake8 src/ --max-line-length=100

validate-rules:
	python scripts/validate_rules.py

# --------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------

docker-build:
	docker build -t sentinel3:latest .

docker-up:
	docker-compose up -d
	@echo ""
	@echo "✅ Sentinel3 is running!"
	@echo ""
	@echo "📊 Dashboard:     http://localhost:8080/frontend/index.html"
	@echo "⚙️  Admin Console: http://localhost:8080/frontend/admin.html"
	@echo "📚 API Docs:      http://localhost:8080/api/docs"

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-restart:
	docker-compose restart

docker-full:
	docker-compose --profile full up -d

docker-monitoring:
	docker-compose --profile monitoring up -d

# --------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true

# --------------------------------------------------------------------------
# Production
# --------------------------------------------------------------------------

deploy-prod:
	@echo "🚀 Deploying to production..."
	docker-compose -f docker-compose.yml up -d --build
	@echo "✅ Deployed!"

backup-config:
	@mkdir -p backups
	@tar -czf backups/config-$$(date +%Y%m%d-%H%M%S).tar.gz config/
	@echo "✅ Config backed up to backups/"

