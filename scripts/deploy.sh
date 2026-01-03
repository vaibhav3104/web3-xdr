#!/bin/bash
# ============================================================================
# Web3 XDR - Deployment Script
# ============================================================================

set -e

echo "🛡️  Web3 XDR Deployment Script"
echo "================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo "   Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker is installed${NC}"

# Check for .env file
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  No .env file found${NC}"
    echo "   Creating from template..."
    cp env.example .env
    echo -e "${YELLOW}   Please edit .env with your configuration${NC}"
    echo ""
fi

# Parse arguments
PROFILE=""
DETACH=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            PROFILE="--profile full"
            shift
            ;;
        --monitoring)
            PROFILE="--profile monitoring"
            shift
            ;;
        -d|--detach)
            DETACH="-d"
            shift
            ;;
        --build)
            BUILD="--build"
            shift
            ;;
        --stop)
            echo "🛑 Stopping Web3 XDR..."
            docker-compose down
            exit 0
            ;;
        --logs)
            docker-compose logs -f
            exit 0
            ;;
        --help)
            echo "Usage: ./deploy.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --full        Include Redis and PostgreSQL"
            echo "  --monitoring  Include Prometheus and Grafana"
            echo "  -d, --detach  Run in background"
            echo "  --build       Force rebuild"
            echo "  --stop        Stop all services"
            echo "  --logs        Show logs"
            echo "  --help        Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Build and start
echo ""
echo "🚀 Starting Web3 XDR..."
echo ""

docker-compose $PROFILE up $BUILD $DETACH

if [ -n "$DETACH" ]; then
    echo ""
    echo -e "${GREEN}✅ Web3 XDR is running!${NC}"
    echo ""
    echo "📊 Dashboard:     http://localhost:8080/frontend/index.html"
    echo "⚙️  Admin Console: http://localhost:8080/frontend/admin.html"
    echo "📚 API Docs:      http://localhost:8080/api/docs"
    echo ""
    echo "Commands:"
    echo "  View logs:  ./scripts/deploy.sh --logs"
    echo "  Stop:       ./scripts/deploy.sh --stop"
fi

