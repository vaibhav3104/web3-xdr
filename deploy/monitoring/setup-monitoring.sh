#!/bin/bash
# Sentinel3 Monitoring Setup Script

set -e

echo "============================================"
echo "  Sentinel3 Monitoring Setup"
echo "============================================"

# Check for required tools
command -v docker >/dev/null 2>&1 || { echo "Docker required but not installed."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose required but not installed."; exit 1; }

echo ""
echo "Select monitoring option:"
echo "1) Local Docker (Grafana + Prometheus)"
echo "2) Google Cloud Monitoring Dashboard"
echo "3) Both"
echo ""
read -p "Enter choice [1-3]: " choice

case $choice in
    1|3)
        echo ""
        echo "🐳 Starting local monitoring stack..."
        docker-compose up -d
        
        echo ""
        echo "✅ Local monitoring started!"
        echo ""
        echo "📊 Grafana: http://localhost:3000"
        echo "   Username: admin"
        echo "   Password: sentinel3admin"
        echo ""
        echo "📈 Prometheus: http://localhost:9090"
        ;;
esac

case $choice in
    2|3)
        echo ""
        echo "☁️ Creating Google Cloud Monitoring dashboard..."
        
        # Check if gcloud is configured
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
        if [ -z "$PROJECT_ID" ]; then
            echo "Please configure gcloud: gcloud config set project YOUR_PROJECT_ID"
            exit 1
        fi
        
        echo "Project: $PROJECT_ID"
        
        # Create dashboard
        gcloud monitoring dashboards create --config-from-file=gcloud-dashboard.json 2>/dev/null || \
            echo "Dashboard may already exist or requires manual setup"
        
        echo ""
        echo "✅ Google Cloud Monitoring configured!"
        echo ""
        echo "📊 View dashboard at:"
        echo "   https://console.cloud.google.com/monitoring/dashboards?project=$PROJECT_ID"
        ;;
esac

echo ""
echo "============================================"
echo "  Setup Complete!"
echo "============================================"
echo ""
echo "Quick commands:"
echo "  docker-compose logs -f     # View logs"
echo "  docker-compose down        # Stop monitoring"
echo "  docker-compose restart     # Restart services"
echo ""
