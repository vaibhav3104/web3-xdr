#!/bin/bash
# Sentinel3 - Post-Deployment Health Check Script
# =============================================================================
# Verifies that the dual-service deployment is working correctly.
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=============================================================================="
echo "Sentinel3 - Post-Deployment Health Check"
echo "=============================================================================="
echo ""

# Get gcloud path
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

# Set project
PROJECT_ID="web3-xdr"
REGION="us-central1"

echo -e "${BLUE}Project: ${PROJECT_ID}${NC}"
echo -e "${BLUE}Region: ${REGION}${NC}"
echo ""

# =============================================================================
# Step 1: Get Service URLs
# =============================================================================
echo "Step 1: Getting service URLs..."

API_SERVICE="web3-xdr-production-api"
WORKER_SERVICE="web3-xdr-production-worker"

API_URL=$(gcloud run services describe ${API_SERVICE} \
    --region=${REGION} \
    --project=${PROJECT_ID} \
    --format='value(status.url)' 2>/dev/null || echo "")

WORKER_URL=$(gcloud run services describe ${WORKER_SERVICE} \
    --region=${REGION} \
    --project=${PROJECT_ID} \
    --format='value(status.url)' 2>/dev/null || echo "")

if [ -z "$API_URL" ]; then
    echo -e "${RED}✗ API Service not found or not deployed${NC}"
    echo "  Service: ${API_SERVICE}"
    exit 1
else
    echo -e "${GREEN}✓ API Service URL: ${API_URL}${NC}"
fi

if [ -z "$WORKER_URL" ]; then
    echo -e "${YELLOW}⚠ Worker Service not found or not deployed${NC}"
    echo "  Service: ${WORKER_SERVICE}"
else
    echo -e "${GREEN}✓ Worker Service URL: ${WORKER_URL}${NC}"
fi

echo ""

# =============================================================================
# Step 2: Check API Health
# =============================================================================
echo "Step 2: Checking API health endpoint..."

if [ -n "$API_URL" ]; then
    HEALTH_RESPONSE=$(curl -s "${API_URL}/health" 2>/dev/null || echo "")
    
    if [ -n "$HEALTH_RESPONSE" ]; then
        echo -e "${GREEN}✓ API Health Response:${NC}"
        echo "${HEALTH_RESPONSE}" | python3 -m json.tool 2>/dev/null || echo "${HEALTH_RESPONSE}"
        
        # Check for expected fields
        if echo "${HEALTH_RESPONSE}" | grep -q "healthy"; then
            echo -e "${GREEN}✓ API is healthy${NC}"
        else
            echo -e "${YELLOW}⚠ API health check returned unexpected response${NC}"
        fi
    else
        echo -e "${RED}✗ API health endpoint not responding${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Skipping API health check (service not found)${NC}"
fi

echo ""

# =============================================================================
# Step 3: Check Worker Logs
# =============================================================================
echo "Step 3: Checking Worker logs for initialization signals..."
echo ""

WORKER_LOGS=$(gcloud logging read \
    "resource.type=cloud_run_revision AND resource.labels.service_name=${WORKER_SERVICE}" \
    --limit=100 \
    --format="value(textPayload,jsonPayload.message)" \
    --project=${PROJECT_ID} 2>/dev/null || echo "")

if [ -z "$WORKER_LOGS" ]; then
    echo -e "${YELLOW}⚠ No worker logs found (service may not be running yet)${NC}"
else
    # Check for key initialization signals
    SIGNALS=(
        "Worker initialized"
        "worker_initialized"
        "Connected to Redis"
        "redis"
        "Checkpoint"
        "checkpoint"
        "PassiveNonEVMListener"
        "Event bus"
        "event_bus"
    )
    
    FOUND_SIGNALS=0
    for signal in "${SIGNALS[@]}"; do
        if echo "${WORKER_LOGS}" | grep -qi "${signal}"; then
            echo -e "${GREEN}✓ Found: ${signal}${NC}"
            FOUND_SIGNALS=$((FOUND_SIGNALS + 1))
        fi
    done
    
    if [ $FOUND_SIGNALS -eq 0 ]; then
        echo -e "${YELLOW}⚠ No initialization signals found in logs${NC}"
        echo "  This may mean the worker hasn't started yet or there's an issue"
    fi
    
    # Check for errors
    ERROR_COUNT=$(echo "${WORKER_LOGS}" | grep -ci "error\|ERROR\|Error\|failed\|FAILED" || echo "0")
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo -e "${RED}✗ Found ${ERROR_COUNT} error(s) in worker logs${NC}"
        echo ""
        echo "Recent errors:"
        echo "${WORKER_LOGS}" | grep -i "error\|ERROR\|Error\|failed\|FAILED" | head -5
    else
        echo -e "${GREEN}✓ No errors found in worker logs${NC}"
    fi
fi

echo ""

# =============================================================================
# Step 4: Check Database Connectivity
# =============================================================================
echo "Step 4: Checking database connectivity..."

DB_ERRORS=$(gcloud logging read \
    "resource.type=cloud_run_revision AND (resource.labels.service_name=${API_SERVICE} OR resource.labels.service_name=${WORKER_SERVICE}) AND (textPayload=~\"database\" OR textPayload=~\"postgres\" OR textPayload=~\"DB\" OR severity>=ERROR)" \
    --limit=20 \
    --format="value(textPayload)" \
    --project=${PROJECT_ID} 2>/dev/null || echo "")

if echo "${DB_ERRORS}" | grep -qi "error\|failed\|timeout"; then
    echo -e "${RED}✗ Database connectivity issues detected${NC}"
    echo "${DB_ERRORS}" | grep -i "error\|failed\|timeout" | head -3
else
    echo -e "${GREEN}✓ No database connectivity errors found${NC}"
fi

# Check for migration logs (good sign)
MIGRATION_LOGS=$(gcloud logging read \
    "resource.type=cloud_run_revision AND textPayload=~\"alembic\|migration\|schema\"" \
    --limit=5 \
    --format="value(textPayload)" \
    --project=${PROJECT_ID} 2>/dev/null || echo "")

if [ -n "$MIGRATION_LOGS" ]; then
    echo -e "${GREEN}✓ Database migrations detected (schema is being applied)${NC}"
fi

echo ""

# =============================================================================
# Step 5: Verify Service Status
# =============================================================================
echo "Step 5: Checking service status..."

API_STATUS=$(gcloud run services describe ${API_SERVICE} \
    --region=${REGION} \
    --project=${PROJECT_ID} \
    --format='value(status.conditions[0].status)' 2>/dev/null || echo "UNKNOWN")

WORKER_STATUS=$(gcloud run services describe ${WORKER_SERVICE} \
    --region=${REGION} \
    --project=${PROJECT_ID} \
    --format='value(status.conditions[0].status)' 2>/dev/null || echo "UNKNOWN")

if [ "$API_STATUS" = "True" ]; then
    echo -e "${GREEN}✓ API Service: Running${NC}"
else
    echo -e "${RED}✗ API Service: ${API_STATUS}${NC}"
fi

if [ "$WORKER_STATUS" = "True" ]; then
    echo -e "${GREEN}✓ Worker Service: Running${NC}"
else
    echo -e "${RED}✗ Worker Service: ${WORKER_STATUS}${NC}"
fi

echo ""

# =============================================================================
# Step 6: Check Recent Logs Summary
# =============================================================================
echo "Step 6: Recent log summary (last 10 entries)..."
echo ""

echo -e "${BLUE}API Service Logs:${NC}"
gcloud logging read \
    "resource.type=cloud_run_revision AND resource.labels.service_name=${API_SERVICE}" \
    --limit=10 \
    --format="table(timestamp,severity,textPayload)" \
    --project=${PROJECT_ID} 2>/dev/null | head -12 || echo "No logs found"

echo ""
echo -e "${BLUE}Worker Service Logs:${NC}"
gcloud logging read \
    "resource.type=cloud_run_revision AND resource.labels.service_name=${WORKER_SERVICE}" \
    --limit=10 \
    --format="table(timestamp,severity,textPayload)" \
    --project=${PROJECT_ID} 2>/dev/null | head -12 || echo "No logs found"

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=============================================================================="
echo "Health Check Summary"
echo "=============================================================================="
echo ""
echo "API Service:"
echo "  URL: ${API_URL}"
echo "  Status: ${API_STATUS}"
echo ""
echo "Worker Service:"
echo "  URL: ${WORKER_URL}"
echo "  Status: ${WORKER_STATUS}"
echo ""
echo "Next Steps:"
echo "  1. Open API Dashboard: ${API_URL}"
echo "  2. View Worker Logs: gcloud logging read \"resource.type=cloud_run_revision AND resource.labels.service_name=${WORKER_SERVICE}\" --limit=50"
echo "  3. Check metrics: ${API_URL}/metrics (if available)"
echo ""

