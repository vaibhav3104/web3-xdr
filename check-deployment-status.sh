#!/bin/bash

echo "🔍 DEPLOYMENT STATUS CHECK"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Check GitHub commit
echo "📝 Latest Commit:"
git log -1 --oneline
echo ""

# Check Cloud Run services
echo "☁️  Cloud Run Services:"
gcloud run services list --project=web3-xdr --region=us-central1 --format="table(SERVICE,URL,LAST_DEPLOYED_AT)" 2>/dev/null
echo ""

# Check recent Cloud Build
echo "🏗️  Recent Cloud Build (if any):"
gcloud builds list --limit=3 --project=web3-xdr 2>/dev/null || echo "No recent builds or Cloud Build not enabled"
echo ""

# Try to access services
echo "🔬 Testing Services:"
echo ""

API_URL=$(gcloud run services describe web3-xdr-production-api --region us-central1 --project=web3-xdr --format='value(status.url)' 2>/dev/null)
if [ -n "$API_URL" ]; then
    echo "  API URL: $API_URL"
    echo -n "  API Health: "
    curl -s -o /dev/null -w "%{http_code}" "$API_URL/health" --max-time 5 || echo "TIMEOUT"
    echo ""
else
    echo "  ❌ API service not found"
fi
echo ""

WORKER_URL=$(gcloud run services describe web3-xdr-production-worker --region us-central1 --project=web3-xdr --format='value(status.url)' 2>/dev/null)
if [ -n "$WORKER_URL" ]; then
    echo "  Worker URL: $WORKER_URL"
    echo -n "  Worker Health: "
    curl -s -o /dev/null -w "%{http_code}" "$WORKER_URL/health" --max-time 5 || echo "TIMEOUT"
    echo ""
    echo -n "  Worker UI (root): "
    curl -s -o /dev/null -w "%{http_code}" "$WORKER_URL/" --max-time 5 || echo "TIMEOUT"
    echo ""
else
    echo "  ❌ Worker service not found"
fi
echo ""

echo "════════════════════════════════════════════════════════════════"
echo ""
echo "📊 To check GitHub Actions:"
echo "   https://github.com/vaibhav3104/web3-xdr/actions"
echo ""
echo "📋 To view detailed logs:"
echo "   gcloud logging read 'resource.type=cloud_run_revision' --limit 50 --project=web3-xdr"
echo ""
