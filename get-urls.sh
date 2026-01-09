#!/bin/bash
echo "🔍 Fetching deployed service URLs..."
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "PRODUCTION SERVICES"
echo "═══════════════════════════════════════════════════════════════"
echo ""
API_URL=$(gcloud run services describe web3-xdr-production-api --region us-central1 --format='value(status.url)' 2>/dev/null)
WORKER_URL=$(gcloud run services describe web3-xdr-production-worker --region us-central1 --format='value(status.url)' 2>/dev/null)

if [ -n "$API_URL" ]; then
  echo "✅ API Service: $API_URL"
else
  echo "⏳ API Service: Deploying..."
fi

if [ -n "$WORKER_URL" ]; then
  echo "✅ Worker Service (with UI): $WORKER_URL"
  echo ""
  echo "🎨 WAR ROOM UI: $WORKER_URL/"
  echo "💓 Health Check: $WORKER_URL/health"
  echo "📊 Metrics: $WORKER_URL/metrics"
  echo "🔌 WebSocket: wss://${WORKER_URL#https://}/ws"
else
  echo "⏳ Worker Service: Deploying..."
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
