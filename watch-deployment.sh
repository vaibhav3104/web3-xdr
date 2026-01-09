#!/bin/bash
echo "👀 Watching GitHub Actions deployment..."
echo "Press Ctrl+C to stop"
echo ""

while true; do
  clear
  echo "═══════════════════════════════════════════════════════════════"
  echo "🚀 Web3 XDR Deployment Status"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "📊 GitHub Actions: https://github.com/vaibhav3104/web3-xdr/actions"
  echo ""
  
  # Check if services are deployed
  API_STATUS=$(gcloud run services describe web3-xdr-production-api --region us-central1 --format='value(status.conditions[0].status)' 2>/dev/null || echo "Not deployed")
  WORKER_STATUS=$(gcloud run services describe web3-xdr-production-worker --region us-central1 --format='value(status.conditions[0].status)' 2>/dev/null || echo "Not deployed")
  
  echo "Cloud Run Services:"
  echo "  API:    $API_STATUS"
  echo "  Worker: $WORKER_STATUS"
  echo ""
  
  if [ "$API_STATUS" = "True" ] && [ "$WORKER_STATUS" = "True" ]; then
    echo "✅ DEPLOYMENT COMPLETE!"
    echo ""
    ./get-urls.sh
    break
  fi
  
  echo "⏳ Deployment in progress... (refreshing in 30s)"
  sleep 30
done
