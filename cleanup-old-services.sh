#!/bin/bash
# Cleanup old/unused Cloud Run services

echo "🧹 Cleaning up old Cloud Run services..."
echo ""
echo "Services to keep (current production):"
echo "  ✅ web3-xdr-production-api     (API service)"
echo "  ✅ web3-xdr-production-worker  (Worker + UI)"
echo ""
echo "Services to delete (old/unused):"
echo "  ❌ web3-xdr                    (legacy)"
echo "  ❌ web3-xdr-production         (legacy)"
echo ""
read -p "Do you want to delete the old services? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Deleting old services..."
    
    echo "  Deleting: web3-xdr..."
    gcloud run services delete web3-xdr \
      --region us-central1 \
      --project web3-xdr \
      --quiet || echo "    Service not found or already deleted"
    
    echo "  Deleting: web3-xdr-production..."
    gcloud run services delete web3-xdr-production \
      --region us-central1 \
      --project web3-xdr \
      --quiet || echo "    Service not found or already deleted"
    
    echo ""
    echo "✅ Cleanup complete!"
    echo ""
    echo "Remaining services:"
    gcloud run services list --project=web3-xdr --region=us-central1
else
    echo "Cleanup cancelled."
fi
