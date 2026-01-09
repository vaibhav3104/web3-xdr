# Update Worker to Latest Image

This document describes how to update the production/staging worker to use the latest Docker image.

## When to Use

- **Worker stuck on old revision**: Worker is running outdated code
- **Schema mismatch fix**: Database has old schema, need fallback code deployed
- **Quick update**: Need latest code without full CI/CD pipeline
- **After hotfix**: Pushed a fix and need worker to pick it up immediately

## Option 1: Shell Script (Local)

```bash
# From project root
./scripts/update_worker_to_latest.sh
```

**What it does:**
1. Finds latest Docker image in Artifact Registry (by timestamp)
2. Gets current worker revision
3. Updates `web3-xdr-production-worker` to use latest image
4. Forces new revision (via `LAST_IMAGE_UPDATE` env var)
5. Waits 60 seconds for deployment
6. Verifies new revision
7. Checks Events API for data

**Requirements:**
- `gcloud` CLI installed and authenticated
- Access to `web3-xdr` GCP project

## Option 2: GitHub Actions (Manual Trigger)

1. Go to: https://github.com/vaibhav3104/web3-xdr/actions
2. Select **"Update Worker to Latest"** workflow
3. Click **"Run workflow"**
4. Choose environment: `production` or `staging`
5. Click **"Run workflow"** button

**What it does:**
- Same as shell script but runs in GitHub's infrastructure
- No local gcloud setup needed
- Uses `GCP_SA_KEY` secret for authentication

## Option 3: Direct gcloud Command

```bash
# Update to specific image
gcloud run services update web3-xdr-production-worker \
  --region us-central1 \
  --project web3-xdr \
  --image us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr:latest

# Or use commit SHA from Artifact Registry
gcloud run services update web3-xdr-production-worker \
  --region us-central1 \
  --project web3-xdr \
  --image us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr:<commit-sha>
```

## Verify Update

```bash
# Check current image
gcloud run services describe web3-xdr-production-worker \
  --region us-central1 --project web3-xdr \
  --format="value(spec.template.spec.containers[0].image)"

# Check latest revision
gcloud run revisions list --service=web3-xdr-production-worker \
  --region us-central1 --project web3-xdr --limit=3

# Check events
curl -s 'https://web3-xdr-production-api-ipje7qz66q-uc.a.run.app/api/events?limit=5'
```

## Troubleshooting

**Revision didn't change:**
- Script now uses `--update-env-vars` to force new revision
- Check `latestCreatedRevisionName` not just `latestReadyRevisionName`

**Events still not showing:**
- Wait 2-3 minutes for event collection cycle
- Check worker logs: `gcloud logging read "resource.labels.service_name=web3-xdr-production-worker" --limit=50 --project=web3-xdr`
- Look for: `fallback`, `events_batch_saved`, `schema_mismatch`

**Image not found:**
- Ensure GitHub Actions has completed build
- Check: `gcloud container images list-tags us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr --limit=5 --project=web3-xdr`
