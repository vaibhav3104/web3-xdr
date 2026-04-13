# Deployment & Rollback Runbook

## Standard Deployment

Deployments are automated via GitHub Actions on push to `main`.

### Pipeline stages
1. **Tests** — pytest + bandit SAST + import validation
2. **Docker build** — multi-stage image with smoke test (health check)
3. **Deploy API** — Cloud Run service `web3-xdr-production-api`
4. **Deploy Worker** — Cloud Run service `web3-xdr-production-worker`

### Pre-deployment checklist
- [ ] All CI checks green (Tests, Lint, YAML rules, Docker build)
- [ ] No critical Dependabot/security alerts open
- [ ] `ENVIRONMENT=production` set in Cloud Run
- [ ] `JWT_SECRET_KEY` set in GCP Secret Manager
- [ ] `CORS_ALLOWED_ORIGINS` set (required in production)
- [ ] At least one `XDR_USER_*` admin user configured

## Rollback

### Option 1: Revert commit (preferred)
```bash
git revert <bad-commit-sha>
git push origin main
# CI will auto-deploy the revert
```

### Option 2: Cloud Run revision rollback (immediate)
```bash
# List revisions
gcloud run revisions list --service web3-xdr-production-api --region us-central1

# Route 100% traffic to previous revision
gcloud run services update-traffic web3-xdr-production-api \
  --to-revisions=<previous-revision>=100 \
  --region us-central1

# Same for worker
gcloud run services update-traffic web3-xdr-production-worker \
  --to-revisions=<previous-revision>=100 \
  --region us-central1
```

### Option 3: Redeploy specific commit
```bash
# Tag the known-good commit and push
git tag v-rollback-$(date +%s) <good-commit-sha>
git push origin --tags
# The deploy workflow triggers on v* tags
```

## Database Migrations

Migrations run automatically on container startup via `entrypoint.sh`.

### If a migration fails
1. Check container logs: `gcloud run services logs read web3-xdr-production-api`
2. Migration failures are non-fatal — the app still starts
3. To manually run: `alembic upgrade head` from within the container
4. To rollback a migration: `alembic downgrade -1`

### If migration causes data issues
1. DO NOT run `alembic downgrade` on production without a backup
2. Take a Cloud SQL backup first: `gcloud sql backups create --instance=web3-xdr-db`
3. Then downgrade: `alembic downgrade <target-revision>`

## Scaling

### API service
- Auto-scales 1-10 instances (production)
- Each instance: 2 vCPU, 2Gi RAM
- Scale manually: `gcloud run services update web3-xdr-production-api --max-instances=20`

### Worker service
- Auto-scales 1-3 instances
- Each instance: 2 vCPU, 4Gi RAM, 300s request timeout
- Scale manually: `gcloud run services update web3-xdr-production-worker --max-instances=5`

## Health Verification Post-Deploy

```bash
# Basic health
curl https://<API_URL>/health

# Detailed health (DB + Redis connectivity)
curl https://<API_URL>/health/detailed

# Readiness (DB query succeeds)
curl https://<API_URL>/health/ready

# Check metrics are flowing
curl https://<API_URL>/metrics | head -20
```
