# Deployment Guidelines

## ⚠️ IMPORTANT: All Deployments Must Go Through CI/CD

**Direct deployments to GCP are NOT allowed.**

All changes must:
1. Be committed to a branch
2. Create a Pull Request to `main`
3. Pass all tests
4. Be merged to `main`
5. CI/CD will automatically deploy

## Deployment Flow

```
Developer → Git Push → GitHub Actions → GCP Cloud Run
                ↓
         ┌─────────────┐
         │   Tests     │ ← Must pass
         └─────────────┘
                ↓
         ┌─────────────┐
         │   Build     │ ← Docker image
         └─────────────┘
                ↓
         ┌─────────────┐
         │   Deploy    │ ← Cloud Run
         └─────────────┘
```

## No Manual Deployments

❌ `gcloud run deploy ...` - NOT ALLOWED
❌ `gcloud builds submit ...` - NOT ALLOWED
✅ `git push origin main` - CORRECT WAY

## Environments

| Branch | Environment | Auto-Deploy |
|--------|-------------|-------------|
| `main` | Production  | ✅ Yes      |
| `dev`  | Staging     | ✅ Yes      |
| `*`    | -           | ❌ No       |

## Rollback

To rollback, revert the commit and push:
```bash
git revert HEAD
git push origin main
```

CI/CD will automatically deploy the reverted state.
