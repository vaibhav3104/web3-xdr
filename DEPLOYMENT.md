# Sentinel3 Deployment Guide

## 🌍 Environments

| Environment | Branch | URL | Auto-Deploy |
|-------------|--------|-----|-------------|
| **Staging** | `develop` | https://web3-xdr-1003459948096.us-central1.run.app | ✅ Yes |
| **Production** | `main` | https://web3-xdr-production-1003459948096.us-central1.run.app | ✅ Yes |

---

## 🚀 Deployment Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DEPLOYMENT FLOW                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   STAGING (Testing)                                                     │
│   ─────────────────                                                     │
│   1. Create feature branch from 'develop'                               │
│   2. Make changes                                                       │
│   3. Push to 'develop' branch                                           │
│   4. CI/CD deploys to STAGING automatically                             │
│   5. Test on staging URL                                                │
│                                                                         │
│   PRODUCTION (Live)                                                     │
│   ─────────────────                                                     │
│   1. Create PR from 'develop' to 'main'                                 │
│   2. Review and approve PR                                              │
│   3. Merge to 'main'                                                    │
│   4. CI/CD deploys to PRODUCTION automatically                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Commands

### Deploy to Staging
```bash
git checkout develop
git pull origin develop
# Make changes...
git add .
git commit -m "feat: Your feature"
git push origin develop
# → Automatically deploys to STAGING
```

### Deploy to Production
```bash
git checkout main
git pull origin main
git merge develop
git push origin main
# → Automatically deploys to PRODUCTION
```

---

## ⚠️ Rules

1. **NO manual deployments** - Everything goes through CI/CD
2. **Test on staging first** - Always verify on staging before production
3. **Use PRs for production** - Merge from develop to main via PR

---

## 🔄 Rollback

### Rollback Production
```bash
git checkout main
git revert HEAD
git push origin main
# CI/CD will deploy the reverted state
```

### Rollback Staging
```bash
git checkout develop
git revert HEAD
git push origin develop
```
