#!/bin/bash
# Setup GitHub Actions Service Account for web3-xdr

set -e

PROJECT_ID="web3-xdr"
SA_NAME="github-actions"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
KEY_FILE="github-actions-key.json"

echo "🔧 Setting up GitHub Actions Service Account..."
echo "Project: $PROJECT_ID"
echo ""

# Set project
gcloud config set project $PROJECT_ID

# Check if service account exists
if gcloud iam service-accounts describe $SA_EMAIL &>/dev/null; then
    echo "✅ Service account already exists: $SA_EMAIL"
else
    echo "📝 Creating service account: $SA_EMAIL"
    gcloud iam service-accounts create $SA_NAME \
        --display-name="GitHub Actions CI/CD" \
        --description="Service account for automated deployments via GitHub Actions"
    echo "✅ Service account created"
fi

echo ""
echo "🔐 Granting required permissions..."

# Grant permissions
for role in run.admin artifactregistry.writer iam.serviceAccountUser secretmanager.secretAccessor; do
    echo "  - roles/${role}"
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/${role}" \
        --condition=None \
        >/dev/null 2>&1
done

echo "✅ Permissions granted"
echo ""

# Create key
if [ -f "$KEY_FILE" ]; then
    echo "⚠️  Key file already exists: $KEY_FILE"
    read -p "Do you want to create a new key? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Using existing key file."
    else
        rm $KEY_FILE
        echo "📄 Creating new JSON key..."
        gcloud iam service-accounts keys create $KEY_FILE \
            --iam-account=$SA_EMAIL
        echo "✅ New key created: $KEY_FILE"
    fi
else
    echo "📄 Creating JSON key..."
    gcloud iam service-accounts keys create $KEY_FILE \
        --iam-account=$SA_EMAIL
    echo "✅ Key created: $KEY_FILE"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "🎉 Service Account Setup Complete!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1️⃣  Copy the key content:"
echo "    cat $KEY_FILE | pbcopy"
echo "    (The key is now in your clipboard)"
echo ""
echo "2️⃣  Add to GitHub:"
echo "    • Go to: https://github.com/vaibhav3104/web3-xdr/settings/secrets/actions"
echo "    • Click 'New repository secret'"
echo "    • Name: GCP_SA_KEY"
echo "    • Value: Paste from clipboard"
echo "    • Click 'Add secret'"
echo ""
echo "3️⃣  Deploy:"
echo "    git push origin develop"
echo ""
echo "⚠️  IMPORTANT: Keep this key file secure!"
echo "    Do NOT commit it to git (it's in .gitignore)"
echo ""
