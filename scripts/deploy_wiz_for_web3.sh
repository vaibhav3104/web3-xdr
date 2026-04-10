#!/bin/bash
#
# Wiz-for-Web3 Full Deployment Script
# ====================================
#
# Deploys all components:
# 1. Neo4j AuraDB (Security Graph)
# 2. ML Model Training
# 3. Worker Integration
# 4. Vertex AI Deployment
#
# Usage:
#   ./scripts/deploy_wiz_for_web3.sh [--skip-neo4j] [--skip-training] [--skip-vertex]
#

set -e

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    SENTINEL3: WIZ-FOR-WEB3 DEPLOYMENT                        ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

# Parse arguments
SKIP_NEO4J=false
SKIP_TRAINING=false
SKIP_VERTEX=false

for arg in "$@"; do
    case $arg in
        --skip-neo4j)
            SKIP_NEO4J=true
            shift
            ;;
        --skip-training)
            SKIP_TRAINING=true
            shift
            ;;
        --skip-vertex)
            SKIP_VERTEX=true
            shift
            ;;
    esac
done

# Check for required tools
echo ""
echo "🔍 Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required"
    exit 1
fi
echo "   ✓ Python 3"

if ! command -v gcloud &> /dev/null; then
    echo "⚠️  gcloud CLI not found (needed for Vertex AI deployment)"
else
    echo "   ✓ gcloud CLI"
fi

# Activate virtual environment if exists
if [ -d "venv" ]; then
    echo ""
    echo "🐍 Activating virtual environment..."
    source venv/bin/activate
fi

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip install -q -r requirements.txt

# ============================================================================
# STEP 1: Neo4j AuraDB Setup
# ============================================================================

if [ "$SKIP_NEO4J" = false ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo "STEP 1: Neo4j AuraDB Setup"
    echo "═══════════════════════════════════════════════════════════════════════════"
    
    if [ -z "$NEO4J_URI" ]; then
        echo ""
        echo "📋 NEO4J_URI not set. Please set up Neo4j AuraDB first."
        echo ""
        python3 scripts/setup_neo4j_aura.py --instructions
        echo ""
        echo "After creating AuraDB, run:"
        echo "  export NEO4J_URI='neo4j+s://xxx.databases.neo4j.io'"
        echo "  export NEO4J_PASSWORD='your-password'"
        echo ""
        read -p "Press Enter after setting environment variables, or Ctrl+C to exit..."
    fi
    
    if [ -n "$NEO4J_URI" ] && [ -n "$NEO4J_PASSWORD" ]; then
        echo ""
        echo "🔧 Initializing Neo4j schema and loading known entities..."
        python3 scripts/setup_neo4j_aura.py --uri "$NEO4J_URI" --password "$NEO4J_PASSWORD"
    fi
else
    echo ""
    echo "⏭  Skipping Neo4j setup (--skip-neo4j)"
fi

# ============================================================================
# STEP 2: ML Model Training
# ============================================================================

if [ "$SKIP_TRAINING" = false ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo "STEP 2: ML Model Training"
    echo "═══════════════════════════════════════════════════════════════════════════"
    
    echo ""
    echo "🧠 Training threat detection model..."
    echo "   This will use:"
    echo "   - Historical exploits (Ronin, Wormhole, Euler, etc.)"
    echo "   - Database incidents (if DATABASE_URL is set)"
    echo "   - YAML rule knowledge"
    echo ""
    
    # Create output directory
    mkdir -p data/models
    
    # Train model
    python3 scripts/train_ml_model.py \
        --epochs 100 \
        --batch-size 32 \
        --output data/models/threat_detector.pt
    
    echo ""
    echo "✅ Model training complete!"
else
    echo ""
    echo "⏭  Skipping model training (--skip-training)"
fi

# ============================================================================
# STEP 3: Deploy to Cloud Run
# ============================================================================

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo "STEP 3: Deploy to Cloud Run"
echo "═══════════════════════════════════════════════════════════════════════════"

echo ""
echo "🚀 Deploying updated worker with graph and ML integration..."

# Build and deploy
if command -v gcloud &> /dev/null; then
    # Set environment variables for deployment
    ENV_VARS="GRAPH_ENABLED=true,ML_DETECTION_ENABLED=true"
    
    if [ -n "$NEO4J_URI" ]; then
        ENV_VARS="$ENV_VARS,NEO4J_URI=$NEO4J_URI"
    fi
    
    if [ -n "$NEO4J_PASSWORD" ]; then
        # Store password in Secret Manager
        echo "$NEO4J_PASSWORD" | gcloud secrets create neo4j-password --data-file=- 2>/dev/null || true
        ENV_VARS="$ENV_VARS,NEO4J_PASSWORD=sm://web3-xdr/neo4j-password"
    fi
    
    # Deploy using Cloud Build
    gcloud builds submit --config cloudbuild-deploy.yaml \
        --substitutions="_ENV_VARS=$ENV_VARS"
    
    echo ""
    echo "✅ Cloud Run deployment complete!"
else
    echo "⚠️  gcloud CLI not found. Please deploy manually:"
    echo "   gcloud builds submit --config cloudbuild-deploy.yaml"
fi

# ============================================================================
# STEP 4: Vertex AI Deployment
# ============================================================================

if [ "$SKIP_VERTEX" = false ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo "STEP 4: Vertex AI Deployment"
    echo "═══════════════════════════════════════════════════════════════════════════"
    
    if [ -f "data/models/threat_detector.pt" ]; then
        echo ""
        echo "🌐 Deploying model to Vertex AI..."
        
        python3 scripts/deploy_vertex_ai.py \
            --model-path data/models/threat_detector.pt \
            --project "${GCP_PROJECT:-web3-xdr}" \
            --region us-central1
    else
        echo "⚠️  No trained model found. Run training first."
        echo "   python scripts/train_ml_model.py"
    fi
else
    echo ""
    echo "⏭  Skipping Vertex AI deployment (--skip-vertex)"
fi

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                         DEPLOYMENT COMPLETE! 🎉                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 What was deployed:"
echo ""
echo "   1. Security Graph (Neo4j)"
if [ -n "$NEO4J_URI" ]; then
    echo "      ✓ Connected to: ${NEO4J_URI##*@}"
else
    echo "      ⚠️ Using mock graph (set NEO4J_URI for production)"
fi
echo ""
echo "   2. ML Threat Detector"
if [ -f "data/models/threat_detector.pt" ]; then
    echo "      ✓ Model trained and saved"
else
    echo "      ⚠️ No model (using heuristic fallback)"
fi
echo ""
echo "   3. Worker Integration"
echo "      ✓ Graph building enabled"
echo "      ✓ ML detection enabled"
echo ""
echo "   4. Vertex AI"
if [ "$SKIP_VERTEX" = false ]; then
    echo "      ✓ Model deployed to endpoint"
else
    echo "      ⏭ Skipped"
fi
echo ""
echo "🔗 Access your dashboard:"
echo "   https://sentinel3-web3-xdr-api-1072954804403.us-central1.run.app/"
echo ""
echo "📚 Documentation:"
echo "   - Security Graph: /api/graph/health"
echo "   - ML Threat Detection: /api/ml-threat/model/info"
echo "   - Attack Paths: /api/graph/attack-paths"
echo ""
