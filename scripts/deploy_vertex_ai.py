#!/usr/bin/env python3
"""
Vertex AI Model Deployment Script
=================================

Deploys the trained threat detection model to Vertex AI for production inference.

Usage:
    python scripts/deploy_vertex_ai.py --model-path data/models/threat_detector.pt
"""

import os
import sys
import argparse
import json
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Check for Google Cloud SDK
try:
    from google.cloud import aiplatform
    from google.cloud import storage
    GCLOUD_AVAILABLE = True
except ImportError:
    GCLOUD_AVAILABLE = False
    print("⚠️  Google Cloud SDK not installed. Run: pip install google-cloud-aiplatform google-cloud-storage")


def deploy_to_vertex_ai(
    model_path: str,
    project_id: str,
    region: str = "us-central1",
    model_name: str = "sentinel3-threat-detector",
    endpoint_name: str = "sentinel3-threat-endpoint",
    machine_type: str = "n1-standard-4",
    min_replicas: int = 1,
    max_replicas: int = 5
):
    """Deploy model to Vertex AI."""
    
    print("\n" + "="*60)
    print("🚀 Vertex AI Model Deployment")
    print("="*60)
    
    if not GCLOUD_AVAILABLE:
        print("\n❌ Google Cloud SDK not available")
        print("   Run: pip install google-cloud-aiplatform google-cloud-storage")
        return
    
    # Initialize Vertex AI
    print(f"\n📡 Initializing Vertex AI...")
    print(f"   Project: {project_id}")
    print(f"   Region: {region}")
    
    aiplatform.init(project=project_id, location=region)
    
    # Check if model exists
    model_file = Path(model_path)
    if not model_file.exists():
        print(f"\n❌ Model file not found: {model_path}")
        print("   Run training first: python scripts/train_ml_model.py")
        return
    
    # Create GCS bucket for model artifacts
    bucket_name = f"{project_id}-ml-models"
    print(f"\n📦 Uploading model to GCS...")
    
    storage_client = storage.Client(project=project_id)
    
    # Create bucket if it doesn't exist
    try:
        bucket = storage_client.get_bucket(bucket_name)
    except:
        print(f"   Creating bucket: {bucket_name}")
        bucket = storage_client.create_bucket(bucket_name, location=region)
    
    # Upload model file
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    gcs_model_path = f"models/{model_name}/{timestamp}/model.pt"
    
    blob = bucket.blob(gcs_model_path)
    blob.upload_from_filename(str(model_file))
    print(f"   ✓ Uploaded to gs://{bucket_name}/{gcs_model_path}")
    
    # Upload metadata
    meta_file = Path(str(model_file) + ".meta.json")
    if meta_file.exists():
        gcs_meta_path = f"models/{model_name}/{timestamp}/metadata.json"
        meta_blob = bucket.blob(gcs_meta_path)
        meta_blob.upload_from_filename(str(meta_file))
        print(f"   ✓ Uploaded metadata")
    
    # Create custom container spec for PyTorch model
    print(f"\n🔧 Creating model in Vertex AI...")
    
    # Use pre-built PyTorch serving container
    serving_container_image_uri = "us-docker.pkg.dev/vertex-ai/prediction/pytorch-cpu.1-13:latest"
    
    # Create model
    model = aiplatform.Model.upload(
        display_name=model_name,
        artifact_uri=f"gs://{bucket_name}/models/{model_name}/{timestamp}",
        serving_container_image_uri=serving_container_image_uri,
        serving_container_predict_route="/predictions/sentinel3",
        serving_container_health_route="/health",
        serving_container_ports=[8080],
        labels={
            "app": "sentinel3",
            "type": "threat-detector",
            "version": timestamp
        }
    )
    
    print(f"   ✓ Model created: {model.resource_name}")
    
    # Check for existing endpoint
    print(f"\n🌐 Setting up endpoint...")
    
    endpoints = aiplatform.Endpoint.list(
        filter=f'display_name="{endpoint_name}"',
        order_by="create_time desc"
    )
    
    if endpoints:
        endpoint = endpoints[0]
        print(f"   Using existing endpoint: {endpoint.resource_name}")
    else:
        # Create new endpoint
        endpoint = aiplatform.Endpoint.create(
            display_name=endpoint_name,
            labels={
                "app": "sentinel3",
                "type": "threat-detector"
            }
        )
        print(f"   ✓ Created endpoint: {endpoint.resource_name}")
    
    # Deploy model to endpoint
    print(f"\n🚀 Deploying model to endpoint...")
    print(f"   Machine type: {machine_type}")
    print(f"   Replicas: {min_replicas}-{max_replicas}")
    
    model.deploy(
        endpoint=endpoint,
        deployed_model_display_name=f"{model_name}-{timestamp}",
        machine_type=machine_type,
        min_replica_count=min_replicas,
        max_replica_count=max_replicas,
        traffic_percentage=100,
        sync=True
    )
    
    print(f"\n" + "="*60)
    print("✅ Deployment Complete!")
    print("="*60)
    
    print(f"\n📝 Endpoint Details:")
    print(f"   Endpoint ID: {endpoint.name}")
    print(f"   Resource Name: {endpoint.resource_name}")
    
    # Print environment variable to set
    print(f"\n🔧 Set this environment variable in your deployment:")
    print(f"   VERTEX_AI_ENDPOINT={endpoint.name}")
    
    # Test the endpoint
    print(f"\n🧪 Testing endpoint...")
    
    test_instance = {
        "features": [0.0] * 100  # Dummy features
    }
    
    try:
        response = endpoint.predict(instances=[test_instance])
        print(f"   ✓ Endpoint responding correctly")
        print(f"   Response: {response.predictions[0] if response.predictions else 'No predictions'}")
    except Exception as e:
        print(f"   ⚠️ Test failed (model may still be initializing): {e}")
    
    return endpoint.name


def print_manual_instructions():
    """Print manual deployment instructions."""
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     VERTEX AI MANUAL DEPLOYMENT                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  If automated deployment fails, follow these steps:                          ║
║                                                                              ║
║  1. Export model for Vertex AI:                                             ║
║     python scripts/train_ml_model.py                                        ║
║                                                                              ║
║  2. Upload to GCS:                                                          ║
║     gsutil cp -r data/models/vertex_export gs://YOUR_BUCKET/models/         ║
║                                                                              ║
║  3. Create model in Vertex AI Console:                                      ║
║     - Go to https://console.cloud.google.com/vertex-ai/models               ║
║     - Click "Import"                                                        ║
║     - Select your GCS path                                                  ║
║     - Choose PyTorch serving container                                      ║
║                                                                              ║
║  4. Deploy to endpoint:                                                     ║
║     - Click on your model                                                   ║
║     - Click "Deploy to endpoint"                                            ║
║     - Configure machine type (n1-standard-4 recommended)                    ║
║     - Set min/max replicas                                                  ║
║                                                                              ║
║  5. Update your deployment:                                                 ║
║     gcloud run services update sentinel3 \\                                 ║
║       --set-env-vars="VERTEX_AI_ENDPOINT=YOUR_ENDPOINT_ID"                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy threat detection model to Vertex AI")
    parser.add_argument("--model-path", default="data/models/threat_detector.pt", help="Path to trained model")
    parser.add_argument("--project", default=os.getenv("GCP_PROJECT", "web3-xdr"), help="GCP project ID")
    parser.add_argument("--region", default="us-central1", help="GCP region")
    parser.add_argument("--model-name", default="sentinel3-threat-detector", help="Model display name")
    parser.add_argument("--endpoint-name", default="sentinel3-threat-endpoint", help="Endpoint display name")
    parser.add_argument("--machine-type", default="n1-standard-4", help="Machine type for serving")
    parser.add_argument("--min-replicas", type=int, default=1, help="Minimum replicas")
    parser.add_argument("--max-replicas", type=int, default=5, help="Maximum replicas")
    parser.add_argument("--manual", action="store_true", help="Show manual deployment instructions")
    
    args = parser.parse_args()
    
    if args.manual:
        print_manual_instructions()
    else:
        deploy_to_vertex_ai(
            model_path=args.model_path,
            project_id=args.project,
            region=args.region,
            model_name=args.model_name,
            endpoint_name=args.endpoint_name,
            machine_type=args.machine_type,
            min_replicas=args.min_replicas,
            max_replicas=args.max_replicas
        )
