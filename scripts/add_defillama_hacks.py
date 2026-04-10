#!/usr/bin/env python3
"""
Add DeFiLlama Hack Data to ML Training

This script fetches real exploit data from DeFiLlama and adds it to our
training dataset to improve ML model accuracy.
"""

import asyncio
import aiohttp
import json
import os
import numpy as np
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

# Training data paths
DATA_DIR = Path(__file__).parent.parent / "data" / "ml_training"
SAMPLES_FILE = DATA_DIR / "enhanced_samples.json"
METADATA_FILE = DATA_DIR / "metadata.json"

# DeFiLlama API
DEFILLAMA_HACKS_URL = "https://api.llama.fi/hacks"


async def fetch_defillama_hacks() -> List[Dict]:
    """Fetch all hacks from DeFiLlama API."""
    print("📡 Fetching hacks from DeFiLlama...")
    
    async with aiohttp.ClientSession() as session:
        async with session.get(DEFILLAMA_HACKS_URL) as response:
            if response.status == 200:
                data = await response.json()
                hacks = data if isinstance(data, list) else data.get("hacks", [])
                print(f"   ✅ Fetched {len(hacks)} hacks")
                return hacks
            else:
                print(f"   ❌ Failed to fetch: {response.status}")
                return []


def classify_hack_type(hack: Dict) -> str:
    """Classify a hack into our threat categories."""
    # Get technique/category from DeFiLlama
    technique = (hack.get("technique") or "").lower()
    category = (hack.get("category") or "").lower()
    name = (hack.get("name") or "").lower()
    
    # Map to our threat types
    if any(x in technique for x in ["flash loan", "flashloan"]):
        return "flash_loan_attack"
    elif any(x in technique for x in ["reentrancy", "re-entrancy"]):
        return "reentrancy"
    elif any(x in technique for x in ["oracle", "price manipulation"]):
        return "oracle_manipulation"
    elif any(x in technique for x in ["rug pull", "rugpull", "exit scam"]):
        return "rug_pull"
    elif any(x in technique for x in ["bridge", "cross-chain"]):
        return "bridge_exploit"
    elif any(x in technique for x in ["access control", "privilege", "admin key"]):
        return "access_control"
    elif any(x in technique for x in ["governance", "voting"]):
        return "governance_attack"
    elif "honeypot" in technique or "honeypot" in name:
        return "honeypot"
    else:
        # Default based on amount - large hacks are usually more sophisticated
        amount = hack.get("fundsLost", 0) or hack.get("amount", 0) or 0
        if amount > 10_000_000:  # > $10M
            return "bridge_exploit"  # Large hacks often involve bridges
        elif amount > 1_000_000:  # > $1M
            return "flash_loan_attack"  # Medium hacks often use flash loans
        else:
            return "rug_pull"  # Smaller hacks often rug pulls


def extract_features(hack: Dict) -> List[float]:
    """Extract features from a hack for ML training."""
    # Get basic info
    amount = float(hack.get("fundsLost", 0) or hack.get("amount", 0) or 0)
    
    # Handle chain - can be string or list
    chain_raw = hack.get("chain", "")
    if isinstance(chain_raw, list):
        chain = chain_raw[0].lower() if chain_raw else ""
    else:
        chain = str(chain_raw).lower() if chain_raw else ""
    
    technique = (hack.get("technique") or "").lower()
    
    # Create feature vector (16 dimensions to match existing)
    features = [
        1.0,  # is_malicious (always 1 for hacks)
        min(amount / 1_000_000_000, 1.0),  # normalized_amount (cap at $1B)
        1.0 if "flash" in technique else 0.0,
        1.0 if "reentrancy" in technique else 0.0,
        1.0 if "oracle" in technique else 0.0,
        1.0 if "bridge" in technique else 0.0,
        1.0 if "access" in technique else 0.0,
        1.0 if "rug" in technique else 0.0,
        # Chain features
        1.0 if chain in ["ethereum", "eth"] else 0.0,
        1.0 if chain in ["bsc", "binance"] else 0.0,
        1.0 if chain in ["polygon", "matic"] else 0.0,
        1.0 if chain in ["arbitrum", "arb"] else 0.0,
        1.0 if chain in ["avalanche", "avax"] else 0.0,
        1.0 if chain in ["optimism", "op"] else 0.0,
        # Amount buckets
        1.0 if amount > 10_000_000 else 0.0,  # > $10M
        1.0 if amount > 100_000_000 else 0.0,  # > $100M
    ]
    
    return features


def create_training_sample(hack: Dict) -> Optional[Dict]:
    """Create a training sample from a hack."""
    # Skip if no useful data
    if not hack.get("name"):
        return None
    
    amount = float(hack.get("fundsLost", 0) or hack.get("amount", 0) or 0)
    if amount <= 0:
        return None
    
    threat_type = classify_hack_type(hack)
    features = extract_features(hack)
    
    # Get date
    date_str = hack.get("date") or hack.get("timestamp") or ""
    if isinstance(date_str, (int, float)):
        date_str = datetime.fromtimestamp(date_str).isoformat()
    
    # Handle chain - can be string or list
    chain_raw = hack.get("chain", "unknown")
    if isinstance(chain_raw, list):
        chain = chain_raw[0] if chain_raw else "unknown"
    else:
        chain = str(chain_raw) if chain_raw else "unknown"
    
    return {
        "name": hack.get("name", "Unknown"),
        "chain": chain,
        "amount_usd": amount,
        "technique": hack.get("technique", "unknown"),
        "threat_type": threat_type,
        "is_malicious": True,
        "date": date_str,
        "features": features,
        "source": "defillama",
        "defillama_id": hack.get("id") or hack.get("name"),
    }


async def main():
    """Main function to add DeFiLlama hacks to training data."""
    print("=" * 70)
    print("🔥 ADDING DEFILLAMA HACK DATA TO ML TRAINING")
    print("=" * 70)
    print()
    
    # Fetch hacks
    hacks = await fetch_defillama_hacks()
    
    if not hacks:
        print("❌ No hacks fetched, exiting")
        return
    
    # Filter to 2024-2026 hacks
    recent_hacks = []
    for hack in hacks:
        date_str = hack.get("date") or hack.get("timestamp") or ""
        if isinstance(date_str, (int, float)):
            year = datetime.fromtimestamp(date_str).year
        elif isinstance(date_str, str) and date_str:
            try:
                year = datetime.fromisoformat(date_str.replace("Z", "+00:00")).year
            except:
                year = 2024  # Default to recent
        else:
            year = 2024
        
        if year >= 2024:
            recent_hacks.append(hack)
    
    print(f"📅 Found {len(recent_hacks)} hacks from 2024-2026")
    
    # Create training samples
    new_samples = []
    for hack in recent_hacks:
        sample = create_training_sample(hack)
        if sample:
            new_samples.append(sample)
    
    print(f"✅ Created {len(new_samples)} training samples")
    
    # Analyze by threat type
    type_counts = {}
    for sample in new_samples:
        t = sample["threat_type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    
    print("\n📊 Samples by Threat Type:")
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"   {t}: {count}")
    
    # Load existing samples
    existing_samples = []
    if SAMPLES_FILE.exists():
        with open(SAMPLES_FILE, 'r') as f:
            existing_samples = json.load(f)
        print(f"\n📂 Loaded {len(existing_samples)} existing samples")
    
    # Deduplicate by name
    existing_names = {s.get("name", "").lower() for s in existing_samples}
    unique_new = [s for s in new_samples if s["name"].lower() not in existing_names]
    print(f"🆕 {len(unique_new)} new unique samples to add")
    
    # Merge
    all_samples = existing_samples + unique_new
    
    # Save updated samples
    with open(SAMPLES_FILE, 'w') as f:
        json.dump(all_samples, f, indent=2, default=str)
    print(f"💾 Saved {len(all_samples)} total samples to {SAMPLES_FILE}")
    
    # Update numpy arrays for training
    print("\n🔄 Updating training arrays...")
    
    # Extract features and labels
    X = []
    y_threat = []
    y_type = []
    
    # Threat type mapping
    threat_types = [
        "oracle_manipulation",
        "rug_pull", 
        "flash_loan_attack",
        "access_control",
        "reentrancy",
        "safe",
        "bridge_exploit",
        "governance_attack",
        "honeypot",
    ]
    type_to_idx = {t: i for i, t in enumerate(threat_types)}
    
    for sample in all_samples:
        features = sample.get("features")
        if not features or len(features) != 16:
            # Generate features if missing
            features = [
                1.0 if sample.get("is_malicious", True) else 0.0,
                min(sample.get("amount_usd", 0) / 1_000_000_000, 1.0),
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # technique flags
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # chain flags
                1.0 if sample.get("amount_usd", 0) > 10_000_000 else 0.0,
                1.0 if sample.get("amount_usd", 0) > 100_000_000 else 0.0,
            ]
        
        X.append(features)
        
        # Threat label (0 = safe, 1 = malicious)
        y_threat.append(1 if sample.get("is_malicious", True) else 0)
        
        # Type label
        threat_type = sample.get("threat_type", "rug_pull")
        if threat_type not in type_to_idx:
            threat_type = "rug_pull"  # Default
        y_type.append(type_to_idx[threat_type])
    
    # Save numpy arrays
    X = np.array(X, dtype=np.float32)
    y_threat = np.array(y_threat, dtype=np.int64)
    y_type = np.array(y_type, dtype=np.int64)
    
    np.save(DATA_DIR / "X_enhanced.npy", X)
    np.save(DATA_DIR / "y_threat_enhanced.npy", y_threat)
    np.save(DATA_DIR / "y_type_enhanced.npy", y_type)
    
    print(f"   X shape: {X.shape}")
    print(f"   y_threat shape: {y_threat.shape}")
    print(f"   y_type shape: {y_type.shape}")
    
    # Update metadata
    metadata = {
        "total_samples": len(all_samples),
        "feature_dims": 16,
        "threat_types": threat_types,
        "threat_type_mapping": type_to_idx,
        "class_distribution": {
            "threats": int(np.sum(y_threat)),
            "safe": int(len(y_threat) - np.sum(y_threat))
        },
        "sources": {
            "defillama": len([s for s in all_samples if s.get("source") == "defillama"]),
            "internal": len([s for s in all_samples if s.get("source") != "defillama"]),
        },
        "updated_at": datetime.now().isoformat(),
    }
    
    with open(METADATA_FILE, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\n✅ Updated metadata: {metadata['total_samples']} samples")
    print(f"   - DeFiLlama: {metadata['sources']['defillama']}")
    print(f"   - Internal: {metadata['sources']['internal']}")
    
    # Print some example hacks
    print("\n📋 Sample Recent Hacks Added:")
    for sample in unique_new[:5]:
        print(f"   • {sample['name']} ({sample['chain']}): ${sample['amount_usd']:,.0f} - {sample['threat_type']}")
    
    print("\n" + "=" * 70)
    print("✅ DEFILLAMA HACK DATA ADDED SUCCESSFULLY")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Run: python scripts/train_ml_model.py")
    print("2. Deploy: gcloud builds submit --config=cloudbuild-deploy.yaml")


if __name__ == "__main__":
    asyncio.run(main())
