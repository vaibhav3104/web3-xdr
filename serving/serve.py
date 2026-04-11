#!/usr/bin/env python3
"""
Vertex AI Model Serving Container
==================================

Serves the Sentinel3 threat detection model via REST API.
Compatible with Vertex AI custom container prediction.
"""

import os
import json
import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import structlog

logger = structlog.get_logger(__name__)

# Threat types (must match training)
THREAT_TYPES = [
    "safe",
    "flash_loan_attack",
    "reentrancy",
    "oracle_manipulation",
    "rug_pull",
    "sandwich_attack",
    "front_running",
    "governance_attack",
    "bridge_exploit",
    "admin_key_compromise",
    "liquidity_drain",
    "price_manipulation",
    "suspicious_transfer",
    "unknown_threat"
]


class ThreatDetectorModel(nn.Module):
    """PyTorch model for threat detection."""
    
    def __init__(self, input_dim: int = 100, hidden_dim: int = 256, num_classes: int = 14):
        super().__init__()
        
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
        )
        
        # Attention layer
        self.attention = nn.MultiheadAttention(hidden_dim, num_heads=4, batch_first=True)
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim // 2, num_classes)
        )
        
        # Risk score head
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x: torch.Tensor):
        # Encode features
        encoded = self.encoder(x)
        
        # Self-attention (add batch dimension if needed)
        if encoded.dim() == 2:
            encoded = encoded.unsqueeze(1)
        
        attended, _ = self.attention(encoded, encoded, encoded)
        attended = attended.squeeze(1)
        
        # Classify
        logits = self.classifier(attended)
        risk_score = self.risk_head(attended)
        
        return logits, risk_score


# FastAPI app
app = FastAPI(title="Sentinel3 Threat Detector", version="2.0.0")

# Global model instance
model: Optional[ThreatDetectorModel] = None
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class PredictionRequest(BaseModel):
    """Request for threat prediction."""
    instances: List[Dict[str, Any]]


class PredictionResponse(BaseModel):
    """Response with predictions."""
    predictions: List[Dict[str, Any]]


@app.on_event("startup")
async def load_model():
    """Load model on startup."""
    global model
    
    model_path = os.getenv("MODEL_PATH", "/app/model/model.pt")
    
    try:
        # Initialize model
        model = ThreatDetectorModel()
        
        # Load weights if available
        if os.path.exists(model_path):
            state_dict = torch.load(model_path, map_location=device)
            model.load_state_dict(state_dict)
            logger.info("model_loaded", path=model_path)
        else:
            logger.warning("model_not_found", path=model_path, message="Using random weights")
        
        model.to(device)
        model.eval()
        
        logger.info("model_ready", device=str(device))
        
    except Exception as e:
        logger.error("model_load_failed", error=str(e))
        raise


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "model_loaded": model is not None}


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Sentinel3 Threat Detector",
        "version": "2.0.0",
        "threat_types": THREAT_TYPES
    }


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """
    Predict threat type and risk score.
    
    Vertex AI sends requests in this format:
    {
        "instances": [
            {"features": [0.1, 0.2, ...]}
        ]
    }
    """
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    predictions = []
    
    for instance in request.instances:
        try:
            # Extract features
            features = instance.get("features", [])
            
            if not features:
                # Try to extract from flat dict
                features = [float(v) for v in instance.values() if isinstance(v, (int, float))]
            
            # Ensure we have enough features
            if len(features) < 100:
                features = features + [0.0] * (100 - len(features))
            features = features[:100]
            
            # Convert to tensor
            x = torch.tensor([features], dtype=torch.float32).to(device)
            
            # Predict
            with torch.no_grad():
                logits, risk_score = model(x)
                probs = torch.softmax(logits, dim=-1)
                
                # Get top prediction
                top_idx = torch.argmax(probs, dim=-1).item()
                confidence = probs[0, top_idx].item()
                
                # Get risk score
                risk = risk_score[0, 0].item() * 100  # Scale to 0-100
                
                # Determine if it's a threat
                is_threat = top_idx != 0  # 0 = safe
                
                prediction = {
                    "threat_type": THREAT_TYPES[top_idx],
                    "confidence": round(confidence, 4),
                    "risk_score": round(risk, 2),
                    "is_threat": is_threat,
                    "probabilities": {
                        THREAT_TYPES[i]: round(probs[0, i].item(), 4)
                        for i in range(len(THREAT_TYPES))
                        if probs[0, i].item() > 0.01
                    }
                }
                
                predictions.append(prediction)
                
        except Exception as e:
            logger.error("prediction_failed", error=str(e))
            predictions.append({
                "threat_type": "unknown_threat",
                "confidence": 0.0,
                "risk_score": 50.0,
                "is_threat": True,
                "error": str(e)
            })
    
    return PredictionResponse(predictions=predictions)


# Vertex AI compatible endpoint
@app.post("/v1/models/sentinel3:predict")
async def vertex_predict(request: PredictionRequest):
    """Vertex AI compatible prediction endpoint."""
    return await predict(request)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
