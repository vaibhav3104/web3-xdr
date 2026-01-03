"""
AI-Powered Incident Analyzer for Web3 XDR.

Supports multiple LLM backends:
- OpenAI (GPT-4)
- Anthropic (Claude)
- Local fallback (rule-based)
"""

import os
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio

import structlog
import httpx

from .prompts import (
    INCIDENT_ANALYSIS_PROMPT,
    QUICK_SUMMARY_PROMPT,
    RECOMMENDATION_PROMPT,
    ATTACK_PATTERNS
)

logger = structlog.get_logger()


class AIAnalyzer:
    """
    AI-powered incident analyzer using LLMs.
    """
    
    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",  # Use gpt-4o-mini (faster, cheaper, available to all)
        timeout: int = 30
    ):
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.timeout = timeout
        
        # Determine which backend to use
        if self.openai_api_key:
            self.backend = "openai"
        elif self.anthropic_api_key:
            self.backend = "anthropic"
        else:
            self.backend = "local"
            logger.warning("No API keys found, using local rule-based analysis")
        
        logger.info("ai_analyzer_initialized", backend=self.backend, model=model)
    
    async def analyze_incident(
        self,
        incident: Dict[str, Any],
        include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze a security incident using AI.
        
        Returns:
            Dict with analysis, recommendations, and metadata
        """
        start_time = datetime.utcnow()
        
        # Get attack pattern info
        attack_type = incident.get("attack_type", "unknown")
        pattern_info = ATTACK_PATTERNS.get(attack_type, {})
        
        # Build the prompt
        incident_json = json.dumps(incident, indent=2, default=str)
        pattern_info_str = json.dumps(pattern_info, indent=2) if pattern_info else "Unknown attack pattern"
        
        prompt = INCIDENT_ANALYSIS_PROMPT.format(
            incident_json=incident_json,
            attack_pattern_info=pattern_info_str
        )
        
        # Get AI analysis
        if self.backend == "openai":
            analysis = await self._analyze_openai(prompt)
        elif self.backend == "anthropic":
            analysis = await self._analyze_anthropic(prompt)
        else:
            analysis = self._analyze_local(incident, pattern_info)
        
        # Calculate latency
        latency = (datetime.utcnow() - start_time).total_seconds()
        
        return {
            "incident_id": incident.get("id", "unknown"),
            "analysis": analysis,
            "attack_pattern": pattern_info,
            "backend": self.backend,
            "model": self.model if self.backend != "local" else "rule-based",
            "latency_seconds": latency,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def get_quick_summary(self, incident: Dict[str, Any]) -> str:
        """Get a 2-sentence summary for dashboard display."""
        
        if self.backend == "local":
            return self._get_local_summary(incident)
        
        prompt = QUICK_SUMMARY_PROMPT.format(
            incident_title=incident.get("title", "Unknown Incident"),
            attack_type=incident.get("attack_type", "unknown"),
            severity=incident.get("severity", "unknown"),
            total_loss_usd=incident.get("total_loss_usd", 0),
            affected_chains=", ".join(incident.get("affected_chains", []))
        )
        
        if self.backend == "openai":
            return await self._analyze_openai(prompt, max_tokens=150)
        elif self.backend == "anthropic":
            return await self._analyze_anthropic(prompt, max_tokens=150)
        
        return self._get_local_summary(incident)
    
    async def get_recommendations(self, incident: Dict[str, Any]) -> List[str]:
        """Get prioritized recommendations for incident response."""
        
        attack_type = incident.get("attack_type", "unknown")
        pattern_info = ATTACK_PATTERNS.get(attack_type, {})
        
        if self.backend == "local" or not pattern_info:
            return pattern_info.get("immediate_actions", [
                "Monitor the situation closely",
                "Alert security team",
                "Prepare incident response"
            ])
        
        prompt = RECOMMENDATION_PROMPT.format(
            attack_type=attack_type,
            severity=incident.get("severity", "unknown"),
            total_loss_usd=incident.get("total_loss_usd", 0)
        )
        
        if self.backend == "openai":
            response = await self._analyze_openai(prompt, max_tokens=300)
        elif self.backend == "anthropic":
            response = await self._analyze_anthropic(prompt, max_tokens=300)
        else:
            response = ""
        
        # Parse recommendations from response
        recommendations = []
        for line in response.split("\n"):
            line = line.strip()
            if line and (line.startswith("1.") or line.startswith("2.") or line.startswith("3.")):
                recommendations.append(line[2:].strip())
        
        return recommendations if recommendations else pattern_info.get("immediate_actions", [])
    
    async def _analyze_openai(self, prompt: str, max_tokens: int = 1000) -> str:
        """Call OpenAI API."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.openai_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are an expert Web3 security analyst specializing in cross-chain bridge attacks and DeFi exploits."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        "max_tokens": max_tokens,
                        "temperature": 0.3
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return data["choices"][0]["message"]["content"]
                else:
                    logger.error("openai_api_error", status=response.status_code, response=response.text)
                    return self._get_fallback_analysis()
                    
        except Exception as e:
            logger.error("openai_error", error=str(e))
            return self._get_fallback_analysis()
    
    async def _analyze_anthropic(self, prompt: str, max_tokens: int = 1000) -> str:
        """Call Anthropic Claude API."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.anthropic_api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "claude-3-sonnet-20240229",
                        "max_tokens": max_tokens,
                        "messages": [
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ]
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return data["content"][0]["text"]
                else:
                    logger.error("anthropic_api_error", status=response.status_code, response=response.text)
                    return self._get_fallback_analysis()
                    
        except Exception as e:
            logger.error("anthropic_error", error=str(e))
            return self._get_fallback_analysis()
    
    def _analyze_local(self, incident: Dict[str, Any], pattern_info: Dict) -> str:
        """Local rule-based analysis when no API is available."""
        
        attack_type = incident.get("attack_type", "unknown")
        severity = incident.get("severity", "unknown")
        loss = incident.get("total_loss_usd", 0)
        chains = incident.get("affected_chains", [])
        
        # Build analysis based on known patterns
        analysis = f"""## Executive Summary
This is a **{severity.upper()}** severity incident of type **{pattern_info.get('name', attack_type)}**. 
{pattern_info.get('description', 'Analysis based on detected patterns.')}
Estimated financial impact: ${loss:,.0f}

## Technical Breakdown
**Attack Type:** {pattern_info.get('name', attack_type)}
**Known Indicators:**
"""
        
        for indicator in pattern_info.get("indicators", ["Pattern analysis in progress"]):
            analysis += f"- {indicator}\n"
        
        analysis += f"""
## Impact Assessment
- **Financial Impact:** ${loss:,.0f}
- **Affected Chains:** {', '.join(chains)}
- **Similar Historical Attacks:** {', '.join(pattern_info.get('real_examples', ['N/A']))}

## Recommended Actions
"""
        
        for i, action in enumerate(pattern_info.get("immediate_actions", ["Monitor situation"]), 1):
            analysis += f"{i}. {action}\n"
        
        analysis += f"""
## Confidence Level
Analysis confidence: **HIGH** (based on known attack pattern matching)
This analysis is generated using rule-based pattern matching. For enhanced analysis, configure an LLM API key.
"""
        
        return analysis
    
    def _get_local_summary(self, incident: Dict[str, Any]) -> str:
        """Generate local summary without API."""
        attack_type = incident.get("attack_type", "unknown")
        severity = incident.get("severity", "unknown")
        loss = incident.get("total_loss_usd", 0)
        
        pattern = ATTACK_PATTERNS.get(attack_type, {})
        
        if loss > 0:
            summary = f"Detected {pattern.get('name', attack_type)} with ${loss:,.0f} at risk. "
        else:
            summary = f"Detected {pattern.get('name', attack_type)} attempt (blocked or no loss). "
        
        if pattern.get("immediate_actions"):
            summary += f"Immediate action: {pattern['immediate_actions'][0]}"
        else:
            summary += "Monitor the situation and prepare incident response."
        
        return summary
    
    def _get_fallback_analysis(self) -> str:
        """Fallback analysis when API calls fail."""
        return """## Analysis Unavailable

Unable to generate AI analysis at this time. Please:
1. Check your API key configuration
2. Verify network connectivity
3. Review the incident manually using the raw data

For immediate response, follow standard incident response procedures:
1. Assess the scope and impact
2. Contain the threat if possible
3. Document all findings
4. Escalate to security team
"""


# Global analyzer instance
_analyzer: Optional[AIAnalyzer] = None


def get_analyzer() -> AIAnalyzer:
    """Get or create the global AI analyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = AIAnalyzer()
    return _analyzer


async def analyze_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to analyze an incident."""
    analyzer = get_analyzer()
    return await analyzer.analyze_incident(incident)

