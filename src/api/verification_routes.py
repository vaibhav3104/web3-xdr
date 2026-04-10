"""
API Routes for Detection Verification
=====================================

Endpoints for verifying detections against known exploits
and managing the daily monitoring job.
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException
from typing import Dict, List, Optional
import asyncio
from datetime import datetime, timezone

router = APIRouter(prefix="/api/verification", tags=["verification"])

# Global state for background verification
_verification_state = {
    "last_run": None,
    "running": False,
    "results": None,
    "watch_list": [],
    "stats": {}
}


@router.get("/status")
async def get_verification_status() -> Dict:
    """Get current verification status"""
    return {
        "last_run": _verification_state["last_run"],
        "running": _verification_state["running"],
        "watch_list_count": len(_verification_state["watch_list"]),
        "stats": _verification_state["stats"]
    }


@router.post("/run")
async def run_verification(background_tasks: BackgroundTasks) -> Dict:
    """Trigger verification run"""
    if _verification_state["running"]:
        return {"status": "already_running", "message": "Verification is already in progress"}
    
    background_tasks.add_task(_run_verification_task)
    
    return {
        "status": "started",
        "message": "Verification started in background"
    }


@router.get("/report")
async def get_verification_report() -> Dict:
    """Get the latest verification report"""
    if not _verification_state["results"]:
        return {
            "status": "no_data",
            "message": "No verification has been run yet. POST to /api/verification/run first."
        }
    
    results = _verification_state["results"]
    
    # Generate summary
    verified = [r for r in results if r.get("verified")]
    unverified = [r for r in results if not r.get("verified")]
    high_conf = [r for r in unverified if (r.get("our_confidence") or 0) >= 0.7]
    
    return {
        "generated_at": _verification_state["last_run"],
        "summary": {
            "total_incidents": len(results),
            "verified_against_known_exploits": len(verified),
            "pending_verification": len(unverified),
            "high_confidence_watch_list": len(high_conf)
        },
        "verified_matches": verified[:20],  # Top 20
        "watch_list": high_conf[:20],
        "stats": _verification_state["stats"]
    }


@router.get("/watch-list")
async def get_watch_list() -> List[Dict]:
    """Get high-confidence unverified detections"""
    return _verification_state["watch_list"]


@router.get("/twitter-content")
async def get_twitter_content() -> Dict:
    """Generate Twitter-ready content"""
    if not _verification_state["results"]:
        return {
            "status": "no_data",
            "message": "Run verification first"
        }
    
    results = _verification_state["results"]
    verified = [r for r in results if r.get("verified")]
    high_conf = [r for r in results if (r.get("our_confidence") or 0) >= 0.7]
    
    # Count by type
    from collections import Counter
    types = Counter(r.get("our_attack_type") for r in results)
    
    tweets = []
    
    # Tweet 1: Summary
    tweets.append({
        "tweet_number": 1,
        "content": f"""🧵 THREAD: Sentinel3 Threat Detection Report

Our ML analyzed new contracts across 7 chains.

Detected:
🔴 {types.get('Reentrancy Attack', 0)} Reentrancy patterns
🎣 {types.get('Rug Pull', 0)} Rug pull signatures
⚠️ {types.get('Malicious Contract (unknown_threat)', 0)} Unknown threats
📋 {types.get('RULE_TRIGGERED', 0)} YAML rule triggers

Total: {len(results)} incidents flagged

1/5 🧵""",
        "char_count": 0
    })
    tweets[0]["char_count"] = len(tweets[0]["content"])
    
    # Tweet 2: Verified
    if verified:
        total_amount = sum(
            (r.get("matched_exploit") or {}).get("amount_usd", 0) 
            for r in verified
        )
        tweets.append({
            "tweet_number": 2,
            "content": f"""✅ VERIFIED DETECTIONS

{len(verified)} of our flagged contracts match known exploits.

Combined funds at risk: ${total_amount:,.0f}

We cross-referenced against:
• DeFiLlama (449+ hacks)
• SlowMist database
• Rekt News leaderboard

2/5 🧵""",
            "char_count": 0
        })
    else:
        tweets.append({
            "tweet_number": 2,
            "content": f"""⏳ WATCH LIST

{len(high_conf)} high-confidence detections pending verification.

No matches with known exploits yet - could mean:
1. We're catching NEW threats before exploitation
2. Sophisticated attacks not yet documented
3. Additional investigation needed

2/5 🧵""",
            "char_count": 0
        })
    tweets[1]["char_count"] = len(tweets[1]["content"])
    
    # Tweet 3: Example
    if high_conf:
        example = high_conf[0]
        tweets.append({
            "tweet_number": 3,
            "content": f"""🔍 EXAMPLE: High Confidence Detection

Contract: {example.get('contract_address', '')[:20]}...
Chain: {example.get('chain', '').upper()}
Type: {example.get('our_attack_type', '')}
Confidence: {(example.get('our_confidence') or 0) * 100:.0f}%
Etherscan: {'✅' if example.get('etherscan_verified') else '🔴 UNVERIFIED'}

Our Transformer model flagged suspicious bytecode patterns.

3/5 🧵""",
            "char_count": 0
        })
        tweets[2]["char_count"] = len(tweets[2]["content"])
    
    # Tweet 4: How it works
    tweets.append({
        "tweet_number": 4,
        "content": """🤖 HOW SENTINEL3 WORKS

1️⃣ Monitor new contract deployments (7 chains)
2️⃣ Extract bytecode features
3️⃣ Transformer + XGBoost ML analysis
4️⃣ Cross-reference 145 YAML detection rules
5️⃣ Verify against known exploit databases
6️⃣ Real-time alerts in <1 second

4/5 🧵""",
        "char_count": 0
    })
    tweets[-1]["char_count"] = len(tweets[-1]["content"])
    
    # Tweet 5: CTA
    tweets.append({
        "tweet_number": 5,
        "content": """🛡️ PROTECT YOUR PROTOCOL

Sentinel3 catches threats before the first victim transaction.

✅ Real-time ML detection
✅ Multi-chain monitoring  
✅ Emergency pause integration
✅ Exploit database cross-reference

DM for early access.

5/5 🧵

#Web3Security #DeFi #Blockchain""",
        "char_count": 0
    })
    tweets[-1]["char_count"] = len(tweets[-1]["content"])
    
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tweets": tweets,
        "total_tweets": len(tweets)
    }


async def _run_verification_task():
    """Background task to run verification"""
    global _verification_state
    
    _verification_state["running"] = True
    
    try:
        from src.verification.exploit_tracker import ExploitTracker
        
        tracker = ExploitTracker()
        async with tracker:
            await tracker.verify_all()
            
            # Convert results to dicts
            results = []
            for r in tracker.verification_results:
                result_dict = {
                    "incident_id": r.incident_id,
                    "contract_address": r.contract_address,
                    "chain": r.chain,
                    "our_detection_time": r.our_detection_time.isoformat() if r.our_detection_time else None,
                    "our_attack_type": r.our_attack_type,
                    "our_confidence": r.our_confidence,
                    "verified": r.verified,
                    "verification_source": r.verification_source,
                    "lead_time_hours": r.lead_time_hours,
                    "etherscan_verified": r.etherscan_verified,
                    "etherscan_labels": r.etherscan_labels
                }
                
                if r.matched_exploit:
                    result_dict["matched_exploit"] = {
                        "name": r.matched_exploit.name,
                        "amount_usd": r.matched_exploit.amount_usd,
                        "chain": r.matched_exploit.chain,
                        "source": r.matched_exploit.source
                    }
                
                results.append(result_dict)
            
            # Update state
            _verification_state["results"] = results
            _verification_state["watch_list"] = tracker.get_watch_list()
            
            # Calculate stats
            verified = [r for r in results if r.get("verified")]
            _verification_state["stats"] = {
                "total_incidents": len(results),
                "verified_count": len(verified),
                "defillama_hacks": len(tracker.defillama_hacks),
                "slowmist_hacks": len(tracker.slowmist_hacks),
                "rekt_exploits": len(tracker.rekt_hacks)
            }
            
            _verification_state["last_run"] = datetime.now(timezone.utc).isoformat()
    
    except Exception as e:
        _verification_state["stats"]["error"] = str(e)
    
    finally:
        _verification_state["running"] = False


# Scheduled daily job
async def daily_verification_job():
    """Run daily verification check"""
    while True:
        try:
            await _run_verification_task()
        except Exception as e:
            print(f"Daily verification failed: {e}")
        
        # Wait 24 hours
        await asyncio.sleep(24 * 60 * 60)
