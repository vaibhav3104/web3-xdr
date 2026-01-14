#!/usr/bin/env python3
"""
RPC Connection Checker - Tests all EVM, non-EVM chains and Bloxroute
"""

import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Optional
import httpx
import structlog
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

logger = structlog.get_logger()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import yaml
except ImportError:
    print("❌ yaml not installed. Run: pip install pyyaml")
    sys.exit(1)

try:
    from web3 import AsyncWeb3
except ImportError:
    print("❌ web3 not installed. Run: pip install web3")
    sys.exit(1)


class RPCConnectionChecker:
    """Check RPC connections for all configured chains."""
    
    def __init__(self, config_path: str = "config/chains.yaml"):
        self.config_path = config_path
        self.results: Dict[str, Dict] = {}
        
    def load_config(self) -> dict:
        """Load chains configuration."""
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    async def check_evm_chain(self, chain_config: dict) -> Dict:
        """Test EVM chain RPC connection."""
        chain_id = chain_config.get("chain_id", "unknown")
        rpc_url = chain_config.get("rpc_url", "")
        
        if not rpc_url:
            return {
                "status": "error",
                "error": "No RPC URL configured"
            }
        
        try:
            provider = AsyncHTTPProvider(rpc_url, request_kwargs={'timeout': 10})
            w3 = AsyncWeb3(provider)
            
            # Test connection
            start_time = time.time()
            chain_id_result = await asyncio.wait_for(w3.eth.chain_id, timeout=10.0)
            block_number = await asyncio.wait_for(w3.eth.block_number, timeout=10.0)
            latency_ms = int((time.time() - start_time) * 1000)
            
            return {
                "status": "connected",
                "chain_id": chain_id_result,
                "block_number": block_number,
                "latency_ms": latency_ms,
                "rpc_url": rpc_url[:50] + "..." if len(rpc_url) > 50 else rpc_url
            }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "error": "Connection timeout (>10s)"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)[:100]
            }
    
    async def check_solana_chain(self, chain_config: dict) -> Dict:
        """Test Solana RPC connection."""
        chain_id = chain_config.get("chain_id", "unknown")
        rpc_url = chain_config.get("rpc_url", "")
        
        if not rpc_url:
            return {
                "status": "error",
                "error": "No RPC URL configured"
            }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Test getHealth
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getHealth"
                }
                start_time = time.time()
                response = await client.post(rpc_url, json=payload)
                latency_ms = int((time.time() - start_time) * 1000)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("result") == "ok":
                        # Get slot
                        slot_payload = {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "getSlot"
                        }
                        slot_response = await client.post(rpc_url, json=slot_payload)
                        slot_data = slot_response.json()
                        slot = slot_data.get("result", "unknown")
                        
                        return {
                            "status": "connected",
                            "health": "ok",
                            "slot": slot,
                            "latency_ms": latency_ms,
                            "rpc_url": rpc_url[:50] + "..." if len(rpc_url) > 50 else rpc_url
                        }
                    else:
                        return {
                            "status": "error",
                            "error": f"Health check failed: {data.get('result')}"
                        }
                else:
                    return {
                        "status": "error",
                        "error": f"HTTP {response.status_code}"
                    }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "error": "Connection timeout (>10s)"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)[:100]
            }
    
    async def check_cosmos_chain(self, chain_config: dict) -> Dict:
        """Test Cosmos chain RPC connection."""
        chain_id = chain_config.get("chain_id", "unknown")
        rpc_url = chain_config.get("rpc_url", "")
        
        if not rpc_url:
            return {
                "status": "error",
                "error": "No RPC URL configured"
            }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Test /status endpoint
                start_time = time.time()
                response = await client.get(f"{rpc_url}/status")
                latency_ms = int((time.time() - start_time) * 1000)
                
                if response.status_code == 200:
                    data = response.json()
                    result = data.get("result", {})
                    latest_block = result.get("sync_info", {}).get("latest_block_height", "unknown")
                    
                    return {
                        "status": "connected",
                        "block_height": latest_block,
                        "latency_ms": latency_ms,
                        "rpc_url": rpc_url[:50] + "..." if len(rpc_url) > 50 else rpc_url
                    }
                else:
                    return {
                        "status": "error",
                        "error": f"HTTP {response.status_code}"
                    }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "error": "Connection timeout (>10s)"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)[:100]
            }
    
    async def check_aptos_chain(self, chain_config: dict) -> Dict:
        """Test Aptos RPC connection."""
        chain_id = chain_config.get("chain_id", "unknown")
        rpc_url = chain_config.get("rpc_url", "")
        
        if not rpc_url:
            return {
                "status": "error",
                "error": "No RPC URL configured"
            }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Test proper endpoints for Aptos and Sui
                if chain_id == "sui":
                    # Sui uses JSON-RPC, test with proper endpoint
                    test_url = rpc_url.replace(":443", "").rstrip("/")
                    payload = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "sui_getChainIdentifier",
                        "params": []
                    }
                    start_time = time.time()
                    response = await client.post(test_url, json=payload)
                    latency_ms = int((time.time() - start_time) * 1000)
                else:
                    # Aptos REST API - test /v1 endpoint (returns ledger info)
                    test_url = f"{rpc_url.rstrip('/')}/v1"
                    start_time = time.time()
                    response = await client.get(test_url)
                    latency_ms = int((time.time() - start_time) * 1000)
                    
                    # Aptos returns JSON data - check content, not just status code
                    try:
                        data = response.json()
                        if "chain_id" in data or "ledger_version" in data or "block_height" in data:
                            # Valid Aptos response
                            return {
                                "status": "connected",
                                "chain_id": data.get("chain_id", "unknown"),
                                "block_height": data.get("block_height", "unknown"),
                                "latency_ms": latency_ms,
                                "rpc_url": rpc_url[:50] + "..." if len(rpc_url) > 50 else rpc_url
                            }
                    except:
                        pass
                    
                    # If JSON parsing failed, check status code
                    if response.status_code != 200:
                        return {
                            "status": "error",
                            "error": f"HTTP {response.status_code}"
                        }
                    else:
                        return {
                            "status": "connected",
                            "latency_ms": latency_ms,
                            "rpc_url": rpc_url[:50] + "..." if len(rpc_url) > 50 else rpc_url
                        }
                
                # Sui handling (already returned above)
                if chain_id == "sui":
                    if response.status_code == 200:
                        data = response.json()
                        chain_identifier = data.get("result", "unknown")
                        return {
                            "status": "connected",
                            "chain_identifier": chain_identifier,
                            "latency_ms": latency_ms,
                            "rpc_url": rpc_url[:50] + "..." if len(rpc_url) > 50 else rpc_url
                        }
                    else:
                        return {
                            "status": "error",
                            "error": f"HTTP {response.status_code}"
                        }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "error": "Connection timeout (>10s)"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)[:100]
            }
    
    async def check_near_chain(self, chain_config: dict) -> Dict:
        """Test Near RPC connection."""
        chain_id = chain_config.get("chain_id", "unknown")
        rpc_url = chain_config.get("rpc_url", "")
        
        if not rpc_url:
            return {
                "status": "error",
                "error": "No RPC URL configured"
            }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "status",
                    "params": []
                }
                start_time = time.time()
                response = await client.post(rpc_url, json=payload)
                latency_ms = int((time.time() - start_time) * 1000)
                
                if response.status_code == 200:
                    data = response.json()
                    result = data.get("result", {})
                    latest_block = result.get("sync_info", {}).get("latest_block_height", "unknown")
                    
                    return {
                        "status": "connected",
                        "block_height": latest_block,
                        "latency_ms": latency_ms,
                        "rpc_url": rpc_url[:50] + "..." if len(rpc_url) > 50 else rpc_url
                    }
                else:
                    return {
                        "status": "error",
                        "error": f"HTTP {response.status_code}"
                    }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "error": "Connection timeout (>10s)"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)[:100]
            }
    
    async def check_bloxroute(self) -> Dict:
        """Test Bloxroute WebSocket connection."""
        auth_header = os.getenv("BLOXROUTE_AUTH_HEADER", "")
        ws_url = "wss://api.blxrbdn.com/ws"
        
        if not auth_header:
            return {
                "status": "not_configured",
                "error": "BLOXROUTE_AUTH_HEADER not set"
            }
        
        try:
            import websockets
            
            headers = {"Authorization": auth_header}
            
            async with websockets.connect(
                ws_url,
                extra_headers=headers,
                ping_interval=30,
                ping_timeout=10
            ) as websocket:
                # Send test subscription
                test_sub = {
                    "method": "subscribe",
                    "feed": "newTxs",
                    "params": {
                        "include": ["tx_hash"],
                        "filters": "{to} IN ['0x0000000000000000000000000000000000000000']"
                    },
                    "id": 1
                }
                await websocket.send(json.dumps(test_sub))
                
                # Wait for response (with timeout)
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    data = json.loads(response)
                    
                    if data.get("id") == 1:
                        return {
                            "status": "connected",
                            "subscription": "confirmed",
                            "ws_url": ws_url
                        }
                    else:
                        return {
                            "status": "error",
                            "error": f"Unexpected response: {data}"
                        }
                except asyncio.TimeoutError:
                    return {
                        "status": "timeout",
                        "error": "No response from subscription"
                    }
        except ImportError:
            return {
                "status": "error",
                "error": "websockets library not installed"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)[:100]
            }
    
    async def check_all(self):
        """Check all chains and Bloxroute."""
        config = self.load_config()
        chains = config.get("chains", [])
        
        print("🔍 Checking RPC Connections...\n")
        
        # Check EVM chains (exclude non-EVM chains)
        non_evm_chain_ids = ["solana", "cosmos", "osmosis", "injective", "aptos", "sui", "near"]
        evm_chains = [c for c in chains if c.get("chain_id") not in non_evm_chain_ids]
        print(f"📊 EVM Chains ({len(evm_chains)}):")
        for chain in evm_chains:
            chain_id = chain.get("chain_id", "unknown")
            print(f"  ⏳ Testing {chain_id}...", end=" ", flush=True)
            result = await self.check_evm_chain(chain)
            self.results[f"evm_{chain_id}"] = result
            
            if result["status"] == "connected":
                print(f"✅ Connected (Chain ID: {result.get('chain_id')}, Block: {result.get('block_number')}, Latency: {result.get('latency_ms')}ms)")
            else:
                print(f"❌ {result.get('status', 'error')}: {result.get('error', 'Unknown error')}")
        
        # Check non-EVM chains
        # Determine chain type from chain_id if not explicitly set
        non_evm_chains = []
        for c in chains:
            chain_id = c.get("chain_id", "")
            chain_type = c.get("chain_type", "").lower()
            
            # If chain_type not set, infer from chain_id
            if not chain_type:
                if chain_id == "solana":
                    chain_type = "solana"
                elif chain_id in ["cosmos", "osmosis", "injective"]:
                    chain_type = "cosmos"
                elif chain_id == "aptos":
                    chain_type = "aptos"
                elif chain_id == "sui":
                    chain_type = "sui"
                elif chain_id == "near":
                    chain_type = "near"
            
            if chain_type in ["solana", "cosmos", "aptos", "sui", "near"]:
                non_evm_chains.append((c, chain_type))
        
        print(f"\n📊 Non-EVM Chains ({len(non_evm_chains)}):")
        for chain, chain_type in non_evm_chains:
            chain_id = chain.get("chain_id", "unknown")
            print(f"  ⏳ Testing {chain_id} ({chain_type})...", end=" ", flush=True)
            
            if chain_type == "solana":
                result = await self.check_solana_chain(chain)
            elif chain_type == "cosmos":
                result = await self.check_cosmos_chain(chain)
            elif chain_type == "aptos":
                result = await self.check_aptos_chain(chain)
            elif chain_type == "sui":
                result = await self.check_aptos_chain(chain)  # Sui uses similar REST API
            elif chain_type == "near":
                result = await self.check_near_chain(chain)
            else:
                result = {
                    "status": "not_supported",
                    "error": f"Chain type {chain_type} not supported in checker"
                }
            
            self.results[f"{chain_type}_{chain_id}"] = result
            
            if result["status"] == "connected":
                if "block_height" in result:
                    print(f"✅ Connected (Block: {result.get('block_height')}, Latency: {result.get('latency_ms')}ms)")
                elif "slot" in result:
                    print(f"✅ Connected (Slot: {result.get('slot')}, Latency: {result.get('latency_ms')}ms)")
                else:
                    print(f"✅ Connected (Latency: {result.get('latency_ms')}ms)")
            else:
                print(f"❌ {result.get('status', 'error')}: {result.get('error', 'Unknown error')}")
        
        # Check Bloxroute
        print(f"\n📊 Bloxroute:")
        print(f"  ⏳ Testing Bloxroute WebSocket...", end=" ", flush=True)
        bloxroute_result = await self.check_bloxroute()
        self.results["bloxroute"] = bloxroute_result
        
        if bloxroute_result["status"] == "connected":
            print(f"✅ Connected (Subscription: {bloxroute_result.get('subscription')})")
        elif bloxroute_result["status"] == "not_configured":
            print(f"⚠️  Not configured (BLOXROUTE_AUTH_HEADER not set)")
        else:
            print(f"❌ {bloxroute_result.get('status', 'error')}: {bloxroute_result.get('error', 'Unknown error')}")
        
        # Summary
        print("\n" + "="*60)
        print("📊 SUMMARY")
        print("="*60)
        
        connected = sum(1 for r in self.results.values() if r.get("status") == "connected")
        total = len(self.results)
        
        print(f"✅ Connected: {connected}/{total}")
        print(f"❌ Failed: {total - connected}/{total}")
        
        if connected < total:
            print("\n⚠️  Failed Connections:")
            for name, result in self.results.items():
                if result.get("status") != "connected":
                    print(f"  - {name}: {result.get('error', 'Unknown error')}")


async def main():
    """Main entry point."""
    checker = RPCConnectionChecker()
    await checker.check_all()


if __name__ == "__main__":
    asyncio.run(main())
