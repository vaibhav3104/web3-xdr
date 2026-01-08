#!/usr/bin/env python3
"""
Sentinel3 System Verification Script
===================================

Phase 6: Pre-flight checks before deployment.
Verifies connectivity, permissions, and configuration.
"""

import os
import sys
import asyncio
from pathlib import Path
from typing import List, Dict, Tuple
import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import structlog

logger = structlog.get_logger(__name__)

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


class SystemVerifier:
    """Verifies system configuration and connectivity."""
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.passed: List[str] = []
    
    def check(self, name: str, condition: bool, error_msg: str = "", warning_msg: str = ""):
        """Check a condition and record result."""
        if condition:
            self.passed.append(name)
            print(f"{GREEN}✓{RESET} {name}")
        else:
            if error_msg:
                self.errors.append(f"{name}: {error_msg}")
                print(f"{RED}✗{RESET} {name}: {error_msg}")
            else:
                self.warnings.append(f"{name}: {warning_msg}")
                print(f"{YELLOW}⚠{RESET} {name}: {warning_msg}")
    
    async def verify_redis(self) -> bool:
        """Verify Redis connectivity."""
        try:
            import redis
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            client = redis.from_url(redis_url, decode_responses=True)
            client.ping()
            
            # Test write
            test_key = "sentinel3_verify_test"
            client.set(test_key, "test", ex=10)
            value = client.get(test_key)
            client.delete(test_key)
            
            self.check("Redis Connectivity", value == "test")
            return True
        except ImportError:
            self.check("Redis Connectivity", False, "redis library not installed")
            return False
        except Exception as e:
            self.check("Redis Connectivity", False, str(e))
            return False
    
    async def verify_postgres(self) -> bool:
        """Verify PostgreSQL connectivity."""
        try:
            from sqlalchemy import create_engine, text
            
            database_url = os.getenv("DATABASE_URL")
            if not database_url:
                # Try individual env vars
                database_url = f"postgresql://{os.getenv('POSTGRES_USER', 'xdr')}:{os.getenv('POSTGRES_PASSWORD', 'xdr_password')}@{os.getenv('POSTGRES_HOST', 'localhost')}:{os.getenv('POSTGRES_PORT', '5432')}/{os.getenv('POSTGRES_DB', 'web3_xdr')}"
            
            engine = create_engine(database_url)
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                result.fetchone()
            
            # Test write
            with engine.connect() as conn:
                conn.execute(text("CREATE TABLE IF NOT EXISTS sentinel3_verify_test (id INT)"))
                conn.execute(text("INSERT INTO sentinel3_verify_test VALUES (1)"))
                conn.commit()
                conn.execute(text("DROP TABLE sentinel3_verify_test"))
                conn.commit()
            
            self.check("PostgreSQL Connectivity", True)
            return True
        except Exception as e:
            self.check("PostgreSQL Connectivity", False, str(e))
            return False
    
    async def verify_rpc_endpoints(self) -> bool:
        """Verify RPC endpoints from chains.yaml."""
        config_path = Path(__file__).resolve().parent.parent / "config" / "chains.yaml"
        
        if not config_path.exists():
            self.check("RPC Endpoints", False, f"chains.yaml not found at {config_path}")
            return False
        
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
            
            chains = config.get("chains", [])
            if not chains:
                self.check("RPC Endpoints", False, "No chains configured")
                return False
            
            import aiohttp
            
            all_ok = True
            for chain_config in chains:
                chain_id = chain_config.get("chain_id", "unknown")
                chain_type = chain_config.get("chain_type", "evm")
                
                # Get RPC URLs
                rpc_urls = chain_config.get("rpc_urls", [])
                if not rpc_urls and chain_config.get("rpc_url"):
                    rpc_urls = [chain_config["rpc_url"]]
                
                if not rpc_urls:
                    self.check(f"RPC [{chain_id}]", False, "No RPC URLs configured")
                    all_ok = False
                    continue
                
                # Test first RPC URL
                rpc_url = rpc_urls[0]
                try:
                    timeout = aiohttp.ClientTimeout(total=10.0)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        if chain_type == "evm":
                            # Test eth_blockNumber
                            payload = {
                                "jsonrpc": "2.0",
                                "method": "eth_blockNumber",
                                "params": [],
                                "id": 1
                            }
                            async with session.post(rpc_url, json=payload) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    if "result" in data:
                                        self.check(f"RPC [{chain_id}]", True)
                                    else:
                                        self.check(f"RPC [{chain_id}]", False, "Invalid response")
                                        all_ok = False
                                else:
                                    self.check(f"RPC [{chain_id}]", False, f"HTTP {resp.status}")
                                    all_ok = False
                        elif chain_type == "cosmos":
                            # Test Tendermint status
                            async with session.get(f"{rpc_url}/status") as resp:
                                if resp.status == 200:
                                    self.check(f"RPC [{chain_id}]", True)
                                else:
                                    self.check(f"RPC [{chain_id}]", False, f"HTTP {resp.status}")
                                    all_ok = False
                        elif chain_type == "aptos":
                            # Test Aptos REST API
                            async with session.get(f"{rpc_url}/") as resp:
                                if resp.status == 200:
                                    self.check(f"RPC [{chain_id}]", True)
                                else:
                                    self.check(f"RPC [{chain_id}]", False, f"HTTP {resp.status}")
                                    all_ok = False
                        else:
                            self.check(f"RPC [{chain_id}]", False, f"Unsupported chain type: {chain_type}")
                            all_ok = False
                except Exception as e:
                    self.check(f"RPC [{chain_id}]", False, str(e))
                    all_ok = False
            
            return all_ok
        except Exception as e:
            self.check("RPC Endpoints", False, str(e))
            return False
    
    def verify_env_vars(self):
        """Verify critical environment variables."""
        critical_vars = {
            "REDIS_URL": False,  # Optional but recommended
            "DATABASE_URL": False,  # Optional (can use individual vars)
            "POSTGRES_HOST": False,  # Optional if DATABASE_URL set
            "JWT_SECRET_KEY": True,  # Required
        }
        
        for var, required in critical_vars.items():
            value = os.getenv(var)
            if required:
                self.check(f"Env Var [{var}]", value is not None, f"Required but not set")
            else:
                if value:
                    self.check(f"Env Var [{var}]", True)
                else:
                    self.warnings.append(f"{var} not set (optional)")
                    print(f"{YELLOW}⚠{RESET} Env Var [{var}]: Not set (optional)")
    
    def verify_config_files(self):
        """Verify configuration files exist."""
        config_dir = Path(__file__).resolve().parent.parent / "config"
        
        chains_yaml = config_dir / "chains.yaml"
        self.check("Config [chains.yaml]", chains_yaml.exists(), f"Not found at {chains_yaml}")
        
        rules_dir = config_dir / "rules"
        if rules_dir.exists():
            rule_files = list(rules_dir.glob("*.yaml"))
            self.check(f"Config [rules/] ({len(rule_files)} files)", len(rule_files) > 0, "No rule files found")
        else:
            self.check("Config [rules/]", False, f"Directory not found at {rules_dir}")
    
    async def run_all_checks(self) -> Tuple[bool, bool]:
        """
        Run all verification checks.
        
        Returns:
            (all_passed, has_warnings)
        """
        print("\n" + "="*60)
        print("Sentinel3 System Verification")
        print("="*60 + "\n")
        
        print("Checking Configuration Files...")
        self.verify_config_files()
        
        print("\nChecking Environment Variables...")
        self.verify_env_vars()
        
        print("\nChecking Connectivity...")
        await self.verify_redis()
        await self.verify_postgres()
        await self.verify_rpc_endpoints()
        
        print("\n" + "="*60)
        print("Summary")
        print("="*60)
        print(f"{GREEN}Passed: {len(self.passed)}{RESET}")
        print(f"{YELLOW}Warnings: {len(self.warnings)}{RESET}")
        print(f"{RED}Errors: {len(self.errors)}{RESET}")
        
        if self.errors:
            print(f"\n{RED}✗ Verification FAILED{RESET}")
            return False, len(self.warnings) > 0
        elif self.warnings:
            print(f"\n{YELLOW}⚠ Verification PASSED with warnings{RESET}")
            return True, True
        else:
            print(f"\n{GREEN}✓ Verification PASSED{RESET}")
            return True, False


async def main():
    """Main entry point."""
    verifier = SystemVerifier()
    all_passed, has_warnings = await verifier.run_all_checks()
    
    if not all_passed:
        sys.exit(1)
    elif has_warnings:
        sys.exit(0)  # Warnings are OK
    else:
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())

