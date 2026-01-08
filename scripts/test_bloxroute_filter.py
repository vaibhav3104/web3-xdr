#!/usr/bin/env python3
"""
bloXroute Filter Verification Test
==================================

Tests the bloXroute mempool source filter logic to ensure it:
1. Connects successfully
2. Subscribes with correct filter syntax
3. Receives transactions targeting monitored addresses
4. Filters out transactions not targeting monitored addresses

Usage:
    export BLOXROUTE_AUTH_HEADER="your_header_here"
    python scripts/test_bloxroute_filter.py
"""

import asyncio
import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import structlog

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.runtime.intent_sources.bloxroute_source import BloxrouteMempoolSource

logger = structlog.get_logger(__name__)

# Test configuration
TEST_CHAIN_ID = "ethereum"
TEST_MONITORED_ADDRESSES = [
    "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT (high traffic for testing)
    # Add your wallet address here for testing:
    # "0xYOUR_WALLET_ADDRESS",
]


async def test_bloxroute_filter():
    """Test bloXroute filter logic."""
    auth_header = os.getenv("BLOXROUTE_AUTH_HEADER")
    if not auth_header:
        print("❌ ERROR: BLOXROUTE_AUTH_HEADER environment variable not set")
        print("   Set it with: export BLOXROUTE_AUTH_HEADER='your_header_here'")
        sys.exit(1)
    
    print("=" * 70)
    print("bloXroute Filter Verification Test")
    print("=" * 70)
    print(f"Chain ID: {TEST_CHAIN_ID}")
    print(f"Monitored Addresses: {len(TEST_MONITORED_ADDRESSES)}")
    for addr in TEST_MONITORED_ADDRESSES:
        print(f"  - {addr}")
    print()
    
    # Create source
    source = BloxrouteMempoolSource(
        chain_id=TEST_CHAIN_ID,
        auth_header=auth_header,
        monitored_addresses=TEST_MONITORED_ADDRESSES
    )
    
    # Check filter string
    filter_str = source._build_filter_string()
    print(f"Filter String: {filter_str}")
    print()
    
    if not filter_str:
        print("❌ ERROR: Filter string is empty!")
        print("   Check that monitored_addresses list is not empty")
        sys.exit(1)
    
    # Validate filter syntax
    if not filter_str.startswith("{to} IN [") or not filter_str.endswith("]"):
        print("❌ ERROR: Filter string format is incorrect!")
        print(f"   Expected format: {{to}} IN ['0x...', '0x...']")
        print(f"   Got: {filter_str}")
        sys.exit(1)
    
    print("✅ Filter string format is correct")
    print()
    
    # Test connection
    print("Testing WebSocket connection...")
    try:
        await source.start()
        print("✅ Source started successfully")
        print()
        
        # Wait for connection and subscription
        print("Waiting for connection and subscription confirmation...")
        await asyncio.sleep(5)
        
        # Check if running
        if not source.is_running:
            print("❌ ERROR: Source is not running")
            await source.stop()
            sys.exit(1)
        
        print("✅ Source is running")
        print()
        
        # Try to get pending transactions (should be empty initially)
        print("Checking for pending transactions...")
        print("(Send a test transaction to one of the monitored addresses)")
        print()
        
        received_count = 0
        start_time = datetime.now(timezone.utc)
        timeout = timedelta(minutes=2)  # 2 minute timeout
        
        print("Listening for transactions (2 minute timeout)...")
        print("Press Ctrl+C to stop early")
        print()
        
        while datetime.now(timezone.utc) - start_time < timeout:
            try:
                pending_txs = await source.get_pending_txs(limit=10)
                
                if pending_txs:
                    received_count += len(pending_txs)
                    for tx in pending_txs:
                        print(f"✅ Transaction received:")
                        print(f"   Hash: {tx.tx_hash[:16]}...")
                        print(f"   To: {tx.to_address}")
                        print(f"   From: {tx.from_address[:16]}...")
                        print(f"   Value: {tx.value} wei")
                        print(f"   Selector: {tx.selector}")
                        print()
                
                await asyncio.sleep(1.0)
            
            except KeyboardInterrupt:
                print("\n⚠️  Test interrupted by user")
                break
        
        print()
        print("=" * 70)
        print("Test Results")
        print("=" * 70)
        print(f"Filter String: {filter_str}")
        print(f"Transactions Received: {received_count}")
        
        if received_count > 0:
            print("✅ SUCCESS: Filter is working! Transactions are being received.")
            print()
            print("Next Steps:")
            print("1. Remove test addresses from chains.yaml")
            print("2. Add your actual critical contracts")
            print("3. Deploy to production")
        else:
            print("⚠️  WARNING: No transactions received during test period")
            print()
            print("Possible reasons:")
            print("1. No transactions targeting monitored addresses in the last 2 minutes")
            print("2. Filter syntax might be incorrect (check bloXroute docs)")
            print("3. Connection issue (check logs above)")
            print()
            print("To verify filter works:")
            print("1. Send a test transaction to one of the monitored addresses")
            print("2. Or use a high-traffic contract like USDT (already in test list)")
        
        await source.stop()
        print()
        print("✅ Test completed")
    
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        await source.stop()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(test_bloxroute_filter())

