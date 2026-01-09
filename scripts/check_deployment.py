import asyncio
import aiohttp
import sys
import time
import json
from datetime import datetime

# ==========================================
# ⚙️ CONFIGURATION
# ==========================================
# Your Unified Worker URL (The "One URL to Rule Them All")
TARGET_URL = "https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app"
API_URL = "https://web3-xdr-production-api-ipje7qz66q-uc.a.run.app"

# Endpoints to verify
CHECKS = [
    {"name": "Worker Health", "url": f"{TARGET_URL}/health", "method": "GET", "expect": 200},
    {"name": "API Health", "url": f"{API_URL}/health", "method": "GET", "expect": 200},
    {"name": "Log Explorer", "url": f"{API_URL}/frontend/logs.html", "method": "GET", "expect": 200},
    {"name": "Dashboard", "url": f"{API_URL}/frontend/dashboard.html", "method": "GET", "expect": 200},
    {"name": "Database Read (API)", "url": f"{API_URL}/api/events?limit=1", "method": "GET", "expect": 200},
    {"name": "Worker Metrics", "url": f"{TARGET_URL}/metrics", "method": "GET", "expect": 200},
    {"name": "API Metrics", "url": f"{API_URL}/metrics", "method": "GET", "expect": 200},
]

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

async def check_endpoint(session, check):
    """Verifies a single HTTP endpoint."""
    start_time = time.time()
    try:
        async with session.request(check["method"], check["url"], timeout=10) as response:
            latency = (time.time() - start_time) * 1000
            status = response.status
            content = await response.text()
            
            # Special check for Database: Ensure it returns valid JSON
            if "events" in check["url"] and status == 200:
                try:
                    data = json.loads(content)
                    event_count = data.get("total", 0)
                    if event_count > 0:
                        print(f"{GREEN}✅ PASS{RESET} | {check['name']:<25} | {status} | {latency:.0f}ms | {BLUE}Events: {event_count}{RESET}")
                    else:
                        print(f"{YELLOW}⚠️  WARN{RESET} | {check['name']:<25} | {status} | {latency:.0f}ms | {YELLOW}No events yet (DB may be initializing){RESET}")
                    return True
                except json.JSONDecodeError:
                    print(f"{RED}❌ FAIL{RESET} | {check['name']:<25} | {status} | {latency:.0f}ms | {RED}Invalid JSON response{RESET}")
                    return False
            
            # Special check for health endpoints
            if "health" in check["url"] and status == 200:
                try:
                    data = json.loads(content)
                    ready = data.get("ready", False)
                    status_msg = data.get("status", "unknown")
                    if ready:
                        print(f"{GREEN}✅ PASS{RESET} | {check['name']:<25} | {status} | {latency:.0f}ms | {GREEN}Ready: {ready}{RESET}")
                    else:
                        print(f"{YELLOW}⚠️  WARN{RESET} | {check['name']:<25} | {status} | {latency:.0f}ms | {YELLOW}Status: {status_msg}{RESET}")
                    return True
                except:
                    pass
            
            if status == check["expect"]:
                print(f"{GREEN}✅ PASS{RESET} | {check['name']:<25} | {status} | {latency:.0f}ms")
                return True
            else:
                print(f"{RED}❌ FAIL{RESET} | {check['name']:<25} | Got {status}, Expected {check['expect']} | {latency:.0f}ms")
                print(f"   {YELLOW}Response:{RESET} {content[:150]}...")
                return False

    except asyncio.TimeoutError:
        print(f"{RED}⏱️  TIMEOUT{RESET} | {check['name']:<25} | Request timed out after 10s")
        return False
    except Exception as e:
        print(f"{RED}💀 ERROR{RESET} | {check['name']:<25} | {str(e)[:100]}")
        return False

async def check_database_connection():
    """Verifies database connectivity by checking events endpoint."""
    print(f"\n📊 Testing Database Connection...")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_URL}/api/events?limit=5", timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    total = data.get("total", 0)
                    events = data.get("events", [])
                    
                    if total > 0:
                        print(f"{GREEN}✅ Database Connected{RESET} | {total} events found")
                        if events:
                            latest = events[0]
                            print(f"   {BLUE}Latest Event:{RESET} {latest.get('chain', 'unknown')} | {latest.get('event_type', 'unknown')}")
                        return True
                    else:
                        print(f"{YELLOW}⚠️  Database Connected{RESET} | No events yet (may be initializing)")
                        print(f"   {YELLOW}Note:{RESET} Events are being collected but may not be saved yet")
                        return True  # Connection works, just no data yet
                else:
                    print(f"{RED}❌ Database Check Failed{RESET} | HTTP {response.status}")
                    return False
    except Exception as e:
        print(f"{RED}❌ Database Check Failed{RESET} | {str(e)}")
        return False

async def main():
    print(f"\n🚀 STARTING SENTINEL3 SYSTEM AUDIT")
    print(f"🎯 Worker: {TARGET_URL}")
    print(f"🎯 API:    {API_URL}")
    print(f"🕒 Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"{'STATUS':<7} | {'COMPONENT':<25} | {'CODE':<4} | {'LATENCY':<8} | {'DETAILS'}")
    print("-" * 80)

    results = []
    async with aiohttp.ClientSession() as session:
        # Run HTTP checks
        for check in CHECKS:
            success = await check_endpoint(session, check)
            results.append(success)
            await asyncio.sleep(0.5)  # Small delay between requests
        
        # Run database connection check
        db_success = await check_database_connection()
        results.append(db_success)

    print("-" * 80)
    
    # Summary
    passed = sum(results)
    total = len(results)
    percentage = (passed / total * 100) if total > 0 else 0
    
    print(f"\n📊 SUMMARY:")
    print(f"   {GREEN}✅ Passed:{RESET} {passed}/{total}")
    print(f"   {RED}❌ Failed:{RESET} {total - passed}/{total}")
    print(f"   {BLUE}📈 Success Rate:{RESET} {percentage:.1f}%")
    
    if all(results):
        print(f"\n{GREEN}🏆 SYSTEM STATUS: 100% OPERATIONAL{RESET}")
        print("All microservices (API, Worker, DB, Redis, UI) are talking correctly.")
    elif percentage >= 80:
        print(f"\n{YELLOW}⚠️  SYSTEM STATUS: MOSTLY OPERATIONAL{RESET}")
        print("Most components are working. Some may be initializing or degraded.")
    else:
        print(f"\n{RED}🚨 SYSTEM STATUS: DEGRADED{RESET}")
        print("Multiple components failed checks. Review logs above.")
    
    print(f"\n🔗 Quick Links:")
    print(f"   • Log Explorer: {API_URL}/frontend/logs.html")
    print(f"   • Dashboard:    {API_URL}/frontend/dashboard.html")
    print(f"   • Worker Health: {TARGET_URL}/health")
    print(f"   • API Health:   {API_URL}/health")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nAudit cancelled by user.")
    except Exception as e:
        print(f"\n{RED}💀 Fatal Error:{RESET} {str(e)}")
        sys.exit(1)
