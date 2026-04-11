"""
Twitter/X Security Feed Monitor
================================

Monitors security-focused Twitter accounts for exploit alerts:
- @PeckShieldAlert
- @SlowMist_Team
- @BlockSecTeam
- @CertiKAlert
- @samczsun

Requires Twitter API credentials (Bearer Token).
"""

import asyncio
import aiohttp
import re
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)

# Twitter API Configuration
TWITTER_BEARER_TOKEN = os.getenv("TWITTER_BEARER_TOKEN", "")

# Security accounts to monitor
SECURITY_ACCOUNTS = [
    "PeckShieldAlert",
    "SlowMist_Team", 
    "BlockSecTeam",
    "CertiKAlert",
    "samczsun",
    "FortaNetwork",
    "BeosinAlert",
    "AnciliaInc"
]


@dataclass
class TwitterAlert:
    """Represents a security alert from Twitter"""
    tweet_id: str
    author: str
    text: str
    created_at: datetime
    contract_addresses: List[str]
    tx_hashes: List[str]
    mentioned_protocols: List[str]
    estimated_loss: float
    chain: str
    alert_type: str  # "exploit", "rug_pull", "phishing", "vulnerability"


class TwitterSecurityMonitor:
    """
    Monitors Twitter for security alerts from trusted accounts.
    """
    
    def __init__(self, bearer_token: str = TWITTER_BEARER_TOKEN):
        self.bearer_token = bearer_token
        self.session: Optional[aiohttp.ClientSession] = None
        self.alerts: List[TwitterAlert] = []
    
    async def __aenter__(self):
        headers = {}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers=headers
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    def _extract_addresses(self, text: str) -> List[str]:
        """Extract Ethereum addresses from text"""
        return re.findall(r'0x[a-fA-F0-9]{40}', text)
    
    def _extract_tx_hashes(self, text: str) -> List[str]:
        """Extract transaction hashes from text"""
        return re.findall(r'0x[a-fA-F0-9]{64}', text)
    
    def _extract_amount(self, text: str) -> float:
        """Extract estimated loss amount from text"""
        # Look for patterns like "$1.5M", "$500K", "$1,000,000"
        patterns = [
            r'\$(\d+(?:\.\d+)?)\s*[Mm]illion',
            r'\$(\d+(?:\.\d+)?)\s*[Mm]',
            r'\$(\d+(?:\.\d+)?)\s*[Bb]illion',
            r'\$(\d+(?:\.\d+)?)\s*[Bb]',
            r'\$(\d+(?:\.\d+)?)\s*[Kk]',
            r'\$([\d,]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    val = float(match.group(1).replace(',', ''))
                    if 'illion' in pattern.lower() or pattern.endswith('[Mm]'):
                        val *= 1_000_000
                    elif 'illion' in pattern.lower() or pattern.endswith('[Bb]'):
                        val *= 1_000_000_000
                    elif pattern.endswith('[Kk]'):
                        val *= 1_000
                    return val
                except:
                    pass
        return 0
    
    def _detect_chain(self, text: str) -> str:
        """Detect which chain is mentioned"""
        text_lower = text.lower()
        
        chains = {
            'ethereum': ['ethereum', 'eth', 'mainnet'],
            'bsc': ['bsc', 'binance', 'bnb chain'],
            'polygon': ['polygon', 'matic'],
            'arbitrum': ['arbitrum', 'arb'],
            'optimism': ['optimism', 'op'],
            'avalanche': ['avalanche', 'avax'],
            'base': ['base'],
            'solana': ['solana', 'sol'],
        }
        
        for chain, keywords in chains.items():
            for keyword in keywords:
                if keyword in text_lower:
                    return chain
        
        return 'unknown'
    
    def _detect_alert_type(self, text: str) -> str:
        """Detect the type of security alert"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['exploit', 'hacked', 'attack', 'drain']):
            return 'exploit'
        elif any(word in text_lower for word in ['rug', 'rugpull', 'exit scam']):
            return 'rug_pull'
        elif any(word in text_lower for word in ['phishing', 'scam', 'fake']):
            return 'phishing'
        elif any(word in text_lower for word in ['vulnerability', 'bug', 'flaw']):
            return 'vulnerability'
        else:
            return 'unknown'
    
    async def fetch_recent_tweets(self, username: str, max_results: int = 10) -> List[Dict]:
        """Fetch recent tweets from a user"""
        if not self.bearer_token:
            logger.warning("twitter_api_no_token", message="Twitter API token not configured")
            return []
        
        try:
            # First get user ID
            user_url = f"https://api.twitter.com/2/users/by/username/{username}"
            async with self.session.get(user_url) as resp:
                if resp.status != 200:
                    logger.debug("twitter_user_lookup_failed", username=username, status=resp.status)
                    return []
                data = await resp.json()
                user_id = data.get('data', {}).get('id')
            
            if not user_id:
                return []
            
            # Get recent tweets
            tweets_url = f"https://api.twitter.com/2/users/{user_id}/tweets"
            params = {
                "max_results": max_results,
                "tweet.fields": "created_at,text,public_metrics"
            }
            
            async with self.session.get(tweets_url, params=params) as resp:
                if resp.status != 200:
                    logger.debug("twitter_tweets_fetch_failed", username=username, status=resp.status)
                    return []
                
                data = await resp.json()
                tweets = data.get('data', [])
                
                logger.info("twitter_tweets_fetched", username=username, count=len(tweets))
                return tweets
        
        except Exception as e:
            logger.error("twitter_fetch_failed", username=username, error=str(e))
        
        return []
    
    async def fetch_all_security_tweets(self) -> List[TwitterAlert]:
        """Fetch recent tweets from all security accounts"""
        all_alerts = []
        
        for account in SECURITY_ACCOUNTS:
            tweets = await self.fetch_recent_tweets(account)
            
            for tweet in tweets:
                text = tweet.get('text', '')
                
                # Skip if doesn't look like a security alert
                if not any(word in text.lower() for word in ['exploit', 'hack', 'rug', 'scam', 'attack', 'drain', 'vulnerability']):
                    continue
                
                # Parse tweet
                try:
                    created_at = datetime.fromisoformat(tweet.get('created_at', '').replace('Z', '+00:00'))
                except:
                    created_at = datetime.now(timezone.utc)
                
                alert = TwitterAlert(
                    tweet_id=tweet.get('id', ''),
                    author=account,
                    text=text,
                    created_at=created_at,
                    contract_addresses=self._extract_addresses(text),
                    tx_hashes=self._extract_tx_hashes(text),
                    mentioned_protocols=[],  # Would need NLP
                    estimated_loss=self._extract_amount(text),
                    chain=self._detect_chain(text),
                    alert_type=self._detect_alert_type(text)
                )
                all_alerts.append(alert)
            
            # Rate limiting
            await asyncio.sleep(0.5)
        
        self.alerts = all_alerts
        return all_alerts
    
    def cross_reference_with_detections(self, our_incidents: List[Dict]) -> List[Dict]:
        """Cross-reference Twitter alerts with our detections"""
        matches = []
        
        # Build set of our contract addresses
        our_addresses = set()
        for incident in our_incidents:
            for addr in incident.get('affected_contracts', []):
                our_addresses.add(addr.lower())
        
        # Check each Twitter alert
        for alert in self.alerts:
            for addr in alert.contract_addresses:
                if addr.lower() in our_addresses:
                    # Find matching incident
                    for incident in our_incidents:
                        if addr.lower() in [a.lower() for a in incident.get('affected_contracts', [])]:
                            matches.append({
                                "our_incident_id": incident.get('id'),
                                "our_detection_time": incident.get('created_at'),
                                "our_attack_type": incident.get('attack_type'),
                                "twitter_alert": {
                                    "author": alert.author,
                                    "tweet_id": alert.tweet_id,
                                    "text": alert.text[:200],
                                    "created_at": alert.created_at.isoformat(),
                                    "estimated_loss": alert.estimated_loss
                                },
                                "contract_address": addr
                            })
        
        return matches


# Alternative: Use Nitter (Twitter frontend) for scraping without API
class NitterScraper:
    """
    Scrape security tweets from Nitter (Twitter frontend) without API.
    Note: Nitter instances may be rate-limited or unavailable.
    """
    
    NITTER_INSTANCES = [
        "https://nitter.net",
        "https://nitter.it",
        "https://nitter.cz",
    ]
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.working_instance: Optional[str] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "Mozilla/5.0 (compatible; Sentinel3/1.0)"}
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def find_working_instance(self) -> Optional[str]:
        """Find a working Nitter instance"""
        for instance in self.NITTER_INSTANCES:
            try:
                async with self.session.get(instance, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        self.working_instance = instance
                        return instance
            except:
                continue
        return None
    
    async def scrape_user_tweets(self, username: str) -> List[Dict]:
        """Scrape tweets from a user's Nitter page"""
        if not self.working_instance:
            await self.find_working_instance()
        
        if not self.working_instance:
            logger.warning("nitter_no_working_instance")
            return []
        
        try:
            url = f"{self.working_instance}/{username}"
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return []
                
                html = await resp.text()
                
                # Parse tweets from HTML
                tweets = []
                
                # Look for tweet content divs
                tweet_pattern = r'<div class="tweet-content[^"]*"[^>]*>([^<]+(?:<[^>]+>[^<]*)*)</div>'
                matches = re.findall(tweet_pattern, html, re.DOTALL)
                
                for content in matches[:10]:
                    # Clean HTML tags
                    text = re.sub(r'<[^>]+>', '', content).strip()
                    if text:
                        tweets.append({
                            "text": text,
                            "author": username
                        })
                
                return tweets
        
        except Exception as e:
            logger.error("nitter_scrape_failed", username=username, error=str(e))
        
        return []


async def main():
    """Test the Twitter monitor"""
    print("🐦 Twitter Security Monitor")
    print("=" * 50)
    
    # Check if we have API token
    if TWITTER_BEARER_TOKEN:
        print("✅ Twitter API token configured")
        async with TwitterSecurityMonitor() as monitor:
            alerts = await monitor.fetch_all_security_tweets()
            print(f"Found {len(alerts)} security alerts")
            for alert in alerts[:5]:
                print(f"\n@{alert.author}: {alert.text[:100]}...")
    else:
        print("⚠️ No Twitter API token - trying Nitter scraping")
        async with NitterScraper() as scraper:
            for account in SECURITY_ACCOUNTS[:3]:
                tweets = await scraper.scrape_user_tweets(account)
                print(f"\n@{account}: {len(tweets)} tweets")
                for tweet in tweets[:2]:
                    print(f"  - {tweet['text'][:80]}...")


if __name__ == "__main__":
    asyncio.run(main())
