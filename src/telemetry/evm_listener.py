"""
EVM Chain Listener - For Ethereum, Polygon, Arbitrum, etc.
With contract deployment detection and ML-based threat analysis.

Features:
- Robust RPC failover with multiple endpoints
- Automatic health tracking and rotation
- Contract deployment detection with ML analysis
"""

from datetime import datetime
from decimal import Decimal
from typing import AsyncIterator, Dict, List, Optional, Tuple, Union
import asyncio
import json
import hashlib
import structlog

from web3 import AsyncWeb3, AsyncHTTPProvider
from web3.exceptions import BlockNotFound
from web3.middleware import ExtraDataToPOAMiddleware
from eth_abi import decode

from .base import ChainListener, ListenerConfig, BlockMetadata
from .robust_provider import RobustAsyncHTTPProvider, create_robust_provider
from .contract_alerts import (
    ContractThreatAlert, ContractAlertStore, 
    ThreatLevel, AlertStatus, contract_alert_store
)
from .event_signatures import get_event_info, identify_event_type, get_protocol_name, get_event_severity
from .price_feed import get_price_feed, PriceFeed
from ..models.events import SecurityEvent, EventType, Severity

# Try to import ML classifier (may not be available in all environments)
try:
    from ..ai.models.contract_classifier import ContractThreatClassifier, ThreatCategory
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    ContractThreatClassifier = None
    ThreatCategory = None

logger = structlog.get_logger()


# Standard ERC20 Transfer event signature
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Common bridge event signatures
BRIDGE_LOCK_TOPIC = "0x" + "TokensLocked(address,address,uint256,bytes32)".encode().hex()[:64]
BRIDGE_MINT_TOPIC = "0x" + "TokensMinted(address,address,uint256,bytes32)".encode().hex()[:64]

# Well-known event signatures for various bridges
EVENT_SIGNATURES = {
    # Wormhole
    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2": "LogMessagePublished",
    # Polygon Bridge
    "0x9adc2d0a9f8a8d75a7f3d5e8a0f7b5c9e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6": "TokenDeposited",
    "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "TokenWithdrawn",
    # Generic patterns
    "deposit": EventType.LOCK,
    "withdraw": EventType.UNLOCK,
    "mint": EventType.MINT,
    "burn": EventType.BURN,
}


class EVMListener(ChainListener):
    """
    Listener for EVM-compatible chains.
    
    Supports Ethereum, Polygon, Arbitrum, Optimism, BSC, etc.
    Includes:
    - Robust RPC failover with multiple endpoints
    - Contract deployment detection
    - ML-based threat analysis
    """
    
    def __init__(
        self,
        config: ListenerConfig,
        rpc_urls: Optional[List[str]] = None
    ):
        """
        Initialize EVM Listener.
        
        Args:
            config: Listener configuration
            rpc_urls: Optional list of RPC URLs for failover.
                     If not provided, uses config.rpc_url only.
        """
        super().__init__(config)
        self.w3: Optional[AsyncWeb3] = None
        self._subscription_id: Optional[str] = None
        
        # RPC URLs for failover (primary + fallbacks)
        self._rpc_urls: List[str] = []
        if rpc_urls:
            self._rpc_urls = rpc_urls
        elif hasattr(config, 'rpc_urls') and config.rpc_urls:
            self._rpc_urls = config.rpc_urls
        else:
            self._rpc_urls = [config.rpc_url]
        
        # Add fallback URLs if available in config
        if hasattr(config, 'fallback_rpcs') and config.fallback_rpcs:
            self._rpc_urls.extend(config.fallback_rpcs)
        
        # Remove duplicates while preserving order
        seen = set()
        self._rpc_urls = [x for x in self._rpc_urls if not (x in seen or seen.add(x))]
        
        # Provider reference for stats
        self._provider: Optional[RobustAsyncHTTPProvider] = None
        
        # Contract ABIs cache
        self._contract_abis: Dict[str, dict] = {}
        
        # Token decimals cache
        self._token_decimals: Dict[str, int] = {}
        
        # Price feed for USD conversion
        self._price_feed: PriceFeed = get_price_feed()
        
        # Contract deployment detection
        self.analyze_deployments = True  # Enable by default
        self._classifier: Optional[ContractThreatClassifier] = None
        self._analyzed_contracts: set = set()  # Track analyzed contracts
        
        # Initialize ML classifier if available
        if ML_AVAILABLE:
            try:
                self._classifier = ContractThreatClassifier()
                logger.info("ml_classifier_initialized", chain=self.chain_id)
            except Exception as e:
                logger.warning("ml_classifier_init_failed", chain=self.chain_id, error=str(e))
    
    async def connect(self) -> bool:
        """
        Connect to EVM node using robust provider with failover.
        
        Returns:
            True if connected successfully
        """
        try:
            # Create robust provider with all available URLs
            self._provider = RobustAsyncHTTPProvider(self._rpc_urls)
            self.w3 = AsyncWeb3(self._provider)
            
            # Inject POA middleware for chains like Polygon, BSC, Avalanche, etc.
            # This handles the extraData field that POA chains use
            # POA chains: polygon, bsc, avalanche, optimism, base, arbitrum
            poa_chains = ["polygon", "bsc", "avalanche", "optimism", "base", "arbitrum"]
            if self.chain_id.lower() in poa_chains:
                self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
                logger.info("poa_middleware_injected", chain=self.chain_id)
            
            # Test connection by getting chain ID (more reliable than is_connected())
            # is_connected() can return False even when RPC is responding
            try:
                chain_id = await self.w3.eth.chain_id
            except Exception as chain_err:
                raise ConnectionError(f"Failed to connect to any RPC endpoint: {chain_err}")
            
            # Get current block to confirm working
            current_block = await self.w3.eth.block_number
            
            logger.info(
                "evm_connected_robust",
                chain_id=self.chain_id,
                node_chain_id=chain_id,
                current_block=current_block,
                rpc_count=len(self._rpc_urls),
                primary_rpc=self._rpc_urls[0][:50] + "..." if self._rpc_urls else "none"
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "evm_connection_failed",
                chain_id=self.chain_id,
                error=str(e),
                rpc_urls=[url[:40] + "..." for url in self._rpc_urls]
            )
            # Clear w3 on connection failure so it's None
            self.w3 = None
            return False
    
    def get_provider_stats(self) -> Dict:
        """Get RPC provider health statistics."""
        if self._provider:
            return self._provider.get_stats()
        return {"error": "Provider not initialized"}
    
    async def disconnect(self):
        """Disconnect from EVM node."""
        self.w3 = None
    
    async def get_latest_block(self) -> int:
        """Get latest block number."""
        return await self.w3.eth.block_number
    
    async def process_block(self, block_number: int) -> BlockMetadata:
        """
        Process a single block and extract security events.
        Also detects and analyzes new contract deployments.
        """
        logger.debug("evm_listener_process_block_start", chain=self.chain_id, block_number=block_number)
        try:
            block = await self.w3.eth.get_block(block_number, full_transactions=True)
        except BlockNotFound:
            logger.warning("block_not_found", block_number=block_number)
            return BlockMetadata(
                chain_id=self.chain_id,
                block_number=block_number,
                block_hash="",
                timestamp=datetime.utcnow(),
                tx_count=0,
                events_extracted=0
            )
        
        block_timestamp = datetime.utcfromtimestamp(block.timestamp)
        events_count = 0
        
        # =====================================================
        # CONTRACT DEPLOYMENT DETECTION
        # =====================================================
        if self.analyze_deployments:
            contract_deploy_count = 0
            for tx in block.transactions:
                # Contract deployment = tx.to is None
                tx_to = tx.get('to') if isinstance(tx, dict) else getattr(tx, 'to', None)
                if tx_to is None:
                    contract_deploy_count += 1
                    await self._analyze_contract_deployment(tx, block_timestamp, block_number)
            
            if contract_deploy_count > 0:
                logger.info("evm_listener_block_contracts", chain=self.chain_id, block=block_number, tx_count=len(block.transactions), contract_deploys=contract_deploy_count)
        
        # =====================================================
        # LOG PROCESSING - Capture all important DeFi events
        # =====================================================
        # Import event signatures to filter for important events
        from .event_signatures import ALL_SIGNATURES
        
        # Get important event topics (all our monitored event signatures)
        important_topics = list(ALL_SIGNATURES.keys())
        
        # Limit to most critical events to avoid rate limits
        # Priority: Liquidations, Flash Loans, Large Swaps, Admin Changes, Bridge Events
        critical_topics = [
            # ERC20
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",  # Transfer
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",  # Approval
            # Aave V3
            "0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac",  # FlashLoan
            "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286",  # LiquidationCall
            # Compound
            "0x298637f684da70674f26509b10f07ec2fbc77a335ab1e7d6215a4b2484d8bb52",  # LiquidateBorrow
            # Uniswap V3
            "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67",  # Swap
            "0xbdbdb71d7860376ba52b25a5028beea23581364a40522f6bcfb86bb1f2dca633",  # Flash
            # Uniswap V2
            "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822",  # Swap
            # Balancer
            "0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19f3f93ce64d5e2b7c60e9e0e2b4a3f",  # FlashLoan
            # Curve
            "0x8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140",  # TokenExchange
            # Admin
            "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",  # OwnershipTransferred
            "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",  # Upgraded
            # Bridge
            "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2",  # LogMessagePublished (Wormhole)
            "0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3",  # SendToChain (LayerZero)
        ]
        
        monitored_contracts = (
            self.config.bridge_contracts + 
            self.config.token_contracts +
            self.config.governance_contracts
        )
        
        logs = []
        try:
            if monitored_contracts:
                # Filter logs for monitored contracts
                logs = await self.w3.eth.get_logs({
                    "fromBlock": block_number,
                    "toBlock": block_number,
                    "address": monitored_contracts
                })
            else:
                # Get logs for critical event topics (more efficient than all logs)
                # Split into batches to avoid RPC limits
                for i in range(0, len(critical_topics), 4):
                    batch_topics = critical_topics[i:i+4]
                    try:
                        batch_logs = await self.w3.eth.get_logs({
                            "fromBlock": block_number,
                            "toBlock": block_number,
                            "topics": [batch_topics]  # OR filter on topics
                        })
                        logs.extend(batch_logs)
                    except Exception as batch_err:
                        # If batch fails, try without topic filter
                        logger.debug("topic_batch_failed", chain=self.chain_id, error=str(batch_err)[:50])
                        break
        except Exception as log_err:
            logger.warning("get_logs_failed", chain=self.chain_id, block=block_number, error=str(log_err)[:100])
        
        for log in logs:
            events = await self._parse_log(log, block_timestamp)
            for event in events:
                await self.emit_event(event)
                events_count += 1
        
        return BlockMetadata(
            chain_id=self.chain_id,
            block_number=block_number,
            block_hash=block.hash.hex(),
            timestamp=block_timestamp,
            tx_count=len(block.transactions),
            events_extracted=events_count
        )
    
    async def _analyze_contract_deployment(
        self,
        tx: dict,
        block_timestamp: datetime,
        block_number: int
    ):
        """
        Analyze a newly deployed contract for potential threats.
        
        This is called for every transaction where tx.to is None (contract creation).
        """
        try:
            # Get transaction hash
            tx_hash = tx.get('hash') if isinstance(tx, dict) else getattr(tx, 'hash', None)
            if tx_hash is None:
                return
            
            tx_hash_hex = tx_hash.hex() if hasattr(tx_hash, 'hex') else str(tx_hash)
            
            # Skip if already analyzed
            if tx_hash_hex in self._analyzed_contracts:
                return
            self._analyzed_contracts.add(tx_hash_hex)
            
            # Get transaction receipt to find deployed contract address
            receipt = await self.w3.eth.get_transaction_receipt(tx_hash_hex)
            if not receipt or not receipt.get('contractAddress'):
                return
            
            contract_address = receipt['contractAddress']
            deployer = tx.get('from') if isinstance(tx, dict) else getattr(tx, 'from', '')
            deployer = deployer if isinstance(deployer, str) else deployer.hex() if hasattr(deployer, 'hex') else str(deployer)
            
            # Fetch bytecode
            bytecode = await self.w3.eth.get_code(contract_address)
            bytecode_hex = bytecode.hex() if hasattr(bytecode, 'hex') else str(bytecode)
            
            logger.info(
                "evm_listener_contract_deployed",
                chain=self.chain_id,
                address=contract_address[:20] + "...",
                bytecode_size=len(bytecode_hex) // 2,
                deployer=deployer[:20] + "...",
                source="evm_listener"
            )
            
            # Skip tiny bytecode (likely not a real contract)
            if len(bytecode_hex) <= 10:
                logger.debug("skipping_tiny_bytecode", contract=contract_address, size=len(bytecode_hex))
                return
            
            # Calculate bytecode hash
            bytecode_hash = hashlib.sha256(bytecode_hex.encode()).hexdigest()[:16]
            
            # Record that we analyzed this contract
            contract_alert_store.record_analysis(self.chain_id, False)
            
            # Log classifier availability
            logger.debug(
                "contract_analysis_starting",
                chain=self.chain_id,
                contract=contract_address[:20],
                ml_available=self._classifier is not None
            )
            
            # If ML classifier is available, analyze
            if self._classifier:
                result = self._classifier.classify(bytecode_hex, contract_address)
                
                # Map ThreatCategory to ThreatLevel
                threat_level = ThreatLevel.SAFE
                if result.threat_category.value != "safe":
                    if result.confidence > 0.8:
                        threat_level = ThreatLevel.CRITICAL
                    elif result.confidence > 0.6:
                        threat_level = ThreatLevel.HIGH
                    elif result.confidence > 0.4:
                        threat_level = ThreatLevel.MEDIUM
                    else:
                        threat_level = ThreatLevel.LOW
                
                # Only create alert if not safe
                if result.threat_category.value != "safe":
                    alert = ContractThreatAlert(
                        chain_id=self.chain_id,
                        contract_address=contract_address,
                        deployer_address=deployer,
                        tx_hash=tx_hash_hex,
                        block_number=block_number,
                        timestamp=block_timestamp,
                        threat_category=result.threat_category.value,
                        threat_level=threat_level,
                        confidence=result.confidence,
                        risk_score=result.risk_score,
                        risk_factors=result.risk_factors,
                        similar_exploits=result.similar_exploits,
                        recommendation=result.recommendation,
                        bytecode_size=len(bytecode_hex) // 2,
                        bytecode_hash=bytecode_hash,
                        status=AlertStatus.ACTIVE
                    )
                    
                    contract_alert_store.add_alert(alert)
                    
                    # Emit as SecurityEvent too
                    event = SecurityEvent(
                        chain_id=self.chain_id,
                        block_number=block_number,
                        block_timestamp=block_timestamp,
                        tx_hash=tx_hash_hex,
                        event_type=EventType.CONTRACT_DEPLOY,
                        severity=Severity.CRITICAL if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] else Severity.HIGH,
                        source_address=deployer,
                        contract_address=contract_address,
                        raw_event={
                            "type": "contract_deployment",
                            "threat_category": result.threat_category.value,
                            "confidence": result.confidence,
                            "risk_score": result.risk_score,
                            "alert_id": alert.alert_id
                        }
                    )
                    await self.emit_event(event)
                    
                    logger.warning(
                        "malicious_contract_detected",
                        chain=self.chain_id,
                        contract=contract_address,
                        threat=result.threat_category.value,
                        confidence=result.confidence,
                        alert_id=alert.alert_id
                    )
                else:
                    # Safe contract - still emit event for tracking/stats
                    event = SecurityEvent(
                        chain_id=self.chain_id,
                        block_number=block_number,
                        block_timestamp=block_timestamp,
                        tx_hash=tx_hash_hex,
                        event_type=EventType.CONTRACT_DEPLOY,
                        severity=Severity.INFO,  # Safe contracts get INFO severity
                        source_address=deployer,
                        contract_address=contract_address,
                        raw_event={
                            "type": "contract_deployment",
                            "threat_category": "safe",
                            "confidence": result.confidence,
                            "risk_score": result.risk_score,
                            "bytecode_size": len(bytecode_hex) // 2,
                            "bytecode_hash": bytecode_hash
                        }
                    )
                    await self.emit_event(event)
                    
                    logger.info(
                        "contract_analyzed_safe",
                        chain=self.chain_id,
                        contract=contract_address,
                        confidence=result.confidence
                    )
            else:
                # No ML classifier - just emit a contract deployment event
                event = SecurityEvent(
                    chain_id=self.chain_id,
                    block_number=block_number,
                    block_timestamp=block_timestamp,
                    tx_hash=tx_hash_hex,
                    event_type=EventType.CONTRACT_DEPLOY,
                    severity=Severity.MEDIUM,
                    source_address=deployer,
                    contract_address=contract_address,
                    raw_event={
                        "type": "contract_deployment",
                        "bytecode_size": len(bytecode_hex) // 2,
                        "bytecode_hash": bytecode_hash
                    }
                )
                await self.emit_event(event)
                
        except Exception as e:
            logger.error(
                "contract_deployment_analysis_error",
                chain=self.chain_id,
                error=str(e)
            )

    async def _parse_log(
        self,
        log: dict,
        block_timestamp: datetime
    ) -> List[SecurityEvent]:
        """
        Parse a raw EVM log into SecurityEvent(s).
        Uses comprehensive event signature lookup for classification.
        """
        events = []
        
        if not log.topics:
            return events
        
        topic0 = log.topics[0].hex() if hasattr(log.topics[0], 'hex') else log.topics[0]
        if not topic0.startswith("0x"):
            topic0 = "0x" + topic0
        
        contract_address = log.address.lower() if hasattr(log, 'address') else log.get('address', '').lower()
        
        # Get event info from our comprehensive signature database
        event_info = get_event_info(topic0)
        event_type = event_info.get("type", EventType.UNKNOWN)
        event_name = event_info.get("name", "Unknown")
        protocol = event_info.get("protocol", "unknown")
        event_severity = event_info.get("severity", "low")
        
        # Map severity string to Severity enum
        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL
        }
        severity = severity_map.get(event_severity, Severity.INFO)
        
        # Special handling for ERC20 Transfer (most common)
        if topic0.lower() == TRANSFER_TOPIC.lower():
            event = await self._parse_transfer(log, block_timestamp)
            if event:
                events.append(event)
            return events
        
        # Parse known event types
        if event_type != EventType.UNKNOWN:
            event = await self._parse_known_event(
                log, block_timestamp, event_type, event_name, protocol, severity
            )
            if event:
                events.append(event)
            return events
        
        # Check for bridge-specific events (fallback for unknown signatures)
        if contract_address in [c.lower() for c in self.config.bridge_contracts]:
            event = await self._parse_bridge_event(log, block_timestamp)
            if event:
                events.append(event)
            return events
        
        # For DeFi contracts, create a generic event with the contract info
        defi_contracts = getattr(self.config, 'defi_contracts', [])
        if contract_address in [c.lower() for c in defi_contracts]:
            event = await self._parse_defi_event(log, block_timestamp, event_name, protocol)
            if event:
                events.append(event)
        
        return events
    
    async def _parse_known_event(
        self,
        log: dict,
        block_timestamp: datetime,
        event_type: EventType,
        event_name: str,
        protocol: str,
        severity: Severity
    ) -> Optional[SecurityEvent]:
        """
        Parse a known event type using our signature database.
        """
        try:
            contract_address = log.address.lower() if hasattr(log.address, 'lower') else str(log.address).lower()
            tx_hash = log.transactionHash.hex() if hasattr(log.transactionHash, 'hex') else str(log.transactionHash)
            
            # Extract addresses from topics if available
            source_address = ""
            dest_address = ""
            
            if len(log.topics) >= 2:
                source_address = "0x" + log.topics[1].hex()[-40:] if hasattr(log.topics[1], 'hex') else ""
            if len(log.topics) >= 3:
                dest_address = "0x" + log.topics[2].hex()[-40:] if hasattr(log.topics[2], 'hex') else ""
            
            # Try to extract amount from data
            amount = Decimal("0")
            if log.data and len(log.data) >= 32:
                try:
                    data_hex = log.data.hex() if hasattr(log.data, 'hex') else str(log.data)
                    if data_hex.startswith("0x"):
                        data_hex = data_hex[2:]
                    if len(data_hex) >= 64:
                        amount = Decimal(int(data_hex[:64], 16)) / Decimal(10**18)
                except:
                    pass
            
            return SecurityEvent(
                chain_id=self.chain_id,
                block_number=log.blockNumber,
                block_timestamp=block_timestamp,
                tx_hash=tx_hash,
                log_index=log.logIndex if hasattr(log, 'logIndex') else 0,
                event_type=event_type,
                severity=severity,
                source_address=source_address,
                dest_address=dest_address,
                contract_address=contract_address,
                amount=amount,
                bridge_id=protocol if protocol != "unknown" else None,
                raw_event={
                    "event_name": event_name,
                    "protocol": protocol,
                    "topics": [t.hex() if hasattr(t, 'hex') else str(t) for t in log.topics],
                    "data": log.data.hex() if hasattr(log.data, 'hex') else str(log.data)
                }
            )
        except Exception as e:
            logger.warning("known_event_parse_error", error=str(e), event_name=event_name)
            return None
    
    async def _parse_defi_event(
        self,
        log: dict,
        block_timestamp: datetime,
        event_name: str,
        protocol: str
    ) -> Optional[SecurityEvent]:
        """
        Parse a DeFi protocol event.
        """
        try:
            contract_address = log.address.lower() if hasattr(log.address, 'lower') else str(log.address).lower()
            tx_hash = log.transactionHash.hex() if hasattr(log.transactionHash, 'hex') else str(log.transactionHash)
            
            return SecurityEvent(
                chain_id=self.chain_id,
                block_number=log.blockNumber,
                block_timestamp=block_timestamp,
                tx_hash=tx_hash,
                log_index=log.logIndex if hasattr(log, 'logIndex') else 0,
                event_type=EventType.UNKNOWN,
                severity=Severity.LOW,
                contract_address=contract_address,
                raw_event={
                    "event_name": event_name,
                    "protocol": protocol,
                    "type": "defi_event",
                    "topics": [t.hex() if hasattr(t, 'hex') else str(t) for t in log.topics]
                }
            )
        except Exception as e:
            logger.warning("defi_event_parse_error", error=str(e))
            return None
    
    async def _parse_transfer(
        self,
        log: dict,
        block_timestamp: datetime
    ) -> Optional[SecurityEvent]:
        """
        Parse an ERC20 Transfer event with USD conversion.
        """
        try:
            # Transfer(address indexed from, address indexed to, uint256 value)
            from_address = "0x" + log.topics[1].hex()[-40:]
            to_address = "0x" + log.topics[2].hex()[-40:]
            
            # Decode value from data
            value = int(log.data.hex(), 16) if log.data else 0
            
            # Get token decimals
            token_address = log.address.lower() if hasattr(log.address, 'lower') else log.address
            decimals = await self._get_token_decimals(token_address)
            
            amount = Decimal(value) / Decimal(10 ** decimals)
            
            # Get USD price and calculate USD value
            amount_usd = Decimal("0")
            try:
                price = await self._price_feed.get_price(self.chain_id, token_address)
                if price > 0:
                    amount_usd = self._price_feed.calculate_usd_value(amount, price)
            except Exception as price_err:
                logger.debug("price_fetch_error", token=token_address[:10], error=str(price_err))
            
            # Determine event type based on addresses
            event_type = self._classify_transfer(from_address, to_address)
            
            # Determine severity based on USD amount
            severity = self._calculate_severity(amount, token_address, amount_usd)
            
            # Get token symbol for metadata
            token_symbol = self._price_feed.get_token_symbol(self.chain_id, token_address) or "UNKNOWN"
            
            return SecurityEvent(
                chain_id=self.chain_id,
                block_number=log.blockNumber,
                block_timestamp=block_timestamp,
                tx_hash=log.transactionHash.hex() if hasattr(log.transactionHash, 'hex') else log.transactionHash,
                log_index=log.logIndex,
                event_type=event_type,
                severity=severity,
                source_address=from_address,
                dest_address=to_address,
                contract_address=token_address,
                asset_type=token_symbol,
                asset_address=token_address,
                amount=amount,
                amount_usd=amount_usd,
                bridge_id=self._get_bridge_id(from_address, to_address),
                raw_event={
                    **dict(log),
                    "token_symbol": token_symbol,
                    "amount_human": str(amount),
                    "amount_usd": str(amount_usd),
                    "token_price_usd": price if 'price' in dir() else 0,
                }
            )
            
        except Exception as e:
            logger.warning("transfer_parse_error", error=str(e), log=str(log)[:200])
            return None
    
    async def _parse_bridge_event(
        self,
        log: dict,
        block_timestamp: datetime
    ) -> Optional[SecurityEvent]:
        """
        Parse bridge-specific events.
        """
        try:
            topic0 = log.topics[0].hex() if hasattr(log.topics[0], 'hex') else log.topics[0]
            contract_address = log.address.lower() if hasattr(log.address, 'lower') else log.address
            
            # Determine event type based on event signature
            event_type = EventType.UNKNOWN
            
            # Check known signatures
            if "mint" in topic0.lower() or topic0 in [sig for sig in EVENT_SIGNATURES if "mint" in sig.lower()]:
                event_type = EventType.MINT
            elif "lock" in topic0.lower() or "deposit" in topic0.lower():
                event_type = EventType.LOCK
            elif "unlock" in topic0.lower() or "withdraw" in topic0.lower():
                event_type = EventType.UNLOCK
            elif "burn" in topic0.lower():
                event_type = EventType.BURN
            elif "message" in topic0.lower():
                event_type = EventType.MESSAGE_SENT
            
            # Try to decode the data
            amount = Decimal("0")
            source_address = ""
            dest_address = ""
            message_hash = None
            
            if len(log.topics) >= 2:
                source_address = "0x" + log.topics[1].hex()[-40:]
            if len(log.topics) >= 3:
                dest_address = "0x" + log.topics[2].hex()[-40:]
            if log.data and len(log.data) >= 32:
                amount = Decimal(int(log.data[:66].hex(), 16)) / Decimal(10**18)
            if len(log.topics) >= 4:
                message_hash = log.topics[3].hex()
            
            return SecurityEvent(
                chain_id=self.chain_id,
                block_number=log.blockNumber,
                block_timestamp=block_timestamp,
                tx_hash=log.transactionHash.hex() if hasattr(log.transactionHash, 'hex') else log.transactionHash,
                log_index=log.logIndex,
                event_type=event_type,
                severity=Severity.HIGH if event_type in [EventType.MINT, EventType.LOCK] else Severity.MEDIUM,
                source_address=source_address,
                dest_address=dest_address,
                contract_address=contract_address,
                amount=amount,
                bridge_id=self._get_bridge_id_from_contract(contract_address),
                message_hash=message_hash,
                raw_event=dict(log)
            )
            
        except Exception as e:
            logger.warning("bridge_event_parse_error", error=str(e))
            return None
    
    def _classify_transfer(self, from_address: str, to_address: str) -> EventType:
        """
        Classify a transfer based on addresses involved.
        """
        bridge_contracts = [c.lower() for c in self.config.bridge_contracts]
        
        # Zero address = mint or burn
        if from_address == "0x" + "0" * 40:
            return EventType.MINT
        if to_address == "0x" + "0" * 40:
            return EventType.BURN
        
        # Transfer to bridge = lock
        if to_address.lower() in bridge_contracts:
            return EventType.LOCK
        
        # Transfer from bridge = unlock
        if from_address.lower() in bridge_contracts:
            return EventType.UNLOCK
        
        return EventType.TRANSFER
    
    def _calculate_severity(self, amount: Decimal, token_address: str, amount_usd: Optional[Decimal] = None) -> Severity:
        """
        Calculate severity based on transfer amount in USD.
        
        Uses price feed for accurate USD conversion.
        """
        # Use USD value if available
        if amount_usd is not None and amount_usd > 0:
            usd_value = float(amount_usd)
            if usd_value >= 10_000_000:  # $10M+
                return Severity.CRITICAL
            elif usd_value >= 1_000_000:  # $1M+
                return Severity.HIGH
            elif usd_value >= 100_000:  # $100K+
                return Severity.MEDIUM
            elif usd_value >= 10_000:  # $10K+
                return Severity.LOW
            return Severity.INFO
        
        # Fallback to token amount thresholds (less accurate)
        if amount > 1000000:
            return Severity.CRITICAL
        elif amount > 100000:
            return Severity.HIGH
        elif amount > 10000:
            return Severity.MEDIUM
        elif amount > 1000:
            return Severity.LOW
        return Severity.INFO
    
    async def _get_token_decimals(self, token_address: str) -> int:
        """
        Get token decimals, caching results.
        """
        if token_address in self._token_decimals:
            return self._token_decimals[token_address]
        
        try:
            # ERC20 decimals() call
            decimals_data = await self.w3.eth.call({
                "to": token_address,
                "data": "0x313ce567"  # decimals()
            })
            decimals = int(decimals_data.hex(), 16)
            self._token_decimals[token_address] = decimals
            return decimals
        except Exception:
            return 18  # Default to 18
    
    def _get_bridge_id(self, from_address: str, to_address: str) -> Optional[str]:
        """
        Determine bridge ID from addresses.
        """
        bridge_contracts = {c.lower(): f"bridge_{i}" for i, c in enumerate(self.config.bridge_contracts)}
        
        if from_address.lower() in bridge_contracts:
            return bridge_contracts[from_address.lower()]
        if to_address.lower() in bridge_contracts:
            return bridge_contracts[to_address.lower()]
        
        return None
    
    def _get_bridge_id_from_contract(self, contract_address: str) -> Optional[str]:
        """
        Get bridge ID from contract address.
        """
        for i, bridge in enumerate(self.config.bridge_contracts):
            if bridge.lower() == contract_address.lower():
                return f"bridge_{i}"
        return None
    
    async def subscribe_to_events(self) -> AsyncIterator[SecurityEvent]:
        """
        Subscribe to real-time events via WebSocket.
        
        Note: This is a simplified implementation. Production would use
        proper WebSocket subscription with eth_subscribe.
        """
        # For now, fall back to polling
        # Real implementation would use WebSocket provider
        while self.is_running:
            latest = await self.get_latest_block()
            if latest > self.last_processed_block:
                metadata = await self.process_block(latest)
                self.last_processed_block = latest
            await asyncio.sleep(1)
            yield  # Required for async generator

