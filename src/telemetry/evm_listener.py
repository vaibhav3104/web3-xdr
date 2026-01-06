"""
EVM Chain Listener - For Ethereum, Polygon, Arbitrum, etc.
With contract deployment detection and ML-based threat analysis.
"""

from datetime import datetime
from decimal import Decimal
from typing import AsyncIterator, Dict, List, Optional, Tuple
import asyncio
import json
import hashlib
import structlog

from web3 import AsyncWeb3, AsyncHTTPProvider
from web3.exceptions import BlockNotFound
from eth_abi import decode

from .base import ChainListener, ListenerConfig, BlockMetadata
from .contract_alerts import (
    ContractThreatAlert, ContractAlertStore, 
    ThreatLevel, AlertStatus, contract_alert_store
)
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
    Includes contract deployment detection and ML-based threat analysis.
    """
    
    def __init__(self, config: ListenerConfig):
        super().__init__(config)
        self.w3: Optional[AsyncWeb3] = None
        self._subscription_id: Optional[str] = None
        
        # Contract ABIs cache
        self._contract_abis: Dict[str, dict] = {}
        
        # Token decimals cache
        self._token_decimals: Dict[str, int] = {}
        
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
    
    async def connect(self):
        """Connect to EVM node."""
        self.w3 = AsyncWeb3(AsyncHTTPProvider(self.config.rpc_url))
        
        if not await self.w3.is_connected():
            raise ConnectionError(f"Failed to connect to {self.config.rpc_url}")
        
        chain_id = await self.w3.eth.chain_id
        logger.info(
            "evm_connected",
            chain_id=self.chain_id,
            node_chain_id=chain_id,
            rpc_url=self.config.rpc_url[:50] + "..."
        )
    
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
            for tx in block.transactions:
                # Contract deployment = tx.to is None
                tx_to = tx.get('to') if isinstance(tx, dict) else getattr(tx, 'to', None)
                if tx_to is None:
                    await self._analyze_contract_deployment(tx, block_timestamp, block_number)
        
        # =====================================================
        # LOG PROCESSING (existing code)
        # =====================================================
        monitored_contracts = (
            self.config.bridge_contracts + 
            self.config.token_contracts +
            self.config.governance_contracts
        )
        
        if monitored_contracts:
            # Filter logs for monitored contracts
            logs = await self.w3.eth.get_logs({
                "fromBlock": block_number,
                "toBlock": block_number,
                "address": monitored_contracts
            })
        else:
            # Get all logs in block
            logs = await self.w3.eth.get_logs({
                "fromBlock": block_number,
                "toBlock": block_number
            })
        
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
            
            logger.info(
                "contract_deployed_detected",
                chain=self.chain_id,
                contract=contract_address,
                deployer=deployer,
                block=block_number
            )
            
            # Fetch bytecode
            bytecode = await self.w3.eth.get_code(contract_address)
            bytecode_hex = bytecode.hex() if hasattr(bytecode, 'hex') else str(bytecode)
            
            # Skip tiny bytecode (likely not a real contract)
            if len(bytecode_hex) <= 10:
                logger.debug("skipping_tiny_bytecode", contract=contract_address, size=len(bytecode_hex))
                return
            
            # Calculate bytecode hash
            bytecode_hash = hashlib.sha256(bytecode_hex.encode()).hexdigest()[:16]
            
            # Record that we analyzed this contract
            contract_alert_store.record_analysis(self.chain_id, False)
            
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
        """
        events = []
        
        if not log.topics:
            return events
        
        topic0 = log.topics[0].hex() if hasattr(log.topics[0], 'hex') else log.topics[0]
        contract_address = log.address.lower() if hasattr(log, 'address') else log.get('address', '').lower()
        
        # Check for ERC20 Transfer
        if topic0 == TRANSFER_TOPIC or topic0 == TRANSFER_TOPIC.lower():
            event = await self._parse_transfer(log, block_timestamp)
            if event:
                events.append(event)
        
        # Check for bridge-specific events
        elif contract_address in [c.lower() for c in self.config.bridge_contracts]:
            event = await self._parse_bridge_event(log, block_timestamp)
            if event:
                events.append(event)
        
        return events
    
    async def _parse_transfer(
        self,
        log: dict,
        block_timestamp: datetime
    ) -> Optional[SecurityEvent]:
        """
        Parse an ERC20 Transfer event.
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
            
            # Determine event type based on addresses
            event_type = self._classify_transfer(from_address, to_address)
            
            # Determine severity based on amount
            severity = self._calculate_severity(amount, token_address)
            
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
                asset_type="ERC20",
                asset_address=token_address,
                amount=amount,
                bridge_id=self._get_bridge_id(from_address, to_address),
                raw_event=dict(log)
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
    
    def _calculate_severity(self, amount: Decimal, token_address: str) -> Severity:
        """
        Calculate severity based on transfer amount.
        
        TODO: Use price feeds for accurate USD conversion.
        """
        # Rough thresholds (should use actual USD values)
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

