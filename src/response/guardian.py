"""
Guardian System - Automated Contract Pause and Emergency Response
=================================================================

This module provides automated response capabilities:
1. Pause vulnerable contracts when critical threats detected
2. Execute emergency actions via multisig
3. Notify on-call responders
4. Track response actions for audit

IMPORTANT: This requires the protocol to:
- Have a pause() function in their contract
- Grant our guardian address the PAUSER_ROLE
- Or use a timelock/multisig we can trigger
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class ResponseAction(Enum):
    """Types of automated response actions."""
    PAUSE_CONTRACT = "pause_contract"
    UNPAUSE_CONTRACT = "unpause_contract"
    REVOKE_APPROVAL = "revoke_approval"
    EMERGENCY_WITHDRAW = "emergency_withdraw"
    BLACKLIST_ADDRESS = "blacklist_address"
    ALERT_ONLY = "alert_only"
    NOTIFY_MULTISIG = "notify_multisig"


class ResponseStatus(Enum):
    """Status of a response action."""
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    REQUIRES_APPROVAL = "requires_approval"
    TIMEOUT = "timeout"


@dataclass
class ProtocolConfig:
    """Configuration for a protected protocol."""
    protocol_name: str
    chain_id: str
    
    # Contract addresses
    main_contract: str
    pause_contract: Optional[str] = None  # If different from main
    
    # Pause function details
    pause_function: str = "pause()"
    unpause_function: str = "unpause()"
    
    # Access control
    guardian_address: Optional[str] = None  # Our guardian wallet
    guardian_private_key: Optional[str] = None  # For signing (NEVER commit!)
    multisig_address: Optional[str] = None  # If using multisig
    
    # Thresholds
    auto_pause_on_critical: bool = True
    auto_pause_on_high: bool = False
    require_approval_threshold_usd: float = 1_000_000  # Above this, require human approval
    
    # Contact info
    emergency_contacts: List[str] = field(default_factory=list)  # Telegram usernames
    
    # Custom ABI (if non-standard)
    custom_abi: Optional[str] = None


@dataclass
class ResponseRecord:
    """Record of a response action."""
    id: str
    incident_id: str
    action: ResponseAction
    status: ResponseStatus
    protocol: str
    chain_id: str
    contract_address: str
    initiated_at: datetime
    completed_at: Optional[datetime] = None
    tx_hash: Optional[str] = None
    error: Optional[str] = None
    initiated_by: str = "guardian_system"
    approved_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class GuardianSystem:
    """
    Automated response system for pausing contracts during attacks.
    
    Features:
    - Auto-pause on critical threats
    - Multi-protocol support
    - Audit logging
    - Human approval for large amounts
    - Multisig integration
    """
    
    def __init__(self):
        self.protocols: Dict[str, ProtocolConfig] = {}
        self.response_history: List[ResponseRecord] = []
        self.pending_approvals: Dict[str, ResponseRecord] = {}
        self._web3_connections: Dict[str, Any] = {}
        self._is_initialized = False
        
        # Callbacks
        self._on_response_complete: Optional[Callable] = None
        self._on_approval_required: Optional[Callable] = None
    
    async def initialize(self):
        """Initialize Web3 connections for all registered protocols."""
        from web3 import Web3
        
        for protocol_id, config in self.protocols.items():
            try:
                # Get RPC URL for chain (you'd fetch this from config)
                rpc_url = self._get_rpc_url(config.chain_id)
                if rpc_url:
                    w3 = Web3(Web3.HTTPProvider(rpc_url))
                    if w3.is_connected():
                        self._web3_connections[config.chain_id] = w3
                        logger.info(
                            "guardian_web3_connected",
                            protocol=protocol_id,
                            chain=config.chain_id
                        )
            except Exception as e:
                logger.error(
                    "guardian_web3_connection_failed",
                    protocol=protocol_id,
                    error=str(e)
                )
        
        self._is_initialized = True
        logger.info("guardian_system_initialized", protocols=len(self.protocols))
    
    def register_protocol(self, protocol_id: str, config: ProtocolConfig):
        """Register a protocol for guardian protection."""
        self.protocols[protocol_id] = config
        logger.info(
            "protocol_registered",
            protocol_id=protocol_id,
            contract=config.main_contract,
            auto_pause=config.auto_pause_on_critical
        )
    
    async def handle_incident(
        self,
        incident_id: str,
        severity: str,
        attack_type: str,
        affected_protocol: str,
        estimated_loss_usd: float,
        affected_chain: str,
        contract_address: str
    ) -> Optional[ResponseRecord]:
        """
        Handle an incident and determine response action.
        
        Returns the response record if action was taken.
        """
        # Find protocol config
        config = self._find_protocol_config(affected_protocol, contract_address)
        
        if not config:
            logger.info(
                "no_guardian_config",
                protocol=affected_protocol,
                contract=contract_address
            )
            return None
        
        # Determine action based on severity and config
        action = self._determine_action(
            severity=severity,
            config=config,
            estimated_loss_usd=estimated_loss_usd
        )
        
        if action == ResponseAction.ALERT_ONLY:
            logger.info("guardian_alert_only", incident_id=incident_id)
            return None
        
        # Create response record
        record = ResponseRecord(
            id=f"resp-{incident_id[:8]}-{datetime.now(timezone.utc).strftime('%H%M%S')}",
            incident_id=incident_id,
            action=action,
            status=ResponseStatus.PENDING,
            protocol=affected_protocol,
            chain_id=affected_chain,
            contract_address=contract_address,
            initiated_at=datetime.now(timezone.utc),
            metadata={
                "severity": severity,
                "attack_type": attack_type,
                "estimated_loss_usd": estimated_loss_usd
            }
        )
        
        # Check if approval required
        if estimated_loss_usd < config.require_approval_threshold_usd:
            # Auto-execute
            record = await self._execute_response(record, config)
        else:
            # Require human approval
            record.status = ResponseStatus.REQUIRES_APPROVAL
            self.pending_approvals[record.id] = record
            
            logger.warning(
                "guardian_approval_required",
                record_id=record.id,
                estimated_loss=estimated_loss_usd,
                threshold=config.require_approval_threshold_usd
            )
            
            if self._on_approval_required:
                await self._on_approval_required(record)
        
        self.response_history.append(record)
        return record
    
    async def approve_response(
        self,
        response_id: str,
        approved_by: str
    ) -> Optional[ResponseRecord]:
        """Approve a pending response action."""
        record = self.pending_approvals.get(response_id)
        
        if not record:
            logger.error("response_not_found", response_id=response_id)
            return None
        
        config = self._find_protocol_config(record.protocol, record.contract_address)
        if not config:
            return None
        
        record.approved_by = approved_by
        record = await self._execute_response(record, config)
        
        del self.pending_approvals[response_id]
        return record
    
    async def reject_response(
        self,
        response_id: str,
        rejected_by: str,
        reason: str
    ) -> bool:
        """Reject a pending response action."""
        record = self.pending_approvals.get(response_id)
        
        if not record:
            return False
        
        record.status = ResponseStatus.FAILED
        record.error = f"Rejected by {rejected_by}: {reason}"
        record.completed_at = datetime.now(timezone.utc)
        
        del self.pending_approvals[response_id]
        
        logger.info(
            "response_rejected",
            response_id=response_id,
            rejected_by=rejected_by,
            reason=reason
        )
        
        return True
    
    async def _execute_response(
        self,
        record: ResponseRecord,
        config: ProtocolConfig
    ) -> ResponseRecord:
        """Execute the response action."""
        record.status = ResponseStatus.EXECUTING
        
        try:
            if record.action == ResponseAction.PAUSE_CONTRACT:
                tx_hash = await self._pause_contract(config)
                record.tx_hash = tx_hash
                record.status = ResponseStatus.SUCCESS
                
            elif record.action == ResponseAction.NOTIFY_MULTISIG:
                await self._notify_multisig(config, record)
                record.status = ResponseStatus.SUCCESS
                
            elif record.action == ResponseAction.BLACKLIST_ADDRESS:
                # Would implement blacklist logic
                record.status = ResponseStatus.SUCCESS
                
            else:
                record.error = f"Unsupported action: {record.action}"
                record.status = ResponseStatus.FAILED
                
        except Exception as e:
            record.status = ResponseStatus.FAILED
            record.error = str(e)
            logger.error(
                "response_execution_failed",
                record_id=record.id,
                error=str(e)
            )
        
        record.completed_at = datetime.now(timezone.utc)
        
        if self._on_response_complete:
            await self._on_response_complete(record)
        
        return record
    
    async def _pause_contract(self, config: ProtocolConfig) -> Optional[str]:
        """
        Execute pause() on the target contract.

        Uses the signer abstraction (KMS in production, local in dev).
        Falls back to raw private key if no signer is configured.

        Returns transaction hash if successful.
        """
        from web3 import Web3

        w3 = self._web3_connections.get(config.chain_id)
        if not w3:
            raise Exception(f"No Web3 connection for chain {config.chain_id}")

        contract_addr = config.pause_contract or config.main_contract

        # Standard pausable ABI
        pause_abi = [
            {
                "inputs": [],
                "name": "pause",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "unpause",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]

        if config.custom_abi:
            pause_abi = json.loads(config.custom_abi)

        try:
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(contract_addr),
                abi=pause_abi
            )

            # Try signer abstraction first (KMS or local)
            signer = self._get_signer(config, contract_addr)

            if signer:
                guardian_address = signer.get_address()
                tx = contract.functions.pause().build_transaction({
                    'from': guardian_address,
                    'nonce': w3.eth.get_transaction_count(guardian_address),
                    'gas': 100000,
                    'gasPrice': w3.eth.gas_price
                })
                signed = signer.sign_transaction(tx, contract_addr)
                raw_tx = bytes.fromhex(signed["rawTransaction"].replace("0x", ""))
                tx_hash = w3.eth.send_raw_transaction(raw_tx)
            elif config.guardian_private_key:
                # Legacy fallback: raw private key
                logger.warning("using_raw_private_key", contract=contract_addr)
                guardian_account = w3.eth.account.from_key(config.guardian_private_key)
                tx = contract.functions.pause().build_transaction({
                    'from': guardian_account.address,
                    'nonce': w3.eth.get_transaction_count(guardian_account.address),
                    'gas': 100000,
                    'gasPrice': w3.eth.gas_price
                })
                signed_tx = w3.eth.account.sign_transaction(tx, config.guardian_private_key)
                tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            else:
                raise Exception("No signer or private key configured for guardian")

            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if receipt['status'] == 1:
                logger.info(
                    "contract_paused",
                    contract=contract_addr,
                    tx_hash=tx_hash.hex(),
                    gas_used=receipt['gasUsed']
                )
                return tx_hash.hex()
            else:
                raise Exception("Transaction reverted")

        except Exception as e:
            logger.error(
                "pause_failed",
                contract=contract_addr,
                error=str(e)
            )
            raise

    def _get_signer(self, config: ProtocolConfig, contract_addr: str):
        """Get appropriate signer for the protocol, or None if unavailable."""
        import os
        try:
            from .signer import create_signer
            signer_type = os.getenv("SIGNER_TYPE", "local")
            if signer_type == "kms" and os.getenv("KMS_KEY_ID"):
                return create_signer(
                    allowed_contracts=[contract_addr],
                    chain_id=int(config.chain_id) if config.chain_id.isdigit() else 1,
                    signer_type="kms"
                )
            elif config.guardian_private_key or os.getenv("GUARDIAN_PRIVATE_KEY"):
                return create_signer(
                    allowed_contracts=[contract_addr],
                    chain_id=int(config.chain_id) if config.chain_id.isdigit() else 1,
                    signer_type="local"
                )
        except Exception as e:
            logger.debug("signer_init_failed_using_fallback", error=str(e))
        return None
    
    async def _notify_multisig(self, config: ProtocolConfig, record: ResponseRecord):
        """
        Notify multisig signers about required action.
        
        This could:
        - Create a Safe transaction proposal
        - Send Telegram/Discord to signers
        - Trigger a webhook
        """
        logger.info(
            "multisig_notification_sent",
            multisig=config.multisig_address,
            action=record.action.value,
            incident=record.incident_id
        )
        
        # In production, this would:
        # 1. Use Safe SDK to propose transaction
        # 2. Or send Telegram to emergency_contacts
        # 3. Or trigger webhook
        
        for contact in config.emergency_contacts:
            logger.info(f"Would notify: {contact}")
    
    def _determine_action(
        self,
        severity: str,
        config: ProtocolConfig,
        estimated_loss_usd: float
    ) -> ResponseAction:
        """Determine appropriate action based on severity and config."""
        
        if severity == "critical" and config.auto_pause_on_critical:
            if config.guardian_private_key:
                return ResponseAction.PAUSE_CONTRACT
            elif config.multisig_address:
                return ResponseAction.NOTIFY_MULTISIG
            else:
                return ResponseAction.ALERT_ONLY
                
        elif severity == "high" and config.auto_pause_on_high:
            if config.guardian_private_key:
                return ResponseAction.PAUSE_CONTRACT
            else:
                return ResponseAction.NOTIFY_MULTISIG
                
        return ResponseAction.ALERT_ONLY
    
    def _find_protocol_config(
        self,
        protocol_name: str,
        contract_address: str
    ) -> Optional[ProtocolConfig]:
        """Find protocol config by name or contract address."""
        # Try by name first
        for pid, config in self.protocols.items():
            if config.protocol_name.lower() == protocol_name.lower():
                return config
            if config.main_contract.lower() == contract_address.lower():
                return config
        return None
    
    def _get_rpc_url(self, chain_id: str) -> Optional[str]:
        """Get RPC URL for chain (would load from config in production)."""
        # This would be loaded from chains.yaml in production
        rpc_urls = {
            "ethereum": "https://mainnet.infura.io/v3/YOUR_KEY",
            "polygon": "https://polygon-mainnet.infura.io/v3/YOUR_KEY",
            "arbitrum": "https://arbitrum-mainnet.infura.io/v3/YOUR_KEY",
        }
        return rpc_urls.get(chain_id)
    
    async def simulate_pause(self, protocol_id: str) -> Dict[str, Any]:
        """
        Dry-run a pause: build the transaction and simulate via eth_call.

        Returns a dict with success/failure, estimated gas, and any revert reason.
        No transaction is broadcast.
        """
        config = self.protocols.get(protocol_id)
        if not config:
            return {"success": False, "error": f"Protocol '{protocol_id}' not registered"}

        from web3 import Web3

        w3 = self._web3_connections.get(config.chain_id)
        if not w3:
            return {"success": False, "error": f"No Web3 connection for chain {config.chain_id}"}

        contract_addr = config.pause_contract or config.main_contract

        pause_abi = [
            {
                "inputs": [],
                "name": "pause",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        if config.custom_abi:
            pause_abi = json.loads(config.custom_abi)

        try:
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(contract_addr),
                abi=pause_abi
            )

            # Determine caller address (guardian wallet)
            caller = config.guardian_address
            if not caller:
                signer = self._get_signer(config, contract_addr)
                if signer:
                    caller = signer.get_address()

            if not caller:
                return {"success": False, "error": "No guardian address configured for simulation"}

            # Simulate via eth_call — reverts surface as exceptions
            call_data = contract.functions.pause().build_transaction({
                'from': caller,
                'gas': 200000,
                'gasPrice': 0,  # Simulation, no real cost
            })

            result = w3.eth.call({
                'from': caller,
                'to': call_data['to'],
                'data': call_data['data'],
                'gas': 200000,
            })

            # Estimate gas for the real tx
            estimated_gas = w3.eth.estimate_gas({
                'from': caller,
                'to': call_data['to'],
                'data': call_data['data'],
            })

            logger.info(
                "pause_simulation_success",
                protocol=protocol_id,
                contract=contract_addr,
                estimated_gas=estimated_gas,
            )

            return {
                "success": True,
                "protocol_id": protocol_id,
                "contract": contract_addr,
                "chain": config.chain_id,
                "estimated_gas": estimated_gas,
                "guardian_address": caller,
                "message": "Pause transaction would succeed",
            }

        except Exception as e:
            error_msg = str(e)
            logger.warning(
                "pause_simulation_failed",
                protocol=protocol_id,
                contract=contract_addr,
                error=error_msg,
            )
            return {
                "success": False,
                "protocol_id": protocol_id,
                "contract": contract_addr,
                "chain": config.chain_id,
                "error": error_msg,
                "message": "Pause transaction would revert",
            }

    def get_response_history(
        self,
        limit: int = 100,
        status: Optional[ResponseStatus] = None
    ) -> List[ResponseRecord]:
        """Get response action history."""
        history = self.response_history
        
        if status:
            history = [r for r in history if r.status == status]
        
        return history[-limit:]
    
    def get_pending_approvals(self) -> List[ResponseRecord]:
        """Get all pending approval requests."""
        return list(self.pending_approvals.values())
    
    def get_stats(self) -> Dict:
        """Get guardian system statistics."""
        return {
            "registered_protocols": len(self.protocols),
            "total_responses": len(self.response_history),
            "pending_approvals": len(self.pending_approvals),
            "successful_pauses": len([
                r for r in self.response_history
                if r.action == ResponseAction.PAUSE_CONTRACT and r.status == ResponseStatus.SUCCESS
            ]),
            "failed_responses": len([
                r for r in self.response_history
                if r.status == ResponseStatus.FAILED
            ]),
            "is_initialized": self._is_initialized
        }


# Global guardian instance
guardian = GuardianSystem()


async def auto_respond_to_incident(
    incident_id: str,
    severity: str,
    attack_type: str,
    protocol: str,
    estimated_loss_usd: float,
    chain: str,
    contract: str
) -> Optional[ResponseRecord]:
    """
    Convenience function to trigger guardian response.
    
    Usage:
        from src.response.guardian import auto_respond_to_incident
        
        record = await auto_respond_to_incident(
            incident_id="inc-123",
            severity="critical",
            attack_type="unbacked_mint",
            protocol="wormhole",
            estimated_loss_usd=2_500_000,
            chain="ethereum",
            contract="0x..."
        )
    """
    return await guardian.handle_incident(
        incident_id=incident_id,
        severity=severity,
        attack_type=attack_type,
        affected_protocol=protocol,
        estimated_loss_usd=estimated_loss_usd,
        affected_chain=chain,
        contract_address=contract
    )

