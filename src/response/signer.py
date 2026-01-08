"""
Secure Transaction Signer Abstraction
=====================================

Phase 5: Abstract signer interface with whitelist verification.
Prevents signing transactions to unauthorized contracts.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Set
from dataclasses import dataclass
import os
import structlog

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3

logger = structlog.get_logger(__name__)


@dataclass
class SignerConfig:
    """Configuration for transaction signer."""
    # Whitelist of allowed contract addresses
    allowed_contracts: Set[str]
    
    # Guardian address (derived from private key)
    guardian_address: Optional[str] = None
    
    # Chain ID for replay protection
    chain_id: int = 1  # Ethereum mainnet default


class TransactionSigner(ABC):
    """
    Abstract base class for transaction signers.
    
    All signers must:
    1. Verify contract address is whitelisted
    2. Sign transactions securely
    3. Never expose private keys
    """
    
    def __init__(self, config: SignerConfig):
        self.config = config
        self.guardian_address = config.guardian_address
        logger.info(
            "transaction_signer_initialized",
            signer_type=type(self).__name__,
            guardian_address=self.guardian_address
        )
    
    def verify_contract(self, contract_address: str) -> bool:
        """
        Verify that contract address is in whitelist.
        
        Args:
            contract_address: Contract address to verify
        
        Returns:
            True if contract is whitelisted, False otherwise
        """
        # Normalize address (checksum)
        normalized = Web3.to_checksum_address(contract_address.lower())
        
        # Check whitelist
        allowed = normalized.lower() in {addr.lower() for addr in self.config.allowed_contracts}
        
        if not allowed:
            logger.warning(
                "contract_not_whitelisted",
                contract_address=normalized,
                guardian_address=self.guardian_address
            )
        
        return allowed
    
    @abstractmethod
    def sign_transaction(self, transaction: dict, contract_address: str) -> dict:
        """
        Sign a transaction.
        
        Args:
            transaction: Transaction dictionary (to, data, value, gas, etc.)
            contract_address: Contract address (must be whitelisted)
        
        Returns:
            Signed transaction dictionary
        
        Raises:
            ValueError: If contract is not whitelisted
        """
        pass
    
    @abstractmethod
    def get_address(self) -> str:
        """Get the guardian address (public key)."""
        pass


class LocalSigner(TransactionSigner):
    """
    Local signer using private key from environment variable.
    
    ⚠️ WARNING: For development/testing only!
    Production should use KmsSigner with AWS KMS or GCP Secret Manager.
    """
    
    def __init__(self, config: SignerConfig, private_key: Optional[str] = None):
        """
        Initialize local signer.
        
        Args:
            config: Signer configuration
            private_key: Private key (if None, reads from GUARDIAN_PRIVATE_KEY env var)
        """
        # Get private key
        if not private_key:
            private_key = os.getenv("GUARDIAN_PRIVATE_KEY")
        
        if not private_key:
            raise ValueError(
                "GUARDIAN_PRIVATE_KEY environment variable not set. "
                "Cannot initialize LocalSigner."
            )
        
        # Create account
        self.account: LocalAccount = Account.from_key(private_key)
        
        # Update config with guardian address
        config.guardian_address = self.account.address
        
        super().__init__(config)
        
        logger.warning(
            "local_signer_initialized",
            guardian_address=self.account.address,
            warning="⚠️  LocalSigner is for DEV/TEST only. Use KmsSigner in production!"
        )
    
    def sign_transaction(self, transaction: dict, contract_address: str) -> dict:
        """Sign transaction using local private key."""
        # Verify contract is whitelisted
        if not self.verify_contract(contract_address):
            raise ValueError(
                f"Contract {contract_address} is not in whitelist. "
                f"Allowed contracts: {self.config.allowed_contracts}"
            )
        
        # Ensure 'to' field matches contract_address
        if transaction.get("to") and transaction["to"].lower() != contract_address.lower():
            logger.warning(
                "transaction_to_mismatch",
                tx_to=transaction.get("to"),
                contract_address=contract_address
            )
            transaction["to"] = contract_address
        
        # Add chain ID for replay protection
        if "chainId" not in transaction:
            transaction["chainId"] = self.config.chain_id
        
        # Sign transaction
        signed_txn = self.account.sign_transaction(transaction)
        
        logger.info(
            "transaction_signed",
            contract_address=contract_address,
            tx_hash=signed_txn.hash.hex(),
            from_address=self.account.address
        )
        
        return {
            "rawTransaction": signed_txn.rawTransaction.hex(),
            "hash": signed_txn.hash.hex(),
            "r": signed_txn.r,
            "s": signed_txn.s,
            "v": signed_txn.v
        }
    
    def get_address(self) -> str:
        """Get guardian address."""
        return self.account.address


class KmsSigner(TransactionSigner):
    """
    AWS KMS / GCP Secret Manager signer (stub for future implementation).
    
    This is a placeholder for production key management.
    """
    
    def __init__(self, config: SignerConfig, kms_key_id: Optional[str] = None):
        """
        Initialize KMS signer.
        
        Args:
            config: Signer configuration
            kms_key_id: KMS key ID (for AWS) or secret name (for GCP)
        """
        self.kms_key_id = kms_key_id or os.getenv("KMS_KEY_ID")
        
        if not self.kms_key_id:
            raise ValueError(
                "KMS_KEY_ID environment variable not set. "
                "Cannot initialize KmsSigner."
            )
        
        # TODO: Initialize AWS KMS or GCP Secret Manager client
        # For now, this is a stub
        
        super().__init__(config)
        
        logger.info(
            "kms_signer_initialized",
            kms_key_id=self.kms_key_id,
            note="KmsSigner is a stub - implement AWS KMS or GCP Secret Manager integration"
        )
    
    def sign_transaction(self, transaction: dict, contract_address: str) -> dict:
        """Sign transaction using KMS (stub)."""
        # Verify contract is whitelisted
        if not self.verify_contract(contract_address):
            raise ValueError(
                f"Contract {contract_address} is not in whitelist. "
                f"Allowed contracts: {self.config.allowed_contracts}"
            )
        
        # TODO: Implement actual KMS signing
        # For now, raise NotImplementedError
        raise NotImplementedError(
            "KmsSigner.sign_transaction() is not yet implemented. "
            "Integrate with AWS KMS or GCP Secret Manager."
        )
    
    def get_address(self) -> str:
        """Get guardian address from KMS."""
        # TODO: Derive address from KMS public key
        if self.config.guardian_address:
            return self.config.guardian_address
        
        raise NotImplementedError(
            "KmsSigner.get_address() is not yet implemented. "
            "Derive address from KMS public key."
        )


def create_signer(
    allowed_contracts: List[str],
    chain_id: int = 1,
    signer_type: str = "local"
) -> TransactionSigner:
    """
    Factory function to create appropriate signer.
    
    Args:
        allowed_contracts: List of whitelisted contract addresses
        chain_id: Chain ID for replay protection
        signer_type: "local" or "kms"
    
    Returns:
        TransactionSigner instance
    """
    config = SignerConfig(
        allowed_contracts=set(Web3.to_checksum_address(addr) for addr in allowed_contracts),
        chain_id=chain_id
    )
    
    if signer_type == "local":
        return LocalSigner(config)
    elif signer_type == "kms":
        return KmsSigner(config)
    else:
        raise ValueError(f"Unknown signer type: {signer_type}")

