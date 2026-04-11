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
import hashlib
import structlog

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3

# Optional KMS imports
try:
    import boto3
    AWS_KMS_AVAILABLE = True
except ImportError:
    AWS_KMS_AVAILABLE = False

try:
    from google.cloud import kms as gcp_kms
    GCP_KMS_AVAILABLE = True
except ImportError:
    GCP_KMS_AVAILABLE = False

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
    Production signer using AWS KMS asymmetric keys.

    AWS KMS holds the secp256k1 private key in hardware — it never leaves KMS.
    Signing requests go through the AWS API, and we recover the Ethereum address
    from the KMS public key.

    Supports GCP KMS as fallback via KMS_PROVIDER=gcp env var.
    """

    def __init__(self, config: SignerConfig, kms_key_id: Optional[str] = None):
        self.kms_key_id = kms_key_id or os.getenv("KMS_KEY_ID")
        self.kms_provider = os.getenv("KMS_PROVIDER", "aws").lower()
        self.kms_region = os.getenv("KMS_REGION", "us-east-1")

        if not self.kms_key_id:
            raise ValueError(
                "KMS_KEY_ID environment variable not set. "
                "Cannot initialize KmsSigner."
            )

        # Initialize provider client and derive address
        if self.kms_provider == "aws":
            if not AWS_KMS_AVAILABLE:
                raise ImportError("boto3 required for AWS KMS signer. Run: pip install boto3")
            self._client = boto3.client("kms", region_name=self.kms_region)
            self._guardian_address = self._derive_address_aws()
        elif self.kms_provider == "gcp":
            if not GCP_KMS_AVAILABLE:
                raise ImportError("google-cloud-kms required for GCP KMS signer. Run: pip install google-cloud-kms")
            self._client = gcp_kms.KeyManagementServiceClient()
            self._guardian_address = self._derive_address_gcp()
        else:
            raise ValueError(f"Unknown KMS_PROVIDER: {self.kms_provider}. Use 'aws' or 'gcp'.")

        config.guardian_address = self._guardian_address
        super().__init__(config)

        logger.info(
            "kms_signer_initialized",
            provider=self.kms_provider,
            kms_key_id=self.kms_key_id[:20] + "...",
            guardian_address=self._guardian_address,
        )

    def _derive_address_aws(self) -> str:
        """Derive Ethereum address from AWS KMS public key."""
        response = self._client.get_public_key(KeyId=self.kms_key_id)
        public_key_der = response["PublicKey"]
        return self._der_to_eth_address(public_key_der)

    def _derive_address_gcp(self) -> str:
        """Derive Ethereum address from GCP KMS public key."""
        response = self._client.get_public_key(name=self.kms_key_id)
        # GCP returns PEM; convert to DER
        import base64
        pem_lines = response.pem.strip().split("\n")
        der_b64 = "".join(pem_lines[1:-1])
        public_key_der = base64.b64decode(der_b64)
        return self._der_to_eth_address(public_key_der)

    @staticmethod
    def _der_to_eth_address(public_key_der: bytes) -> str:
        """Convert DER-encoded secp256k1 public key to Ethereum address."""
        # DER structure: SEQUENCE { SEQUENCE { OID, OID }, BIT STRING { 0x04 || x || y } }
        # The uncompressed public key (64 bytes of x||y) starts after the DER header.
        # For secp256k1, the BIT STRING payload starts with 0x04 (uncompressed point).
        # Find 0x04 marker in the DER — it precedes the 64-byte x||y.
        idx = public_key_der.index(b'\x04', 20)  # skip past DER headers
        raw_pub = public_key_der[idx + 1: idx + 65]
        addr_hash = Web3.keccak(raw_pub)
        return Web3.to_checksum_address("0x" + addr_hash[-20:].hex())

    def sign_transaction(self, transaction: dict, contract_address: str) -> dict:
        """Sign transaction using KMS."""
        if not self.verify_contract(contract_address):
            raise ValueError(
                f"Contract {contract_address} is not in whitelist. "
                f"Allowed contracts: {self.config.allowed_contracts}"
            )

        if transaction.get("to") and transaction["to"].lower() != contract_address.lower():
            logger.warning(
                "transaction_to_mismatch",
                tx_to=transaction.get("to"),
                contract_address=contract_address
            )
            transaction["to"] = contract_address

        if "chainId" not in transaction:
            transaction["chainId"] = self.config.chain_id

        # Serialize the transaction to get the unsigned hash
        from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
        unsigned_tx = serializable_unsigned_transaction_from_dict(transaction)
        tx_hash = unsigned_tx.hash()

        # Sign the hash via KMS
        if self.kms_provider == "aws":
            signature = self._sign_aws(tx_hash)
        else:
            signature = self._sign_gcp(tx_hash)

        # Decode the DER signature into r, s
        r, s = self._decode_der_signature(signature)

        # Recover v (27 or 28) by trying both and checking which recovers our address
        v = self._recover_v(tx_hash, r, s)

        # Build the signed transaction
        from eth_account._utils.legacy_transactions import encode_transaction
        signed_raw = encode_transaction(unsigned_tx, vrs=(v, r, s))
        signed_hash = Web3.keccak(signed_raw)

        logger.info(
            "transaction_signed_kms",
            contract_address=contract_address,
            tx_hash=signed_hash.hex(),
            provider=self.kms_provider,
        )

        return {
            "rawTransaction": signed_raw.hex(),
            "hash": signed_hash.hex(),
            "r": r,
            "s": s,
            "v": v,
        }

    def _sign_aws(self, msg_hash: bytes) -> bytes:
        """Sign a hash using AWS KMS."""
        response = self._client.sign(
            KeyId=self.kms_key_id,
            Message=msg_hash,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return response["Signature"]

    def _sign_gcp(self, msg_hash: bytes) -> bytes:
        """Sign a hash using GCP KMS."""
        from google.cloud.kms import CryptoKeyVersion
        digest = {"sha256": msg_hash}
        response = self._client.asymmetric_sign(
            name=self.kms_key_id,
            digest=digest,
        )
        return response.signature

    @staticmethod
    def _decode_der_signature(der_sig: bytes) -> tuple:
        """Decode a DER-encoded ECDSA signature into (r, s) integers."""
        # DER: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
        assert der_sig[0] == 0x30
        offset = 2
        assert der_sig[offset] == 0x02
        r_len = der_sig[offset + 1]
        r = int.from_bytes(der_sig[offset + 2: offset + 2 + r_len], "big")
        offset = offset + 2 + r_len
        assert der_sig[offset] == 0x02
        s_len = der_sig[offset + 1]
        s = int.from_bytes(der_sig[offset + 2: offset + 2 + s_len], "big")

        # Enforce low-S per EIP-2 (s must be in the lower half of the curve order)
        SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if s > SECP256K1_ORDER // 2:
            s = SECP256K1_ORDER - s

        return (r, s)

    def _recover_v(self, msg_hash: bytes, r: int, s: int) -> int:
        """Determine v value (27 or 28) by trial recovery."""
        from eth_account._utils.signing import to_standard_v
        from eth_keys import keys

        for v_candidate in (27, 28):
            try:
                # Recover the address for this v
                sig = keys.Signature(vrs=(v_candidate - 27, r, s))
                recovered_pub = sig.recover_public_key_from_msg_hash(msg_hash)
                recovered_addr = recovered_pub.to_checksum_address()
                if recovered_addr.lower() == self._guardian_address.lower():
                    return v_candidate
            except Exception:
                continue

        raise ValueError(
            "Could not recover correct v value. "
            "KMS key may not be secp256k1 or the message hash is incorrect."
        )

    def get_address(self) -> str:
        """Get the guardian address derived from KMS public key."""
        return self._guardian_address


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

