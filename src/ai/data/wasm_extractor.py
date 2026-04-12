"""
WASM Bytecode Feature Extractor
================================

Extracts security-relevant features from WebAssembly (WASM) binary modules
used by Near and CosmWasm (Injective/Cosmos) smart contracts.

WASM binary format: https://webassembly.github.io/spec/core/binary/
"""

import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)

# WASM binary magic and section IDs
WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"

SECTION_TYPE = 1
SECTION_IMPORT = 2
SECTION_FUNCTION = 3
SECTION_TABLE = 4
SECTION_MEMORY = 5
SECTION_GLOBAL = 6
SECTION_EXPORT = 7
SECTION_START = 8
SECTION_ELEMENT = 9
SECTION_CODE = 10
SECTION_DATA = 11
SECTION_CUSTOM = 0

# Dangerous import patterns (env functions that interact with blockchain state)
DANGEROUS_IMPORTS = {
    # Near SDK - external interactions
    "promise_create", "promise_then", "promise_batch_create",
    "promise_batch_action_transfer", "promise_batch_action_function_call",
    "promise_batch_action_deploy_contract", "promise_batch_action_delete_account",
    "promise_batch_action_add_key_with_full_access",
    "promise_results_count", "promise_result",
    # CosmWasm - external interactions
    "db_write", "db_remove", "addr_validate",
    "secp256k1_verify", "ed25519_verify",
    # General WASM env
    "call_indirect",
}

# Suspicious export names
SUSPICIOUS_EXPORTS = {
    # Admin-like functions
    "migrate", "update_contract", "self_destruct", "drain",
    "withdraw_all", "set_owner", "change_owner", "kill",
    # Proxy patterns
    "upgrade", "set_code", "update_code_hash",
}

# Expected safe contract exports (Near)
NEAR_STANDARD_EXPORTS = {
    "memory", "new", "default", "ft_transfer", "ft_transfer_call",
    "ft_total_supply", "ft_balance_of", "storage_deposit",
    "storage_withdraw", "storage_balance_of",
    "nft_transfer", "nft_approve", "nft_token", "nft_tokens",
}


@dataclass
class WasmFeatures:
    """Features extracted from a WASM binary module."""
    # Basic metrics
    binary_size: int = 0
    is_valid_wasm: bool = False
    wasm_version: int = 0

    # Section analysis
    section_count: int = 0
    code_section_size: int = 0
    data_section_size: int = 0
    custom_section_count: int = 0

    # Functions
    function_count: int = 0
    import_count: int = 0
    export_count: int = 0

    # Import analysis
    import_modules: List[str] = field(default_factory=list)
    dangerous_import_count: int = 0
    has_external_call_imports: bool = False

    # Export analysis
    suspicious_export_count: int = 0
    export_names: List[str] = field(default_factory=list)
    has_admin_exports: bool = False
    has_proxy_pattern: bool = False

    # Memory
    memory_pages_min: int = 0
    memory_pages_max: int = 0
    has_memory_grow: bool = False

    # Risk indicators
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)

    # Contract type heuristics
    likely_contract_type: str = "unknown"


class WasmFeatureExtractor:
    """Extract security features from WASM binary bytecode."""

    def extract_features(self, bytecode: bytes) -> WasmFeatures:
        """
        Extract features from raw WASM binary bytes.

        Args:
            bytecode: Raw WASM binary (bytes, not hex)
        """
        features = WasmFeatures(binary_size=len(bytecode))

        if len(bytecode) < 8:
            return features

        # Validate magic bytes
        if bytecode[:4] != WASM_MAGIC:
            return features

        features.is_valid_wasm = True
        features.wasm_version = struct.unpack("<I", bytecode[4:8])[0]

        # Parse sections
        try:
            self._parse_sections(bytecode[8:], features)
        except Exception as e:
            logger.warning("wasm_parse_error", error=str(e))

        # Calculate risk score
        self._calculate_risk(features)

        # Determine contract type
        self._classify_contract_type(features)

        return features

    def extract_features_from_hex(self, hex_bytecode: str) -> WasmFeatures:
        """Extract features from hex-encoded WASM bytecode."""
        hex_bytecode = hex_bytecode.strip()
        if hex_bytecode.startswith("0x"):
            hex_bytecode = hex_bytecode[2:]
        try:
            raw = bytes.fromhex(hex_bytecode)
        except ValueError:
            return WasmFeatures()
        return self.extract_features(raw)

    def _read_leb128_unsigned(self, data: bytes, offset: int) -> Tuple[int, int]:
        """Read an unsigned LEB128-encoded integer. Returns (value, new_offset)."""
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
            if shift > 35:
                break
        return result, offset

    def _read_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Read a WASM name (length-prefixed UTF-8 string)."""
        length, offset = self._read_leb128_unsigned(data, offset)
        if offset + length > len(data):
            return "", len(data)
        name = data[offset:offset + length].decode("utf-8", errors="replace")
        return name, offset + length

    def _parse_sections(self, data: bytes, features: WasmFeatures):
        """Parse all WASM sections."""
        offset = 0

        while offset < len(data):
            if offset >= len(data):
                break

            section_id = data[offset]
            offset += 1

            section_size, offset = self._read_leb128_unsigned(data, offset)
            section_end = offset + section_size

            if section_end > len(data):
                break

            features.section_count += 1
            section_data = data[offset:section_end]

            if section_id == SECTION_IMPORT:
                self._parse_imports(section_data, features)
            elif section_id == SECTION_EXPORT:
                self._parse_exports(section_data, features)
            elif section_id == SECTION_FUNCTION:
                count, _ = self._read_leb128_unsigned(section_data, 0)
                features.function_count += count
            elif section_id == SECTION_MEMORY:
                self._parse_memory(section_data, features)
            elif section_id == SECTION_CODE:
                features.code_section_size = section_size
            elif section_id == SECTION_DATA:
                features.data_section_size = section_size
            elif section_id == SECTION_CUSTOM:
                features.custom_section_count += 1

            offset = section_end

    def _parse_imports(self, data: bytes, features: WasmFeatures):
        """Parse WASM import section."""
        offset = 0
        count, offset = self._read_leb128_unsigned(data, offset)
        features.import_count = count

        for _ in range(count):
            if offset >= len(data):
                break

            # Module name
            module_name, offset = self._read_name(data, offset)
            # Field name
            field_name, offset = self._read_name(data, offset)

            if module_name not in features.import_modules:
                features.import_modules.append(module_name)

            # Check for dangerous imports
            if field_name in DANGEROUS_IMPORTS:
                features.dangerous_import_count += 1

            # Check for external call capability
            if any(kw in field_name for kw in ("promise_create", "promise_batch", "call")):
                features.has_external_call_imports = True

            # Skip import descriptor (type: func=0x00, table=0x01, mem=0x02, global=0x03)
            if offset < len(data):
                import_type = data[offset]
                offset += 1
                if import_type == 0x00:
                    # Function import: read typeidx
                    _, offset = self._read_leb128_unsigned(data, offset)
                elif import_type == 0x01:
                    # Table import: skip elemtype + limits
                    offset += 1  # elemtype
                    flags = data[offset] if offset < len(data) else 0
                    offset += 1
                    _, offset = self._read_leb128_unsigned(data, offset)
                    if flags & 0x01:
                        _, offset = self._read_leb128_unsigned(data, offset)
                elif import_type == 0x02:
                    # Memory import: skip limits
                    flags = data[offset] if offset < len(data) else 0
                    offset += 1
                    _, offset = self._read_leb128_unsigned(data, offset)
                    if flags & 0x01:
                        _, offset = self._read_leb128_unsigned(data, offset)
                elif import_type == 0x03:
                    # Global import: skip valtype + mut
                    offset += 2

    def _parse_exports(self, data: bytes, features: WasmFeatures):
        """Parse WASM export section."""
        offset = 0
        count, offset = self._read_leb128_unsigned(data, offset)
        features.export_count = count

        for _ in range(count):
            if offset >= len(data):
                break

            name, offset = self._read_name(data, offset)
            features.export_names.append(name)

            # Check for suspicious exports
            name_lower = name.lower()
            if name_lower in SUSPICIOUS_EXPORTS:
                features.suspicious_export_count += 1

            if any(kw in name_lower for kw in ("admin", "owner", "drain", "withdraw_all", "kill")):
                features.has_admin_exports = True

            if any(kw in name_lower for kw in ("upgrade", "migrate", "set_code", "update_code")):
                features.has_proxy_pattern = True

            # Skip export descriptor (kind + index)
            if offset < len(data):
                offset += 1  # kind
                _, offset = self._read_leb128_unsigned(data, offset)

    def _parse_memory(self, data: bytes, features: WasmFeatures):
        """Parse WASM memory section."""
        offset = 0
        count, offset = self._read_leb128_unsigned(data, offset)

        if count > 0 and offset < len(data):
            flags = data[offset]
            offset += 1
            features.memory_pages_min, offset = self._read_leb128_unsigned(data, offset)
            if flags & 0x01:
                features.memory_pages_max, offset = self._read_leb128_unsigned(data, offset)

    def _calculate_risk(self, features: WasmFeatures):
        """Calculate risk score based on extracted features."""
        risk = 0.0

        # Dangerous imports
        if features.dangerous_import_count > 5:
            risk += 0.15
            features.risk_factors.append(
                f"High dangerous import count: {features.dangerous_import_count}"
            )
        elif features.dangerous_import_count > 2:
            risk += 0.08

        # External call capability
        if features.has_external_call_imports:
            risk += 0.10
            features.risk_factors.append("Has external call imports (cross-contract calls)")

        # Admin exports
        if features.has_admin_exports:
            risk += 0.15
            features.risk_factors.append("Has admin/owner-control exports")

        # Proxy pattern
        if features.has_proxy_pattern:
            risk += 0.10
            features.risk_factors.append("Has proxy/upgrade pattern")

        # Suspicious export count
        if features.suspicious_export_count > 3:
            risk += 0.10
            features.risk_factors.append(
                f"Multiple suspicious exports: {features.suspicious_export_count}"
            )

        # Very small contract (might be a deploy-and-delegatecall proxy)
        if features.binary_size < 500 and features.has_external_call_imports:
            risk += 0.15
            features.risk_factors.append("Tiny contract with external calls (possible proxy)")

        # Very large code section relative to binary (possibly obfuscated)
        if features.binary_size > 0:
            code_ratio = features.code_section_size / features.binary_size
            if code_ratio > 0.95:
                risk += 0.05
                features.risk_factors.append("Very high code-to-binary ratio")

        # Large memory allocation
        if features.memory_pages_max > 100:  # >6.4MB
            risk += 0.05

        features.risk_score = min(1.0, risk)

    def _classify_contract_type(self, features: WasmFeatures):
        """Heuristically classify the contract type based on exports."""
        export_set = set(name.lower() for name in features.export_names)

        # Check for token contracts (NEP-141 / CW20)
        if any(name in export_set for name in ("ft_transfer", "ft_balance_of", "ft_total_supply")):
            features.likely_contract_type = "fungible_token"
        elif any(name in export_set for name in ("nft_transfer", "nft_token", "nft_tokens")):
            features.likely_contract_type = "nft"
        elif any(name in export_set for name in ("swap", "add_liquidity", "remove_liquidity")):
            features.likely_contract_type = "dex"
        elif any(name in export_set for name in ("stake", "unstake", "get_staked_balance")):
            features.likely_contract_type = "staking"
        elif "migrate" in export_set and features.has_proxy_pattern:
            features.likely_contract_type = "proxy"
        elif features.has_admin_exports and features.export_count < 5:
            features.likely_contract_type = "suspicious_admin"
        else:
            features.likely_contract_type = "generic"
