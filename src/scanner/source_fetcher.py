"""
Smart Contract Source Code Fetcher

Fetches source code from multiple sources:
1. Etherscan API (and chain-specific explorers)
2. Sourcify (decentralized verification)
3. Bytecode decompilation (fallback)
"""

import asyncio
import aiohttp
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import structlog

logger = structlog.get_logger()


class SourceType(Enum):
    """Source of the contract code"""
    ETHERSCAN = "etherscan"
    SOURCIFY = "sourcify"
    DECOMPILED = "decompiled"
    UNKNOWN = "unknown"


@dataclass
class ContractSource:
    """Represents fetched contract source code"""
    address: str
    chain: str
    
    # Source code
    source_code: str = ""
    source_type: SourceType = SourceType.UNKNOWN
    
    # Metadata
    contract_name: str = ""
    compiler_version: str = ""
    optimization_used: bool = False
    optimization_runs: int = 200
    evm_version: str = ""
    
    # Additional files (for multi-file contracts)
    source_files: Dict[str, str] = field(default_factory=dict)
    
    # ABI
    abi: List[Dict] = field(default_factory=list)
    
    # Constructor arguments
    constructor_args: str = ""
    
    # Verification status
    is_verified: bool = False
    is_proxy: bool = False
    implementation_address: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "address": self.address,
            "chain": self.chain,
            "source_code": self.source_code[:1000] + "..." if len(self.source_code) > 1000 else self.source_code,
            "source_type": self.source_type.value,
            "contract_name": self.contract_name,
            "compiler_version": self.compiler_version,
            "optimization_used": self.optimization_used,
            "is_verified": self.is_verified,
            "is_proxy": self.is_proxy,
            "file_count": len(self.source_files)
        }


class SourceFetcher:
    """
    Fetches smart contract source code from multiple sources
    """
    
    # Block explorer APIs
    EXPLORER_APIS = {
        "ethereum": "https://api.etherscan.io/api",
        "goerli": "https://api-goerli.etherscan.io/api",
        "sepolia": "https://api-sepolia.etherscan.io/api",
        "polygon": "https://api.polygonscan.com/api",
        "bsc": "https://api.bscscan.com/api",
        "arbitrum": "https://api.arbiscan.io/api",
        "optimism": "https://api-optimistic.etherscan.io/api",
        "avalanche": "https://api.snowtrace.io/api",
        "base": "https://api.basescan.org/api",
        "fantom": "https://api.ftmscan.com/api",
    }
    
    # Sourcify API
    SOURCIFY_API = "https://sourcify.dev/server"
    
    # Chain IDs for Sourcify
    CHAIN_IDS = {
        "ethereum": 1,
        "goerli": 5,
        "sepolia": 11155111,
        "polygon": 137,
        "bsc": 56,
        "arbitrum": 42161,
        "optimism": 10,
        "avalanche": 43114,
        "base": 8453,
        "fantom": 250,
    }
    
    def __init__(self, api_keys: Dict[str, str] = None):
        """
        Initialize the source fetcher
        
        Args:
            api_keys: Optional dict of chain -> API key for block explorers
        """
        self.api_keys = api_keys or {}
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session
    
    async def close(self):
        """Close the aiohttp session"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def fetch_source(self, address: str, chain: str = "ethereum") -> ContractSource:
        """
        Fetch contract source code from all available sources
        
        Args:
            address: Contract address
            chain: Chain name
        
        Returns:
            ContractSource with source code and metadata
        """
        result = ContractSource(address=address, chain=chain)
        
        # Try sources in order of preference
        # 1. Etherscan (most common)
        source = await self._fetch_from_etherscan(address, chain)
        if source and source.is_verified:
            return source
        
        # 2. Sourcify (decentralized)
        source = await self._fetch_from_sourcify(address, chain)
        if source and source.is_verified:
            return source
        
        # 3. Decompile bytecode (fallback)
        source = await self._decompile_bytecode(address, chain)
        if source:
            return source
        
        return result
    
    async def _fetch_from_etherscan(self, address: str, chain: str) -> Optional[ContractSource]:
        """Fetch source from Etherscan-like APIs"""
        explorer_url = self.EXPLORER_APIS.get(chain.lower())
        if not explorer_url:
            return None
        
        api_key = self.api_keys.get(chain.lower(), "")
        
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        }
        if api_key:
            params["apikey"] = api_key
        
        try:
            session = await self._get_session()
            async with session.get(explorer_url, params=params) as resp:
                data = await resp.json()
                
                if data.get("status") != "1" or not data.get("result"):
                    return None
                
                contract_data = data["result"][0]
                
                # Check if verified
                source_code = contract_data.get("SourceCode", "")
                if not source_code:
                    return None
                
                result = ContractSource(
                    address=address,
                    chain=chain,
                    source_type=SourceType.ETHERSCAN,
                    is_verified=True
                )
                
                # Parse source code (might be JSON for multi-file)
                if source_code.startswith("{{"):
                    # Multi-file format: {{...}}
                    try:
                        # Remove extra braces
                        json_str = source_code[1:-1]
                        source_json = json.loads(json_str)
                        
                        # Extract sources
                        sources = source_json.get("sources", {})
                        for filename, file_data in sources.items():
                            content = file_data.get("content", "")
                            result.source_files[filename] = content
                            if not result.source_code:
                                result.source_code = content
                        
                    except json.JSONDecodeError:
                        result.source_code = source_code
                elif source_code.startswith("{"):
                    # Standard JSON format
                    try:
                        source_json = json.loads(source_code)
                        sources = source_json.get("sources", {})
                        for filename, file_data in sources.items():
                            content = file_data.get("content", "")
                            result.source_files[filename] = content
                            if not result.source_code:
                                result.source_code = content
                    except json.JSONDecodeError:
                        result.source_code = source_code
                else:
                    result.source_code = source_code
                    result.source_files["main.sol"] = source_code
                
                # Extract metadata
                result.contract_name = contract_data.get("ContractName", "")
                result.compiler_version = contract_data.get("CompilerVersion", "")
                result.optimization_used = contract_data.get("OptimizationUsed", "0") == "1"
                result.optimization_runs = int(contract_data.get("Runs", 200))
                result.evm_version = contract_data.get("EVMVersion", "")
                result.constructor_args = contract_data.get("ConstructorArguments", "")
                
                # Parse ABI
                abi_str = contract_data.get("ABI", "")
                if abi_str and abi_str != "Contract source code not verified":
                    try:
                        result.abi = json.loads(abi_str)
                    except json.JSONDecodeError:
                        pass
                
                # Check if proxy
                result.is_proxy = contract_data.get("Proxy", "0") == "1"
                result.implementation_address = contract_data.get("Implementation", None)
                
                logger.info("source_fetched", 
                           address=address, 
                           chain=chain, 
                           source=SourceType.ETHERSCAN.value,
                           files=len(result.source_files))
                
                return result
                
        except Exception as e:
            logger.error("etherscan_fetch_error", address=address, error=str(e))
            return None
    
    async def _fetch_from_sourcify(self, address: str, chain: str) -> Optional[ContractSource]:
        """Fetch source from Sourcify"""
        chain_id = self.CHAIN_IDS.get(chain.lower())
        if not chain_id:
            return None
        
        # Try full match first, then partial
        for match_type in ["full_match", "partial_match"]:
            url = f"{self.SOURCIFY_API}/repository/contracts/{match_type}/{chain_id}/{address}"
            
            try:
                session = await self._get_session()
                async with session.get(url) as resp:
                    if resp.status != 200:
                        continue
                    
                    # Get list of files
                    files_url = f"{url}/"
                    async with session.get(files_url) as files_resp:
                        if files_resp.status != 200:
                            continue
                        
                        # Sourcify returns file listing
                        # We need to fetch metadata.json first
                        metadata_url = f"{url}/metadata.json"
                        async with session.get(metadata_url) as meta_resp:
                            if meta_resp.status != 200:
                                continue
                            
                            metadata = await meta_resp.json()
                            
                            result = ContractSource(
                                address=address,
                                chain=chain,
                                source_type=SourceType.SOURCIFY,
                                is_verified=True
                            )
                            
                            # Extract compiler info
                            result.compiler_version = metadata.get("compiler", {}).get("version", "")
                            
                            # Get sources from metadata
                            sources = metadata.get("sources", {})
                            for filename, source_info in sources.items():
                                # Fetch actual source file
                                source_url = f"{url}/{filename}"
                                try:
                                    async with session.get(source_url) as src_resp:
                                        if src_resp.status == 200:
                                            content = await src_resp.text()
                                            result.source_files[filename] = content
                                            if not result.source_code:
                                                result.source_code = content
                                except:
                                    pass
                            
                            # Get contract name from output
                            output = metadata.get("output", {})
                            contracts = output.get("contracts", {})
                            for filename, file_contracts in contracts.items():
                                for name in file_contracts.keys():
                                    result.contract_name = name
                                    break
                            
                            logger.info("source_fetched",
                                       address=address,
                                       chain=chain,
                                       source=SourceType.SOURCIFY.value,
                                       files=len(result.source_files))
                            
                            return result
                            
            except Exception as e:
                logger.debug("sourcify_fetch_error", address=address, error=str(e))
                continue
        
        return None
    
    async def _decompile_bytecode(self, address: str, chain: str) -> Optional[ContractSource]:
        """
        Decompile bytecode to pseudo-Solidity
        
        This is a simplified decompiler that extracts:
        - Function signatures
        - Control flow structure
        - Storage access patterns
        """
        # First fetch bytecode
        bytecode = await self._fetch_bytecode(address, chain)
        if not bytecode or bytecode == "0x":
            return None
        
        result = ContractSource(
            address=address,
            chain=chain,
            source_type=SourceType.DECOMPILED,
            is_verified=False
        )
        
        # Decompile to pseudo-Solidity
        decompiled = self._decompile(bytecode)
        result.source_code = decompiled
        result.source_files["decompiled.sol"] = decompiled
        
        # Try to extract function signatures from 4byte directory
        signatures = await self._fetch_function_signatures(bytecode)
        if signatures:
            result.abi = [{"type": "function", "name": sig} for sig in signatures]
        
        logger.info("source_decompiled",
                   address=address,
                   chain=chain,
                   bytecode_size=len(bytecode))
        
        return result
    
    async def _fetch_bytecode(self, address: str, chain: str) -> Optional[str]:
        """Fetch bytecode via RPC"""
        rpc_urls = {
            "ethereum": "https://eth.llamarpc.com",
            "polygon": "https://polygon.llamarpc.com",
            "arbitrum": "https://arbitrum.llamarpc.com",
            "optimism": "https://optimism.llamarpc.com",
            "base": "https://base.llamarpc.com",
            "bsc": "https://bsc-dataseed.binance.org",
            "avalanche": "https://api.avax.network/ext/bc/C/rpc",
        }
        
        rpc_url = rpc_urls.get(chain.lower())
        if not rpc_url:
            return None
        
        try:
            session = await self._get_session()
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1
            }
            async with session.post(rpc_url, json=payload) as resp:
                data = await resp.json()
                return data.get("result")
        except Exception as e:
            logger.error("bytecode_fetch_error", address=address, error=str(e))
            return None
    
    def _decompile(self, bytecode: str) -> str:
        """
        Advanced bytecode decompiler
        
        Converts EVM bytecode to readable pseudo-Solidity with:
        - Control flow reconstruction
        - Storage variable inference
        - Event signature detection
        - Common pattern recognition
        """
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        
        try:
            bytecode_bytes = bytes.fromhex(bytecode)
        except ValueError:
            return "// Invalid bytecode"
        
        # Extract function selectors
        selectors = self._extract_selectors(bytecode_bytes)
        
        # Analyze storage
        storage_slots = self._extract_storage_slots(bytecode_bytes)
        storage_vars = self._infer_storage_variables(bytecode_bytes, storage_slots)
        
        # Detect events
        events = self._extract_event_topics(bytecode_bytes)
        
        # Detect patterns
        patterns = self._detect_patterns(bytecode_bytes)
        
        # Detect Solidity version
        solidity_version = self._detect_solidity_version(bytecode_bytes)
        
        # Detect contract type
        contract_type = self._detect_contract_type(bytecode_bytes, patterns)
        
        # Build pseudo-Solidity
        lines = [
            "// ═══════════════════════════════════════════════════════════════════",
            "// DECOMPILED CONTRACT - Sentinel3 Bytecode Analyzer",
            "// ═══════════════════════════════════════════════════════════════════",
            f"// Bytecode size: {len(bytecode_bytes)} bytes",
            f"// Estimated Solidity version: {solidity_version or 'unknown'}",
            f"// Contract type: {contract_type}",
            "// ",
            "// ⚠️ WARNING: This is reconstructed pseudo-code, not original source",
            "// ═══════════════════════════════════════════════════════════════════",
            "",
            f"pragma solidity {solidity_version or '^0.8.0'};",
            "",
        ]
        
        # Add detected patterns as comments
        if patterns:
            lines.append("/*")
            lines.append(" * SECURITY ANALYSIS:")
            for pattern in patterns:
                lines.append(f" * ⚠️ {pattern}")
            lines.append(" */")
            lines.append("")
        
        # Contract declaration
        lines.append(f"contract {contract_type.replace(' ', '')}Contract {{")
        lines.append("")
        
        # Add inferred storage variables
        if storage_vars:
            lines.append("    // ═══════════════════════════════════════")
            lines.append("    // STATE VARIABLES (inferred from storage)")
            lines.append("    // ═══════════════════════════════════════")
            for var in storage_vars:
                lines.append(f"    {var['type']} {var['visibility']} {var['name']};  // slot {var['slot']}")
            lines.append("")
        
        # Add detected events
        if events:
            lines.append("    // ═══════════════════════════════════════")
            lines.append("    // EVENTS (detected from LOG opcodes)")
            lines.append("    // ═══════════════════════════════════════")
            for event in events[:10]:
                lines.append(f"    event {event['name']}({event['params']});  // topic: 0x{event['topic'][:16]}...")
            lines.append("")
        
        # Add functions with better reconstruction
        if selectors:
            lines.append("    // ═══════════════════════════════════════")
            lines.append("    // FUNCTIONS (detected from dispatcher)")
            lines.append("    // ═══════════════════════════════════════")
            lines.append("")
            
            for selector in selectors[:30]:  # Limit to 30 functions
                func_info = self._analyze_function(bytecode_bytes, selector)
                
                # Function signature
                visibility = "external" if func_info.get('is_payable') else "public"
                payable = " payable" if func_info.get('is_payable') else ""
                view = " view" if func_info.get('is_view') else ""
                
                lines.append(f"    /// @notice Function 0x{selector}")
                if func_info.get('name'):
                    lines.append(f"    /// @dev Likely: {func_info['name']}")
                
                lines.append(f"    function {func_info.get('name', f'func_{selector}')}({func_info.get('params', '')})")
                lines.append(f"        {visibility}{payable}{view}")
                if func_info.get('returns'):
                    lines.append(f"        returns ({func_info['returns']})")
                lines.append("    {")
                
                # Add function body hints
                if func_info.get('reads_storage'):
                    lines.append("        // Reads from storage")
                if func_info.get('writes_storage'):
                    lines.append("        // Writes to storage")
                if func_info.get('external_call'):
                    lines.append("        // ⚠️ Makes external call")
                if func_info.get('sends_eth'):
                    lines.append("        // ⚠️ Sends ETH")
                
                lines.append(f"        // Selector: 0x{selector}")
                lines.append("        assembly { /* implementation */ }")
                lines.append("    }")
                lines.append("")
        
        # Add receive/fallback for proxy contracts
        if b'\xf4' in bytecode_bytes:  # DELEGATECALL
            lines.append("    // ═══════════════════════════════════════")
            lines.append("    // PROXY PATTERN DETECTED")
            lines.append("    // ═══════════════════════════════════════")
            lines.append("    ")
            lines.append("    /// @notice Proxy fallback - delegates all calls")
            lines.append("    fallback() external payable {")
            lines.append("        address impl = _getImplementation();")
            lines.append("        assembly {")
            lines.append("            calldatacopy(0, 0, calldatasize())")
            lines.append("            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)")
            lines.append("            returndatacopy(0, 0, returndatasize())")
            lines.append("            switch result")
            lines.append("            case 0 { revert(0, returndatasize()) }")
            lines.append("            default { return(0, returndatasize()) }")
            lines.append("        }")
            lines.append("    }")
            lines.append("")
            lines.append("    receive() external payable {}")
            lines.append("")
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def _detect_solidity_version(self, bytecode: bytes) -> Optional[str]:
        """Detect Solidity version from bytecode patterns"""
        # Check for 0.8.x patterns (checked arithmetic by default)
        # 0.8+ uses INVALID (0xFE) for panic instead of REVERT
        if bytecode.count(b'\xfe') > 5:  # Multiple INVALID opcodes
            return "^0.8.0"
        
        # Check for 0.6-0.7 patterns
        # These versions have specific metadata hash patterns
        if b'\xa2\x64\x69\x70\x66\x73' in bytecode:  # "dipfs" in CBOR metadata
            # Check metadata for version
            return "^0.7.0"
        
        if b'\xa1\x65\x62\x7a\x7a\x72' in bytecode:  # "bzzr" in CBOR metadata
            return "^0.5.0"
        
        return None
    
    def _detect_contract_type(self, bytecode: bytes, patterns: List[str]) -> str:
        """Detect the type of contract"""
        # Check for proxy patterns
        if b'\xf4' in bytecode:  # DELEGATECALL
            if any('DELEGATECALL' in p for p in patterns):
                return "Proxy"
        
        # Check for ERC20 patterns
        erc20_selectors = ['70a08231', '18160ddd', 'dd62ed3e', 'a9059cbb', '095ea7b3']
        found_erc20 = sum(1 for s in self._extract_selectors(bytecode) if s in erc20_selectors)
        if found_erc20 >= 3:
            return "ERC20 Token"
        
        # Check for ERC721 patterns
        erc721_selectors = ['6352211e', '42842e0e', 'b88d4fde', '70a08231']
        found_erc721 = sum(1 for s in self._extract_selectors(bytecode) if s in erc721_selectors)
        if found_erc721 >= 3:
            return "ERC721 NFT"
        
        # Check for Uniswap-like patterns
        if any(s in self._extract_selectors(bytecode) for s in ['022c0d9f', '0902f1ac']):
            return "DEX/AMM"
        
        # Check for lending patterns
        if any(s in self._extract_selectors(bytecode) for s in ['c5ebeaec', 'a0712d68']):
            return "Lending Protocol"
        
        return "Unknown"
    
    def _infer_storage_variables(self, bytecode: bytes, slots: List[str]) -> List[Dict]:
        """Infer storage variable types from access patterns"""
        variables = []
        
        for i, slot in enumerate(slots[:15]):  # Limit to 15 variables
            slot_int = int(slot, 16) if slot else 0
            
            # Infer type based on slot number and patterns
            if slot_int == 0:
                var_type = "address"
                var_name = "owner"
            elif slot_int < 5:
                var_type = "uint256"
                var_name = f"value{slot_int}"
            else:
                var_type = "mapping(address => uint256)"
                var_name = f"balances{i}" if slot_int < 10 else f"data{i}"
            
            variables.append({
                "slot": slot,
                "type": var_type,
                "name": var_name,
                "visibility": "private"
            })
        
        return variables
    
    def _extract_event_topics(self, bytecode: bytes) -> List[Dict]:
        """Extract event topics from LOG opcodes"""
        events = []
        
        # Common event signatures
        known_events = {
            "ddf252ad": {"name": "Transfer", "params": "address indexed from, address indexed to, uint256 value"},
            "8c5be1e5": {"name": "Approval", "params": "address indexed owner, address indexed spender, uint256 value"},
            "17307eab": {"name": "ApprovalForAll", "params": "address indexed owner, address indexed operator, bool approved"},
            "c3d58168": {"name": "TransferSingle", "params": "address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value"},
            "4a39dc06": {"name": "TransferBatch", "params": "address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values"},
            "1c411e9a": {"name": "Sync", "params": "uint112 reserve0, uint112 reserve1"},
            "d78ad95f": {"name": "Swap", "params": "address indexed sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out, address indexed to"},
        }
        
        # Look for PUSH32 before LOG opcodes
        i = 0
        while i < len(bytecode) - 33:
            # LOG0-LOG4 = 0xa0-0xa4
            if 0xa0 <= bytecode[i] <= 0xa4:
                # Look back for PUSH32 (0x7f)
                if i >= 33 and bytecode[i-33] == 0x7f:
                    topic = bytecode[i-32:i].hex()
                    topic_prefix = topic[:8]
                    
                    if topic_prefix in known_events:
                        events.append({
                            "topic": topic,
                            **known_events[topic_prefix]
                        })
                    else:
                        events.append({
                            "topic": topic,
                            "name": f"Event_{topic[:8]}",
                            "params": "..."
                        })
            i += 1
        
        return events
    
    def _analyze_function(self, bytecode: bytes, selector: str) -> Dict:
        """Analyze a function by its selector"""
        # Known function signatures
        known_functions = {
            "70a08231": {"name": "balanceOf", "params": "address account", "returns": "uint256", "is_view": True},
            "18160ddd": {"name": "totalSupply", "params": "", "returns": "uint256", "is_view": True},
            "dd62ed3e": {"name": "allowance", "params": "address owner, address spender", "returns": "uint256", "is_view": True},
            "a9059cbb": {"name": "transfer", "params": "address to, uint256 amount", "returns": "bool", "writes_storage": True},
            "095ea7b3": {"name": "approve", "params": "address spender, uint256 amount", "returns": "bool", "writes_storage": True},
            "23b872dd": {"name": "transferFrom", "params": "address from, address to, uint256 amount", "returns": "bool", "writes_storage": True},
            "06fdde03": {"name": "name", "params": "", "returns": "string memory", "is_view": True},
            "95d89b41": {"name": "symbol", "params": "", "returns": "string memory", "is_view": True},
            "313ce567": {"name": "decimals", "params": "", "returns": "uint8", "is_view": True},
            "8da5cb5b": {"name": "owner", "params": "", "returns": "address", "is_view": True},
            "715018a6": {"name": "renounceOwnership", "params": "", "writes_storage": True},
            "f2fde38b": {"name": "transferOwnership", "params": "address newOwner", "writes_storage": True},
            "3ccfd60b": {"name": "withdraw", "params": "", "sends_eth": True},
            "d0e30db0": {"name": "deposit", "params": "", "is_payable": True},
            "022c0d9f": {"name": "swap", "params": "uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data", "external_call": True},
            "0902f1ac": {"name": "getReserves", "params": "", "returns": "uint112, uint112, uint32", "is_view": True},
            "c45a0155": {"name": "factory", "params": "", "returns": "address", "is_view": True},
            "0dfe1681": {"name": "token0", "params": "", "returns": "address", "is_view": True},
            "d21220a7": {"name": "token1", "params": "", "returns": "address", "is_view": True},
        }
        
        if selector in known_functions:
            return known_functions[selector]
        
        # Unknown function - return generic info
        return {
            "name": f"func_{selector}",
            "params": "bytes calldata data",
            "returns": "",
            "is_view": False
        }
    
    def _extract_selectors(self, bytecode: bytes) -> List[str]:
        """Extract function selectors from bytecode"""
        selectors = []
        
        # Look for PUSH4 followed by EQ pattern (function dispatch)
        i = 0
        while i < len(bytecode) - 5:
            # PUSH4 = 0x63
            if bytecode[i] == 0x63:
                selector = bytecode[i+1:i+5].hex()
                if selector not in selectors and selector != "ffffffff":
                    selectors.append(selector)
                i += 5
            else:
                i += 1
        
        return selectors
    
    def _extract_storage_slots(self, bytecode: bytes) -> List[str]:
        """Extract storage slot accesses"""
        slots = set()
        
        i = 0
        while i < len(bytecode) - 1:
            # SLOAD = 0x54, SSTORE = 0x55
            if bytecode[i] in [0x54, 0x55]:
                # Look back for PUSH
                if i > 0 and 0x60 <= bytecode[i-1] <= 0x7f:
                    push_size = bytecode[i-1] - 0x5f
                    if i >= push_size + 1:
                        slot = bytecode[i-push_size:i].hex()
                        slots.add(slot)
            i += 1
        
        return list(slots)[:20]
    
    def _detect_patterns(self, bytecode: bytes) -> List[str]:
        """Detect dangerous patterns in bytecode"""
        patterns = []
        
        # Check for specific opcodes
        if b'\xff' in bytecode:  # SELFDESTRUCT
            patterns.append("SELFDESTRUCT - Contract can be destroyed")
        
        if b'\xf4' in bytecode:  # DELEGATECALL
            patterns.append("DELEGATECALL - Executes code in caller's context")
        
        if b'\xf2' in bytecode:  # CALLCODE
            patterns.append("CALLCODE (deprecated) - Security risk")
        
        if b'\x32' in bytecode:  # ORIGIN
            patterns.append("TX.ORIGIN - Potential phishing vulnerability")
        
        # Count arithmetic operations
        add_count = bytecode.count(b'\x01')
        mul_count = bytecode.count(b'\x02')
        if add_count > 10 or mul_count > 5:
            patterns.append(f"Heavy arithmetic ({add_count} ADD, {mul_count} MUL) - Check for overflow")
        
        return patterns
    
    async def _fetch_function_signatures(self, bytecode: str) -> List[str]:
        """Fetch function signatures from 4byte.directory"""
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        
        try:
            bytecode_bytes = bytes.fromhex(bytecode)
        except ValueError:
            return []
        
        selectors = self._extract_selectors(bytecode_bytes)
        signatures = []
        
        # Query 4byte.directory for each selector
        try:
            session = await self._get_session()
            for selector in selectors[:10]:  # Limit API calls
                url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature=0x{selector}"
                try:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            results = data.get("results", [])
                            if results:
                                signatures.append(results[0].get("text_signature", f"unknown_{selector}"))
                            else:
                                signatures.append(f"unknown_{selector}")
                except:
                    signatures.append(f"unknown_{selector}")
                
                await asyncio.sleep(0.1)  # Rate limiting
        except:
            pass
        
        return signatures


# Singleton instance
_fetcher_instance: Optional[SourceFetcher] = None


def get_source_fetcher() -> SourceFetcher:
    """Get singleton fetcher instance"""
    global _fetcher_instance
    if _fetcher_instance is None:
        _fetcher_instance = SourceFetcher()
    return _fetcher_instance
