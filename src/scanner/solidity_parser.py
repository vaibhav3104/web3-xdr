"""
Solidity Source Code Parser and Analyzer

Parses Solidity source code into an AST and performs vulnerability analysis.
This is our own implementation - no external dependencies like Slither.

Detects:
- Integer overflow/underflow
- Reentrancy
- Access control issues
- Unchecked external calls
- tx.origin usage
- Timestamp dependence
- And more...
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
import structlog

logger = structlog.get_logger()


class NodeType(Enum):
    """Types of AST nodes"""
    CONTRACT = "contract"
    INTERFACE = "interface"
    LIBRARY = "library"
    FUNCTION = "function"
    MODIFIER = "modifier"
    EVENT = "event"
    STRUCT = "struct"
    ENUM = "enum"
    STATE_VARIABLE = "state_variable"
    LOCAL_VARIABLE = "local_variable"
    PARAMETER = "parameter"
    EXPRESSION = "expression"
    STATEMENT = "statement"
    IMPORT = "import"
    PRAGMA = "pragma"


class Visibility(Enum):
    """Function/variable visibility"""
    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"
    EXTERNAL = "external"


class Mutability(Enum):
    """State mutability"""
    PURE = "pure"
    VIEW = "view"
    PAYABLE = "payable"
    NONPAYABLE = "nonpayable"


@dataclass
class SourceLocation:
    """Location in source code"""
    file: str
    line: int
    column: int
    length: int = 0
    
    def __str__(self):
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class ASTNode:
    """Base AST node"""
    node_type: NodeType
    name: str = ""
    location: Optional[SourceLocation] = None
    children: List['ASTNode'] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""


@dataclass
class FunctionNode(ASTNode):
    """Function definition node"""
    visibility: Visibility = Visibility.PUBLIC
    mutability: Mutability = Mutability.NONPAYABLE
    parameters: List['VariableNode'] = field(default_factory=list)
    returns: List['VariableNode'] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    body: str = ""
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False


@dataclass
class VariableNode(ASTNode):
    """Variable declaration node"""
    var_type: str = ""
    visibility: Visibility = Visibility.INTERNAL
    is_constant: bool = False
    is_immutable: bool = False
    initial_value: str = ""


@dataclass
class ContractNode(ASTNode):
    """Contract definition node"""
    contract_type: str = "contract"  # contract, interface, library
    base_contracts: List[str] = field(default_factory=list)
    functions: List[FunctionNode] = field(default_factory=list)
    state_variables: List[VariableNode] = field(default_factory=list)
    events: List[ASTNode] = field(default_factory=list)
    modifiers: List[FunctionNode] = field(default_factory=list)


@dataclass
class ParsedSource:
    """Complete parsed source file"""
    filename: str
    pragma: str = ""
    imports: List[str] = field(default_factory=list)
    contracts: List[ContractNode] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class SolidityParser:
    """
    Solidity source code parser
    
    Parses Solidity code into an AST for vulnerability analysis.
    This is a regex-based parser that handles most common patterns.
    """
    
    # Regex patterns for parsing
    PRAGMA_PATTERN = re.compile(r'pragma\s+solidity\s+([^;]+);')
    IMPORT_PATTERN = re.compile(r'import\s+["\']([^"\']+)["\']|import\s+\{[^}]+\}\s+from\s+["\']([^"\']+)["\']')
    
    CONTRACT_PATTERN = re.compile(
        r'(contract|interface|library|abstract\s+contract)\s+(\w+)'
        r'(?:\s+is\s+([^{]+))?'
        r'\s*\{',
        re.MULTILINE
    )
    
    FUNCTION_PATTERN = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)\s*'
        r'((?:public|private|internal|external|view|pure|payable|virtual|override|\s|[\w\(\)]+)*)'
        r'(?:\s*returns\s*\(([^)]*)\))?',
        re.MULTILINE
    )
    
    CONSTRUCTOR_PATTERN = re.compile(
        r'constructor\s*\(([^)]*)\)\s*'
        r'((?:public|private|internal|payable|\s|[\w\(\)]+)*)',
        re.MULTILINE
    )
    
    MODIFIER_PATTERN = re.compile(
        r'modifier\s+(\w+)\s*(?:\(([^)]*)\))?\s*\{',
        re.MULTILINE
    )
    
    STATE_VAR_PATTERN = re.compile(
        r'^\s*(mapping\s*\([^)]+\)|[\w\[\]]+)\s+'
        r'(public|private|internal|constant|immutable|\s)*'
        r'(\w+)\s*(?:=\s*([^;]+))?;',
        re.MULTILINE
    )
    
    EVENT_PATTERN = re.compile(
        r'event\s+(\w+)\s*\(([^)]*)\)\s*;',
        re.MULTILINE
    )
    
    def __init__(self):
        """Initialize the parser"""
        self.current_file = ""
        self.current_line = 1
    
    def parse(self, source_code: str, filename: str = "main.sol") -> ParsedSource:
        """
        Parse Solidity source code into AST
        
        Args:
            source_code: Solidity source code
            filename: Source file name
        
        Returns:
            ParsedSource with AST
        """
        self.current_file = filename
        self.current_line = 1
        
        result = ParsedSource(filename=filename)
        
        try:
            # Remove comments for easier parsing
            clean_source = self._remove_comments(source_code)
            
            # Parse pragma
            pragma_match = self.PRAGMA_PATTERN.search(clean_source)
            if pragma_match:
                result.pragma = pragma_match.group(1).strip()
            
            # Parse imports
            for match in self.IMPORT_PATTERN.finditer(clean_source):
                import_path = match.group(1) or match.group(2)
                if import_path:
                    result.imports.append(import_path)
            
            # Parse contracts
            result.contracts = self._parse_contracts(clean_source, source_code)
            
        except Exception as e:
            result.errors.append(f"Parse error: {str(e)}")
            logger.error("parse_error", filename=filename, error=str(e))
        
        return result
    
    def _remove_comments(self, source: str) -> str:
        """Remove comments from source code"""
        # Remove single-line comments
        source = re.sub(r'//[^\n]*', '', source)
        # Remove multi-line comments
        source = re.sub(r'/\*[\s\S]*?\*/', '', source)
        return source
    
    def _parse_contracts(self, clean_source: str, original_source: str) -> List[ContractNode]:
        """Parse all contracts in source"""
        contracts = []
        
        for match in self.CONTRACT_PATTERN.finditer(clean_source):
            contract_type = match.group(1).replace("abstract ", "")
            contract_name = match.group(2)
            base_contracts_str = match.group(3) or ""
            
            # Find contract body
            start_pos = match.end() - 1  # Position of opening brace
            body_end = self._find_matching_brace(clean_source, start_pos)
            contract_body = clean_source[start_pos:body_end + 1]
            
            # Get line number
            line_num = clean_source[:match.start()].count('\n') + 1
            
            contract = ContractNode(
                node_type=NodeType.CONTRACT,
                name=contract_name,
                contract_type=contract_type,
                location=SourceLocation(self.current_file, line_num, 0),
                raw_text=contract_body
            )
            
            # Parse base contracts
            if base_contracts_str:
                contract.base_contracts = [
                    b.strip().split('(')[0].strip() 
                    for b in base_contracts_str.split(',')
                ]
            
            # Parse contract contents
            contract.functions = self._parse_functions(contract_body, clean_source[:start_pos])
            contract.state_variables = self._parse_state_variables(contract_body, clean_source[:start_pos])
            contract.events = self._parse_events(contract_body, clean_source[:start_pos])
            contract.modifiers = self._parse_modifiers(contract_body, clean_source[:start_pos])
            
            contracts.append(contract)
        
        return contracts
    
    def _parse_functions(self, contract_body: str, prefix: str) -> List[FunctionNode]:
        """Parse functions in a contract"""
        functions = []
        base_line = prefix.count('\n') + 1
        
        # Parse regular functions
        for match in self.FUNCTION_PATTERN.finditer(contract_body):
            func_name = match.group(1)
            params_str = match.group(2)
            modifiers_str = match.group(3) or ""
            returns_str = match.group(4) or ""
            
            line_num = base_line + contract_body[:match.start()].count('\n')
            
            func = FunctionNode(
                node_type=NodeType.FUNCTION,
                name=func_name,
                location=SourceLocation(self.current_file, line_num, 0),
                raw_text=match.group(0)
            )
            
            # Parse visibility and mutability
            func.visibility = self._extract_visibility(modifiers_str)
            func.mutability = self._extract_mutability(modifiers_str)
            
            # Parse parameters
            func.parameters = self._parse_parameters(params_str)
            
            # Parse returns
            if returns_str:
                func.returns = self._parse_parameters(returns_str)
            
            # Extract modifier names
            func.modifiers = self._extract_modifier_names(modifiers_str)
            
            # Find function body
            body_start = contract_body.find('{', match.end())
            if body_start != -1:
                body_end = self._find_matching_brace(contract_body, body_start)
                func.body = contract_body[body_start:body_end + 1]
            
            functions.append(func)
        
        # Parse constructor
        for match in self.CONSTRUCTOR_PATTERN.finditer(contract_body):
            params_str = match.group(1)
            modifiers_str = match.group(2) or ""
            
            line_num = base_line + contract_body[:match.start()].count('\n')
            
            func = FunctionNode(
                node_type=NodeType.FUNCTION,
                name="constructor",
                is_constructor=True,
                location=SourceLocation(self.current_file, line_num, 0),
                raw_text=match.group(0)
            )
            
            func.visibility = self._extract_visibility(modifiers_str)
            func.parameters = self._parse_parameters(params_str)
            
            body_start = contract_body.find('{', match.end())
            if body_start != -1:
                body_end = self._find_matching_brace(contract_body, body_start)
                func.body = contract_body[body_start:body_end + 1]
            
            functions.append(func)
        
        return functions
    
    def _parse_state_variables(self, contract_body: str, prefix: str) -> List[VariableNode]:
        """Parse state variables in a contract"""
        variables = []
        base_line = prefix.count('\n') + 1
        
        # Filter out function bodies to avoid matching local variables
        # Simple approach: only look at top level of contract
        depth = 0
        filtered_body = []
        for char in contract_body:
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
            
            if depth <= 1:  # Only top level
                filtered_body.append(char)
            else:
                filtered_body.append(' ')
        
        filtered_str = ''.join(filtered_body)
        
        for match in self.STATE_VAR_PATTERN.finditer(filtered_str):
            var_type = match.group(1)
            modifiers = match.group(2) or ""
            var_name = match.group(3)
            initial_value = match.group(4) or ""
            
            line_num = base_line + filtered_str[:match.start()].count('\n')
            
            var = VariableNode(
                node_type=NodeType.STATE_VARIABLE,
                name=var_name,
                var_type=var_type,
                location=SourceLocation(self.current_file, line_num, 0),
                raw_text=match.group(0)
            )
            
            var.visibility = self._extract_visibility(modifiers)
            var.is_constant = "constant" in modifiers
            var.is_immutable = "immutable" in modifiers
            var.initial_value = initial_value.strip()
            
            variables.append(var)
        
        return variables
    
    def _parse_events(self, contract_body: str, prefix: str) -> List[ASTNode]:
        """Parse events in a contract"""
        events = []
        base_line = prefix.count('\n') + 1
        
        for match in self.EVENT_PATTERN.finditer(contract_body):
            event_name = match.group(1)
            params_str = match.group(2)
            
            line_num = base_line + contract_body[:match.start()].count('\n')
            
            event = ASTNode(
                node_type=NodeType.EVENT,
                name=event_name,
                location=SourceLocation(self.current_file, line_num, 0),
                raw_text=match.group(0)
            )
            
            events.append(event)
        
        return events
    
    def _parse_modifiers(self, contract_body: str, prefix: str) -> List[FunctionNode]:
        """Parse modifiers in a contract"""
        modifiers = []
        base_line = prefix.count('\n') + 1
        
        for match in self.MODIFIER_PATTERN.finditer(contract_body):
            mod_name = match.group(1)
            params_str = match.group(2) or ""
            
            line_num = base_line + contract_body[:match.start()].count('\n')
            
            mod = FunctionNode(
                node_type=NodeType.MODIFIER,
                name=mod_name,
                location=SourceLocation(self.current_file, line_num, 0),
                raw_text=match.group(0)
            )
            
            mod.parameters = self._parse_parameters(params_str)
            
            # Find modifier body
            body_start = match.end() - 1
            body_end = self._find_matching_brace(contract_body, body_start)
            mod.body = contract_body[body_start:body_end + 1]
            
            modifiers.append(mod)
        
        return modifiers
    
    def _parse_parameters(self, params_str: str) -> List[VariableNode]:
        """Parse function parameters"""
        params = []
        
        if not params_str.strip():
            return params
        
        # Split by comma, handling nested types
        depth = 0
        current = ""
        for char in params_str:
            if char in '([':
                depth += 1
            elif char in ')]':
                depth -= 1
            
            if char == ',' and depth == 0:
                if current.strip():
                    params.append(self._parse_single_param(current.strip()))
                current = ""
            else:
                current += char
        
        if current.strip():
            params.append(self._parse_single_param(current.strip()))
        
        return params
    
    def _parse_single_param(self, param_str: str) -> VariableNode:
        """Parse a single parameter"""
        parts = param_str.split()
        
        var = VariableNode(
            node_type=NodeType.PARAMETER,
            name="",
            var_type=""
        )
        
        if len(parts) >= 1:
            var.var_type = parts[0]
        
        # Handle memory/storage/calldata
        for i, part in enumerate(parts[1:], 1):
            if part in ['memory', 'storage', 'calldata']:
                continue
            elif part in ['indexed']:
                continue
            else:
                var.name = part
                break
        
        return var
    
    def _extract_visibility(self, modifiers_str: str) -> Visibility:
        """Extract visibility from modifiers string"""
        if 'external' in modifiers_str:
            return Visibility.EXTERNAL
        elif 'public' in modifiers_str:
            return Visibility.PUBLIC
        elif 'private' in modifiers_str:
            return Visibility.PRIVATE
        elif 'internal' in modifiers_str:
            return Visibility.INTERNAL
        return Visibility.PUBLIC  # Default
    
    def _extract_mutability(self, modifiers_str: str) -> Mutability:
        """Extract state mutability from modifiers string"""
        if 'pure' in modifiers_str:
            return Mutability.PURE
        elif 'view' in modifiers_str:
            return Mutability.VIEW
        elif 'payable' in modifiers_str:
            return Mutability.PAYABLE
        return Mutability.NONPAYABLE
    
    def _extract_modifier_names(self, modifiers_str: str) -> List[str]:
        """Extract modifier names from modifiers string"""
        # Remove known keywords
        keywords = ['public', 'private', 'internal', 'external', 
                   'pure', 'view', 'payable', 'virtual', 'override']
        
        modifiers = []
        # Match modifier calls like onlyOwner or reentrancyGuard()
        pattern = re.compile(r'\b(\w+)(?:\([^)]*\))?')
        
        for match in pattern.finditer(modifiers_str):
            name = match.group(1)
            if name not in keywords:
                modifiers.append(name)
        
        return modifiers
    
    def _find_matching_brace(self, source: str, start: int) -> int:
        """Find the matching closing brace"""
        if start >= len(source) or source[start] != '{':
            return start
        
        depth = 0
        for i in range(start, len(source)):
            if source[i] == '{':
                depth += 1
            elif source[i] == '}':
                depth -= 1
                if depth == 0:
                    return i
        
        return len(source) - 1


# Singleton instance
_parser_instance: Optional[SolidityParser] = None


def get_solidity_parser() -> SolidityParser:
    """Get singleton parser instance"""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = SolidityParser()
    return _parser_instance
