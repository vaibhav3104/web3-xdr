"""
Lucene Query Parser for Sentinel3 Log Explorer
Supports standard Lucene syntax for querying normalized events

Supported Syntax:
- Field queries: field:value, field:"exact phrase"
- Boolean: AND, OR, NOT, &&, ||, !
- Wildcards: *, ? (e.g., chain:eth*, event_type:T?ansfer)
- Ranges: field:[min TO max], field:{min TO max} (exclusive)
- Grouping: (term1 OR term2) AND term3
- Existence: _exists_:field, _missing_:field
- Regex: field:/pattern/

Examples:
- chain:ethereum AND severity:critical
- event_type:Transfer AND amount:[1000 TO *]
- (chain:ethereum OR chain:polygon) AND NOT severity:info
- contract_address:0x* AND timestamp:[2024-01-01 TO 2024-01-31]
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class TokenType(Enum):
    """Token types for the lexer"""
    FIELD = "FIELD"
    VALUE = "VALUE"
    QUOTED = "QUOTED"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    COLON = "COLON"
    TO = "TO"
    WILDCARD = "WILDCARD"
    REGEX = "REGEX"
    EXISTS = "EXISTS"
    MISSING = "MISSING"
    EOF = "EOF"


@dataclass
class Token:
    """Lexer token"""
    type: TokenType
    value: str
    position: int = 0


@dataclass
class QueryNode:
    """Base class for AST nodes"""
    pass


@dataclass
class FieldQuery(QueryNode):
    """Field:value query"""
    field: str
    value: str
    is_wildcard: bool = False
    is_regex: bool = False
    is_phrase: bool = False


@dataclass
class RangeQuery(QueryNode):
    """Range query [min TO max] or {min TO max}"""
    field: str
    min_val: Optional[str]
    max_val: Optional[str]
    include_min: bool = True
    include_max: bool = True


@dataclass
class ExistsQuery(QueryNode):
    """Field existence check"""
    field: str
    exists: bool = True  # False for _missing_


@dataclass
class BoolQuery(QueryNode):
    """Boolean combination of queries"""
    operator: str  # AND, OR
    left: QueryNode
    right: QueryNode


@dataclass
class NotQuery(QueryNode):
    """Negation of a query"""
    query: QueryNode


@dataclass
class GroupQuery(QueryNode):
    """Grouped query (parentheses)"""
    query: QueryNode


class LuceneLexer:
    """Tokenizer for Lucene queries"""
    
    def __init__(self, query: str):
        self.query = query
        self.pos = 0
        self.tokens: List[Token] = []
    
    def tokenize(self) -> List[Token]:
        """Convert query string to tokens"""
        while self.pos < len(self.query):
            self._skip_whitespace()
            if self.pos >= len(self.query):
                break
            
            char = self.query[self.pos]
            
            # Operators and special characters
            if char == '(':
                self.tokens.append(Token(TokenType.LPAREN, '(', self.pos))
                self.pos += 1
            elif char == ')':
                self.tokens.append(Token(TokenType.RPAREN, ')', self.pos))
                self.pos += 1
            elif char == '[':
                self.tokens.append(Token(TokenType.LBRACKET, '[', self.pos))
                self.pos += 1
            elif char == ']':
                self.tokens.append(Token(TokenType.RBRACKET, ']', self.pos))
                self.pos += 1
            elif char == '{':
                self.tokens.append(Token(TokenType.LBRACE, '{', self.pos))
                self.pos += 1
            elif char == '}':
                self.tokens.append(Token(TokenType.RBRACE, '}', self.pos))
                self.pos += 1
            elif char == ':':
                self.tokens.append(Token(TokenType.COLON, ':', self.pos))
                self.pos += 1
            elif char == '"':
                self._read_quoted()
            elif char == '/':
                self._read_regex()
            elif char == '*' or char == '?':
                self.tokens.append(Token(TokenType.WILDCARD, char, self.pos))
                self.pos += 1
            elif self._check_keyword('AND') or self._check_keyword('&&'):
                self.tokens.append(Token(TokenType.AND, 'AND', self.pos))
                self.pos += 3 if self.query[self.pos:self.pos+3].upper() == 'AND' else 2
            elif self._check_keyword('OR') or self._check_keyword('||'):
                self.tokens.append(Token(TokenType.OR, 'OR', self.pos))
                self.pos += 2
            elif self._check_keyword('NOT') or char == '!':
                self.tokens.append(Token(TokenType.NOT, 'NOT', self.pos))
                self.pos += 3 if self.query[self.pos:self.pos+3].upper() == 'NOT' else 1
            elif self._check_keyword('TO'):
                self.tokens.append(Token(TokenType.TO, 'TO', self.pos))
                self.pos += 2
            elif self._check_keyword('_exists_'):
                self.tokens.append(Token(TokenType.EXISTS, '_exists_', self.pos))
                self.pos += 8
            elif self._check_keyword('_missing_'):
                self.tokens.append(Token(TokenType.MISSING, '_missing_', self.pos))
                self.pos += 9
            else:
                self._read_value()
        
        self.tokens.append(Token(TokenType.EOF, '', self.pos))
        return self.tokens
    
    def _skip_whitespace(self):
        """Skip whitespace characters"""
        while self.pos < len(self.query) and self.query[self.pos].isspace():
            self.pos += 1
    
    def _check_keyword(self, keyword: str) -> bool:
        """Check if current position matches a keyword"""
        end = self.pos + len(keyword)
        if end > len(self.query):
            return False
        
        text = self.query[self.pos:end]
        if text.upper() == keyword.upper():
            # Make sure it's not part of a larger word
            if end < len(self.query) and self.query[end].isalnum():
                return False
            return True
        return False
    
    def _read_quoted(self):
        """Read a quoted string"""
        start = self.pos
        self.pos += 1  # Skip opening quote
        value = ""
        
        while self.pos < len(self.query):
            char = self.query[self.pos]
            if char == '"':
                self.pos += 1  # Skip closing quote
                break
            elif char == '\\' and self.pos + 1 < len(self.query):
                self.pos += 1
                value += self.query[self.pos]
            else:
                value += char
            self.pos += 1
        
        self.tokens.append(Token(TokenType.QUOTED, value, start))
    
    def _read_regex(self):
        """Read a regex pattern /pattern/"""
        start = self.pos
        self.pos += 1  # Skip opening /
        value = ""
        
        while self.pos < len(self.query):
            char = self.query[self.pos]
            if char == '/':
                self.pos += 1  # Skip closing /
                break
            elif char == '\\' and self.pos + 1 < len(self.query):
                self.pos += 1
                value += '\\' + self.query[self.pos]
            else:
                value += char
            self.pos += 1
        
        self.tokens.append(Token(TokenType.REGEX, value, start))
    
    def _read_value(self):
        """Read an unquoted value"""
        start = self.pos
        value = ""
        
        while self.pos < len(self.query):
            char = self.query[self.pos]
            # Stop at special characters
            if char in ' \t\n():[]{}":' or char == '/' and value:
                break
            value += char
            self.pos += 1
        
        if value:
            # Check if it contains wildcards
            if '*' in value or '?' in value:
                self.tokens.append(Token(TokenType.WILDCARD, value, start))
            else:
                self.tokens.append(Token(TokenType.VALUE, value, start))


class LuceneParser:
    """Parser for Lucene queries - builds AST"""
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
    
    @property
    def current(self) -> Token:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else Token(TokenType.EOF, '', -1)
    
    def advance(self) -> Token:
        token = self.current
        self.pos += 1
        return token
    
    def peek(self, offset: int = 1) -> Token:
        pos = self.pos + offset
        return self.tokens[pos] if pos < len(self.tokens) else Token(TokenType.EOF, '', -1)
    
    def parse(self) -> Optional[QueryNode]:
        """Parse the token stream into an AST"""
        if self.current.type == TokenType.EOF:
            return None
        return self._parse_or()
    
    def _parse_or(self) -> QueryNode:
        """Parse OR expressions"""
        left = self._parse_and()
        
        while self.current.type == TokenType.OR:
            self.advance()  # consume OR
            right = self._parse_and()
            left = BoolQuery('OR', left, right)
        
        return left
    
    def _parse_and(self) -> QueryNode:
        """Parse AND expressions (implicit and explicit)"""
        left = self._parse_not()
        
        while True:
            if self.current.type == TokenType.AND:
                self.advance()  # consume AND
                right = self._parse_not()
                left = BoolQuery('AND', left, right)
            elif self.current.type not in (TokenType.OR, TokenType.RPAREN, TokenType.EOF):
                # Implicit AND
                right = self._parse_not()
                left = BoolQuery('AND', left, right)
            else:
                break
        
        return left
    
    def _parse_not(self) -> QueryNode:
        """Parse NOT expressions"""
        if self.current.type == TokenType.NOT:
            self.advance()  # consume NOT
            query = self._parse_primary()
            return NotQuery(query)
        return self._parse_primary()
    
    def _parse_primary(self) -> QueryNode:
        """Parse primary expressions (field queries, groups, etc.)"""
        token = self.current
        
        # Grouped expression
        if token.type == TokenType.LPAREN:
            self.advance()  # consume (
            query = self._parse_or()
            if self.current.type == TokenType.RPAREN:
                self.advance()  # consume )
            return GroupQuery(query)
        
        # _exists_ or _missing_
        if token.type == TokenType.EXISTS:
            self.advance()
            if self.current.type == TokenType.COLON:
                self.advance()
            field = self.advance().value
            return ExistsQuery(field, exists=True)
        
        if token.type == TokenType.MISSING:
            self.advance()
            if self.current.type == TokenType.COLON:
                self.advance()
            field = self.advance().value
            return ExistsQuery(field, exists=False)
        
        # Field:value or standalone value
        if token.type in (TokenType.VALUE, TokenType.WILDCARD):
            field_or_value = self.advance().value
            
            # Check for field:value
            if self.current.type == TokenType.COLON:
                self.advance()  # consume :
                return self._parse_field_value(field_or_value)
            else:
                # Standalone value - search all fields
                is_wildcard = '*' in field_or_value or '?' in field_or_value
                return FieldQuery('_all', field_or_value, is_wildcard=is_wildcard)
        
        # Quoted value
        if token.type == TokenType.QUOTED:
            value = self.advance().value
            return FieldQuery('_all', value, is_phrase=True)
        
        # Skip unknown tokens
        self.advance()
        return FieldQuery('_all', '*', is_wildcard=True)
    
    def _parse_field_value(self, field: str) -> QueryNode:
        """Parse the value part of a field:value query"""
        token = self.current
        
        # Range query [min TO max] or {min TO max}
        if token.type in (TokenType.LBRACKET, TokenType.LBRACE):
            include_min = token.type == TokenType.LBRACKET
            self.advance()
            
            min_val = None
            if self.current.type in (TokenType.VALUE, TokenType.WILDCARD):
                min_val = self.advance().value
                if min_val == '*':
                    min_val = None
            
            if self.current.type == TokenType.TO:
                self.advance()
            
            max_val = None
            if self.current.type in (TokenType.VALUE, TokenType.WILDCARD):
                max_val = self.advance().value
                if max_val == '*':
                    max_val = None
            
            include_max = self.current.type == TokenType.RBRACKET
            if self.current.type in (TokenType.RBRACKET, TokenType.RBRACE):
                self.advance()
            
            return RangeQuery(field, min_val, max_val, include_min, include_max)
        
        # Quoted value
        if token.type == TokenType.QUOTED:
            value = self.advance().value
            return FieldQuery(field, value, is_phrase=True)
        
        # Regex
        if token.type == TokenType.REGEX:
            pattern = self.advance().value
            return FieldQuery(field, pattern, is_regex=True)
        
        # Wildcard or regular value
        if token.type in (TokenType.VALUE, TokenType.WILDCARD):
            value = self.advance().value
            is_wildcard = '*' in value or '?' in value
            return FieldQuery(field, value, is_wildcard=is_wildcard)
        
        # Default
        return FieldQuery(field, '*', is_wildcard=True)


class LuceneQueryExecutor:
    """Execute parsed Lucene queries against event data"""
    
    # Field aliases for common queries
    FIELD_ALIASES = {
        'chain': ['chain_id', 'chain'],
        'type': ['event_type', 'type'],
        'severity': ['severity'],
        'address': ['contract_address', 'from_address', 'to_address', 'address'],
        'hash': ['tx_hash', 'block_hash', 'hash'],
        'amount': ['amount', 'value'],
        'block': ['block_number', 'block'],
        'timestamp': ['timestamp', 'block_timestamp'],
        'protocol': ['protocol', 'bridge_id'],
        'token': ['token_symbol', 'token_address', 'token'],
    }
    
    def __init__(self):
        self.stats = {
            'queries_executed': 0,
            'events_matched': 0,
            'errors': 0,
        }
    
    def execute(self, query: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute a Lucene query against a list of events"""
        if not query or not query.strip():
            return events
        
        try:
            # Parse query
            lexer = LuceneLexer(query)
            tokens = lexer.tokenize()
            parser = LuceneParser(tokens)
            ast = parser.parse()
            
            if ast is None:
                return events
            
            # Execute against events
            results = []
            for event in events:
                if self._evaluate(ast, event):
                    results.append(event)
            
            self.stats['queries_executed'] += 1
            self.stats['events_matched'] += len(results)
            
            logger.debug(
                "lucene_query_executed",
                query=query,
                total_events=len(events),
                matched=len(results)
            )
            
            return results
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error("lucene_query_error", query=query, error=str(e))
            # Fall back to simple text search
            return self._fallback_search(query, events)
    
    def _evaluate(self, node: QueryNode, event: Dict[str, Any]) -> bool:
        """Evaluate a query node against an event"""
        if isinstance(node, FieldQuery):
            return self._eval_field_query(node, event)
        elif isinstance(node, RangeQuery):
            return self._eval_range_query(node, event)
        elif isinstance(node, ExistsQuery):
            return self._eval_exists_query(node, event)
        elif isinstance(node, BoolQuery):
            return self._eval_bool_query(node, event)
        elif isinstance(node, NotQuery):
            return not self._evaluate(node.query, event)
        elif isinstance(node, GroupQuery):
            return self._evaluate(node.query, event)
        return False
    
    def _eval_field_query(self, node: FieldQuery, event: Dict[str, Any]) -> bool:
        """Evaluate a field:value query"""
        # Get field value(s)
        if node.field == '_all':
            # Search all fields
            values = [str(v) for v in event.values() if v is not None]
        else:
            # Get specific field(s)
            fields = self.FIELD_ALIASES.get(node.field, [node.field])
            values = []
            for f in fields:
                if f in event and event[f] is not None:
                    values.append(str(event[f]))
        
        if not values:
            return False
        
        # Match value
        search_val = node.value.lower()
        
        for value in values:
            value_lower = value.lower()
            
            if node.is_regex:
                try:
                    if re.search(search_val, value_lower):
                        return True
                except re.error:
                    pass
            elif node.is_wildcard:
                # Convert wildcards to regex
                pattern = search_val.replace('*', '.*').replace('?', '.')
                if re.match(f'^{pattern}$', value_lower):
                    return True
            elif node.is_phrase:
                if search_val in value_lower:
                    return True
            else:
                if search_val == value_lower:
                    return True
        
        return False
    
    def _eval_range_query(self, node: RangeQuery, event: Dict[str, Any]) -> bool:
        """Evaluate a range query"""
        fields = self.FIELD_ALIASES.get(node.field, [node.field])
        
        for f in fields:
            if f not in event or event[f] is None:
                continue
            
            value = event[f]
            
            # Try to compare as numbers
            try:
                num_val = float(value)
                min_num = float(node.min_val) if node.min_val else None
                max_num = float(node.max_val) if node.max_val else None
                
                if min_num is not None:
                    if node.include_min and num_val < min_num:
                        continue
                    if not node.include_min and num_val <= min_num:
                        continue
                
                if max_num is not None:
                    if node.include_max and num_val > max_num:
                        continue
                    if not node.include_max and num_val >= max_num:
                        continue
                
                return True
                
            except (ValueError, TypeError):
                # Compare as strings
                str_val = str(value)
                min_str = node.min_val if node.min_val else ''
                max_str = node.max_val if node.max_val else '\uffff'
                
                if node.include_min and str_val < min_str:
                    continue
                if not node.include_min and str_val <= min_str:
                    continue
                if node.include_max and str_val > max_str:
                    continue
                if not node.include_max and str_val >= max_str:
                    continue
                
                return True
        
        return False
    
    def _eval_exists_query(self, node: ExistsQuery, event: Dict[str, Any]) -> bool:
        """Evaluate an existence query"""
        fields = self.FIELD_ALIASES.get(node.field, [node.field])
        
        for f in fields:
            exists = f in event and event[f] is not None
            if exists:
                return node.exists
        
        return not node.exists
    
    def _eval_bool_query(self, node: BoolQuery, event: Dict[str, Any]) -> bool:
        """Evaluate a boolean query"""
        left_result = self._evaluate(node.left, event)
        
        if node.operator == 'AND':
            if not left_result:
                return False
            return self._evaluate(node.right, event)
        else:  # OR
            if left_result:
                return True
            return self._evaluate(node.right, event)
    
    def _fallback_search(self, query: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simple text search fallback"""
        query_lower = query.lower()
        results = []
        
        for event in events:
            for value in event.values():
                if value is not None and query_lower in str(value).lower():
                    results.append(event)
                    break
        
        return results


# Singleton executor
_executor = LuceneQueryExecutor()


def parse_lucene_query(query: str) -> Optional[QueryNode]:
    """Parse a Lucene query string into an AST"""
    lexer = LuceneLexer(query)
    tokens = lexer.tokenize()
    parser = LuceneParser(tokens)
    return parser.parse()


def execute_lucene_query(query: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Execute a Lucene query against events"""
    return _executor.execute(query, events)


def get_query_syntax_help() -> Dict[str, Any]:
    """Get help documentation for Lucene query syntax"""
    return {
        "title": "Lucene Query Syntax",
        "description": "Powerful query language for searching events",
        "operators": {
            "AND": "Both conditions must match (also: &&)",
            "OR": "Either condition must match (also: ||)",
            "NOT": "Negates the condition (also: !)",
        },
        "field_queries": {
            "field:value": "Exact match on field",
            'field:"phrase"': "Phrase match (contains)",
            "field:val*": "Wildcard (* = any chars, ? = single char)",
            "field:/regex/": "Regular expression match",
        },
        "range_queries": {
            "[min TO max]": "Inclusive range (includes min and max)",
            "{min TO max}": "Exclusive range (excludes min and max)",
            "[min TO *]": "Greater than or equal to min",
            "[* TO max]": "Less than or equal to max",
        },
        "existence": {
            "_exists_:field": "Field exists and is not null",
            "_missing_:field": "Field is missing or null",
        },
        "field_aliases": {
            "chain": "chain_id",
            "type": "event_type",
            "address": "contract_address, from_address, to_address",
            "hash": "tx_hash, block_hash",
            "amount": "amount, value",
            "block": "block_number",
            "protocol": "protocol, bridge_id",
        },
        "examples": [
            {
                "query": "chain:ethereum AND severity:critical",
                "description": "Critical events on Ethereum"
            },
            {
                "query": "event_type:Transfer AND amount:[1000 TO *]",
                "description": "Transfer events with amount >= 1000"
            },
            {
                "query": "(chain:ethereum OR chain:polygon) AND NOT severity:info",
                "description": "Non-info events on Ethereum or Polygon"
            },
            {
                "query": "address:0x* AND type:Mint",
                "description": "Mint events for any address starting with 0x"
            },
            {
                "query": 'protocol:"Wormhole" AND severity:[warning TO critical]',
                "description": "Warning to critical Wormhole events"
            },
            {
                "query": "_exists_:tx_hash AND chain:arbitrum",
                "description": "Arbitrum events with transaction hash"
            },
        ],
    }

