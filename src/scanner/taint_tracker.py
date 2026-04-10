"""
Taint Analysis for Smart Contract Security

Tracks the flow of untrusted data (user inputs) through the contract
to detect when tainted data reaches sensitive operations.

Taint Sources:
- CALLDATALOAD (user input)
- CALLER (msg.sender)
- ORIGIN (tx.origin)
- CALLVALUE (msg.value)

Taint Sinks (dangerous operations with tainted data):
- SSTORE (storage write)
- CALL/DELEGATECALL target
- SELFDESTRUCT recipient
- CREATE/CREATE2 value
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
import structlog

logger = structlog.get_logger()


class TaintSource(Enum):
    """Sources of tainted (untrusted) data"""
    CALLDATA = "calldata"          # User-provided call data
    CALLER = "caller"              # msg.sender
    ORIGIN = "origin"              # tx.origin
    CALLVALUE = "callvalue"        # msg.value
    RETURNDATA = "returndata"      # Data from external calls
    EXTCODESIZE = "extcodesize"    # External contract info
    BALANCE = "balance"            # Account balance (can be manipulated)


class TaintSink(Enum):
    """Sensitive operations that shouldn't receive tainted data"""
    STORAGE_WRITE = "storage_write"      # SSTORE
    CALL_TARGET = "call_target"          # Target of CALL
    CALL_VALUE = "call_value"            # Value sent in CALL
    DELEGATECALL_TARGET = "delegatecall" # Target of DELEGATECALL
    SELFDESTRUCT = "selfdestruct"        # SELFDESTRUCT recipient
    CREATE_VALUE = "create_value"        # Value for CREATE/CREATE2
    JUMP_DEST = "jump_dest"              # JUMP destination


@dataclass
class TaintedValue:
    """Represents a tainted value with its source"""
    source: TaintSource
    source_pc: int  # Where the taint originated
    propagation_path: List[int] = field(default_factory=list)  # PCs through which taint flowed
    
    def __hash__(self):
        return hash((self.source, self.source_pc))


@dataclass
class TaintViolation:
    """Represents a taint violation (tainted data reaching a sink)"""
    sink: TaintSink
    sink_pc: int
    tainted_value: TaintedValue
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    
    def to_dict(self) -> Dict:
        return {
            "sink": self.sink.value,
            "sink_pc": self.sink_pc,
            "source": self.tainted_value.source.value,
            "source_pc": self.tainted_value.source_pc,
            "propagation_path": self.tainted_value.propagation_path,
            "severity": self.severity,
            "description": self.description
        }


class TaintTracker:
    """
    Taint analysis engine for EVM bytecode
    
    Tracks flow of untrusted data through contract execution
    and reports when tainted data reaches sensitive operations.
    """
    
    # Opcodes that introduce taint
    TAINT_SOURCES = {
        0x35: TaintSource.CALLDATA,     # CALLDATALOAD
        0x33: TaintSource.CALLER,       # CALLER
        0x32: TaintSource.ORIGIN,       # ORIGIN
        0x34: TaintSource.CALLVALUE,    # CALLVALUE
        0x3D: TaintSource.RETURNDATA,   # RETURNDATASIZE
        0x3E: TaintSource.RETURNDATA,   # RETURNDATACOPY
        0x3B: TaintSource.EXTCODESIZE,  # EXTCODESIZE
        0x31: TaintSource.BALANCE,      # BALANCE
    }
    
    # Opcodes that are taint sinks
    TAINT_SINKS = {
        0x55: TaintSink.STORAGE_WRITE,     # SSTORE
        0xF1: TaintSink.CALL_TARGET,       # CALL
        0xF2: TaintSink.CALL_TARGET,       # CALLCODE
        0xF4: TaintSink.DELEGATECALL_TARGET, # DELEGATECALL
        0xFF: TaintSink.SELFDESTRUCT,      # SELFDESTRUCT
        0xF0: TaintSink.CREATE_VALUE,      # CREATE
        0xF5: TaintSink.CREATE_VALUE,      # CREATE2
        0x56: TaintSink.JUMP_DEST,         # JUMP
    }
    
    # Opcodes that propagate taint
    PROPAGATING_OPCODES = {
        # Arithmetic (result is tainted if any operand is tainted)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        # Comparison (result is tainted if any operand is tainted)
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        # Bitwise (result is tainted if any operand is tainted)
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        # SHA3 (result is tainted if input is tainted)
        0x20,
    }
    
    # Opcodes that sanitize taint (under certain conditions)
    SANITIZING_OPCODES = {
        0x14,  # EQ - can sanitize if comparing with constant
        0x15,  # ISZERO - can sanitize
    }
    
    def __init__(self):
        """Initialize the taint tracker"""
        self.violations: List[TaintViolation] = []
        self.tainted_stack: List[Optional[TaintedValue]] = []
        self.tainted_memory: Dict[int, TaintedValue] = {}
        self.tainted_storage: Dict[int, TaintedValue] = {}
    
    def analyze(self, bytecode: str) -> List[TaintViolation]:
        """
        Perform taint analysis on bytecode
        
        Args:
            bytecode: Contract bytecode (hex string)
        
        Returns:
            List of taint violations found
        """
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        
        try:
            bytecode_bytes = bytes.fromhex(bytecode)
        except ValueError:
            logger.error("invalid_bytecode")
            return []
        
        self.violations = []
        self.tainted_stack = []
        self.tainted_memory = {}
        self.tainted_storage = {}
        
        pc = 0
        max_iterations = len(bytecode_bytes) * 2  # Prevent infinite loops
        iterations = 0
        
        while pc < len(bytecode_bytes) and iterations < max_iterations:
            iterations += 1
            opcode = bytecode_bytes[pc]
            
            # Check if this is a taint source
            if opcode in self.TAINT_SOURCES:
                self._handle_taint_source(opcode, pc)
            
            # Check if this is a taint sink
            elif opcode in self.TAINT_SINKS:
                self._handle_taint_sink(opcode, pc)
            
            # Check if this propagates taint
            elif opcode in self.PROPAGATING_OPCODES:
                self._handle_taint_propagation(opcode, pc)
            
            # Handle stack operations
            else:
                self._handle_stack_operation(opcode, pc)
            
            # Move to next instruction
            if 0x60 <= opcode <= 0x7F:  # PUSH
                push_size = opcode - 0x5F
                pc += push_size + 1
            else:
                pc += 1
            
            # Handle control flow (simplified)
            if opcode == 0x56:  # JUMP
                break  # Can't follow dynamic jumps easily
            elif opcode == 0x00 or opcode == 0xF3 or opcode == 0xFD:  # STOP/RETURN/REVERT
                break
        
        return self.violations
    
    def _handle_taint_source(self, opcode: int, pc: int):
        """Handle opcodes that introduce taint"""
        source = self.TAINT_SOURCES[opcode]
        tainted = TaintedValue(source=source, source_pc=pc)
        
        # Push tainted value to stack
        self.tainted_stack.append(tainted)
        
        logger.debug("taint_introduced", source=source.value, pc=pc)
    
    def _handle_taint_sink(self, opcode: int, pc: int):
        """Handle opcodes that are taint sinks"""
        sink = self.TAINT_SINKS[opcode]
        
        # Check which stack position is the sensitive one
        sensitive_positions = self._get_sensitive_positions(opcode)
        
        for pos in sensitive_positions:
            if pos < len(self.tainted_stack):
                idx = -(pos + 1)  # Convert to negative index
                if idx >= -len(self.tainted_stack):
                    tainted = self.tainted_stack[idx]
                    if tainted is not None:
                        # Found taint flowing to sink!
                        violation = self._create_violation(sink, pc, tainted)
                        self.violations.append(violation)
                        logger.warning(
                            "taint_violation",
                            sink=sink.value,
                            source=tainted.source.value,
                            pc=pc
                        )
        
        # Pop consumed stack elements
        self._pop_stack(self._get_pop_count(opcode))
        
        # Push result if applicable
        if opcode in [0xF1, 0xF2, 0xF4, 0xFA]:  # CALL variants
            self.tainted_stack.append(None)  # Return value could be tainted
    
    def _handle_taint_propagation(self, opcode: int, pc: int):
        """Handle opcodes that propagate taint"""
        pop_count = self._get_pop_count(opcode)
        push_count = self._get_push_count(opcode)
        
        # Check if any operand is tainted
        tainted_operand = None
        for i in range(min(pop_count, len(self.tainted_stack))):
            idx = -(i + 1)
            if idx >= -len(self.tainted_stack) and self.tainted_stack[idx] is not None:
                tainted_operand = self.tainted_stack[idx]
                break
        
        # Pop operands
        self._pop_stack(pop_count)
        
        # Push result (tainted if any operand was tainted)
        for _ in range(push_count):
            if tainted_operand:
                # Propagate taint
                new_taint = TaintedValue(
                    source=tainted_operand.source,
                    source_pc=tainted_operand.source_pc,
                    propagation_path=tainted_operand.propagation_path + [pc]
                )
                self.tainted_stack.append(new_taint)
            else:
                self.tainted_stack.append(None)
    
    def _handle_stack_operation(self, opcode: int, pc: int):
        """Handle general stack operations"""
        
        # POP
        if opcode == 0x50:
            self._pop_stack(1)
        
        # DUP1-DUP16
        elif 0x80 <= opcode <= 0x8F:
            dup_pos = opcode - 0x7F
            if dup_pos <= len(self.tainted_stack):
                idx = -dup_pos
                self.tainted_stack.append(
                    self.tainted_stack[idx] if idx >= -len(self.tainted_stack) else None
                )
        
        # SWAP1-SWAP16
        elif 0x90 <= opcode <= 0x9F:
            swap_pos = opcode - 0x8F
            if swap_pos < len(self.tainted_stack):
                idx = -(swap_pos + 1)
                if idx >= -len(self.tainted_stack):
                    self.tainted_stack[-1], self.tainted_stack[idx] = \
                        self.tainted_stack[idx], self.tainted_stack[-1]
        
        # PUSH1-PUSH32
        elif 0x60 <= opcode <= 0x7F:
            self.tainted_stack.append(None)  # Constants are not tainted
        
        # MLOAD
        elif opcode == 0x51:
            self._pop_stack(1)  # Pop offset
            # Check if memory location is tainted
            # Simplified: just push None
            self.tainted_stack.append(None)
        
        # MSTORE
        elif opcode == 0x52:
            if len(self.tainted_stack) >= 2:
                offset = self.tainted_stack[-2] if len(self.tainted_stack) >= 2 else None
                value = self.tainted_stack[-1] if len(self.tainted_stack) >= 1 else None
                # Track taint in memory (simplified)
                if value is not None and isinstance(offset, int):
                    self.tainted_memory[offset] = value
            self._pop_stack(2)
        
        # SLOAD
        elif opcode == 0x54:
            self._pop_stack(1)  # Pop slot
            # Check if storage slot is tainted
            self.tainted_stack.append(None)  # Simplified
        
        # SSTORE handled in sink
        
        # Other opcodes - simplified handling
        else:
            pop_count = self._get_pop_count(opcode)
            push_count = self._get_push_count(opcode)
            self._pop_stack(pop_count)
            for _ in range(push_count):
                self.tainted_stack.append(None)
    
    def _pop_stack(self, count: int):
        """Pop items from tainted stack"""
        for _ in range(min(count, len(self.tainted_stack))):
            self.tainted_stack.pop()
    
    def _get_sensitive_positions(self, opcode: int) -> List[int]:
        """Get stack positions that are sensitive for this sink opcode"""
        # Position 0 = top of stack
        if opcode == 0x55:  # SSTORE
            return [1]  # Value being stored
        elif opcode == 0xF1:  # CALL
            return [1, 2]  # Target address, value
        elif opcode == 0xF4:  # DELEGATECALL
            return [1]  # Target address
        elif opcode == 0xFF:  # SELFDESTRUCT
            return [0]  # Recipient
        elif opcode == 0x56:  # JUMP
            return [0]  # Destination
        elif opcode in [0xF0, 0xF5]:  # CREATE/CREATE2
            return [0]  # Value
        return []
    
    def _get_pop_count(self, opcode: int) -> int:
        """Get number of stack items consumed by opcode"""
        pop_counts = {
            0x01: 2, 0x02: 2, 0x03: 2, 0x04: 2, 0x05: 2,  # Arithmetic
            0x06: 2, 0x07: 2, 0x08: 3, 0x09: 3, 0x0A: 2,
            0x10: 2, 0x11: 2, 0x12: 2, 0x13: 2, 0x14: 2,  # Comparison
            0x15: 1,  # ISZERO
            0x16: 2, 0x17: 2, 0x18: 2, 0x19: 1,  # Bitwise
            0x20: 2,  # SHA3
            0x50: 1,  # POP
            0x51: 1,  # MLOAD
            0x52: 2,  # MSTORE
            0x54: 1,  # SLOAD
            0x55: 2,  # SSTORE
            0x56: 1,  # JUMP
            0x57: 2,  # JUMPI
            0xF1: 7,  # CALL
            0xF4: 6,  # DELEGATECALL
            0xFF: 1,  # SELFDESTRUCT
        }
        return pop_counts.get(opcode, 0)
    
    def _get_push_count(self, opcode: int) -> int:
        """Get number of stack items produced by opcode"""
        push_counts = {
            0x01: 1, 0x02: 1, 0x03: 1, 0x04: 1, 0x05: 1,  # Arithmetic
            0x06: 1, 0x07: 1, 0x08: 1, 0x09: 1, 0x0A: 1,
            0x10: 1, 0x11: 1, 0x12: 1, 0x13: 1, 0x14: 1,  # Comparison
            0x15: 1,  # ISZERO
            0x16: 1, 0x17: 1, 0x18: 1, 0x19: 1,  # Bitwise
            0x20: 1,  # SHA3
            0x30: 1, 0x31: 1, 0x32: 1, 0x33: 1, 0x34: 1,  # Environment
            0x35: 1, 0x36: 1, 0x42: 1, 0x43: 1,
            0x51: 1,  # MLOAD
            0x54: 1,  # SLOAD
            0xF1: 1,  # CALL
            0xF4: 1,  # DELEGATECALL
        }
        return push_counts.get(opcode, 0)
    
    def _create_violation(
        self,
        sink: TaintSink,
        pc: int,
        tainted: TaintedValue
    ) -> TaintViolation:
        """Create a taint violation object"""
        
        # Determine severity based on sink type
        severity_map = {
            TaintSink.DELEGATECALL_TARGET: "CRITICAL",
            TaintSink.CALL_TARGET: "HIGH",
            TaintSink.SELFDESTRUCT: "CRITICAL",
            TaintSink.STORAGE_WRITE: "MEDIUM",
            TaintSink.CALL_VALUE: "HIGH",
            TaintSink.CREATE_VALUE: "HIGH",
            TaintSink.JUMP_DEST: "CRITICAL",
        }
        
        severity = severity_map.get(sink, "MEDIUM")
        
        # Create description
        descriptions = {
            TaintSink.DELEGATECALL_TARGET: 
                f"User input ({tainted.source.value}) flows to DELEGATECALL target. "
                f"Attacker could execute arbitrary code in contract's context.",
            TaintSink.CALL_TARGET:
                f"User input ({tainted.source.value}) flows to CALL target address. "
                f"Attacker could redirect funds to arbitrary address.",
            TaintSink.SELFDESTRUCT:
                f"User input ({tainted.source.value}) flows to SELFDESTRUCT recipient. "
                f"Attacker could destroy contract and steal funds.",
            TaintSink.STORAGE_WRITE:
                f"User input ({tainted.source.value}) flows to storage write. "
                f"Attacker could corrupt contract state.",
            TaintSink.CALL_VALUE:
                f"User input ({tainted.source.value}) flows to CALL value. "
                f"Attacker could manipulate ETH transfer amount.",
            TaintSink.JUMP_DEST:
                f"User input ({tainted.source.value}) flows to JUMP destination. "
                f"Attacker could hijack control flow.",
        }
        
        description = descriptions.get(
            sink,
            f"Tainted data ({tainted.source.value}) reaches sensitive operation ({sink.value})"
        )
        
        return TaintViolation(
            sink=sink,
            sink_pc=pc,
            tainted_value=tainted,
            severity=severity,
            description=description
        )
    
    def get_summary(self) -> Dict:
        """Get summary of taint analysis"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for violation in self.violations:
            severity_counts[violation.severity] = \
                severity_counts.get(violation.severity, 0) + 1
        
        return {
            "total_violations": len(self.violations),
            "by_severity": severity_counts,
            "violations": [v.to_dict() for v in self.violations]
        }
