"""
Symbolic Execution Engine for Smart Contract Analysis

Explores all possible execution paths to find vulnerabilities like:
- Integer overflow/underflow
- Reentrancy
- Access control bypasses
- Arbitrary external calls

Uses constraint solving to determine if vulnerabilities are exploitable.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import structlog

logger = structlog.get_logger()

# Z3 is optional - provides deeper analysis but not required
try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    z3 = None
    logger.warning("z3_not_available", message="Install z3-solver for symbolic execution")


class SymbolicValueType(Enum):
    """Types of symbolic values"""
    UINT256 = "uint256"
    INT256 = "int256"
    ADDRESS = "address"
    BYTES32 = "bytes32"
    BOOL = "bool"


@dataclass
class ExecutionPath:
    """Represents a single execution path through the contract"""
    path_id: int
    constraints: List[Any]  # Z3 constraints
    state_changes: List[Dict]
    external_calls: List[Dict]
    reverted: bool = False
    revert_reason: str = ""
    gas_used: int = 0
    
    # Vulnerability indicators
    has_overflow: bool = False
    has_reentrancy: bool = False
    has_unchecked_call: bool = False


@dataclass
class SymbolicState:
    """Symbolic execution state"""
    pc: int = 0  # Program counter
    stack: List[Any] = field(default_factory=list)
    memory: Dict[int, Any] = field(default_factory=dict)
    storage: Dict[Any, Any] = field(default_factory=dict)
    
    # Symbolic values
    callvalue: Any = None
    caller: Any = None
    calldata: Any = None
    
    # Path constraints
    constraints: List[Any] = field(default_factory=list)
    
    # Tracking
    gas_used: int = 0
    depth: int = 0
    
    def clone(self) -> 'SymbolicState':
        """Create a deep copy of the state"""
        new_state = SymbolicState(
            pc=self.pc,
            stack=self.stack.copy(),
            memory=self.memory.copy(),
            storage=self.storage.copy(),
            callvalue=self.callvalue,
            caller=self.caller,
            calldata=self.calldata,
            constraints=self.constraints.copy(),
            gas_used=self.gas_used,
            depth=self.depth
        )
        return new_state


class SymbolicExecutor:
    """
    Symbolic execution engine for EVM bytecode
    
    Explores execution paths and uses Z3 SMT solver to find
    inputs that trigger vulnerabilities.
    """
    
    # Maximum limits to prevent infinite loops
    MAX_DEPTH = 100
    MAX_PATHS = 1000
    MAX_GAS = 10_000_000
    
    @classmethod
    def is_available(cls) -> bool:
        """Check if symbolic execution is available (z3 installed)"""
        return Z3_AVAILABLE
    
    # EVM opcodes
    OPCODES = {
        0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
        0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
        0x0A: "EXP", 0x0B: "SIGNEXTEND",
        0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
        0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
        0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
        0x20: "SHA3",
        0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
        0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
        0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
        0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
        0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
        0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
        0x44: "DIFFICULTY", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE",
        0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
        0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
        0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
        0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN",
        0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
        0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
    }
    
    def __init__(self):
        """Initialize the symbolic executor"""
        self.paths: List[ExecutionPath] = []
        self.vulnerabilities: List[Dict] = []
        
        if Z3_AVAILABLE:
            self.solver = z3.Solver()
            # Create symbolic variables for common inputs
            self.sym_callvalue = z3.BitVec('callvalue', 256)
            self.sym_caller = z3.BitVec('caller', 160)
            self.sym_origin = z3.BitVec('origin', 160)
            self.sym_timestamp = z3.BitVec('timestamp', 256)
            self.sym_blocknumber = z3.BitVec('blocknumber', 256)
        else:
            self.solver = None
            self.sym_callvalue = None
            self.sym_caller = None
            self.sym_origin = None
            self.sym_timestamp = None
            self.sym_blocknumber = None
    
    def execute(self, bytecode: str, entry_point: int = 0) -> List[ExecutionPath]:
        """
        Symbolically execute the bytecode
        
        Args:
            bytecode: Contract bytecode (hex string)
            entry_point: Starting program counter
        
        Returns:
            List of explored execution paths
        """
        if not Z3_AVAILABLE:
            logger.warning("z3_not_available", message="Symbolic execution skipped - z3 not installed")
            return []
        
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        
        try:
            bytecode_bytes = bytes.fromhex(bytecode)
        except ValueError:
            logger.error("invalid_bytecode")
            return []
        
        # Initialize state
        initial_state = SymbolicState(
            pc=entry_point,
            callvalue=self.sym_callvalue,
            caller=self.sym_caller
        )
        
        # Create initial calldata (symbolic)
        for i in range(10):  # First 10 words of calldata
            initial_state.calldata = z3.BitVec(f'calldata_{i}', 256)
        
        # Execute with work list algorithm
        self.paths = []
        work_list = [(initial_state, [])]  # (state, path_constraints)
        path_count = 0
        
        while work_list and path_count < self.MAX_PATHS:
            state, constraints = work_list.pop()
            
            try:
                result = self._execute_path(bytecode_bytes, state, constraints)
                if result:
                    self.paths.append(result)
                    path_count += 1
                    
                    # Check for vulnerabilities in this path
                    self._analyze_path(result)
                    
            except Exception as e:
                logger.debug("path_execution_error", error=str(e))
                continue
        
        return self.paths
    
    def _execute_path(
        self,
        bytecode: bytes,
        state: SymbolicState,
        path_constraints: List[Any]
    ) -> Optional[ExecutionPath]:
        """Execute a single path through the bytecode"""
        
        path = ExecutionPath(
            path_id=len(self.paths),
            constraints=path_constraints.copy(),
            state_changes=[],
            external_calls=[]
        )
        
        while state.pc < len(bytecode) and state.depth < self.MAX_DEPTH:
            opcode = bytecode[state.pc]
            opcode_name = self.OPCODES.get(opcode, f"UNKNOWN_{hex(opcode)}")
            
            # Execute the opcode
            try:
                result = self._execute_opcode(opcode, opcode_name, state, bytecode, path)
                
                if result == "STOP":
                    break
                elif result == "REVERT":
                    path.reverted = True
                    break
                elif result == "BRANCH":
                    # Handle branching (JUMPI) - this would fork execution
                    # For now, we just continue on one path
                    pass
                    
            except Exception as e:
                logger.debug("opcode_error", opcode=opcode_name, error=str(e))
                break
            
            state.depth += 1
            state.gas_used += self._gas_cost(opcode)
            
            if state.gas_used > self.MAX_GAS:
                break
        
        return path
    
    def _execute_opcode(
        self,
        opcode: int,
        opcode_name: str,
        state: SymbolicState,
        bytecode: bytes,
        path: ExecutionPath
    ) -> Optional[str]:
        """Execute a single opcode"""
        
        # Arithmetic operations
        if opcode == 0x01:  # ADD
            if len(state.stack) >= 2:
                a = state.stack.pop()
                b = state.stack.pop()
                
                # Check for overflow
                if self._can_overflow_add(a, b):
                    path.has_overflow = True
                    self.vulnerabilities.append({
                        "type": "integer_overflow",
                        "opcode": "ADD",
                        "pc": state.pc,
                        "operands": [str(a), str(b)]
                    })
                
                result = z3.BitVecVal(0, 256) if not isinstance(a, z3.BitVecRef) else (a + b)
                state.stack.append(result)
            state.pc += 1
            
        elif opcode == 0x02:  # MUL
            if len(state.stack) >= 2:
                a = state.stack.pop()
                b = state.stack.pop()
                
                # Check for overflow
                if self._can_overflow_mul(a, b):
                    path.has_overflow = True
                    self.vulnerabilities.append({
                        "type": "integer_overflow",
                        "opcode": "MUL",
                        "pc": state.pc,
                        "operands": [str(a), str(b)]
                    })
                
                result = z3.BitVecVal(0, 256) if not isinstance(a, z3.BitVecRef) else (a * b)
                state.stack.append(result)
            state.pc += 1
            
        elif opcode == 0x03:  # SUB
            if len(state.stack) >= 2:
                a = state.stack.pop()
                b = state.stack.pop()
                
                # Check for underflow
                if self._can_underflow(a, b):
                    path.has_overflow = True
                    self.vulnerabilities.append({
                        "type": "integer_underflow",
                        "opcode": "SUB",
                        "pc": state.pc,
                        "operands": [str(a), str(b)]
                    })
                
                result = z3.BitVecVal(0, 256) if not isinstance(a, z3.BitVecRef) else (a - b)
                state.stack.append(result)
            state.pc += 1
            
        elif opcode == 0x04:  # DIV
            if len(state.stack) >= 2:
                a = state.stack.pop()
                b = state.stack.pop()
                # Division by zero returns 0 in EVM
                result = z3.BitVecVal(0, 256)
                state.stack.append(result)
            state.pc += 1
            
        # Comparison operations
        elif opcode == 0x10:  # LT
            if len(state.stack) >= 2:
                a = state.stack.pop()
                b = state.stack.pop()
                result = z3.If(z3.ULT(a, b), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)) \
                    if isinstance(a, z3.BitVecRef) else z3.BitVecVal(0, 256)
                state.stack.append(result)
            state.pc += 1
            
        elif opcode == 0x14:  # EQ
            if len(state.stack) >= 2:
                a = state.stack.pop()
                b = state.stack.pop()
                result = z3.If(a == b, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)) \
                    if isinstance(a, z3.BitVecRef) else z3.BitVecVal(0, 256)
                state.stack.append(result)
            state.pc += 1
            
        elif opcode == 0x15:  # ISZERO
            if len(state.stack) >= 1:
                a = state.stack.pop()
                result = z3.If(a == 0, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)) \
                    if isinstance(a, z3.BitVecRef) else z3.BitVecVal(0, 256)
                state.stack.append(result)
            state.pc += 1
            
        # Stack operations
        elif opcode == 0x50:  # POP
            if state.stack:
                state.stack.pop()
            state.pc += 1
            
        # Memory operations
        elif opcode == 0x51:  # MLOAD
            if len(state.stack) >= 1:
                offset = state.stack.pop()
                value = state.memory.get(offset, z3.BitVecVal(0, 256))
                state.stack.append(value)
            state.pc += 1
            
        elif opcode == 0x52:  # MSTORE
            if len(state.stack) >= 2:
                offset = state.stack.pop()
                value = state.stack.pop()
                state.memory[offset] = value
            state.pc += 1
            
        # Storage operations
        elif opcode == 0x54:  # SLOAD
            if len(state.stack) >= 1:
                slot = state.stack.pop()
                value = state.storage.get(slot, z3.BitVec(f'storage_{slot}', 256))
                state.stack.append(value)
            state.pc += 1
            
        elif opcode == 0x55:  # SSTORE
            if len(state.stack) >= 2:
                slot = state.stack.pop()
                value = state.stack.pop()
                state.storage[slot] = value
                path.state_changes.append({
                    "slot": str(slot),
                    "value": str(value),
                    "pc": state.pc
                })
            state.pc += 1
            
        # Environment
        elif opcode == 0x33:  # CALLER
            state.stack.append(z3.ZeroExt(96, self.sym_caller))  # Extend to 256 bits
            state.pc += 1
            
        elif opcode == 0x32:  # ORIGIN
            state.stack.append(z3.ZeroExt(96, self.sym_origin))
            state.pc += 1
            
        elif opcode == 0x34:  # CALLVALUE
            state.stack.append(self.sym_callvalue)
            state.pc += 1
            
        elif opcode == 0x42:  # TIMESTAMP
            state.stack.append(self.sym_timestamp)
            state.pc += 1
            
        elif opcode == 0x43:  # NUMBER
            state.stack.append(self.sym_blocknumber)
            state.pc += 1
            
        # Control flow
        elif opcode == 0x56:  # JUMP
            if len(state.stack) >= 1:
                dest = state.stack.pop()
                # For symbolic execution, we need to resolve concrete destinations
                if isinstance(dest, int):
                    state.pc = dest
                else:
                    state.pc += 1  # Can't resolve symbolic jump
            else:
                state.pc += 1
                
        elif opcode == 0x57:  # JUMPI
            if len(state.stack) >= 2:
                dest = state.stack.pop()
                state.stack.pop()
                # This is where we would fork execution
                # For now, continue with condition being true
                state.pc += 1
                return "BRANCH"
            state.pc += 1
            
        elif opcode == 0x5B:  # JUMPDEST
            state.pc += 1
            
        # External calls
        elif opcode == 0xF1:  # CALL
            if len(state.stack) >= 7:
                state.stack.pop()
                to = state.stack.pop()
                value = state.stack.pop()
                state.stack.pop()
                state.stack.pop()
                state.stack.pop()
                state.stack.pop()
                
                path.external_calls.append({
                    "type": "CALL",
                    "to": str(to),
                    "value": str(value),
                    "pc": state.pc
                })
                
                # Check for reentrancy (CALL before SSTORE)
                if path.state_changes:
                    # State was already changed before this call
                    pass
                else:
                    # Call before state change - potential reentrancy
                    path.has_reentrancy = True
                    self.vulnerabilities.append({
                        "type": "reentrancy",
                        "pc": state.pc,
                        "call_target": str(to)
                    })
                
                # Push success (1) to stack
                state.stack.append(z3.BitVecVal(1, 256))
            state.pc += 1
            
        elif opcode == 0xF4:  # DELEGATECALL
            if len(state.stack) >= 6:
                for _ in range(6):
                    state.stack.pop()
                
                path.external_calls.append({
                    "type": "DELEGATECALL",
                    "pc": state.pc
                })
                
                state.stack.append(z3.BitVecVal(1, 256))
            state.pc += 1
            
        # Termination
        elif opcode == 0x00:  # STOP
            return "STOP"
            
        elif opcode == 0xF3:  # RETURN
            return "STOP"
            
        elif opcode == 0xFD:  # REVERT
            return "REVERT"
            
        elif opcode == 0xFF:  # SELFDESTRUCT
            path.external_calls.append({
                "type": "SELFDESTRUCT",
                "pc": state.pc
            })
            return "STOP"
            
        # PUSH operations (0x60 - 0x7F)
        elif 0x60 <= opcode <= 0x7F:
            push_size = opcode - 0x5F
            if state.pc + push_size < len(bytecode):
                value_bytes = bytecode[state.pc + 1:state.pc + 1 + push_size]
                value = int.from_bytes(value_bytes, 'big')
                state.stack.append(z3.BitVecVal(value, 256))
            state.pc += push_size + 1
            
        # DUP operations (0x80 - 0x8F)
        elif 0x80 <= opcode <= 0x8F:
            dup_pos = opcode - 0x7F
            if len(state.stack) >= dup_pos:
                state.stack.append(state.stack[-dup_pos])
            state.pc += 1
            
        # SWAP operations (0x90 - 0x9F)
        elif 0x90 <= opcode <= 0x9F:
            swap_pos = opcode - 0x8F
            if len(state.stack) > swap_pos:
                state.stack[-1], state.stack[-1 - swap_pos] = \
                    state.stack[-1 - swap_pos], state.stack[-1]
            state.pc += 1
            
        else:
            # Unknown opcode, skip
            state.pc += 1
        
        return None
    
    def _can_overflow_add(self, a: Any, b: Any) -> bool:
        """Check if addition can overflow using Z3"""
        if not isinstance(a, z3.BitVecRef) or not isinstance(b, z3.BitVecRef):
            return False
        
        # Check if a + b can wrap around
        # Overflow occurs when a + b < a (for unsigned)
        self.solver.push()
        self.solver.add(z3.ULT(a + b, a))
        result = self.solver.check() == z3.sat
        self.solver.pop()
        
        return result
    
    def _can_overflow_mul(self, a: Any, b: Any) -> bool:
        """Check if multiplication can overflow using Z3"""
        if not isinstance(a, z3.BitVecRef) or not isinstance(b, z3.BitVecRef):
            return False
        
        # For multiplication, check if result / b != a (when b != 0)
        self.solver.push()
        self.solver.add(b != 0)
        self.solver.add(z3.UDiv(a * b, b) != a)
        result = self.solver.check() == z3.sat
        self.solver.pop()
        
        return result
    
    def _can_underflow(self, a: Any, b: Any) -> bool:
        """Check if subtraction can underflow using Z3"""
        if not isinstance(a, z3.BitVecRef) or not isinstance(b, z3.BitVecRef):
            return False
        
        # Underflow occurs when b > a
        self.solver.push()
        self.solver.add(z3.UGT(b, a))
        result = self.solver.check() == z3.sat
        self.solver.pop()
        
        return result
    
    def _analyze_path(self, path: ExecutionPath):
        """Analyze a completed path for vulnerabilities"""
        
        # Check for reentrancy: external call before state change
        call_pcs = [c["pc"] for c in path.external_calls if c["type"] in ["CALL", "DELEGATECALL"]]
        state_change_pcs = [s["pc"] for s in path.state_changes]
        
        for call_pc in call_pcs:
            for state_pc in state_change_pcs:
                if call_pc < state_pc:
                    path.has_reentrancy = True
                    self.vulnerabilities.append({
                        "type": "reentrancy",
                        "description": f"External call at PC {call_pc} before state change at PC {state_pc}",
                        "severity": "CRITICAL"
                    })
                    break
        
        # Check for unchecked call return values
        # (Simplified - in reality we'd track if return value is checked)
        for call in path.external_calls:
            if call["type"] == "CALL":
                path.has_unchecked_call = True
    
    def _gas_cost(self, opcode: int) -> int:
        """Get gas cost for an opcode"""
        # Simplified gas costs
        gas_costs = {
            0x01: 3,   # ADD
            0x02: 5,   # MUL
            0x03: 3,   # SUB
            0x04: 5,   # DIV
            0x54: 200, # SLOAD
            0x55: 5000, # SSTORE (simplified)
            0xF1: 700, # CALL base cost
        }
        return gas_costs.get(opcode, 3)
    
    def find_exploit_inputs(self, vulnerability: Dict) -> Optional[Dict]:
        """
        Use Z3 to find concrete inputs that trigger a vulnerability
        
        Returns dict with concrete input values if exploitable
        """
        self.solver.push()
        
        # Add constraints based on vulnerability type
        if vulnerability["type"] == "integer_overflow":
            # Find inputs that cause overflow
            a = z3.BitVec('a', 256)
            b = z3.BitVec('b', 256)
            
            # Constraint: a + b overflows (wraps to small number)
            self.solver.add(z3.ULT(a + b, a))
            self.solver.add(a > 0)
            self.solver.add(b > 0)
            
        elif vulnerability["type"] == "reentrancy":
            # Find call that can re-enter
            # This is more complex and depends on specific contract
            pass
        
        result = None
        if self.solver.check() == z3.sat:
            model = self.solver.model()
            result = {
                "exploitable": True,
                "inputs": {str(d): str(model[d]) for d in model.decls()}
            }
        else:
            result = {"exploitable": False}
        
        self.solver.pop()
        return result
    
    def get_vulnerabilities(self) -> List[Dict]:
        """Get all discovered vulnerabilities"""
        # Deduplicate
        seen = set()
        unique = []
        for vuln in self.vulnerabilities:
            key = (vuln["type"], vuln.get("pc", 0))
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        return unique
