# Phase 3: Bridge Adapters & Protocol-Specific Invariants - Implementation Summary

## Overview

Phase 3 successfully implements protocol-aware bridge adapters and protocol-specific invariants, replacing the generic "mint/lock" logic with semantic understanding of different bridge types.

**Status**: ✅ **COMPLETE**

---

## Components Implemented

### 1. Bridge Adapter Framework ✅

**Base Class** (`src/bridges/adapters/base.py`):
- ✅ Abstract `BridgeAdapter` class with required methods
- ✅ `BridgeProtocol` enum (Wormhole, LayerZero, Stargate, etc.)
- ✅ `BridgeEventSemantic` enum (LOCK, MINT, DEPOSIT, FILL, MESSAGE_SENT, etc.)
- ✅ `CorrelationKey` dataclass for cross-chain matching
- ✅ `ExpectedAmounts` dataclass for fee calculations

**Methods:**
- `identify_protocol()`: Check if event belongs to this protocol
- `classify_event()`: Map raw event to semantic type
- `extract_correlation_key()`: Extract unique correlation identifier
- `expected_amounts()`: Calculate expected amounts after fees
- `supported_invariants()`: List which invariants apply

### 2. Concrete Adapters ✅

#### **Wormhole Adapter** (`src/bridges/adapters/wormhole.py`)
- ✅ Identifies Wormhole events by contract address and event signature
- ✅ Extracts correlation key: `(emitterChainId, emitterAddress, sequence)`
- ✅ Classifies: `LogMessagePublished` → LOCK, `TransferRedeemed` → MINT
- ✅ Expected amounts: 10 bps fee (0.1%)
- ✅ Supports: `MINT_LOCK_PARITY`, `SEQUENCE_CONTINUITY`, `MESSAGE_VERIFICATION`

**Key Features:**
- Handles Wormhole chain ID mapping
- High confidence correlation (sequence numbers are unique)
- Mint/burn model (canonical)

#### **LayerZero Adapter** (`src/bridges/adapters/layerzero.py`)
- ✅ Identifies LayerZero events
- ✅ Extracts correlation key: `(srcChainId, srcAddress, nonce, payloadHash)`
- ✅ Classifies: `Packet` → MESSAGE_SENT, `PacketReceived` → MESSAGE_RECEIVED
- ✅ Expected amounts: Fees paid separately (not deducted from amount)
- ✅ Supports: `MESSAGE_VERIFICATION`, `SEQUENCE_CONTINUITY`, `PAYLOAD_INTEGRITY`

**Key Features:**
- Ultra Light Node (ULN) verification model
- Payload hash-based correlation
- Message-based (not token-based)

#### **Stargate Adapter** (`src/bridges/adapters/stargate.py`)
- ✅ Identifies Stargate events
- ✅ **CRITICAL**: Classifies as `DEPOSIT`/`FILL` (NOT LOCK/MINT)
- ✅ Expected amounts: 10 bps fee (0.1%)
- ✅ Supports: `LIQUIDITY_PARITY`, `POOL_RESERVE_CHECK`, `FEE_CONSISTENCY`
- ✅ **Does NOT support**: `MINT_LOCK_PARITY` (liquidity bridge, not mint/burn)

**Key Features:**
- Liquidity pool model (not canonical mint/burn)
- Fees deducted from swap amount
- Important distinction from Wormhole

### 3. Adapter Registry ✅

**Registry** (`src/bridges/registry.py`):
- ✅ Auto-detects protocol from events
- ✅ Routes to correct adapter
- ✅ Caching for performance
- ✅ `get_adapter()`: Returns adapter for event
- ✅ `get_adapter_by_protocol()`: Returns adapter by protocol ID

### 4. Protocol-Specific Invariants ✅

**New Invariants** (`src/invariants/bridge_specific.py`):

#### **MintBurnInvariant**
- ✅ Applies ONLY to mint/burn bridges (Wormhole)
- ✅ Checks: Mint Amount <= Lock Amount (with tolerance)
- ✅ Detects: MINT_WITHOUT_LOCK, AMOUNT_MISMATCH
- ✅ Uses adapter to classify events and extract correlation keys

#### **LiquidityInvariant**
- ✅ Applies ONLY to liquidity bridges (Stargate, Across, Hop)
- ✅ Checks: Fill Amount <= Deposit Amount * (1 - MaxFee) + tolerance
- ✅ Detects: FILL_WITHOUT_DEPOSIT, FILL_AMOUNT_TOO_LOW
- ✅ **Does NOT apply mint/lock parity** (different model)

#### **SequenceInvariant**
- ✅ Applies to messaging protocols (Wormhole, LayerZero)
- ✅ Checks for skipped nonces/sequences
- ✅ Detects sequence gaps (potential message loss/replay)

### 5. Adapter-Based Correlation ✅

**Correlation Engine** (`src/correlation/adapter_based.py`):
- ✅ Uses adapters to extract correlation keys
- ✅ Builds correlation paths (not just A-to-B matching)
- ✅ Supports multi-hop bridging
- ✅ Checks semantic compatibility (LOCK matches MINT, DEPOSIT matches FILL)
- ✅ Detects violations: MINT_WITHOUT_LOCK, FILL_WITHOUT_DEPOSIT, AMOUNT_MISMATCH

**Key Features:**
- `CorrelationPath`: Represents multi-chain paths
- `AdapterBasedCorrelator`: Main correlation engine
- Path completion detection
- Violation detection

### 6. Testing ✅

**Test Suite** (`tests/test_adapters.py`):
- ✅ Wormhole adapter tests (identification, correlation, classification)
- ✅ Stargate adapter tests (ensures NOT lock/mint)
- ✅ LayerZero adapter tests
- ✅ Registry auto-detection tests
- ✅ Real log payloads (mocked)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SecurityEvent                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  BridgeAdapterRegistry │
         └───────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
  ┌─────────────┐      ┌─────────────┐
  │  Wormhole   │      │  Stargate   │
  │   Adapter   │      │   Adapter   │
  └──────┬──────┘      └──────┬──────┘
         │                    │
         │ classify_event()   │ classify_event()
         │ extract_key()      │ extract_key()
         │                    │
         ▼                    ▼
  ┌─────────────────────────────────────┐
  │   BridgeEventSemantic               │
  │   (LOCK, MINT, DEPOSIT, FILL)       │
  └─────────────────────────────────────┘
         │                    │
         ▼                    ▼
  ┌─────────────────────────────────────┐
  │   Protocol-Specific Invariants       │
  │   - MintBurnInvariant (Wormhole)     │
  │   - LiquidityInvariant (Stargate)    │
  └─────────────────────────────────────┘
```

---

## Key Distinctions

### Mint/Burn Bridges (Wormhole)
- **Model**: Lock tokens → Mint wrapped tokens
- **Invariant**: Mint Amount <= Lock Amount
- **Correlation**: Sequence numbers
- **Fees**: Minimal (0.1%)

### Liquidity Bridges (Stargate)
- **Model**: Deposit into pool → Fill from pool
- **Invariant**: Fill Amount <= Deposit Amount - Fees
- **Correlation**: Transaction-based (fallback)
- **Fees**: Deducted from amount (0.1%)
- **⚠️ NOT mint/burn**: Uses existing liquidity

### Messaging Protocols (LayerZero)
- **Model**: Send message → Receive message
- **Invariant**: Message verification, sequence continuity
- **Correlation**: Payload hash, nonce
- **Fees**: Paid separately (not deducted)

---

## Usage

### Using Adapters

```python
from src.bridges.registry import BridgeAdapterRegistry
from src.models.events import SecurityEvent

registry = BridgeAdapterRegistry()

# Auto-detect protocol
adapter = registry.get_adapter(event)

if adapter:
    # Classify event
    semantic = adapter.classify_event(event)
    # LOCK, MINT, DEPOSIT, FILL, etc.
    
    # Extract correlation key
    corr_key = adapter.extract_correlation_key(event)
    # (protocol_id, key, src_chain, dst_chain)
    
    # Calculate expected amounts
    expected = adapter.expected_amounts(source_event, dest_event)
    # ExpectedAmounts(source_amount, dest_amount, fee_amount, ...)
```

### Using Protocol-Specific Invariants

```python
from src.invariants.bridge_specific import MintBurnInvariant, LiquidityInvariant
from src.invariants.base import InvariantContext

# For Wormhole (mint/burn)
invariant = MintBurnInvariant(protocol_id="wormhole", tolerance_bps=50)
result = await invariant.evaluate(context)

# For Stargate (liquidity)
invariant = LiquidityInvariant(protocol_id="stargate", tolerance_bps=50)
result = await invariant.evaluate(context)
```

### Using Adapter-Based Correlation

```python
from src.correlation.adapter_based import AdapterBasedCorrelator

correlator = AdapterBasedCorrelator()

# Process events
path = correlator.process_event(event)

if path and path.is_complete():
    violations = path.get_violations()
    if violations:
        # Handle violations
        pass
```

---

## Testing

```bash
# Run adapter tests
pytest tests/test_adapters.py -v

# Test specific adapter
pytest tests/test_adapters.py::TestWormholeAdapter -v
pytest tests/test_adapters.py::TestStargateAdapter -v
```

---

## Backwards Compatibility

✅ **Maintained**: Existing `SecurityEvent` schema unchanged
- New fields added via adapters (not required in base model)
- Correlation keys stored in `canonical_event_hash` field
- Semantic types derived from adapters (not stored)

---

## Next Steps

1. ✅ **Phase 3 Complete** - Bridge adapters implemented
2. 🚧 **Phase 4 Next** - Explainability upgrades + incident lifecycle
3. 🚧 **Phase 5** - Guardian hardening
4. 🚧 **Phase 6** - Non-EVM fixes

---

## Summary

**Phase 3 is complete and production-ready:**

- ✅ Protocol-aware bridge adapters (Wormhole, LayerZero, Stargate)
- ✅ Semantic event classification (LOCK, MINT, DEPOSIT, FILL)
- ✅ Protocol-specific invariants (MintBurn, Liquidity, Sequence)
- ✅ Adapter-based correlation with path building
- ✅ Comprehensive test suite

The system now understands the difference between mint/burn bridges (Wormhole) and liquidity bridges (Stargate), enabling precise, protocol-specific invariant checking.

