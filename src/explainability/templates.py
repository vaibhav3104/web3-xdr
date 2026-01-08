"""
Explanation Templates - Human-Readable Narratives
==================================================

Phase 4: Template system for generating natural language explanations.
"""

from decimal import Decimal
from typing import List, Optional, Any
import structlog

logger = structlog.get_logger(__name__)


class ExplanationTemplate:
    """
    Template system for generating explanations.
    
    Uses f-strings for simplicity (can be upgraded to Jinja2 if needed).
    """
    
    def generate_summary(
        self,
        violation_type: str,
        protocol_id: str,
        source_chain: str,
        target_chain: Optional[str],
        event_count: int,
        total_value: Decimal,
        evidence: List[Any]  # List[Evidence] but avoiding circular import
    ) -> str:
        """
        Generate one-sentence summary.
        
        Examples:
        - "Detected Mint-Without-Lock on Wormhole. Source chain Ethereum shows NO lock for sequence #123, but Solana minted 50,000 USDC."
        - "Detected Fill-Without-Deposit on Stargate. Ethereum deposit missing for swap #456, but Polygon filled 100,000 USDT."
        """
        # Format value
        value_str = self._format_value(total_value)
        
        # Build chain description
        chain_desc = source_chain
        if target_chain:
            chain_desc = f"{source_chain} → {target_chain}"
        
        # Generate based on violation type
        if "MINT_WITHOUT_LOCK" in violation_type:
            return self._mint_without_lock_summary(
                protocol_id=protocol_id,
                chain_desc=chain_desc,
                event_count=event_count,
                value=value_str,
                evidence=evidence
            )
        elif "FILL_WITHOUT_DEPOSIT" in violation_type:
            return self._fill_without_deposit_summary(
                protocol_id=protocol_id,
                chain_desc=chain_desc,
                event_count=event_count,
                value=value_str,
                evidence=evidence
            )
        elif "AMOUNT_MISMATCH" in violation_type:
            return self._amount_mismatch_summary(
                protocol_id=protocol_id,
                chain_desc=chain_desc,
                event_count=event_count,
                value=value_str,
                evidence=evidence
            )
        elif "SEQUENCE" in violation_type:
            return self._sequence_violation_summary(
                protocol_id=protocol_id,
                chain_desc=chain_desc,
                event_count=event_count,
                evidence=evidence
            )
        else:
            return self._generic_summary(
                violation_type=violation_type,
                protocol_id=protocol_id,
                chain_desc=chain_desc,
                event_count=event_count,
                value=value_str
            )
    
    def _mint_without_lock_summary(
        self,
        protocol_id: str,
        chain_desc: str,
        event_count: int,
        value: str,
        evidence: List[Any]
    ) -> str:
        """Generate summary for mint-without-lock violation."""
        # Extract sequence or correlation key from evidence
        seq_info = ""
        if evidence:
            ev = evidence[0]
            if ev.source_msg_id:
                seq_info = f" for message {ev.source_msg_id[:16]}"
            elif ev.correlation_key:
                seq_info = f" for correlation key {ev.correlation_key[:16]}"
        
        if event_count == 1:
            return f"Detected Mint-Without-Lock on {protocol_id}. Source chain {chain_desc.split(' → ')[0]} shows NO lock{seq_info}, but {chain_desc.split(' → ')[-1] if ' → ' in chain_desc else 'destination'} minted {value}."
        else:
            return f"Detected {event_count} Mint-Without-Lock violations on {protocol_id} ({chain_desc}). Total value at risk: {value}."
    
    def _fill_without_deposit_summary(
        self,
        protocol_id: str,
        chain_desc: str,
        event_count: int,
        value: str,
        evidence: List[Any]
    ) -> str:
        """Generate summary for fill-without-deposit violation."""
        if event_count == 1:
            return f"Detected Fill-Without-Deposit on {protocol_id}. Source chain {chain_desc.split(' → ')[0]} shows NO deposit, but {chain_desc.split(' → ')[-1] if ' → ' in chain_desc else 'destination'} filled {value}."
        else:
            return f"Detected {event_count} Fill-Without-Deposit violations on {protocol_id} ({chain_desc}). Total value at risk: {value}."
    
    def _amount_mismatch_summary(
        self,
        protocol_id: str,
        chain_desc: str,
        event_count: int,
        value: str,
        evidence: List[Any]
    ) -> str:
        """Generate summary for amount mismatch violation."""
        amount_info = ""
        if evidence:
            ev = evidence[0]
            if ev.source_amount and ev.dest_amount:
                amount_info = f" (Expected: {self._format_value(ev.source_amount)}, Got: {self._format_value(ev.dest_amount)})"
        
        return f"Detected Amount Mismatch on {protocol_id} ({chain_desc}). {event_count} violation(s) detected{amount_info}. Total deviation: {value}."
    
    def _sequence_violation_summary(
        self,
        protocol_id: str,
        chain_desc: str,
        event_count: int,
        evidence: List[Any]
    ) -> str:
        """Generate summary for sequence violation."""
        return f"Detected Sequence Gap on {protocol_id} ({chain_desc}). {event_count} missing sequence(s) detected, indicating potential message loss or replay attack."
    
    def _generic_summary(
        self,
        violation_type: str,
        protocol_id: str,
        chain_desc: str,
        event_count: int,
        value: str
    ) -> str:
        """Generate generic summary."""
        return f"Detected {violation_type} on {protocol_id} ({chain_desc}). {event_count} violation(s) detected. Total value at risk: {value}."
    
    def _format_value(self, value: Decimal) -> str:
        """Format value for display."""
        if value >= Decimal("1000000"):
            return f"${value / Decimal('1000000'):.2f}M"
        elif value >= Decimal("1000"):
            return f"${value / Decimal('1000'):.2f}K"
        else:
            return f"${value:.2f}"
