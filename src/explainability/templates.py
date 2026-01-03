"""
Explanation Templates - Deterministic templates for each attack type.
"""

from typing import Any, Dict

from ..models.incidents import AttackType


class ExplanationTemplates:
    """
    Deterministic explanation templates.
    
    NO AI-generated text - all explanations are template-based
    with evidence-backed variable substitution.
    """
    
    TEMPLATES: Dict[str, Dict[str, str]] = {
        "UNBACKED_MINT": {
            "title": "Unbacked Cross-Chain Mint Detected",
            
            "what_happened": """
{minted_amount} {asset} was minted on {dest_chain} without corresponding lock on {source_chain}.

**Evidence:**
- **Mints detected:** {mint_count} transaction(s) totaling {minted_amount} {asset}
- **Locks detected:** {lock_count} transaction(s) totaling {locked_amount} {asset}
- **Gap:** {gap_amount} {asset} ({gap_usd} USD) minted without backing

**Key Transactions:**
{transaction_list}
""",
            
            "why_dangerous": """
This indicates one of:
1. **Forged bridge message:** Attacker submitted fake proof of lock
2. **Validator compromise:** Attacker controls enough validators to approve fake messages
3. **Contract vulnerability:** Mint function bypassed lock verification

The minted tokens are unbacked - they have no real value on the source chain. If the attacker sells/swaps these tokens, legitimate users holding the same token will suffer losses.
""",
            
            "blast_radius": """
- **Current confirmed loss:** {gap_usd} USD
- **Bridge TVL at risk:** {bridge_tvl} USD
- **Estimated drain rate:** {drain_rate_per_block} USD/block
- **Time to full drain at current rate:** {time_to_drain}

If not stopped, the attacker could drain the entire bridge TVL.
""",
            
            "what_to_do": """
1. ⚠️ **PAUSE BRIDGE IMMEDIATELY** - Every block increases loss
2. Verify guardian/validator key status
3. Check for unauthorized message submissions on source chain
4. Prepare incident response communication for users
5. Engage security partners for forensics
"""
        },
        
        "VALIDATOR_COMPROMISE": {
            "title": "Validator Key Compromise Detected",
            
            "what_happened": """
Bridge operations were executed with fewer signatures than required.

**Evidence:**
- **Signatures provided:** {signature_count}
- **Threshold required:** {threshold}
- **Shortfall:** {shortfall} signatures

This means either:
- Validator keys have been compromised
- Threshold was maliciously lowered
- Signature verification was bypassed
""",
            
            "why_dangerous": """
Validators are the security backbone of the bridge. A compromise allows:
1. **Arbitrary minting** of wrapped tokens
2. **Theft** of all locked assets
3. **Permanent loss** for all bridge users

This is typically the precursor to a full bridge drain.
""",
            
            "blast_radius": """
- **Transactions signed below threshold:** {below_threshold_count}
- **Total value moved:** {total_value_usd} USD
- **Bridge TVL at risk:** {bridge_tvl} USD
- **All bridge users** are at risk until resolved
""",
            
            "what_to_do": """
1. 🔴 **EMERGENCY PAUSE** - Immediately halt all bridge operations
2. Identify which validator keys are compromised
3. Initiate validator key rotation procedure
4. Review ALL recent bridge operations for illegitimate transfers
5. Prepare to revoke/rotate compromised keys
6. Engage law enforcement if theft confirmed
"""
        },
        
        "GOVERNANCE_ATTACK": {
            "title": "Governance Attack Detected",
            
            "what_happened": """
A governance action was executed without respecting the required timelock delay.

**Evidence:**
- **Action executed:** {action_type}
- **Time since proposal:** {elapsed_time}
- **Required delay:** {required_delay}
- **Shortfall:** {delay_shortfall}

The governance timelock is designed to give users time to exit if they disagree with changes. Bypassing it indicates an attack.
""",
            
            "why_dangerous": """
Governance controls can:
1. **Change critical parameters** (fees, limits, addresses)
2. **Upgrade contracts** to malicious versions
3. **Drain treasury** or locked funds
4. **Disable security controls**

Bypassing timelock means users have no warning before malicious changes take effect.
""",
            
            "blast_radius": """
- **Action executed:** {action_type}
- **Contracts affected:** {affected_contracts}
- **Protocol TVL at risk:** {protocol_tvl} USD
- **If contract upgrade:** Entire protocol may be compromised
""",
            
            "what_to_do": """
1. ⚠️ **PAUSE AFFECTED CONTRACTS** if possible
2. Review the executed governance action
3. Check if admin/governance keys are compromised
4. Prepare to revert changes if safe to do so
5. Alert users to withdraw funds if protocol compromised
6. Engage security team for full audit
"""
        },
        
        "LIQUIDITY_DRAIN": {
            "title": "Abnormal Liquidity Drain Detected",
            
            "what_happened": """
Bridge TVL decreased by {drain_percent}% ({drain_usd} USD) in {time_window}.

**Evidence:**
- **TVL {time_window} ago:** {tvl_before} USD
- **TVL now:** {tvl_now} USD
- **Drain rate:** {drain_rate_per_block} USD/block

This rate of withdrawal is {multiplier}x higher than normal.
""",
            
            "why_dangerous": """
Rapid TVL drain typically indicates:
1. **Active exploit** - Attacker systematically draining funds
2. **Panic withdrawal** - Users front-running suspected exploit
3. **Liquidity attack** - Coordinated drain for arbitrage

If this is an exploit, every block of delay increases losses.
""",
            
            "blast_radius": """
- **Already drained:** {drain_usd} USD ({drain_percent}%)
- **Remaining TVL:** {tvl_now} USD
- **Time to full drain at current rate:** {time_to_drain}
- **Estimated final loss if unchecked:** {tvl_now} USD
""",
            
            "what_to_do": """
1. Investigate largest withdrawals in the last hour
2. Check for transaction patterns suggesting exploit
3. Consider temporary withdrawal pause if exploit suspected
4. Monitor for continued abnormal activity
5. Prepare incident communication if confirmed attack
"""
        },
        
        "FLASH_LOAN_EXPLOIT": {
            "title": "Flash Loan Exploit Pattern Detected",
            
            "what_happened": """
A flash loan was used in a single-block attack pattern.

**Evidence:**
- **Flash loan amount:** {flash_loan_amount} {flash_asset}
- **Operations in same block:** {operation_count}
- **Total volume:** {total_volume} USD
- **All operations in transaction:** {tx_hash}

Flash loans provide massive capital for a single block, enabling attacks that wouldn't be economically viable otherwise.
""",
            
            "why_dangerous": """
Flash loan attacks typically exploit:
1. **Price oracle manipulation** - Temporary price changes within a block
2. **Reentrancy** - Calling back into vulnerable contracts
3. **Logic flaws** - Exploiting edge cases in contract logic

The attacker profits from the price difference or logic flaw, then repays the loan - all atomically.
""",
            
            "blast_radius": """
- **Flash loan size:** {flash_loan_amount} {flash_asset}
- **Estimated profit extracted:** {estimated_profit} USD
- **Protocol reserves at risk:** {reserves_at_risk} USD
- **If exploitable repeatedly:** Entire protocol value at risk
""",
            
            "what_to_do": """
1. Analyze the exploit transaction in detail
2. Identify which contract logic was exploited
3. **PAUSE** the vulnerable contract if possible
4. Prepare hotfix for the vulnerability
5. Assess impact on protocol reserves
6. Consider reimbursement strategy for affected users
"""
        },
        
        "CROSS_CHAIN_LAUNDERING": {
            "title": "Cross-Chain Fund Movement Alert",
            
            "what_happened": """
Significant funds are being moved across chains in a pattern consistent with laundering or attack proceeds.

**Evidence:**
- **Total volume:** {total_volume} USD across {chain_count} chains
- **Hop count:** {hop_count} transfers
- **Time span:** {time_span}
- **Origin:** {origin_chain} → ... → {current_chain}

This pattern is consistent with obfuscating fund origins.
""",
            
            "why_dangerous": """
Cross-chain movement can be used to:
1. **Launder stolen funds** from other exploits
2. **Evade detection** by fragmenting trail
3. **Convert to mixers** or privacy chains
4. **Exit via CEX** after chain-hopping

If these are proceeds from a known exploit, tracking is critical for recovery.
""",
            
            "blast_radius": """
- **Volume traced:** {total_volume} USD
- **Chains involved:** {chains_list}
- **Connected addresses:** {address_count}
- **Potential link to known exploit:** {known_exploit_link}
""",
            
            "what_to_do": """
1. Cross-reference with known exploit addresses
2. Alert downstream protocols/exchanges
3. Work with chain analytics providers
4. Report to law enforcement if theft confirmed
5. Coordinate with bridge operators on affected chains
"""
        },
        
        "UNKNOWN": {
            "title": "Suspicious Activity Detected",
            
            "what_happened": """
Anomalous activity detected that doesn't match known attack patterns.

**Evidence:**
{evidence_summary}

This may be a new attack vector or false positive requiring investigation.
""",
            
            "why_dangerous": """
Unknown patterns require investigation because:
1. May be a **novel attack** not yet documented
2. Could be **legitimate but unusual** activity
3. May be **precursor activity** before main attack

Without investigation, risk cannot be assessed.
""",
            
            "blast_radius": """
- **Confidence:** {confidence}%
- **Violations detected:** {violation_count}
- **Estimated exposure:** {estimated_exposure} USD
- **Further investigation required** to assess actual risk
""",
            
            "what_to_do": """
1. Review the flagged transactions in detail
2. Check if activity matches known patterns
3. Monitor for continued anomalies
4. Escalate if pattern continues or worsens
5. Document findings for future reference
"""
        }
    }
    
    @classmethod
    def get_template(cls, attack_type: AttackType) -> Dict[str, str]:
        """Get template for attack type."""
        type_name = attack_type.value.upper()
        return cls.TEMPLATES.get(type_name, cls.TEMPLATES["UNKNOWN"])
    
    @classmethod
    def render(
        cls,
        attack_type: AttackType,
        section: str,
        variables: Dict[str, Any]
    ) -> str:
        """
        Render a template section with variables.
        
        Missing variables are replaced with "Unknown".
        """
        template = cls.get_template(attack_type)
        section_template = template.get(section, "")
        
        # Safe format - replace missing vars with "Unknown"
        class SafeDict(dict):
            def __missing__(self, key):
                return f"[{key}: Unknown]"
        
        try:
            return section_template.format_map(SafeDict(variables))
        except Exception:
            return section_template
    
    @classmethod
    def format_usd(cls, amount: float) -> str:
        """Format amount as USD string."""
        if amount >= 1_000_000:
            return f"${amount/1_000_000:.2f}M"
        elif amount >= 1_000:
            return f"${amount/1_000:.1f}K"
        else:
            return f"${amount:.2f}"
    
    @classmethod
    def format_duration(cls, seconds: float) -> str:
        """Format duration as human-readable string."""
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        else:
            return f"{seconds/86400:.1f} days"

