"""
Contract Deployment Monitor
Real-time monitoring of new contract deployments for threat detection
"""

import asyncio
import json
from typing import Dict, List, Optional, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    print("Warning: web3.py not installed")

from ..models.contract_classifier import ContractThreatClassifier, ClassificationResult, ThreatCategory

@dataclass
class DeploymentEvent:
    """Represents a new contract deployment"""
    tx_hash: str
    block_number: int
    deployer_address: str
    contract_address: str
    bytecode: str
    timestamp: datetime
    chain: str
    gas_used: int
    value_wei: int

@dataclass
class ThreatAlert:
    """Alert for detected threat"""
    id: str
    deployment: DeploymentEvent
    classification: ClassificationResult
    alert_time: datetime
    status: str  # new, acknowledged, resolved, false_positive
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "deployment": {
                "tx_hash": self.deployment.tx_hash,
                "block_number": self.deployment.block_number,
                "deployer_address": self.deployment.deployer_address,
                "contract_address": self.deployment.contract_address,
                "chain": self.deployment.chain,
                "timestamp": self.deployment.timestamp.isoformat(),
            },
            "classification": {
                "threat_category": self.classification.threat_category.value,
                "confidence": self.classification.confidence,
                "risk_score": self.classification.risk_score,
                "risk_factors": self.classification.risk_factors,
                "recommendation": self.classification.recommendation,
            },
            "alert_time": self.alert_time.isoformat(),
            "status": self.status
        }

class ContractDeploymentMonitor:
    """
    Monitor blockchain for new contract deployments
    and classify them for threats in real-time
    """
    
    def __init__(
        self,
        rpc_url: str,
        chain_name: str,
        classifier: Optional[ContractThreatClassifier] = None,
        alert_callback: Optional[Callable[[ThreatAlert], None]] = None
    ):
        self.chain_name = chain_name
        self.classifier = classifier or ContractThreatClassifier()
        self.alert_callback = alert_callback
        self.alerts: List[ThreatAlert] = []
        self.processed_blocks: set = set()
        self.running = False
        
        # Initialize Web3
        if WEB3_AVAILABLE:
            self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        else:
            self.web3 = None
    
    async def start(self, start_block: Optional[int] = None):
        """Start monitoring for new contract deployments"""
        if not self.web3:
            print("Web3 not available. Running in simulation mode.")
            return
        
        self.running = True
        current_block = start_block or self.web3.eth.block_number
        
        print(f"🔍 Starting contract deployment monitor on {self.chain_name}")
        print(f"   Starting from block: {current_block}")
        
        while self.running:
            try:
                latest_block = self.web3.eth.block_number
                
                if current_block <= latest_block:
                    await self._process_block(current_block)
                    current_block += 1
                else:
                    # Wait for new blocks
                    await asyncio.sleep(2)
            
            except Exception as e:
                print(f"Error processing block {current_block}: {e}")
                await asyncio.sleep(5)
    
    def stop(self):
        """Stop the monitor"""
        self.running = False
    
    async def _process_block(self, block_number: int):
        """Process a single block for contract deployments"""
        if block_number in self.processed_blocks:
            return
        
        try:
            block = self.web3.eth.get_block(block_number, full_transactions=True)
            
            for tx in block.transactions:
                # Contract deployment: to is None and input data is bytecode
                if tx.to is None and tx.input:
                    await self._handle_deployment(tx, block)
            
            self.processed_blocks.add(block_number)
            
            # Keep processed_blocks from growing too large
            if len(self.processed_blocks) > 10000:
                min_block = min(self.processed_blocks)
                self.processed_blocks.discard(min_block)
        
        except Exception as e:
            print(f"Error processing block {block_number}: {e}")
    
    async def _handle_deployment(self, tx, block):
        """Handle a contract deployment transaction"""
        try:
            # Get contract address from receipt
            receipt = self.web3.eth.get_transaction_receipt(tx.hash)
            contract_address = receipt.contractAddress
            
            if not contract_address:
                return
            
            # Get deployed bytecode
            bytecode = self.web3.eth.get_code(contract_address).hex()
            
            # Create deployment event
            deployment = DeploymentEvent(
                tx_hash=tx.hash.hex(),
                block_number=block.number,
                deployer_address=tx['from'],
                contract_address=contract_address,
                bytecode=bytecode,
                timestamp=datetime.fromtimestamp(block.timestamp),
                chain=self.chain_name,
                gas_used=receipt.gasUsed,
                value_wei=tx.value
            )
            
            # Classify the contract
            await self._classify_and_alert(deployment)
        
        except Exception as e:
            print(f"Error handling deployment: {e}")
    
    async def _classify_and_alert(self, deployment: DeploymentEvent):
        """Classify deployment and generate alert if needed"""
        # Classify
        result = self.classifier.classify(
            deployment.bytecode,
            deployment.contract_address
        )
        
        # Generate alert if threat detected
        if result.threat_category != ThreatCategory.SAFE:
            alert = ThreatAlert(
                id=f"alert_{deployment.tx_hash[:16]}",
                deployment=deployment,
                classification=result,
                alert_time=datetime.now(timezone.utc),
                status="new"
            )
            
            self.alerts.append(alert)
            
            # Print alert
            self._print_alert(alert)
            
            # Call callback if provided
            if self.alert_callback:
                self.alert_callback(alert)
    
    def _print_alert(self, alert: ThreatAlert):
        """Print alert to console"""
        severity_emoji = {
            ThreatCategory.FLASH_LOAN_EXPLOIT: "🔴",
            ThreatCategory.REENTRANCY_EXPLOIT: "🔴",
            ThreatCategory.BRIDGE_EXPLOIT: "🔴",
            ThreatCategory.ORACLE_MANIPULATION: "🟠",
            ThreatCategory.GOVERNANCE_ATTACK: "🟠",
            ThreatCategory.RUG_PULL: "🔴",
            ThreatCategory.HONEYPOT: "🟠",
            ThreatCategory.UNKNOWN_THREAT: "🟡",
        }
        
        emoji = severity_emoji.get(alert.classification.threat_category, "⚪")
        
        print("\n" + "=" * 70)
        print(f"{emoji} THREAT DETECTED: {alert.classification.threat_category.value.upper()}")
        print("=" * 70)
        print(f"Contract:    {alert.deployment.contract_address}")
        print(f"Deployer:    {alert.deployment.deployer_address}")
        print(f"Chain:       {alert.deployment.chain}")
        print(f"Block:       {alert.deployment.block_number}")
        print(f"TX Hash:     {alert.deployment.tx_hash}")
        print(f"Confidence:  {alert.classification.confidence:.2%}")
        print(f"Risk Score:  {alert.classification.risk_score}/100")
        print(f"Risk Factors:")
        for factor in alert.classification.risk_factors:
            print(f"  - {factor}")
        print(f"\nRecommendation: {alert.classification.recommendation}")
        print("=" * 70 + "\n")
    
    def get_alerts(self, status: Optional[str] = None) -> List[ThreatAlert]:
        """Get alerts, optionally filtered by status"""
        if status:
            return [a for a in self.alerts if a.status == status]
        return self.alerts
    
    def acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.status = "acknowledged"
                return True
        return False
    
    def mark_false_positive(self, alert_id: str):
        """Mark alert as false positive (for retraining)"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.status = "false_positive"
                return True
        return False

# Multi-chain monitor
class MultiChainDeploymentMonitor:
    """Monitor multiple chains simultaneously"""
    
    def __init__(self, classifier: Optional[ContractThreatClassifier] = None):
        self.monitors: Dict[str, ContractDeploymentMonitor] = {}
        self.classifier = classifier or ContractThreatClassifier()
        self.alert_callback: Optional[Callable[[ThreatAlert], None]] = None
    
    def add_chain(self, chain_name: str, rpc_url: str):
        """Add a chain to monitor"""
        self.monitors[chain_name] = ContractDeploymentMonitor(
            rpc_url=rpc_url,
            chain_name=chain_name,
            classifier=self.classifier,
            alert_callback=self.alert_callback
        )
    
    async def start_all(self):
        """Start monitoring all chains"""
        tasks = [
            monitor.start()
            for monitor in self.monitors.values()
        ]
        await asyncio.gather(*tasks)
    
    def stop_all(self):
        """Stop all monitors"""
        for monitor in self.monitors.values():
            monitor.stop()
    
    def get_all_alerts(self) -> List[ThreatAlert]:
        """Get alerts from all chains"""
        alerts = []
        for monitor in self.monitors.values():
            alerts.extend(monitor.get_alerts())
        return sorted(alerts, key=lambda a: a.alert_time, reverse=True)

# Simulation for testing
class SimulatedDeploymentMonitor:
    """Simulated monitor for testing without real blockchain"""
    
    def __init__(self, classifier: Optional[ContractThreatClassifier] = None):
        self.classifier = classifier or ContractThreatClassifier()
        self.alerts: List[ThreatAlert] = []
    
    def simulate_deployment(
        self,
        bytecode: str,
        deployer: str = "0x1234567890abcdef1234567890abcdef12345678",
        chain: str = "ethereum"
    ) -> Optional[ThreatAlert]:
        """Simulate a contract deployment and classification"""
        import hashlib
        
        # Generate fake contract address
        contract_address = "0x" + hashlib.sha256(bytecode.encode()).hexdigest()[:40]
        
        deployment = DeploymentEvent(
            tx_hash="0x" + hashlib.sha256(f"{bytecode}{deployer}".encode()).hexdigest(),
            block_number=12345678,
            deployer_address=deployer,
            contract_address=contract_address,
            bytecode=bytecode,
            timestamp=datetime.now(timezone.utc),
            chain=chain,
            gas_used=500000,
            value_wei=0
        )
        
        # Classify
        result = self.classifier.classify(bytecode, contract_address)
        
        if result.threat_category != ThreatCategory.SAFE:
            alert = ThreatAlert(
                id=f"sim_alert_{len(self.alerts)}",
                deployment=deployment,
                classification=result,
                alert_time=datetime.now(timezone.utc),
                status="new"
            )
            self.alerts.append(alert)
            return alert
        
        return None

if __name__ == "__main__":
    # Demo with simulation
    print("=" * 60)
    print("CONTRACT DEPLOYMENT MONITOR - SIMULATION")
    print("=" * 60)
    
    monitor = SimulatedDeploymentMonitor()
    
    # Simulate deploying an exploit-like contract
    exploit_bytecode = """
    608060405263c3924ed6000000000000000000f1f1f155555555ff
    """
    
    alert = monitor.simulate_deployment(
        bytecode=exploit_bytecode,
        deployer="0xAttacker1234567890abcdef1234567890",
        chain="ethereum"
    )
    
    if alert:
        print(f"\n🚨 Alert generated: {alert.classification.threat_category.value}")
        print(json.dumps(alert.to_dict(), indent=2))
    else:
        print("\n✅ Contract classified as safe")
