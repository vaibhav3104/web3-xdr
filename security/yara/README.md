# Sentinel3 YARA Rules

This directory contains YARA rules for detecting malicious patterns in:
- Smart contract bytecode (honeypots, rug pulls, exploits)
- Container runtime activity (reverse shells, cryptominers, credential theft)
- Configuration file tampering (detection rule bypasses)
- Incident response forensics (attacker tools, memory artifacts)

## Directory Structure

```
security/yara/
├── rules/
│   ├── web3/                    # Smart contract detection
│   │   ├── malicious_contracts.yar   # Honeypots, rug pulls, reentrancy
│   │   └── event_signatures.yar      # Malicious tx signatures, known exploits
│   ├── container/               # Runtime security
│   │   └── sentinel3_runtime.yar     # Reverse shells, cryptominers, escapes
│   ├── config/                  # Configuration tampering
│   │   └── config_tampering.yar      # Rule/policy modification detection
│   ├── incident_response/       # Forensics
│   │   └── forensics.yar             # Attacker tools, memory artifacts
│   └── malware/                 # General malware (add your own)
├── scanner.py                   # Python YARA scanner integration
└── README.md
```

## Installation

```bash
# Install YARA Python bindings
pip install yara-python

# Verify installation
python -c "import yara; print(yara.YARA_VERSION)"
```

## Usage

### Command Line

```bash
# Scan a single file
python security/yara/scanner.py /app/config/rules/advanced_attacks.yaml

# Scan contract bytecode
python security/yara/scanner.py "0x608060405234801561001057600080fd5b50..." -t bytecode

# Scan a directory recursively
python security/yara/scanner.py /app/ -t dir -r

# Output as JSON
python security/yara/scanner.py /app/config/ -t dir -o json

# Scan specific categories only
python security/yara/scanner.py /app/ -t dir -c config -c container
```

### Python Integration

```python
from security.yara.scanner import YARAScanner, ContractBytecodeScanner

# Initialize scanner
scanner = YARAScanner()

# Scan contract bytecode
result = scanner.scan_bytecode(
    "0x608060405234801561001057600080fd5b50...",
    contract_address="0x1234..."
)

if result.has_critical:
    print(f"CRITICAL threats detected in {result.target}")
    for match in result.matches:
        print(f"  - {match.rule_name}: {match.description}")

# Scan configuration files
results = scanner.scan_config_files("/app/config")
for result in results:
    if result.has_matches:
        print(f"Config tampering detected: {result.target}")

# Full contract analysis
contract_scanner = ContractBytecodeScanner()
report = contract_scanner.analyze(bytecode, "0x1234...")
print(f"Risk score: {report['risk_score']}/100")
```

### Kubernetes Integration

```yaml
# Add to cloudbuild-security.yaml
- name: 'python:3.11'
  id: 'yara-scan'
  entrypoint: 'bash'
  args:
    - '-c'
    - |
      pip install yara-python
      python security/yara/scanner.py /workspace/ -t dir -o json > yara-report.json
      # Fail if critical matches
      if grep -q '"severity": "CRITICAL"' yara-report.json; then
        echo "CRITICAL YARA matches found!"
        cat yara-report.json
        exit 1
      fi
```

## Rule Categories

### Web3 Contract Rules (`web3/`)

| Rule | Severity | Description |
|------|----------|-------------|
| `Honeypot_Common_Prefix` | CRITICAL | Common honeypot bytecode patterns |
| `Honeypot_Hidden_Transfer_Block` | CRITICAL | Blocks transfers after initial buys |
| `Rugpull_Hidden_Mint` | CRITICAL | Owner can mint unlimited tokens |
| `Rugpull_Liquidity_Removal` | CRITICAL | Can remove all liquidity |
| `Reentrancy_Classic` | CRITICAL | Classic reentrancy vulnerability |
| `Reentrancy_Cross_Function` | CRITICAL | Cross-function reentrancy |
| `FlashLoan_Attack_Pattern` | CRITICAL | Flash loan exploit pattern |
| `Oracle_TWAP_Manipulation` | CRITICAL | TWAP oracle manipulation |
| `Dangerous_SelfDestruct` | CRITICAL | Contains SELFDESTRUCT opcode |
| `Dangerous_DelegateCall_To_Input` | CRITICAL | Delegatecall to user input |
| `TxOrigin_Authentication` | HIGH | Phishing-vulnerable auth |
| `Unlimited_Approval` | HIGH | Requests max uint256 approval |
| `MEV_Sandwich_Vulnerable` | HIGH | No slippage protection |

### Event Signature Rules (`web3/`)

| Rule | Severity | Description |
|------|----------|-------------|
| `Event_OwnershipTransferred` | HIGH | Admin change detected |
| `Event_AdminChanged` | CRITICAL | Proxy admin changed |
| `Event_Upgraded` | CRITICAL | Implementation upgraded |
| `Event_FlashLoan_AAVE` | HIGH | AAVE flash loan event |
| `Event_Wormhole_MessagePublished` | MEDIUM | Wormhole bridge event |
| `Event_LiquidationCall_AAVE` | HIGH | AAVE liquidation |
| `Exploit_Ronin_Bridge` | CRITICAL | Known Ronin exploit pattern |
| `Exploit_Wormhole` | CRITICAL | Known Wormhole exploit pattern |
| `Exploit_Nomad_Bridge` | CRITICAL | Known Nomad exploit pattern |

### Container Runtime Rules (`container/`)

| Rule | Severity | Description |
|------|----------|-------------|
| `ReverseShell_Bash` | CRITICAL | Bash reverse shell |
| `ReverseShell_Python` | CRITICAL | Python reverse shell |
| `ReverseShell_Netcat` | CRITICAL | Netcat reverse shell |
| `Cryptominer_XMRig` | HIGH | XMRig cryptocurrency miner |
| `CredentialTheft_EnvDump` | HIGH | Environment variable dump |
| `CredentialTheft_PrivateKey` | CRITICAL | Private key access |
| `CredentialTheft_KubeSecrets` | CRITICAL | K8s secret access |
| `ContainerEscape_DockerSocket` | CRITICAL | Docker socket access |
| `Sentinel3_RuleConfigTampering` | CRITICAL | Detection rule modification |
| `Sentinel3_MLModelTampering` | CRITICAL | ML model modification |
| `Sentinel3_RPCHijacking` | CRITICAL | RPC endpoint hijacking |

### Config Tampering Rules (`config/`)

| Rule | Severity | Description |
|------|----------|-------------|
| `Config_RuleDisabled` | CRITICAL | Detection rule disabled |
| `Config_SeverityDowngraded` | HIGH | Rule severity lowered |
| `Config_ThresholdRaised` | HIGH | Detection threshold raised |
| `Config_ExclusionListModified` | CRITICAL | Whitelist/exclusion added |
| `Config_FalcoRuleDisabled` | CRITICAL | Falco rule disabled |
| `Config_NetworkPolicyWeakened` | CRITICAL | NetworkPolicy weakened |
| `Config_RBACEscalation` | CRITICAL | RBAC permissions escalated |
| `Config_KyvernoPolicyDeleted` | CRITICAL | Admission policy deleted |
| `Config_PSSDowngraded` | CRITICAL | Pod Security downgraded |

### Forensics Rules (`incident_response/`)

| Rule | Severity | Description |
|------|----------|-------------|
| `Tool_Peirates` | CRITICAL | K8s penetration tool |
| `Tool_KubeHunter` | HIGH | K8s security scanner |
| `Tool_Metasploit_K8s` | CRITICAL | Metasploit K8s modules |
| `Memory_CleartextCredentials` | CRITICAL | Credentials in memory |
| `Memory_ProcessInjection` | CRITICAL | Process injection artifacts |
| `Log_BruteForceAttempt` | HIGH | Auth brute force in logs |
| `Log_SQLInjectionAttempt` | HIGH | SQLi in logs |
| `Artifact_FlashLoanExploit` | CRITICAL | Flash loan exploit artifacts |
| `Artifact_BridgeExploit` | CRITICAL | Bridge exploit artifacts |

## Integration with Sentinel3

### Event Processing Pipeline

Add YARA scanning to the event processing pipeline:

```python
# In src/api/routes.py or event processor
from security.yara.scanner import YARAScanner

scanner = YARAScanner()

@app.post("/api/contracts/analyze")
async def analyze_contract(request: ContractAnalysisRequest):
    # YARA scan
    yara_result = scanner.scan_bytecode(
        request.bytecode,
        request.address
    )
    
    if yara_result.has_critical:
        # Immediately alert
        await send_critical_alert(
            alert_type="malicious_contract",
            contract=request.address,
            yara_matches=[m.to_alert() for m in yara_result.matches]
        )
    
    return {
        "address": request.address,
        "yara_scan": yara_result.to_dict(),
        "is_malicious": yara_result.has_critical
    }
```

### Config Monitoring

Monitor configuration changes:

```python
# In src/worker/main.py or separate watcher
import asyncio
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class ConfigChangeHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner
    
    def on_modified(self, event):
        if event.src_path.endswith(('.yaml', '.yml')):
            result = self.scanner.scan_file(
                event.src_path,
                categories=[ScanCategory.CONFIG_TAMPERING]
            )
            if result.has_critical:
                # CRITICAL: Detection rules may be compromised
                send_alert_to_separate_channel(result)
```

### CI/CD Security Gate

```yaml
# cloudbuild-security.yaml addition
steps:
  - name: 'python:3.11-slim'
    id: 'yara-scan'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        pip install yara-python
        
        # Scan source code
        python security/yara/scanner.py src/ -t dir -o json > yara-src.json
        
        # Scan config files
        python security/yara/scanner.py config/ -t dir -c config -o json > yara-config.json
        
        # Check for critical findings
        CRITICAL_COUNT=$(jq '.critical_count' yara-src.json yara-config.json | awk '{s+=$1} END {print s}')
        
        if [ "$CRITICAL_COUNT" -gt "0" ]; then
          echo "❌ YARA scan found $CRITICAL_COUNT critical issues"
          jq '.scan_results[] | select(.matches[].severity == "CRITICAL")' yara-*.json
          exit 1
        fi
        
        echo "✅ YARA scan passed"
```

## Writing Custom Rules

Add custom rules to detect project-specific threats:

```yara
// security/yara/rules/web3/custom.yar

rule Custom_KnownMaliciousContract
{
    meta:
        description = "Known malicious contract from incident XYZ"
        severity = "CRITICAL"
        category = "known_malicious"
        confidence = 100
        incident_id = "INC-2024-001"
    
    strings:
        // Bytecode hash of known malicious contract
        $bytecode_hash = { 60 80 60 40 52 34 80 15 ... }
        
        // Or specific function selectors
        $malicious_func = { de ad be ef }
    
    condition:
        any of them
}
```

## Performance Considerations

- YARA rules are compiled once at startup
- Bytecode scans are fast (~1-5ms per contract)
- File scans depend on file size (50MB limit by default)
- For high-volume scanning, consider:
  - Running YARA scanner as a separate microservice
  - Using Redis to cache scan results by bytecode hash
  - Implementing scan result TTL (e.g., 24 hours)

## References

- [YARA Documentation](https://yara.readthedocs.io/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Sentinel3 Detection Rules](../config/rules/)
- [Falco Runtime Rules](../deploy/kubernetes/security/falco-rules.yaml)
