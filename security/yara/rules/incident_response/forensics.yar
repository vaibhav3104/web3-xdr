/*
 * Sentinel3 YARA Rules - Incident Response & Forensics
 * =====================================================
 * Rules for post-incident forensic analysis.
 * Run against memory dumps, disk images, and log files.
 * 
 * Usage:
 *   yara -r security/yara/rules/incident_response/ /path/to/evidence/
 *   yara security/yara/rules/incident_response/forensics.yar memory_dump.raw
 */

// ============================================================================
// KNOWN ATTACKER TOOLS
// ============================================================================

rule Tool_Peirates
{
    meta:
        description = "Peirates Kubernetes penetration testing tool"
        severity = "CRITICAL"
        category = "attacker_tool"
        reference = "https://github.com/inguardians/peirates"
        confidence = 95
    
    strings:
        $peirates1 = "peirates"
        $peirates2 = "Peirates"
        $peirates3 = "kubectl-psp_advisor"
        $menu = "Peirates Main Menu"
        
    condition:
        any of them
}

rule Tool_KubeHunter
{
    meta:
        description = "kube-hunter Kubernetes security scanner"
        severity = "HIGH"
        category = "reconnaissance"
        reference = "https://github.com/aquasecurity/kube-hunter"
        confidence = 90
    
    strings:
        $hunter1 = "kube-hunter"
        $hunter2 = "kube_hunter"
        $aqua = "aquasecurity"
        
    condition:
        any of them
}

rule Tool_KubeStriker
{
    meta:
        description = "KubeStriker security auditing tool"
        severity = "HIGH"
        category = "reconnaissance"
        confidence = 90
    
    strings:
        $striker = "kubestriker"
        $striker2 = "KubeStriker"
        
    condition:
        any of them
}

rule Tool_Kubectl_Exploit
{
    meta:
        description = "Kubectl being used for exploitation"
        severity = "HIGH"
        category = "attacker_tool"
        confidence = 80
    
    strings:
        // Dangerous kubectl commands
        $exec_shell = /kubectl\s+exec.*--\s*(\/bin\/)?(ba)?sh/
        $cp_out = /kubectl\s+cp.*:\//  // Copying from container
        $port_forward = /kubectl\s+port-forward/
        $create_token = /kubectl\s+create\s+token/
        $auth_can_i = /kubectl\s+auth\s+can-i\s+\*/
        
    condition:
        any of them
}

rule Tool_Metasploit_K8s
{
    meta:
        description = "Metasploit Kubernetes modules"
        severity = "CRITICAL"
        category = "attacker_tool"
        confidence = 95
    
    strings:
        $msf1 = "exploit/multi/kubernetes"
        $msf2 = "auxiliary/scanner/kubernetes"
        $msf3 = "post/kubernetes"
        $meterpreter = "meterpreter"
        
    condition:
        any of them
}

// ============================================================================
// MEMORY FORENSICS
// ============================================================================

rule Memory_CleartextCredentials
{
    meta:
        description = "Cleartext credentials in memory"
        severity = "CRITICAL"
        category = "credential_exposure"
        confidence = 80
    
    strings:
        // Database connection strings
        $postgres_uri = /postgres(ql)?:\/\/[^:]+:[^@]+@/
        $mysql_uri = /mysql:\/\/[^:]+:[^@]+@/
        $redis_uri = /redis:\/\/:[^@]+@/
        
        // API keys in memory
        $infura_key = /[a-f0-9]{32}/ // Infura project ID
        $etherscan_key = /etherscan.*[A-Z0-9]{34}/i
        
        // Private keys (should NEVER be in memory for this app)
        $eth_privkey = /0x[a-fA-F0-9]{64}/
        $mnemonic = /(abandon|ability|able|about|above|absent).{100,300}(zoo|zone|zero)/i
        
    condition:
        any of them
}

rule Memory_ShellHistory
{
    meta:
        description = "Shell command history in memory"
        severity = "MEDIUM"
        category = "forensics"
        confidence = 85
    
    strings:
        // Bash history markers
        $bash_history = ".bash_history"
        $zsh_history = ".zsh_history"
        $history_cmd = "HISTFILE="
        
        // Suspicious commands
        $curl_post = "curl"
        $wget_exec = "wget"
        $nc_listen = "nc -l"
        
    condition:
        ($bash_history or $zsh_history or $history_cmd) and ($curl_post or $wget_exec or $nc_listen)
}

rule Memory_ProcessInjection
{
    meta:
        description = "Process injection artifacts in memory"
        severity = "CRITICAL"
        category = "execution"
        mitre_attack = "T1055"
        confidence = 75
    
    strings:
        // Linux process injection
        $ptrace = "ptrace"
        $memfd_create = "memfd_create"
        $proc_mem = "/proc/self/mem"
        
        // Python injection
        $ctypes_injection = /ctypes.*CDLL.*libc/
        
    condition:
        any of them
}

// ============================================================================
// DISK FORENSICS
// ============================================================================

rule Disk_HiddenFiles
{
    meta:
        description = "Suspicious hidden files"
        severity = "HIGH"
        category = "persistence"
        confidence = 80
    
    strings:
        // Hidden directories
        $hidden1 = "/.hidden"
        $hidden2 = "/..data"
        $hidden3 = "/.../"
        
        // Common attacker hiding spots
        $tmp_hidden = "/tmp/."
        $var_tmp = "/var/tmp/."
        $dev_shm = "/dev/shm/."
        
    condition:
        any of them
}

rule Disk_ModifiedBinaries
{
    meta:
        description = "System binary modification indicators"
        severity = "CRITICAL"
        category = "persistence"
        mitre_attack = "T1036"
        confidence = 85
    
    strings:
        // Rootkit indicators
        $ld_preload = "LD_PRELOAD"
        $ld_library = "LD_LIBRARY_PATH"
        
        // Common hiding patterns in modified binaries
        $hidden_miner = "xmrig"
        $grep_hide = "grep -v"
        
    condition:
        ($ld_preload or $ld_library) or ($hidden_miner and $grep_hide)
}

rule Disk_WebshellArtifacts
{
    meta:
        description = "Webshell file artifacts"
        severity = "CRITICAL"
        category = "persistence"
        confidence = 85
    
    strings:
        // Common webshell filenames
        $name1 = "c99.php"
        $name2 = "r57.php"
        $name3 = "wso.php"
        $name4 = "shell.py"
        $name5 = "cmd.jsp"
        
        // Obfuscated webshell patterns
        $obf1 = /base64_decode\s*\(\s*\$_/
        $obf2 = /eval\s*\(\s*gzuncompress/
        $obf3 = /assert\s*\(\s*\$_/
        
    condition:
        any of them
}

// ============================================================================
// LOG FORENSICS
// ============================================================================

rule Log_BruteForceAttempt
{
    meta:
        description = "Brute force authentication attempts in logs"
        severity = "HIGH"
        category = "initial_access"
        mitre_attack = "T1110"
        confidence = 80
    
    strings:
        // Failed auth patterns
        $fail1 = "authentication failed"
        $fail2 = "invalid password"
        $fail3 = "access denied"
        $fail4 = "401 Unauthorized"
        $fail5 = "403 Forbidden"
        
        // Rate indicators
        $rate1 = /\d{3,}\s*(failed|invalid|denied)/i
        
    condition:
        #fail1 > 10 or #fail2 > 10 or #fail3 > 10 or #fail4 > 10 or #fail5 > 10 or $rate1
}

rule Log_SQLInjectionAttempt
{
    meta:
        description = "SQL injection attempt in logs"
        severity = "HIGH"
        category = "initial_access"
        mitre_attack = "T1190"
        confidence = 85
    
    strings:
        // Classic SQLi
        $sqli1 = "' OR '1'='1"
        $sqli2 = "'; DROP TABLE"
        $sqli3 = "UNION SELECT"
        $sqli4 = "1=1--"
        $sqli5 = "' OR 1=1#"
        
        // Error messages indicating SQLi
        $error1 = "syntax error" nocase
        $error2 = "SQL syntax" nocase
        $error3 = "query failed" nocase
        
    condition:
        any of ($sqli*) or (any of ($error*) and /SELECT|INSERT|UPDATE|DELETE/i)
}

rule Log_KubernetesAudit_Suspicious
{
    meta:
        description = "Suspicious Kubernetes audit log entries"
        severity = "HIGH"
        category = "discovery"
        confidence = 85
    
    strings:
        // Sensitive operations
        $secrets_list = /"verb":"list".*"resource":"secrets"/
        $secrets_get = /"verb":"get".*"resource":"secrets"/
        $exec = /"verb":"create".*"resource":"pods\/exec"/
        $portforward = /"verb":"create".*"resource":"pods\/portforward"/
        
        // Cluster-wide enumeration
        $list_all = /"verb":"list".*"namespace":""/
        $watch_all = /"verb":"watch".*"namespace":""/
        
    condition:
        any of them
}

rule Log_Sentinel3_AttackCorrelation
{
    meta:
        description = "Sentinel3 logs indicating correlated attack"
        severity = "CRITICAL"
        category = "impact"
        confidence = 90
    
    strings:
        // Sentinel3 critical alerts
        $critical1 = "severity: critical"
        $critical2 = "CRITICAL_RUNTIME"
        
        // Attack patterns
        $flash_loan = "flash_loan"
        $rug_pull = "rug_pull"
        $honeypot = "honeypot"
        $bridge_exploit = "bridge_exploit"
        
        // High volume indicator
        $many_alerts = /"alert_count":\s*[1-9]\d{2,}/
        
    condition:
        any of ($critical*) and any of ($flash_loan, $rug_pull, $honeypot, $bridge_exploit) or $many_alerts
}

// ============================================================================
// TIMELINE RECONSTRUCTION
// ============================================================================

rule Timeline_InitialCompromise
{
    meta:
        description = "Indicators of initial compromise timestamp"
        severity = "CRITICAL"
        category = "forensics"
        confidence = 75
    
    strings:
        // First malicious activity markers
        $first_exec = /first.*exec|initial.*command/i
        $first_shell = /shell.*started|reverse.*connect/i
        
        // Persistence establishment
        $persist = /cronjob.*created|systemd.*enabled/i
        
    condition:
        any of them
}

rule Timeline_LateralMovement
{
    meta:
        description = "Lateral movement timeline indicators"
        severity = "HIGH"
        category = "forensics"
        confidence = 75
    
    strings:
        // Network movement
        $ssh_new = /ssh.*new.*connection/i
        $rdp_new = /rdp.*session.*established/i
        
        // Kubernetes movement
        $k8s_exec = /kubectl.*exec.*-it/
        $k8s_cp = /kubectl.*cp.*:/
        
    condition:
        any of them
}

rule Timeline_Exfiltration
{
    meta:
        description = "Data exfiltration timeline indicators"
        severity = "CRITICAL"
        category = "forensics"
        confidence = 80
    
    strings:
        // Large data transfer
        $large_transfer = /bytes.*[1-9]\d{9,}/  // > 1GB
        $upload = /upload.*complete|transfer.*finish/i
        
        // Database dumps
        $db_dump = /pg_dump|mysqldump|mongodump/
        
        // Archive creation
        $archive = /tar.*czf|zip.*-r|7z.*a/
        
    condition:
        any of them
}

// ============================================================================
// KNOWN WEB3 EXPLOIT ARTIFACTS
// ============================================================================

rule Artifact_FlashLoanExploit
{
    meta:
        description = "Flash loan exploit contract artifacts"
        severity = "CRITICAL"
        category = "web3_exploit"
        confidence = 90
    
    strings:
        // Flash loan interfaces
        $aave = "executeOperation"
        $dydx = "callFunction"
        $balancer = "receiveFlashLoan"
        
        // Manipulation functions
        $swap = "swapExactTokensForTokens"
        $liquidate = "liquidationCall"
        
        // High value indicators
        $high_value = /amount.*[1-9]\d{18,}/  // > 1 ETH in wei
        
    condition:
        any of ($aave, $dydx, $balancer) and any of ($swap, $liquidate) and $high_value
}

rule Artifact_BridgeExploit
{
    meta:
        description = "Cross-chain bridge exploit artifacts"
        severity = "CRITICAL"
        category = "web3_exploit"
        confidence = 90
    
    strings:
        // Bridge protocols
        $wormhole = "wormhole"
        $layerzero = "layerzero"
        $multichain = "anyswap"
        
        // Exploit indicators
        $fake_msg = "forged message"
        $replay = "replay"
        $validator_bypass = "validator.*bypass"
        
    condition:
        any of ($wormhole, $layerzero, $multichain) and any of ($fake_msg, $replay, $validator_bypass)
}

rule Artifact_RugPullExploit
{
    meta:
        description = "Rug pull exploit artifacts"
        severity = "CRITICAL"
        category = "web3_exploit"
        confidence = 85
    
    strings:
        // Liquidity removal
        $remove_liq = "removeLiquidity"
        $remove_all = /remove.*100\s*%/i
        
        // Token manipulation
        $mint_hidden = "hiddenMint"
        $blacklist = "blacklist"
        $max_tx = "maxTransactionAmount"
        
        // Exit scam
        $exit_scam = /exit.*scam|rug.*pull/i
        
    condition:
        any of them
}
