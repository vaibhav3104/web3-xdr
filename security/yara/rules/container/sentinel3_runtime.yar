/*
 * Sentinel3 YARA Rules - Container Runtime Security
 * ==================================================
 * Detects malicious activity inside Sentinel3 containers.
 * Complement to Falco rules for file-based detection.
 * 
 * Usage:
 *   yara -r security/yara/rules/container/ /proc/<pid>/exe
 *   yara -r security/yara/rules/container/ /app/
 */

// ============================================================================
// REVERSE SHELL DETECTION
// ============================================================================

rule ReverseShell_Bash
{
    meta:
        description = "Bash reverse shell pattern"
        severity = "CRITICAL"
        category = "execution"
        mitre_attack = "T1059.004"
        confidence = 95
    
    strings:
        $bash_i = "bash -i"
        $bash_redirect = "/dev/tcp/"
        $bash_exec = "exec 5<>/dev/tcp"
        $bash_socket = "0<&196;exec 196<>/dev/tcp"
        
    condition:
        any of them
}

rule ReverseShell_Python
{
    meta:
        description = "Python reverse shell pattern"
        severity = "CRITICAL"
        category = "execution"
        mitre_attack = "T1059.006"
        confidence = 95
    
    strings:
        $py_socket_subprocess = /socket.*subprocess|subprocess.*socket/
        $py_pty_spawn = "pty.spawn"
        $py_os_dup2 = /os\.dup2.*socket/
        $py_reverse = /socket\.socket.*connect.*\(\s*["'][^"']+["']\s*,\s*\d+\s*\)/
        
    condition:
        any of them
}

rule ReverseShell_Netcat
{
    meta:
        description = "Netcat reverse shell"
        severity = "CRITICAL"
        category = "execution"
        confidence = 95
    
    strings:
        $nc_e = "nc -e"
        $ncat_e = "ncat -e"
        $nc_shell = /nc.*\/bin\/(ba)?sh/
        $mkfifo = "mkfifo /tmp/"
        
    condition:
        any of them
}

rule ReverseShell_Perl
{
    meta:
        description = "Perl reverse shell pattern"
        severity = "CRITICAL"
        category = "execution"
        confidence = 90
    
    strings:
        $perl_socket = /perl.*socket.*connect/
        $perl_fork = /perl.*fork.*exec/
        
    condition:
        any of them
}

// ============================================================================
// CRYPTOMINER DETECTION
// ============================================================================

rule Cryptominer_XMRig
{
    meta:
        description = "XMRig cryptocurrency miner"
        severity = "HIGH"
        category = "cryptomining"
        mitre_attack = "T1496"
        confidence = 95
    
    strings:
        $xmrig1 = "xmrig" nocase
        $xmrig2 = "XMRig"
        $stratum = "stratum+tcp://"
        $stratum_ssl = "stratum+ssl://"
        $pool_port = /:\d{4,5}\s/
        $monero_addr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
        
    condition:
        any of ($xmrig*) or (($stratum or $stratum_ssl) and $pool_port) or $monero_addr
}

rule Cryptominer_Generic
{
    meta:
        description = "Generic cryptocurrency miner indicators"
        severity = "HIGH"
        category = "cryptomining"
        confidence = 80
    
    strings:
        $pool1 = "pool.minexmr.com"
        $pool2 = "xmrpool.eu"
        $pool3 = "supportxmr.com"
        $pool4 = "nanopool.org"
        $pool5 = "hashvault.pro"
        $pool6 = "f2pool.com"
        $algo1 = "cryptonight"
        $algo2 = "randomx"
        $algo3 = "kawpow"
        
    condition:
        any of ($pool*) or any of ($algo*)
}

// ============================================================================
// CREDENTIAL THEFT
// ============================================================================

rule CredentialTheft_EnvDump
{
    meta:
        description = "Environment variable dumping (credential theft)"
        severity = "HIGH"
        category = "credential_access"
        mitre_attack = "T1552.001"
        confidence = 90
    
    strings:
        $proc_environ = "/proc/self/environ"
        $proc_1_environ = "/proc/1/environ"
        $printenv = "printenv"
        $env_dump = /env\s*[|>]/
        
    condition:
        any of them
}

rule CredentialTheft_PrivateKey
{
    meta:
        description = "Private key file access patterns"
        severity = "CRITICAL"
        category = "credential_access"
        confidence = 95
    
    strings:
        // File extensions
        $ext_pem = ".pem"
        $ext_key = ".key"
        $ext_p12 = ".p12"
        $ext_pfx = ".pfx"
        
        // Web3 specific
        $keystore = "keystore"
        $wallet = "wallet.json"
        $mnemonic = "mnemonic"
        $seed_phrase = "seed_phrase"
        $private_key = "private_key"
        
        // Key content patterns
        $begin_private = "-----BEGIN PRIVATE KEY-----"
        $begin_rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $begin_ec = "-----BEGIN EC PRIVATE KEY-----"
        
    condition:
        any of them
}

rule CredentialTheft_KubeSecrets
{
    meta:
        description = "Kubernetes secret access from container"
        severity = "CRITICAL"
        category = "credential_access"
        mitre_attack = "T1552.007"
        confidence = 95
    
    strings:
        $sa_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        $sa_ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        $sa_namespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        $run_secrets = "/run/secrets/"
        
    condition:
        any of them
}

// ============================================================================
// CONTAINER ESCAPE INDICATORS
// ============================================================================

rule ContainerEscape_DockerSocket
{
    meta:
        description = "Docker socket access (container escape)"
        severity = "CRITICAL"
        category = "privilege_escalation"
        mitre_attack = "T1611"
        confidence = 95
    
    strings:
        $docker_sock = "/var/run/docker.sock"
        $docker_api = "unix:///var/run/docker.sock"
        $containerd_sock = "/run/containerd/containerd.sock"
        
    condition:
        any of them
}

rule ContainerEscape_ProcMount
{
    meta:
        description = "Dangerous /proc mount access"
        severity = "CRITICAL"
        category = "privilege_escalation"
        confidence = 90
    
    strings:
        $proc_sys = "/proc/sys/"
        $proc_sysrq = "/proc/sysrq-trigger"
        $proc_kcore = "/proc/kcore"
        $proc_kmem = "/proc/kmem"
        
    condition:
        any of them
}

rule ContainerEscape_CGROUPs
{
    meta:
        description = "Cgroup escape technique"
        severity = "CRITICAL"
        category = "privilege_escalation"
        confidence = 90
    
    strings:
        $cgroup_release = "/sys/fs/cgroup/*/release_agent"
        $cgroup_notify = "notify_on_release"
        $cgroup_mount = "mount -t cgroup"
        
    condition:
        any of them
}

// ============================================================================
// SUPPLY CHAIN ATTACKS
// ============================================================================

rule SupplyChain_RuntimePackageInstall
{
    meta:
        description = "Package installation at runtime (supply chain attack)"
        severity = "HIGH"
        category = "persistence"
        mitre_attack = "T1195.002"
        confidence = 90
    
    strings:
        $pip_install = "pip install"
        $pip3_install = "pip3 install"
        $npm_install = "npm install"
        $yarn_add = "yarn add"
        $apt_install = "apt-get install"
        $apt_install2 = "apt install"
        $apk_add = "apk add"
        $yum_install = "yum install"
        $gem_install = "gem install"
        $cargo_install = "cargo install"
        
    condition:
        any of them
}

rule SupplyChain_MaliciousPyPI
{
    meta:
        description = "Known malicious PyPI package names"
        severity = "CRITICAL"
        category = "supply_chain"
        confidence = 85
    
    strings:
        // Known malicious PyPI packages (typosquats and malware)
        $mal1 = "colourama"      // Typosquat of colorama
        $mal2 = "python-sqlite"   // Malicious package
        $mal3 = "discordsafety"   // Malicious package
        $mal4 = "aiohttp-socks5"  // Malicious package
        $mal5 = "requestss"       // Typosquat of requests
        $mal6 = "djanga"          // Typosquat of django
        
    condition:
        any of ($mal*)
}

// ============================================================================
// WEBSHELL DETECTION
// ============================================================================

rule Webshell_Python
{
    meta:
        description = "Python webshell pattern"
        severity = "CRITICAL"
        category = "persistence"
        confidence = 85
    
    strings:
        $exec_request = /exec\s*\(\s*request\./
        $eval_request = /eval\s*\(\s*request\./
        $os_popen = /os\.popen\s*\(\s*request\./
        $subprocess_req = /subprocess\.\w+\s*\(\s*request\./
        
    condition:
        any of them
}

rule Webshell_Generic
{
    meta:
        description = "Generic webshell indicators"
        severity = "HIGH"
        category = "persistence"
        confidence = 75
    
    strings:
        $cmd_param = /[?&]cmd=/
        $exec_param = /[?&]exec=/
        $shell_param = /[?&]shell=/
        $passwd = "etc/passwd"
        $shadow = "etc/shadow"
        
    condition:
        any of them
}

// ============================================================================
// SENTINEL3-SPECIFIC THREATS
// ============================================================================

rule Sentinel3_RuleConfigTampering
{
    meta:
        description = "Attempt to modify Sentinel3 detection rules"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 90
    
    strings:
        $rules_path = "/app/config/rules/"
        $yaml_write = /open\s*\([^)]*rules[^)]*\.yaml[^)]*,\s*['"]w/
        $configmap_patch = "kubectl patch configmap sentinel3-rules"
        
    condition:
        any of them
}

rule Sentinel3_MLModelTampering
{
    meta:
        description = "Attempt to modify Sentinel3 ML models"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 90
    
    strings:
        $model_path = "/app/data/models/"
        $pt_write = /\.pt['"]\s*,\s*['"]wb/
        $joblib_write = /joblib\.dump/
        $torch_save = /torch\.save/
        
    condition:
        ($model_path and any of ($pt_write, $joblib_write, $torch_save))
}

rule Sentinel3_RPCHijacking
{
    meta:
        description = "RPC endpoint hijacking attempt"
        severity = "CRITICAL"
        category = "impact"
        confidence = 85
    
    strings:
        $rpc_url_env = "RPC_URL="
        $infura_replace = /INFURA.*=.*http/
        $provider_mod = /provider.*=.*['"](http|ws)/
        $eth_rpc_mod = "ETH_RPC_URL"
        
    condition:
        any of them
}

rule Sentinel3_DatabaseExfiltration
{
    meta:
        description = "Database credential theft or exfiltration"
        severity = "CRITICAL"
        category = "exfiltration"
        confidence = 85
    
    strings:
        $pg_dump = "pg_dump"
        $database_url = "DATABASE_URL"
        $postgres_pass = "POSTGRES_PASSWORD"
        $neo4j_pass = "NEO4J_PASSWORD"
        $bulk_select = /SELECT\s+\*\s+FROM\s+\w+\s*;/i
        
    condition:
        ($pg_dump) or (any of ($database_url, $postgres_pass, $neo4j_pass) and $bulk_select)
}

// ============================================================================
// NETWORK INDICATORS
// ============================================================================

rule Network_C2_Indicators
{
    meta:
        description = "Command and control communication indicators"
        severity = "HIGH"
        category = "command_and_control"
        mitre_attack = "T1071"
        confidence = 70
    
    strings:
        // Encoded/obfuscated data patterns
        $base64_exec = /base64.*\|\s*(ba)?sh/
        $gzip_pipe = /gzip.*\|\s*(ba)?sh/
        
        // Unusual user agents
        $ua_bot = "User-Agent: Bot"
        $ua_empty = "User-Agent: "
        
        // DNS tunneling indicators
        $dns_txt = "TXT record"
        $long_subdomain = /[a-zA-Z0-9]{30,}\./
        
    condition:
        any of them
}

rule Network_DataExfiltration
{
    meta:
        description = "Data exfiltration patterns"
        severity = "HIGH"
        category = "exfiltration"
        mitre_attack = "T1048"
        confidence = 75
    
    strings:
        $curl_data = /curl.*-d.*@/
        $wget_post = "wget --post-data"
        $nc_file = /nc.*<\s*\//
        $curl_upload = /curl.*--upload-file/
        
    condition:
        any of them
}
