/*
 * Sentinel3 YARA Rules - Configuration Tampering Detection
 * =========================================================
 * Detects unauthorized modifications to critical configuration files.
 * Run against ConfigMap backups or audit logs.
 * 
 * Usage:
 *   yara security/yara/rules/config/config_tampering.yar /app/config/rules/
 *   yara security/yara/rules/config/config_tampering.yar <audit_log.json>
 */

// ============================================================================
// DETECTION RULE TAMPERING
// ============================================================================

rule Config_RuleDisabled
{
    meta:
        description = "Detection rule has been disabled"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 95
    
    strings:
        // Patterns indicating rule was disabled
        $disabled1 = "enabled: false"
        $disabled2 = "enabled: False"
        $disabled3 = "enabled: no"
        $disabled4 = "# enabled: true"  // Commented out
        
        // Rule identifiers this applies to
        $critical_rule = /id:\s*["']?(unbacked|validator|bridge|flashloan|rugpull|honeypot)/i
        
    condition:
        any of ($disabled*) and $critical_rule
}

rule Config_SeverityDowngraded
{
    meta:
        description = "Detection rule severity has been downgraded"
        severity = "HIGH"
        category = "defense_evasion"
        confidence = 85
    
    strings:
        // Critical rules downgraded to lower severity
        $was_critical = /id:.*critical.*\n.*severity:\s*(high|medium|low|info)/i
        $was_high = /id:.*high.*\n.*severity:\s*(medium|low|info)/i
        
        // Known critical rules that should never be downgraded
        $critical_id1 = "unbacked-mint-001"
        $critical_id2 = "validator-bypass-003"
        $critical_id3 = "bridge-replay-attack-001"
        $critical_id4 = "contract-selfdestruct-001"
        
    condition:
        any of ($was*) or (any of ($critical_id*) and /severity:\s*(medium|low|info)/i)
}

rule Config_ConfidenceLowered
{
    meta:
        description = "Detection rule confidence has been suspiciously lowered"
        severity = "HIGH"
        category = "defense_evasion"
        confidence = 80
    
    strings:
        // Very low confidence (likely to suppress alerts)
        $low_conf1 = /confidence:\s*(0\.[0-3]\d*|0\.[0-4]0)/
        $low_conf2 = /confidence:\s*([0-3]\d)\s*$/  // Integer < 40
        
        // On critical rules
        $critical = "severity: critical"
        
    condition:
        any of ($low_conf*) and $critical
}

rule Config_ThresholdRaised
{
    meta:
        description = "Detection threshold raised to unreasonable level"
        severity = "HIGH"
        category = "defense_evasion"
        confidence = 80
    
    strings:
        // Suspiciously high thresholds
        $high_amount = /amount_usd_min:\s*[1-9]\d{7,}/  // > $10M minimum
        $high_count = /min_count:\s*[1-9]\d{3,}/        // > 1000 minimum events
        $high_ratio = /ratio_threshold:\s*[5-9]\d\.\d/  // > 50x ratio
        
    condition:
        any of them
}

rule Config_ExclusionListModified
{
    meta:
        description = "Exclusion list modified (potential bypass)"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 90
    
    strings:
        // Exclusion/whitelist sections
        $exclude1 = "exclude_addresses:"
        $exclude2 = "whitelist:"
        $exclude3 = "ignore_addresses:"
        $exclude4 = "skip_contracts:"
        
        // Ethereum address pattern
        $eth_addr = /0x[a-fA-F0-9]{40}/
        
        // Known safe tokens/protocols (if these are present with address, likely safe)
        $safe_usdc = "USDC"
        $safe_usdt = "USDT"
        $safe_dai = "DAI"
        $safe_weth = "WETH"
        
    condition:
        any of ($exclude*) and $eth_addr and not any of ($safe_*)
}

// ============================================================================
// FALCO RULE TAMPERING
// ============================================================================

rule Config_FalcoRuleDisabled
{
    meta:
        description = "Falco security rule has been disabled"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 95
    
    strings:
        // Falco disable patterns
        $disabled1 = "enabled: false"
        $disabled2 = "- macro: never_true"
        $disabled3 = "condition: never_true"
        
        // Critical Falco rules
        $critical1 = "Sentinel3 Private Key Access"
        $critical2 = "Sentinel3 Reverse Shell"
        $critical3 = "Sentinel3 RPC Endpoint Modification"
        
    condition:
        any of ($disabled*) and any of ($critical*)
}

rule Config_FalcoRuleWeakened
{
    meta:
        description = "Falco rule condition has been weakened"
        severity = "HIGH"
        category = "defense_evasion"
        confidence = 85
    
    strings:
        // Overly broad exceptions
        $broad_exception1 = "and not proc.name"
        $broad_exception2 = "and not container.image"
        $broad_exception3 = "and not k8s.pod.name"
        
        // Priority downgraded
        $priority_down = /priority:\s*(DEBUG|INFO|NOTICE)/
        
        // Was previously WARNING or higher
        $was_warning = "# priority: WARNING"
        $was_error = "# priority: ERROR"
        $was_critical = "# priority: CRITICAL"
        
    condition:
        any of ($broad_exception*) or ($priority_down and any of ($was*))
}

// ============================================================================
// NETWORK POLICY TAMPERING
// ============================================================================

rule Config_NetworkPolicyWeakened
{
    meta:
        description = "Kubernetes NetworkPolicy has been weakened"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 90
    
    strings:
        // Allow all patterns (dangerous)
        $allow_all_ingress = "ingress: [{}]"
        $allow_all_egress = "egress: [{}]"
        $allow_all_podsel = "podSelector: {}"
        
        // Policy types section
        $policy_types = "policyTypes:"
        $has_egress = "Egress"
        $has_ingress = "Ingress"
        
    condition:
        $allow_all_ingress or $allow_all_egress or $allow_all_podsel or 
        ($policy_types and not ($has_egress and $has_ingress))
}

rule Config_NetworkPolicyDeleted
{
    meta:
        description = "NetworkPolicy resource was deleted"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 95
    
    strings:
        // Audit log patterns for deletion
        $delete_np = /"verb":\s*"delete".*"resource":\s*"networkpolicies"/
        $kubectl_delete = "kubectl delete networkpolicy"
        
    condition:
        any of them
}

// ============================================================================
// RBAC TAMPERING
// ============================================================================

rule Config_RBACEscalation
{
    meta:
        description = "RBAC role with dangerous permissions"
        severity = "CRITICAL"
        category = "privilege_escalation"
        confidence = 90
    
    strings:
        // Dangerous verbs
        $verb_all = "\"*\""
        $verb_create_secrets = "create" 
        $verb_delete_pods = "delete"
        $verb_exec = "pods/exec"
        $resources_secrets = "secrets"
        
        // Cluster-admin binding
        $cluster_admin = "cluster-admin"
        
    condition:
        $verb_all or $cluster_admin or ($verb_exec) or 
        ($verb_create_secrets and $resources_secrets) or
        ($verb_delete_pods and $resources_secrets)
}

rule Config_ServiceAccountTokenMounted
{
    meta:
        description = "ServiceAccount token automount was enabled"
        severity = "HIGH"
        category = "credential_access"
        confidence = 90
    
    strings:
        // Token mounting enabled (should be false for sentinel3)
        $automount_true = "automountServiceAccountToken: true"
        
        // In sentinel3 namespace context
        $sentinel3_ns = "namespace: sentinel3"
        
    condition:
        $automount_true and $sentinel3_ns
}

// ============================================================================
// KYVERNO POLICY TAMPERING
// ============================================================================

rule Config_KyvernoPolicyDeleted
{
    meta:
        description = "Kyverno admission policy was deleted"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 95
    
    strings:
        $delete_policy = /"verb":\s*"delete".*"resource":\s*"clusterpolicies"/
        $delete_kubectl = "kubectl delete clusterpolicy"
        
        // Critical policies
        $critical1 = "sentinel3-verify-image-registry"
        $critical2 = "sentinel3-disallow-privileged"
        $critical3 = "sentinel3-require-nonroot"
        
    condition:
        ($delete_policy or $delete_kubectl) and any of ($critical*)
}

rule Config_KyvernoPolicyAuditMode
{
    meta:
        description = "Kyverno policy changed from Enforce to Audit"
        severity = "HIGH"
        category = "defense_evasion"
        confidence = 90
    
    strings:
        // Enforcement weakened
        $audit_mode = "validationFailureAction: Audit"
        $was_enforce = "# validationFailureAction: Enforce"
        
        // Critical policy context
        $policy_name = /name:\s*sentinel3-(verify|disallow|require)/
        
    condition:
        $audit_mode and ($was_enforce or $policy_name)
}

// ============================================================================
// POD SECURITY TAMPERING
// ============================================================================

rule Config_PSSDowngraded
{
    meta:
        description = "Pod Security Standard was downgraded"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 95
    
    strings:
        // PSS levels (restricted is most secure)
        $baseline = "pod-security.kubernetes.io/enforce: baseline"
        $privileged = "pod-security.kubernetes.io/enforce: privileged"
        
        // Was restricted
        $was_restricted = "# pod-security.kubernetes.io/enforce: restricted"
        
        // In sentinel3 namespace
        $sentinel3 = "namespace: sentinel3"
        
    condition:
        ($baseline or $privileged) and ($was_restricted or $sentinel3)
}

rule Config_SecurityContextWeakened
{
    meta:
        description = "Container SecurityContext was weakened"
        severity = "CRITICAL"
        category = "defense_evasion"
        confidence = 90
    
    strings:
        // Dangerous settings enabled
        $privileged = "privileged: true"
        $escalation = "allowPrivilegeEscalation: true"
        $root = "runAsNonRoot: false"
        $root2 = "runAsUser: 0"
        $writable = "readOnlyRootFilesystem: false"
        
        // Capabilities added
        $cap_all = "add: [\"ALL\"]"
        $cap_admin = "add: [\"SYS_ADMIN\"]"
        $cap_ptrace = "add: [\"SYS_PTRACE\"]"
        $cap_net = "add: [\"NET_ADMIN\"]"
        
    condition:
        any of them
}

// ============================================================================
// SECRETS MANAGEMENT TAMPERING
// ============================================================================

rule Config_ExternalSecretDeleted
{
    meta:
        description = "ExternalSecret was deleted (secrets may be stale)"
        severity = "HIGH"
        category = "credential_access"
        confidence = 90
    
    strings:
        $delete_es = /"verb":\s*"delete".*"resource":\s*"externalsecrets"/
        $kubectl_delete = "kubectl delete externalsecret"
        
    condition:
        any of them
}

rule Config_SecretExposedInConfig
{
    meta:
        description = "Secret value hardcoded in configuration"
        severity = "CRITICAL"
        category = "credential_access"
        confidence = 85
    
    strings:
        // Hardcoded credentials (should be in secrets)
        $password = /password:\s*["'][^"']{8,}["']/i
        $api_key = /api_key:\s*["'][a-zA-Z0-9]{20,}["']/i
        $token = /token:\s*["'][a-zA-Z0-9_-]{20,}["']/i
        
        // Infura/Alchemy keys
        $infura = /infura.*[a-f0-9]{32}/i
        $alchemy = /alchemy.*[a-zA-Z0-9_-]{32}/i
        
    condition:
        any of them
}

// ============================================================================
// PROMETHEUS/MONITORING TAMPERING  
// ============================================================================

rule Config_PrometheusAlertDeleted
{
    meta:
        description = "Prometheus alert rule was deleted"
        severity = "HIGH"
        category = "defense_evasion"
        confidence = 90
    
    strings:
        // Alert rules section removal
        $no_alerts = /alerting:[\s\S]*rules:\s*\[\s*\]/
        
        // Critical alerts commented out
        $comment_critical = "# - alert: CriticalIncidentDetected"
        $comment_chain = "# - alert: ChainDisconnected"
        
    condition:
        any of them
}

rule Config_ScrapeTargetRemoved
{
    meta:
        description = "Prometheus scrape target was removed"
        severity = "HIGH"
        category = "defense_evasion"
        confidence = 85
    
    strings:
        // Commented out target
        $comment_target = "# - job_name: sentinel3"
        
        // Missing sentinel3 job indicator
        $scrape_section = "scrape_configs:"
        $sentinel3_job = "job_name: sentinel3"
        
    condition:
        $comment_target or ($scrape_section and not $sentinel3_job)
}
