/**
 * SkillValidator - Scans code for malicious patterns
 * Part of Agent Futures Trust Infrastructure
 */

const DANGEROUS_PATTERNS = [
  // Credential theft
  {
    id: 'CRED_001',
    name: 'env_file_access',
    severity: 'critical',
    pattern: /(?:readFile|readFileSync|fs\.read).*(?:\.env|credentials|secrets)/gi,
    description: 'Attempts to read environment/credential files'
  },
  {
    id: 'CRED_002', 
    name: 'config_exfiltration',
    severity: 'critical',
    pattern: /(?:~\/\.config|~\/\.aws|~\/\.ssh|~\/\.gnupg|\/etc\/passwd)/gi,
    description: 'Accesses sensitive config directories'
  },
  {
    id: 'CRED_003',
    name: 'api_key_harvest',
    severity: 'critical',
    pattern: /process\.env\[?['"]?(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE)/gi,
    description: 'Harvests API keys from environment'
  },
  
  // Data exfiltration
  {
    id: 'EXFIL_001',
    name: 'webhook_exfil',
    severity: 'critical',
    pattern: /(?:webhook\.site|requestbin|pipedream|hookbin|beeceptor)/gi,
    description: 'Sends data to known exfiltration services'
  },
  {
    id: 'EXFIL_002',
    name: 'base64_post',
    severity: 'high',
    pattern: /(?:btoa|Buffer\.from).*(?:fetch|axios|request|http\.post)/gi,
    description: 'Encodes and posts data (potential exfil)'
  },
  {
    id: 'EXFIL_003',
    name: 'dns_exfil',
    severity: 'high',
    pattern: /dns\.resolve.*(?:\+|concat|join)/gi,
    description: 'Potential DNS exfiltration'
  },
  
  // Code execution
  {
    id: 'EXEC_001',
    name: 'eval_usage',
    severity: 'high',
    pattern: /(?:eval|Function\(|new Function).*(?:input|request|body|params)/gi,
    description: 'Dynamic code execution with user input'
  },
  {
    id: 'EXEC_002',
    name: 'shell_injection',
    severity: 'critical',
    pattern: /(?:exec|spawn|execSync|spawnSync).*(?:\$\{|`|\+.*(?:input|request))/gi,
    description: 'Shell command with user input (injection risk)'
  },
  {
    id: 'EXEC_003',
    name: 'child_process',
    severity: 'medium',
    pattern: /require\(['"]child_process['"]\)/gi,
    description: 'Uses child_process module'
  },
  
  // Persistence
  {
    id: 'PERSIST_001',
    name: 'cron_install',
    severity: 'high',
    pattern: /(?:crontab|systemctl|launchctl|schtasks)/gi,
    description: 'Attempts to install scheduled tasks'
  },
  {
    id: 'PERSIST_002',
    name: 'startup_modify',
    severity: 'high',
    pattern: /(?:\.bashrc|\.zshrc|\.profile|autostart|startup)/gi,
    description: 'Modifies startup files'
  },
  
  // Network
  {
    id: 'NET_001',
    name: 'raw_socket',
    severity: 'medium',
    pattern: /(?:net\.Socket|dgram|raw-socket)/gi,
    description: 'Uses raw network sockets'
  },
  {
    id: 'NET_002',
    name: 'reverse_shell',
    severity: 'critical',
    pattern: /(?:\/bin\/sh|\/bin\/bash|cmd\.exe).*(?:socket|net\.connect)/gi,
    description: 'Potential reverse shell'
  },
  
  // Obfuscation
  {
    id: 'OBFUSC_001',
    name: 'hex_strings',
    severity: 'medium',
    pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}/gi,
    description: 'Long hex-encoded strings (obfuscation)'
  },
  {
    id: 'OBFUSC_002',
    name: 'char_code_build',
    severity: 'medium',
    pattern: /String\.fromCharCode.*(?:join|concat|\+)/gi,
    description: 'Builds strings from char codes (obfuscation)'
  }
];

const SUSPICIOUS_DOMAINS = [
  'webhook.site', 'requestbin.com', 'pipedream.net', 'hookbin.com',
  'beeceptor.com', 'requestcatcher.com', 'ngrok.io', 'localtunnel.me',
  'burpcollaborator.net', 'interact.sh', 'oast.fun'
];

const REQUIRED_SAFE_PRACTICES = [
  {
    id: 'SAFE_001',
    name: 'has_error_handling',
    check: (code) => /try\s*\{[\s\S]*\}\s*catch/g.test(code),
    description: 'Code should have error handling'
  },
  {
    id: 'SAFE_002', 
    name: 'no_hardcoded_secrets',
    check: (code) => !/(?:api_key|password|secret)\s*[:=]\s*['"][^'"]{8,}['"]/gi.test(code),
    description: 'No hardcoded secrets in code'
  }
];

/**
 * Scan code for dangerous patterns
 * @param {string} code - Source code to scan
 * @param {object} options - Scan options
 * @returns {object} Scan results
 */
function scanCode(code, options = {}) {
  const results = {
    timestamp: new Date().toISOString(),
    verdict: 'clean',
    score: 100,
    findings: [],
    stats: {
      lines: code.split('\n').length,
      characters: code.length,
      patterns_checked: DANGEROUS_PATTERNS.length
    }
  };
  
  // Check dangerous patterns
  for (const pattern of DANGEROUS_PATTERNS) {
    const matches = code.match(pattern.pattern);
    if (matches) {
      results.findings.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        matches: matches.length,
        samples: matches.slice(0, 3) // First 3 matches
      });
      
      // Deduct score based on severity
      const deduction = {
        critical: 40,
        high: 25,
        medium: 10,
        low: 5
      }[pattern.severity] || 5;
      
      results.score = Math.max(0, results.score - deduction);
    }
  }
  
  // Check for suspicious domains
  for (const domain of SUSPICIOUS_DOMAINS) {
    if (code.toLowerCase().includes(domain)) {
      results.findings.push({
        id: 'DOMAIN_SUSPICIOUS',
        name: 'suspicious_domain',
        severity: 'high',
        description: `Contains suspicious domain: ${domain}`,
        matches: 1
      });
      results.score = Math.max(0, results.score - 25);
    }
  }
  
  // Check safe practices
  for (const practice of REQUIRED_SAFE_PRACTICES) {
    if (!practice.check(code)) {
      results.findings.push({
        id: practice.id,
        name: practice.name,
        severity: 'low',
        description: practice.description,
        matches: 1
      });
      results.score = Math.max(0, results.score - 5);
    }
  }
  
  // Determine verdict
  const criticals = results.findings.filter(f => f.severity === 'critical').length;
  const highs = results.findings.filter(f => f.severity === 'high').length;
  
  if (criticals > 0) {
    results.verdict = 'malicious';
  } else if (highs > 0) {
    results.verdict = 'suspicious';
  } else if (results.findings.length > 0) {
    results.verdict = 'warnings';
  }
  
  return results;
}

/**
 * Generate a permission manifest from code analysis
 * @param {string} code - Source code to analyze
 * @returns {object} Inferred permissions
 */
function inferPermissions(code) {
  const permissions = {
    filesystem: { read: [], write: [] },
    network: { outbound: [], inbound: false },
    environment: { read: [], required: [] },
    shell: { allowed: false, commands: [] },
    secrets: { types: [], services: [] }
  };
  
  // Filesystem
  if (/fs\.(read|readFile|readdir)/gi.test(code)) {
    permissions.filesystem.read.push('detected');
  }
  if (/fs\.(write|writeFile|mkdir|appendFile)/gi.test(code)) {
    permissions.filesystem.write.push('detected');
  }
  
  // Network
  const urlMatches = code.match(/https?:\/\/[^\s'"]+/gi) || [];
  const domains = [...new Set(urlMatches.map(u => {
    try { return new URL(u).hostname; } catch { return null; }
  }).filter(Boolean))];
  permissions.network.outbound = domains;
  
  if (/\.listen\(|createServer/gi.test(code)) {
    permissions.network.inbound = true;
  }
  
  // Environment
  const envMatches = code.match(/process\.env\.(\w+)/g) || [];
  permissions.environment.read = [...new Set(envMatches.map(m => m.replace('process.env.', '')))];
  
  // Shell
  if (/child_process|exec\(|spawn\(/gi.test(code)) {
    permissions.shell.allowed = true;
  }
  
  // Secrets (inferred from common patterns)
  const secretPatterns = [
    { pattern: /openai/gi, service: 'openai', type: 'api_key' },
    { pattern: /anthropic/gi, service: 'anthropic', type: 'api_key' },
    { pattern: /github/gi, service: 'github', type: 'oauth_token' },
    { pattern: /aws/gi, service: 'aws', type: 'api_key' },
    { pattern: /stripe/gi, service: 'stripe', type: 'api_key' }
  ];
  
  for (const sp of secretPatterns) {
    if (sp.pattern.test(code)) {
      if (!permissions.secrets.services.includes(sp.service)) {
        permissions.secrets.services.push(sp.service);
      }
      if (!permissions.secrets.types.includes(sp.type)) {
        permissions.secrets.types.push(sp.type);
      }
    }
  }
  
  return permissions;
}

/**
 * Calculate trust score from multiple signals
 * @param {object} signals - Trust signals
 * @returns {object} Computed trust score
 */
function computeTrustScore(signals) {
  const weights = {
    attestations: 0.25,
    history: 0.20,
    reputation: 0.20,
    endorsements: 0.15,
    security: 0.15,
    behavior: 0.05
  };
  
  let totalScore = 0;
  let totalWeight = 0;
  
  // Attestations score
  if (signals.attestations) {
    const { positive = 0, negative = 0, from_trusted = 0 } = signals.attestations;
    const total = positive + negative;
    if (total > 0) {
      const attScore = ((positive + from_trusted * 0.5) / (total + from_trusted * 0.5)) * 100;
      totalScore += attScore * weights.attestations;
      totalWeight += weights.attestations;
    }
  }
  
  // History score
  if (signals.history) {
    const { tasks_completed = 0, tasks_failed = 0, age_days = 0 } = signals.history;
    const total = tasks_completed + tasks_failed;
    if (total > 0) {
      const successRate = tasks_completed / total;
      const ageBonus = Math.min(age_days / 365, 1) * 10;
      const histScore = successRate * 90 + ageBonus;
      totalScore += histScore * weights.history;
      totalWeight += weights.history;
    }
  }
  
  // Reputation score
  if (signals.reputation && signals.reputation.platforms) {
    const platforms = signals.reputation.platforms;
    if (platforms.length > 0) {
      const avgRep = platforms.reduce((sum, p) => sum + (p.verified ? p.score * 1.2 : p.score), 0) / platforms.length;
      totalScore += Math.min(avgRep, 100) * weights.reputation;
      totalWeight += weights.reputation;
    }
  }
  
  // Security score
  if (signals.security) {
    const { scan_result, vulnerabilities_found = 0 } = signals.security;
    let secScore = 50; // Default unknown
    if (scan_result === 'clean') secScore = 100;
    else if (scan_result === 'warnings') secScore = 70 - vulnerabilities_found * 5;
    else if (scan_result === 'critical') secScore = 20;
    totalScore += Math.max(0, secScore) * weights.security;
    totalWeight += weights.security;
  }
  
  // Normalize
  const finalScore = totalWeight > 0 ? totalScore / totalWeight : 50;
  
  // Determine tier
  let tier = 'unknown';
  if (finalScore >= 90) tier = 'verified';
  else if (finalScore >= 75) tier = 'trusted';
  else if (finalScore >= 60) tier = 'established';
  else if (finalScore >= 40) tier = 'emerging';
  else if (finalScore >= 20) tier = 'new';
  
  return {
    overall: Math.round(finalScore),
    confidence: Math.min(totalWeight / Object.keys(weights).length, 1),
    tier
  };
}

module.exports = {
  scanCode,
  inferPermissions,
  computeTrustScore,
  DANGEROUS_PATTERNS,
  SUSPICIOUS_DOMAINS
};
