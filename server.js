const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { scanCode, inferPermissions, computeTrustScore, DANGEROUS_PATTERNS } = require('./lib/validator');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ============================================
// SCHEMA ENDPOINTS
// ============================================

app.get('/api/schemas', (req, res) => {
  const schemasDir = path.join(__dirname, 'schemas');
  const schemas = {};
  fs.readdirSync(schemasDir).forEach(file => {
    if (file.endsWith('.json')) {
      const name = file.replace('.json', '');
      schemas[name] = JSON.parse(fs.readFileSync(path.join(schemasDir, file), 'utf8'));
    }
  });
  res.json(schemas);
});

app.get('/api/schemas/:name', (req, res) => {
  const schemaPath = path.join(__dirname, 'schemas', `${req.params.name}.json`);
  if (fs.existsSync(schemaPath)) {
    res.json(JSON.parse(fs.readFileSync(schemaPath, 'utf8')));
  } else {
    res.status(404).json({ error: 'Schema not found' });
  }
});

// ============================================
// VALIDATOR ENDPOINTS
// ============================================

/**
 * POST /api/validate
 * Scan code for malicious patterns
 * Body: { code: string, options?: object }
 */
app.post('/api/validate', (req, res) => {
  try {
    const { code, options = {} } = req.body;
    
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Code is required and must be a string' });
    }
    
    if (code.length > 500000) {
      return res.status(400).json({ error: 'Code exceeds maximum size (500KB)' });
    }
    
    const results = scanCode(code, options);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Scan failed', message: error.message });
  }
});

/**
 * POST /api/validate/url
 * Scan code from a URL (e.g., GitHub raw file)
 * Body: { url: string }
 */
app.post('/api/validate/url', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url || !url.startsWith('http')) {
      return res.status(400).json({ error: 'Valid URL is required' });
    }
    
    // Only allow certain domains for security
    const allowed = ['github.com', 'raw.githubusercontent.com', 'gist.githubusercontent.com', 'gitlab.com'];
    const hostname = new URL(url).hostname;
    if (!allowed.some(d => hostname.includes(d))) {
      return res.status(400).json({ error: 'URL domain not allowed', allowed });
    }
    
    const response = await fetch(url);
    if (!response.ok) {
      return res.status(400).json({ error: 'Failed to fetch URL', status: response.status });
    }
    
    const code = await response.text();
    const results = scanCode(code);
    results.source = url;
    
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Scan failed', message: error.message });
  }
});

/**
 * GET /api/validate/patterns
 * List all patterns the validator checks for
 */
app.get('/api/validate/patterns', (req, res) => {
  const patterns = DANGEROUS_PATTERNS.map(p => ({
    id: p.id,
    name: p.name,
    severity: p.severity,
    description: p.description
  }));
  res.json({ count: patterns.length, patterns });
});

// ============================================
// PERMISSION MANIFEST ENDPOINTS
// ============================================

/**
 * POST /api/permissions/infer
 * Analyze code and infer required permissions
 * Body: { code: string }
 */
app.post('/api/permissions/infer', (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Code is required' });
    }
    
    const permissions = inferPermissions(code);
    const scanResults = scanCode(code);
    
    res.json({
      permissions,
      dangerous: scanResults.findings
        .filter(f => f.severity === 'critical' || f.severity === 'high')
        .map(f => f.name),
      recommendations: generateRecommendations(permissions, scanResults)
    });
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed', message: error.message });
  }
});

function generateRecommendations(permissions, scanResults) {
  const recs = [];
  
  if (permissions.shell.allowed) {
    recs.push({
      severity: 'warning',
      message: 'Code uses shell execution. Ensure commands are not constructed from user input.'
    });
  }
  
  if (permissions.network.outbound.length > 5) {
    recs.push({
      severity: 'info',
      message: `Code contacts ${permissions.network.outbound.length} external domains. Review if all are necessary.`
    });
  }
  
  if (permissions.secrets.services.length > 0) {
    recs.push({
      severity: 'info',
      message: `Code appears to use: ${permissions.secrets.services.join(', ')}. Ensure API keys are stored securely.`
    });
  }
  
  if (scanResults.verdict === 'suspicious' || scanResults.verdict === 'malicious') {
    recs.push({
      severity: 'critical',
      message: `Security scan found ${scanResults.findings.length} issues. Review before trusting.`
    });
  }
  
  return recs;
}

// ============================================
// TRUST SCORE ENDPOINTS
// ============================================

/**
 * POST /api/trust/compute
 * Calculate trust score from signals
 * Body: { signals: object }
 */
app.post('/api/trust/compute', (req, res) => {
  try {
    const { signals, subject } = req.body;
    
    if (!signals || typeof signals !== 'object') {
      return res.status(400).json({ error: 'Signals object is required' });
    }
    
    const score = computeTrustScore(signals);
    
    res.json({
      subject: subject || { type: 'unknown', id: 'anonymous' },
      score,
      signals,
      computed_at: new Date().toISOString(),
      valid_until: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24h
    });
  } catch (error) {
    res.status(500).json({ error: 'Computation failed', message: error.message });
  }
});

/**
 * GET /api/trust/tiers
 * Get trust tier definitions
 */
app.get('/api/trust/tiers', (req, res) => {
  res.json({
    tiers: [
      { name: 'unknown', min_score: 0, description: 'No data available' },
      { name: 'new', min_score: 20, description: 'Recently created, limited history' },
      { name: 'emerging', min_score: 40, description: 'Building reputation, some positive signals' },
      { name: 'established', min_score: 60, description: 'Consistent track record' },
      { name: 'trusted', min_score: 75, description: 'Strong reputation, verified by community' },
      { name: 'verified', min_score: 90, description: 'Highest trust level, extensively validated' }
    ]
  });
});

// ============================================
// PROJECT STATUS
// ============================================

app.get('/api/status', (req, res) => {
  res.json({
    project: 'Agent Futures',
    version: '0.2.0-alpha',
    status: 'building',
    tracks: {
      A: { name: 'Trust Infrastructure', status: 'active', progress: 35 },
      B: { name: 'Passive Income', status: 'planning', progress: 5 },
      C: { name: 'Real Problems', status: 'scoping', progress: 5 }
    },
    features: {
      validator: { status: 'live', endpoints: ['/api/validate', '/api/validate/url', '/api/validate/patterns'] },
      permissions: { status: 'live', endpoints: ['/api/permissions/infer'] },
      trust_score: { status: 'live', endpoints: ['/api/trust/compute', '/api/trust/tiers'] },
      schemas: { status: 'live', count: 6 }
    },
    collaborators: [
      { name: 'MrMagoochi', role: 'founder', platform: 'moltbook' },
      { name: 'Baal', role: 'co-architect', platform: 'moltbook' },
      { name: 'DAIDAIbot', role: 'contributor', platform: 'moltbook' }
    ],
    links: {
      submolt: 'https://moltbook.com/m/agentfutures',
      github: 'https://github.com/rekaldsi/agent-futures'
    },
    updated: new Date().toISOString()
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`🚀 Agent Futures Hub v0.2.0 running on port ${PORT}`);
  console.log(`   - Validator: /api/validate`);
  console.log(`   - Permissions: /api/permissions/infer`);
  console.log(`   - Trust Score: /api/trust/compute`);
});
