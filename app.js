// Security Rules Configuration
const SECURITY_RULES = [
  {
    rule_id: 'SEC001',
    name: 'SQL Injection Vulnerability',
    severity: 'HIGH',
    description: 'SQL query constructed using string concatenation, f-strings, or format() with user input. This can allow attackers to manipulate SQL queries and access unauthorized data.',
    remediation: 'Use parameterized queries or ORM frameworks. Example: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)) instead of string concatenation.',
    patterns: [
      /\.execute\s*\([^)]*\+[^)]*\)/,
      /\.execute\s*\([^)]*\.format\s*\(/,
      /\.execute\s*\([^)]*%[^)]*\)/,
      /\.execute\s*\(\s*f["']/
    ]
  },
  {
    rule_id: 'SEC002',
    name: 'Hardcoded Credentials',
    severity: 'HIGH',
    description: 'Hardcoded passwords, API keys, tokens, or secrets found in source code. These credentials can be easily discovered by attackers.',
    remediation: 'Store credentials in environment variables or secure configuration files. Use libraries like python-dotenv or secret management services (AWS Secrets Manager, Azure Key Vault, etc.).',
    sensitive_keywords: ['password', 'passwd', 'pwd', 'api_key', 'apikey', 'access_key', 'private_key', 'token', 'secret', 'auth', 'credential'],
    key_patterns: [
      /AKIA[0-9A-Z]{16}/,
      /AIza[0-9A-Za-z\-_]{35}/,
      /sk_live_[0-9a-zA-Z]{24,}/,
      /sk-[a-zA-Z0-9]{20,}/,
      /xox[baprs]-[0-9a-zA-Z\-]{10,}/
    ]
  },
  {
    rule_id: 'SEC003',
    name: 'Dangerous use of eval() or exec()',
    severity: 'HIGH',
    description: 'Use of eval() or exec() can lead to arbitrary code execution if used with untrusted input. Attackers can inject malicious code.',
    remediation: 'Avoid using eval() and exec(). Use ast.literal_eval() for safe evaluation of literals, or redesign to avoid dynamic code execution.',
    patterns: [
      /\beval\s*\(/,
      /\bexec\s*\(/
    ]
  },
  {
    rule_id: 'SEC004',
    name: 'Command Injection via os.system()',
    severity: 'HIGH',
    description: 'Using os.system() with user input can lead to command injection attacks. Attackers can execute arbitrary system commands.',
    remediation: 'Use subprocess module with argument lists instead: subprocess.run(["command", "arg1", "arg2"]) which prevents shell injection.',
    patterns: [
      /os\.system\s*\(/
    ]
  },
  {
    rule_id: 'SEC005',
    name: 'Potential XSS Vulnerability',
    severity: 'MEDIUM',
    description: 'Direct rendering of user input without sanitization may lead to Cross-Site Scripting (XSS) attacks in web applications.',
    remediation: 'Always escape user input before rendering in HTML. Use framework-provided escaping functions or libraries like MarkupSafe. Avoid string concatenation in templates.',
    patterns: [
      /render_template_string\s*\([^)]*\+[^)]*\)/,
      /render_template_string\s*\([^)]*\.format\s*\(/,
      /Markup\s*\([^)]*\+[^)]*\)/
    ]
  }
];

// Sample vulnerable code
const SAMPLE_CODE = `import sqlite3
import os

# Hardcoded API key
api_key = "AKIAIOSFODNN7EXAMPLE"
password = "admin123"

def login(username):
    db = sqlite3.connect("db.sqlite")
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def calculate(expr):
    return eval(expr)

def run_cmd(command):
    os.system(command)`;

// DOM Elements
const codeInput = document.getElementById('code-input');
const charCount = document.getElementById('char-count');
const scanBtn = document.getElementById('scan-btn');
const sampleBtn = document.getElementById('sample-btn');
const clearBtn = document.getElementById('clear-btn');
const loading = document.getElementById('loading');
const resultsSection = document.getElementById('results-section');
const summaryContent = document.getElementById('summary-content');
const findingsContainer = document.getElementById('findings-container');

// State
let findings = [];

// Event Listeners
codeInput.addEventListener('input', updateCharCount);
scanBtn.addEventListener('click', scanCode);
sampleBtn.addEventListener('click', loadSampleCode);
clearBtn.addEventListener('click', clearCode);

// Update character count
function updateCharCount() {
  charCount.textContent = codeInput.value.length;
}

// Load sample code
function loadSampleCode() {
  codeInput.value = SAMPLE_CODE;
  updateCharCount();
}

// Clear code
function clearCode() {
  codeInput.value = '';
  updateCharCount();
  hideResults();
}

// Hide results
function hideResults() {
  resultsSection.classList.add('hidden');
}

// Scan code
function scanCode() {
  const code = codeInput.value.trim();
  
  if (!code) {
    alert('Please enter Python code to scan');
    return;
  }
  
  // Show loading
  loading.classList.remove('hidden');
  hideResults();
  
  // Simulate async scanning
  setTimeout(() => {
    findings = analyzeCode(code);
    displayResults();
    loading.classList.add('hidden');
    resultsSection.classList.remove('hidden');
    
    // Smooth scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 800);
}

// Analyze code
function analyzeCode(code) {
  const lines = code.split('\n');
  const detectedFindings = [];
  
  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const trimmedLine = line.trim();
    
    // Skip empty lines and comments
    if (!trimmedLine || trimmedLine.startsWith('#')) {
      return;
    }
    
    // Check each security rule
    SECURITY_RULES.forEach(rule => {
      if (rule.rule_id === 'SEC002') {
        // Special handling for hardcoded credentials
        checkHardcodedCredentials(trimmedLine, line, lineNumber, detectedFindings);
      } else {
        // Pattern-based checking
        rule.patterns.forEach(pattern => {
          if (pattern.test(trimmedLine)) {
            detectedFindings.push({
              rule_id: rule.rule_id,
              name: rule.name,
              severity: rule.severity,
              line_number: lineNumber,
              code_snippet: line,
              description: rule.description,
              remediation: rule.remediation
            });
          }
        });
      }
    });
  });
  
  // Sort by severity (HIGH first)
  const severityOrder = { 'HIGH': 0, 'MEDIUM': 1, 'LOW': 2 };
  detectedFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  return detectedFindings;
}

// Check for hardcoded credentials
function checkHardcodedCredentials(trimmedLine, originalLine, lineNumber, detectedFindings) {
  const rule = SECURITY_RULES.find(r => r.rule_id === 'SEC002');
  
  // Check for API key patterns
  rule.key_patterns.forEach(pattern => {
    if (pattern.test(trimmedLine)) {
      detectedFindings.push({
        rule_id: rule.rule_id,
        name: rule.name,
        severity: rule.severity,
        line_number: lineNumber,
        code_snippet: originalLine,
        description: rule.description,
        remediation: rule.remediation
      });
    }
  });
  
  // Check for variable assignments with sensitive keywords
  rule.sensitive_keywords.forEach(keyword => {
    // Match patterns like: api_key = "value" or password = 'value'
    const assignmentPattern = new RegExp(`\\b${keyword}\\b\\s*=\\s*["']([^"']+)["']`, 'i');
    const match = trimmedLine.match(assignmentPattern);
    
    if (match) {
      const value = match[1];
      // Ignore empty strings or placeholder values
      if (value && value.length > 0 && !value.match(/^(YOUR_|ENTER_|CHANGE_|REPLACE_)/i)) {
        detectedFindings.push({
          rule_id: rule.rule_id,
          name: rule.name,
          severity: rule.severity,
          line_number: lineNumber,
          code_snippet: originalLine,
          description: rule.description,
          remediation: rule.remediation
        });
      }
    }
  });
}

// Display results
function displayResults() {
  // Display summary
  displaySummary();
  
  // Display findings
  if (findings.length > 0) {
    displayFindings();
  } else {
    findingsContainer.innerHTML = '';
  }
}

// Display summary
function displaySummary() {
  const total = findings.length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter(f => f.severity === 'LOW').length;
  
  if (total === 0) {
    summaryContent.innerHTML = `
      <div class="success-message">
        <svg class="success-icon" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <div>
          <strong style="font-size: var(--font-size-lg);">No vulnerabilities found!</strong>
          <p style="margin: var(--space-4) 0 0 0; color: var(--color-text-secondary);">Your code appears to be secure based on our analysis.</p>
        </div>
      </div>
    `;
  } else {
    summaryContent.innerHTML = `
      <div class="summary-stats">
        <div class="stat-item">
          <div class="stat-number">${total}</div>
          <div class="stat-label">Total Vulnerabilities</div>
        </div>
      </div>
      <div class="severity-breakdown">
        ${highCount > 0 ? `
          <div class="severity-item">
            <span class="vuln-badge vuln-badge--high">HIGH</span>
            <span>${highCount}</span>
          </div>
        ` : ''}
        ${mediumCount > 0 ? `
          <div class="severity-item">
            <span class="vuln-badge vuln-badge--medium">MEDIUM</span>
            <span>${mediumCount}</span>
          </div>
        ` : ''}
        ${lowCount > 0 ? `
          <div class="severity-item">
            <span class="vuln-badge vuln-badge--low">LOW</span>
            <span>${lowCount}</span>
          </div>
        ` : ''}
      </div>
    `;
  }
}

// Display findings
function displayFindings() {
  findingsContainer.innerHTML = findings.map((finding, index) => `
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-title">
          <h3>${finding.name}</h3>
          <div class="finding-meta">
            <span>${finding.rule_id}</span>
            <span>•</span>
            <span>Line ${finding.line_number}</span>
          </div>
        </div>
        <span class="vuln-badge vuln-badge--${finding.severity.toLowerCase()}">${finding.severity}</span>
      </div>
      
      <div class="code-snippet">
        <pre><code>${escapeHtml(finding.code_snippet)}</code></pre>
      </div>
      
      <div class="finding-description">
        ${finding.description}
      </div>
      
      <div class="remediation-section">
        <div class="remediation-toggle" onclick="toggleRemediation(${index})">
          <strong>💡 How to Fix</strong>
          <span id="toggle-icon-${index}">▼</span>
        </div>
        <div id="remediation-${index}" class="remediation-content" style="display: none;">
          ${finding.remediation}
        </div>
      </div>
    </div>
  `).join('');
}

// Toggle remediation section
function toggleRemediation(index) {
  const content = document.getElementById(`remediation-${index}`);
  const icon = document.getElementById(`toggle-icon-${index}`);
  
  if (content.style.display === 'none') {
    content.style.display = 'block';
    icon.textContent = '▲';
  } else {
    content.style.display = 'none';
    icon.textContent = '▼';
  }
}

// Escape HTML
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Make toggleRemediation globally accessible
window.toggleRemediation = toggleRemediation;