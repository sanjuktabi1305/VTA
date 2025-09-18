// rules.js
// Heuristic detection rules (kept focused on risky constructs)
// These are RegExp objects (with flags) so index.html can reuse them.

const RULES = [
  // Dangerous eval/dynamic execution
  { id: 'eval', regex: /\beval\s*\(/gi, severity: 'high', issue: 'Use of eval()', description: 'Executing strings as code is dangerous.', fix: 'Remove eval; use safe parsers.' },

  // DOM XSS risky APIs
  { id: 'innerHTML', regex: /\.innerHTML\s*=/gi, severity: 'high', issue: 'innerHTML assignment', description: 'Assigning untrusted content to innerHTML can cause XSS.', fix: 'Use textContent or sanitize input.' },
  { id: 'documentWrite', regex: /document\.write\s*\(/gi, severity: 'high', issue: 'document.write()', description: 'document.write may inject unescaped HTML.', fix: 'Avoid document.write.' },

  // SQL concatenation: (string literal <op> var) OR (var <op> string literal)
  // We'll additionally verify 'select/where/from' nearby in index.html to reduce false positives.
  { id: 'sql_concat', regex: /((["'`][^"'`]{0,500}["'`]\s*\+\s*[A-Za-z0-9_.$\[\]]+)|([A-Za-z0-9_.$\[\]]+\s*\+\s*["'`][^"'`]{1,500}["'`]))/gi, severity: 'high', issue: 'String concatenation around SQL (possible SQLi)', description: 'Building SQL via concatenation is dangerous.', fix: 'Use parameterized queries / prepared statements.' },

  // Hardcoded secrets assigned to typical variable names
  { id: 'secret', regex: /\b(?:api[_-]?key|apikey|password|passwd|pwd|secret|token)\b\s*[:=]\s*(['"`])[^'"]+\1/gi, severity: 'high', issue: 'Hardcoded secret', description: 'Secrets hardcoded in source may be leaked.', fix: 'Move secrets to environment variables or secret manager.' },

  // JWT-like token in code
  { id: 'jwt', regex: /eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/gi, severity: 'high', issue: 'Hardcoded JWT-like token', description: 'Looks like a JWT in code.', fix: 'Do not hardcode tokens.' },

  // Command execution APIs
  { id: 'cmd_exec', regex: /\b(os\.system|child_process\.exec|subprocess\.(call|Popen|run))\s*\(/gi, severity: 'high', issue: 'OS/command execution', description: 'Executing shell commands with untrusted input can be exploited.', fix: 'Avoid shell commands; use safe APIs and validate inputs.' },

  // Weak crypto
  { id: 'weak_crypto', regex: /\b(md5|sha1)\s*\(/gi, severity: 'medium', issue: 'Weak crypto (MD5/SHA1)', description: 'MD5/SHA1 are weak; use SHA-256+ or better KDFs.', fix: 'Use modern cryptography.' },

  // Insecure HTTP
  { id: 'insecure_http', regex: /\bhttp:\/\//gi, severity: 'medium', issue: 'Insecure HTTP', description: 'Plain HTTP may expose sensitive data.', fix: 'Use HTTPS.' },

  // Debug prints that print variables (not literal-only)
  { id: 'print_var', regex: /\bprint\s*\(\s*(?!['"`])[^)]*\)/gi, severity: 'low', issue: 'Debug print may leak data', description: 'Printing variables may leak secrets in logs.', fix: 'Remove or use structured logging and redact secrets.' },
  { id: 'console_log_var', regex: /\bconsole\.log\s*\(\s*(?!['"`])[^)]*\)/gi, severity: 'low', issue: 'console.log may leak data', description: 'Remove or use structured logging and redact secrets.' }
];

window.RULES = RULES;
