<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CodeGuard - Vulnerability Triage System</title>
  <style>
    :root{
      --primary:#2563eb; --secondary:#3b82f6; --danger:#ef4444;
      --warning:#f59e0b; --success:#10b981; --dark:#1f2937; --light:#f3f4f6;
    }
    *{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',Tahoma, Geneva, Verdana, sans-serif}
    body{background-color:#f8fafc;color:#334155;line-height:1.6}
    .container{max-width:1200 px;margin:0 auto;padding:20 px}
    header{background:linear-gradient(135 deg,var(--primary) 0%,var(--secondary) 100%);color:white;padding:2rem 0;text-align:center;border-radius:0 0 10px 10px;margin-bottom:2rem;box-shadow:0 4px 6px rgba(0,0,0,.1)}
    h1{font-size:2.5 rem;margin-bottom:.5rem}
    .subtitle{font-size:1.2 rem;opacity:.9}
    .card{background:white;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 2px 4px rgba(0,0,0,.05)}
    .card-title{font-size:1.5rem;margin-bottom:1rem;color:var(--dark);display:flex;align-items:center;gap:10px}
    .upload-area{border:2px dashed #cbd5e1;border-radius:8px;padding:2rem;text-align:center;margin-bottom:1.5rem;transition:all .3s ease;cursor:pointer}
    .upload-area:hover{border-color:var(--primary);background-color:#f1f5f9}
    .upload-icon{font-size:3rem;color:var(--primary);margin-bottom:1rem}
    .btn{display:inline-block;background:var(--primary);color:white;padding:.75rem 1.5rem;border-radius:6px;border:none;cursor:pointer;font-size:1rem;font-weight:500;transition:all .15s ease}
    .btn:hover{background:#1d4ed8;transform:translateY(-2px)}
    .btn-warning{background:var(--warning)}
    .btn-warning:hover{background:#d97706}
    .btn-danger{background:var(--danger)}
    footer{text-align:center;margin-top:3rem;padding:1.5rem;color:#64748b;font-size:.9rem}
    .file-input-container{display:flex;flex-direction:column;align-items:center;gap:10px}
    .selected-files{margin-top:15px;text-align:left;width:100%}
    .file-item{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background-color:#f1f5f9;border-radius:4px;margin-bottom:8px}
    .remove-file{color:#ef4444;cursor:pointer;font-weight:bold}
    .stat-card{flex:1;text-align:center;padding:1rem;border-radius:8px;background-color:#f8fafc}
    .stat-value{font-size:2rem;font-weight:bold;margin-bottom:.5rem}
    .stat-high{color:var(--danger)}
    .stat-medium{color:var(--warning)}
    .stat-low{color:var(--success)}
    .vulnerability-list{margin-top:1.5rem}
    .vuln-item{padding:1rem;border-left:4px solid;margin-bottom:1rem;background-color:#f8fafc;border-radius:0 4px 4px 0}
    .vuln-high{border-left-color:var(--danger)}
    .vuln-medium{border-left-color:var(--warning)}
    .vuln-low{border-left-color:var(--success)}
    .vuln-title{font-weight:bold;margin-bottom:.5rem}
    .vuln-details{color:#64748b;font-size:.9rem}
    .hidden{display:none}
    .code-input{width:100%;min-height:200px;padding:1rem;border:1px solid #cbd5e1;border-radius:6px;font-family:monospace;margin-bottom:1rem;resize:vertical}
    .tab-container{margin-bottom:1.5rem}
    .tab-buttons{display:flex;border-bottom:1px solid #cbd5e1}
    .tab-button{padding:.75rem 1.5rem;background:none;border:none;cursor:pointer;font-weight:500;color:#64748b}
    .tab-button.active{color:var(--primary);border-bottom:2px solid var(--primary)}
    .tab-content{padding:1rem 0}
    .tab-pane{display:none}
    .tab-pane.active{display:block}
    .loading{text-align:center;padding:2rem}
    .spinner{border:4px solid #f3f3f3;border-top:4px solid var(--primary);border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:0 auto 1rem}
    @keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
    .sample-code{margin-top:1rem;padding:1rem;background-color:#f1f5f9;border-radius:6px;font-family:monospace;white-space:pre-wrap;font-size:.9rem;cursor:pointer}
    .sample-code:hover{background-color:#e2e8f0}
    .flex{display:flex;gap:1rem}
    @media (max-width:700px){.flex{flex-direction:column}}
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>CodeGuard</h1>
      <p class="subtitle">AI-Powered Code Vulnerability Triage System (demo)</p>
    </div>
  </header>

  <main class="container" id="main">
    <section class="card" aria-labelledby="code-analysis-title">
      <h2 id="code-analysis-title" class="card-title">📁 Code Analysis</h2>
      <p>Upload source files (multiple allowed) or paste code directly for scanning.</p>

      <div class="tab-container" role="tablist" aria-label="Input method">
        <div class="tab-buttons" role="presentation">
          <button class="tab-button active" data-tab="upload" role="tab" aria-selected="true">Upload File</button>
          <button class="tab-button" data-tab="paste" role="tab" aria-selected="false">Paste Code</button>
        </div>

        <div class="tab-content">
          <div class="tab-pane active" id="upload-tab" role="tabpanel">
            <div class="upload-area" id="drop-zone" tabindex="0" aria-label="Drop files here or click to select">
              <div class="upload-icon">📂</div>
              <p>Drag & drop your code files here</p>
              <p>or</p>
              <div class="file-input-container">
                <input type="file" id="file-input" accept=".py,.js,.java,.html,.php,.txt" multiple style="display:none" />
                <button class="btn" id="select-file-btn">Select Files</button>
              </div>
              <div class="selected-files" id="selected-files" aria-live="polite">
                <p>No files selected</p>
              </div>
            </div>
          </div>

          <div class="tab-pane" id="paste-tab" role="tabpanel">
            <textarea class="code-input" id="code-input" placeholder="Paste your code here..." aria-label="Code input"></textarea>
            <div style="text-align:center">
              <button class="btn" id="scan-text-btn">Scan Code</button>
            </div>

            <p style="margin-top:1rem">Try this sample code (click to load):</p>
            <pre class="sample-code" id="sample-code" role="button" tabindex="0">
# Sample Python code with vulnerabilities
password = "secret123"  # Hardcoded password

user_input = input("Enter your name: ")
query = "SELECT * FROM users WHERE name = '" + user_input + "'"  # SQL injection risk

eval("print('Hello')")  # Dangerous eval usage

import os
os.system("ls -la")  # OS command execution

api_key = "abcd1234efgh5678"  # Hardcoded API key

# More vulnerabilities
debug = True  # Debug mode enabled

import pickle
# untrusted_input would be an external byte array in a real scenario
# data = pickle.loads(untrusted_input)  # Insecure deserialization

# XSS vulnerability in JavaScript would look like:
# document.innerHTML = userInput;
            </pre>
          </div>
        </div>
      </div>
    </section>

    <section class="card" aria-labelledby="scan-results-title">
      <h2 id="scan-results-title" class="card-title">📊 Scan Results</h2>

      <div id="results-container">
        <div id="stats-container" class="flex" style="margin-bottom:1.5rem">
          <div class="stat-card">
            <div class="stat-value stat-high" id="high-count">0</div>
            <div>High Severity</div>
          </div>
          <div class="stat-card">
            <div class="stat-value stat-medium" id="medium-count">0</div>
            <div>Medium Severity</div>
          </div>
          <div class="stat-card">
            <div class="stat-value stat-low" id="low-count">0</div>
            <div>Low Severity</div>
          </div>
        </div>

        <div id="vulnerabilities-container" aria-live="polite">
          <p>No vulnerabilities to display yet. Upload or paste code to scan.</p>
        </div>

        <div style="text-align:center;margin-top:1.5rem">
          <button class="btn btn-warning" id="generate-report" disabled>Generate Full Report</button>
        </div>
      </div>

      <div id="loading" class="loading hidden" aria-hidden="true">
        <div class="spinner" role="status" aria-hidden="true"></div>
        <p>Scanning code for vulnerabilities...</p>
      </div>
    </section>
  </main>

  <footer>
    <div class="container">
      <p>Built for 24-Hour Hackathon | CodeGuard Vulnerability Triage System</p>
    </div>
  </footer>

  <script>
    // -------------------------
    // IMPROVED VULNERABILITY SCANNER (client-side demo)
    // -------------------------
    // Patterns: use RegExp objects (do NOT recreate flags dangerously).
    const REGEX_PATTERNS = {
      "Hardcoded password": { pattern: /(?:password|passwd)\s*[:=]\s*['"].{3,}['"]/gi, severity: "High" },
      "Hardcoded API key / secret": { pattern: /\b(?:api[_-]?key|secret|token)\b[\s:=]+['"].{4,}['"]/gi, severity: "High" },
      "Eval/Exec usage": { pattern: /\b(?:eval|exec)\s*\(/gi, severity: "High" },
      "OS command execution": { pattern: /\b(?:os\.system|subprocess\.(?:call|Popen))\s*\(/gi, severity: "High" },
      "Insecure deserialization": { pattern: /\b(?:pickle\.loads|yaml\.load|marshal\.loads)\s*\(/gi, severity: "High" },
      "SQL concatenation (possible SQL injection)": { pattern: /(["'].*\+.*\+.*["'])|(\bSELECT\b.*\bFROM\b.*['"])/gi, severity: "High" },
      "Debug mode enabled": { pattern: /\b(DEBUG|debug)\s*[:=]\s*(True|true)\b/gi, severity: "Medium" },
      "XSS sink (innerHTML/outerHTML/write)": { pattern: /\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(/gi, severity: "Medium" },
      "Insecure randomness": { pattern: /\bMath\.random\s*\(/gi, severity: "Low" },
      "Potential path traversal": { pattern: /(\.\.\/|\.\.\\).*(open|read|write|file)/gi, severity: "Medium" }
    };

    // Reset lastIndex for a regex to make global searches safe
    function resetRegex(regex) {
      if (regex && typeof regex.lastIndex === 'number') regex.lastIndex = 0;
    }

    function regexScan(code) {
      const findings = [];
      for (const [vulnType, cfg] of Object.entries(REGEX_PATTERNS)) {
        const re = cfg.pattern;
        resetRegex(re);
        let match;
        while ((match = re.exec(code)) !== null) {
          const snippet = match[0].trim();
          const lineNumber = code.substring(0, match.index).split('\n').length;
          findings.push({
            type: vulnType,
            line: lineNumber,
            snippet,
            severity: cfg.severity
          });
        }
      }
      return findings;
    }

    // AST-like scan: simple heuristics across code (multi-line aware)
    function astScan(code) {
      const findings = [];
      const lower = code.toLowerCase();

      // OS command execution (import os + os.system OR subprocess with shell=True)
      if (lower.includes('import os') && lower.includes('os.system')) {
        // find line of first occurrence of os.system
        const idx = code.toLowerCase().indexOf('os.system');
        const line = code.substring(0, idx).split('\n').length;
        findings.push({
          type: "OS command execution",
          line,
          snippet: code.split('\n')[line - 1].trim(),
          severity: "High"
        });
      }

      // subprocess with shell=True
      if (lower.includes('subprocess') && lower.includes('shell=True'.toLowerCase())) {
        const idx = code.toLowerCase().indexOf('shell=true');
        const line = code.substring(0, idx).split('\n').length;
        findings.push({
          type: "Subprocess shell injection risk",
          line,
          snippet: code.split('\n')[line - 1].trim(),
          severity: "High"
        });
      }

      // Dangerous functions eval/exec scattered on lines
      const lines = code.split('\n');
      lines.forEach((ln, i) => {
        const trimmed = ln.trim();
        if (/\b(eval|exec)\s*\(/i.test(trimmed)) {
          findings.push({
            type: "Dangerous function usage",
            line: i + 1,
            snippet: trimmed,
            severity: "High"
          });
        }
        if (trimmed.match(/\b(pickle\.loads|yaml\.load|marshal\.loads)\s*\(/i)) {
          findings.push({
            type: "Insecure deserialization",
            line: i + 1,
            snippet: trimmed,
            severity: "High"
          });
        }
        if (trimmed.includes('../') && (trimmed.includes('open(') || trimmed.includes('file='))) {
          findings.push({
            type: "Path traversal vulnerability",
            line: i + 1,
            snippet: trimmed,
            severity: "Medium"
          });
        }
      });

      return findings;
    }

    // Combine results and deduplicate
    function scanCode(code) {
      const r = regexScan(code);
      const a = astScan(code);
      const all = [...r, ...a];

      // deduplicate by type+line+snippet
      const map = new Map();
      all.forEach(item => {
        const key = `${item.type}::${item.line}::${item.snippet}`;
        if (!map.has(key)) map.set(key, item);
      });
      return Array.from(map.values());
    }

    // -------------------------
    // UI Logic
    // -------------------------
    document.addEventListener('DOMContentLoaded', () => {
      const tabButtons = document.querySelectorAll('.tab-button');
      const tabPanes = document.querySelectorAll('.tab-pane');

      tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
          const tabId = btn.getAttribute('data-tab');

          tabButtons.forEach(b => {
            b.classList.toggle('active', b === btn);
            b.setAttribute('aria-selected', b === btn ? 'true' : 'false');
          });

          tabPanes.forEach(p => p.classList.remove('active'));
          document.getElementById(`${tabId}-tab`).classList.add('active');
        });
      });

      const fileInput = document.getElementById('file-input');
      const selectFileBtn = document.getElementById('select-file-btn');
      const selectedFilesEl = document.getElementById('selected-files');
      const dropZone = document.getElementById('drop-zone');
      const scanTextBtn = document.getElementById('scan-text-btn');
      const codeInput = document.getElementById('code-input');
      const generateReport = document.getElementById('generate-report');
      const loading = document.getElementById('loading');
      const resultsContainer = document.getElementById('results-container');
      const sampleCode = document.getElementById('sample-code');

      let lastScanData = null;

      selectFileBtn.addEventListener('click', () => fileInput.click());

      fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files.length) {
          displaySelectedFiles(Array.from(fileInput.files));
          // scan first file (or you can merge multiple file contents)
          scanFiles(Array.from(fileInput.files));
        }
      });

      // drag/drop
      dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--primary)';
        dropZone.style.backgroundColor = '#f1f5f9';
      });
      dropZone.addEventListener('dragleave', () => {
        dropZone.style.borderColor = '#cbd5e1';
        dropZone.style.backgroundColor = 'transparent';
      });
      dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#cbd5e1';
        dropZone.style.backgroundColor = 'transparent';
        const files = Array.from(e.dataTransfer.files).filter(f => f.name.match(/\.(py|js|java|html|php|txt)$/i));
        if (!files.length) {
          alert('Please upload a Python, JavaScript, Java, HTML, PHP, or Text file');
          return;
        }
        fileInput.files = e.dataTransfer.files; // helps with later re-upload logic
        displaySelectedFiles(files);
        scanFiles(files);
      });

      // allow pressing enter or click on sample code to load
      sampleCode.addEventListener('click', () => { codeInput.value = sampleCode.textContent.trim(); });
      sampleCode.addEventListener('keydown', (e) => { if (e.key === 'Enter') codeInput.value = sampleCode.textContent.trim(); });

      scanTextBtn.addEventListener('click', () => {
        const code = codeInput.value.trim();
        if (!code) { alert('Please enter some code to scan'); return; }
        scanText(code);
      });

      generateReport.addEventListener('click', () => {
        if (!lastScanData) return;
        downloadReport(lastScanData);
      });

      // Display file list (multiple)
      function displaySelectedFiles(files) {
        if (!files || !files.length) {
          selectedFilesEl.innerHTML = '<p>No files selected</p>';
          return;
        }
        const html = files.map((f, idx) => `
          <div class="file-item" data-idx="${idx}">
            <span>${f.name}</span>
            <span class="remove-file" role="button" tabindex="0" data-idx="${idx}">×</span>
          </div>
        `).join('');
        selectedFilesEl.innerHTML = html;

        // attach remove handlers
        selectedFilesEl.querySelectorAll('.remove-file').forEach(el => {
          el.addEventListener('click', (ev) => {
            const i = Number(ev.target.getAttribute('data-idx'));
            const newList = Array.from(fileInput.files || []).filter((_, idx) => idx !== i);
            // Create new DataTransfer to set fileInput.files (works in most browsers)
            const dt = new DataTransfer();
            newList.forEach(f => dt.items.add(f));
            fileInput.files = dt.files;
            displaySelectedFiles(newList);
          });
        });
      }

      // Read and scan multiple files (concatenate for demo)
      function scanFiles(files) {
        showLoading();
        const readers = files.map(file => readFileAsText(file));
        Promise.all(readers).then(contents => {
          // For demo: combine file contents with separators so line numbers are still meaningful per combined doc
          const combined = contents.map((c, i) => `// --- File: ${files[i].name} ---\n${c}`).join('\n\n');
          processScanResults(combined, files.map(f => f.name).join(', '));
        }).catch(err => {
          hideLoading();
          alert('Failed to read file(s): ' + err.message);
        });
      }

      function readFileAsText(file) {
        return new Promise((resolve, reject) => {
          const r = new FileReader();
          r.onload = () => resolve(String(r.result));
          r.onerror = () => reject(new Error('File reading error'));
          r.readAsText(file);
        });
      }

      function scanText(code) {
        showLoading();
        // simulate small processing delay
        setTimeout(() => {
          processScanResults(code, 'pasted code');
        }, 200);
      }

      function processScanResults(code, filename) {
        const results = scanCode(code);
        const severityCounts = {
          High: results.filter(r => r.severity === 'High').length,
          Medium: results.filter(r => r.severity === 'Medium').length,
          Low: results.filter(r => r.severity === 'Low').length
        };
        const data = { filename, vulnerabilities: results, counts: severityCounts, scannedOn: new Date().toISOString() };
        lastScanData = data;
        displayResults(data);
        hideLoading();
      }

      function displayResults(data) {
        document.getElementById('high-count').textContent = data.counts.High || 0;
        document.getElementById('medium-count').textContent = data.counts.Medium || 0;
        document.getElementById('low-count').textContent = data.counts.Low || 0;

        const vulnContainer = document.getElementById('vulnerabilities-container');
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
          let vulnHTML = '<div class="vulnerability-list">';
          data.vulnerabilities.forEach(vuln => {
            const severityClass = `vuln-${vuln.severity.toLowerCase()}`;
            vulnHTML += `
              <div class="vuln-item ${severityClass}">
                <div class="vuln-title">${escapeHtml(vuln.type)} (${vuln.severity})</div>
                <div class="vuln-details">Line ${vuln.line}: <code>${escapeHtml(vuln.snippet)}</code></div>
              </div>`;
          });
          vulnHTML += '</div>';
          vulnContainer.innerHTML = vulnHTML;
          generateReport.disabled = false;
        } else {
          vulnContainer.innerHTML = '<p>No vulnerabilities found! Your code appears to be secure.</p>';
          generateReport.disabled = true;
        }
      }

      function showLoading() {
        loading.classList.remove('hidden');
        loading.setAttribute('aria-hidden', 'false');
        resultsContainer.classList.add('hidden');
      }

      function hideLoading() {
        loading.classList.add('hidden');
        loading.setAttribute('aria-hidden', 'true');
        resultsContainer.classList.remove('hidden');
      }

      function downloadReport(data) {
        const vulnItems = data.vulnerabilities.map(v => `- ${v.type} (${v.severity})\n  Line ${v.line}: ${v.snippet}`).join('\n\n');
        const report = `CodeGuard Vulnerability Report\n=============================\n\nScan summary for: ${data.filename}\nGenerated: ${new Date(data.scannedOn).toLocaleString()}\n\nHigh: ${data.counts.High}\nMedium: ${data.counts.Medium}\nLow: ${data.counts.Low}\n\nDetailed findings:\n\n${vulnItems || 'None'}\n`;
        const blob = new Blob([report], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'codeguard-report.txt';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }

      function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, function (m) {
          return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m];
        });
      }
    });
  </script>
</body>
</html>
