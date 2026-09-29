// =========================================================
// LEXGUARD CYBER DEFENSE PLATFORM — MAIN JS CONTROLLER
// =========================================================

// Theme Switcher
function applyTheme(theme) {
    const light = theme === 'light';
    document.body.classList.toggle('light-theme', light);
    localStorage.setItem('lexguard-theme', light ? 'light' : 'dark');
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    const btn = document.getElementById('themeToggle');
    if (icon) icon.textContent = light ? '☾' : '☀';
    if (label) label.textContent = light ? 'DARK MODE' : 'LIGHT MODE';
    if (btn) btn.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
}

function toggleTheme() {
    applyTheme(document.body.classList.contains('light-theme') ? 'dark' : 'light');
}

(function initTheme() {
    const saved = localStorage.getItem('lexguard-theme') || 'dark';
    applyTheme(saved);
})();

// Navigation Pages Mapping
const pages = {
    dashboard: 'SOC Security Dashboard',
    analyze: 'Threat Intelligence & Heuristic Analysis',
    crypto: 'Cryptographic Security Suite',
    dlp: 'Data Loss Prevention & Privacy Vault',
    evidence: 'Digital Evidence Vault & Custody',
    legal: 'Cyber Law & Legal Enforcement Center',
    wireless: 'Wireless & Mobile Threat Radar',
    response: 'SOC Incident Response Center',
    investigate: 'Case Investigation & Forensics',
    lab: 'Security Triage Lab',
    simulator: 'Attack Scenario Simulator'
};

function showPage(id) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active-page'));
    const target = document.getElementById(id);
    if (target) target.classList.add('active-page');
    
    document.querySelectorAll('.nav').forEach(n => n.classList.toggle('active', n.dataset.page === id));
    document.getElementById('pageTitle').textContent = pages[id] || 'Security Console';
    
    if (id === 'evidence') loadEvidence();
    if (id === 'investigate') { loadCases(); loadIocs(); }
    if (id === 'dashboard') loadDashboard();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.querySelectorAll('.nav').forEach(n => {
    n.onclick = () => showPage(n.dataset.page);
});

// Helper for API POST calls
async function post(url, body, options = {}) {
    const r = await fetch(url, {
        method: 'POST',
        headers: options.headers || { 'Content-Type': 'application/json' },
        body: options.raw ? body : JSON.stringify(body)
    });
    if (options.download) return r;
    if (!r.ok) {
        const e = await r.json().catch(() => ({ error: 'Operation failed' }));
        throw new Error(e.error || 'Server request failed');
    }
    return r.json();
}

function riskClass(r) {
    return 'risk-' + (r || 'low').toLowerCase();
}

function copyToClipboard(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.innerText || el.value;
    navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard successfully!');
    }).catch(() => {
        alert('Failed to copy text.');
    });
}

// =========================================================
// 1. DASHBOARD TELEMETRY
// =========================================================
async function loadDashboard() {
    try {
        const res = await fetch('/api/dashboard');
        const d = await res.json();
        
        document.getElementById('dashIncidents').textContent = d.total_incidents;
        document.getElementById('dashCritical').textContent = d.critical_high;
        document.getElementById('dashEvidence').textContent = d.evidence_count;
        document.getElementById('dashIocs').textContent = d.ioc_count;
        
        const tDist = document.getElementById('threatDistribution');
        if (Object.keys(d.threat_distribution).length === 0) {
            tDist.innerHTML = '<span class="muted">No incident data recorded yet. Run an analysis to populate telemetry.</span>';
        } else {
            tDist.innerHTML = Object.entries(d.threat_distribution).map(([k, v]) => `
                <div class="dist-row">
                    <span>${k}</span>
                    <div class="dist-bar"><div style="width:${Math.min(100, v * 20)}%"></div></div>
                    <b>${v}</b>
                </div>
            `).join('');
        }
        
        const oDist = document.getElementById('offenceDistribution');
        if (Object.keys(d.offence_distribution).length === 0) {
            oDist.innerHTML = '<span class="muted">No cyber offence records registered.</span>';
        } else {
            oDist.innerHTML = Object.entries(d.offence_distribution).map(([k, v]) => `
                <div class="dist-row">
                    <span>${k}</span>
                    <div class="dist-bar"><div style="width:${Math.min(100, v * 20)}%" class="offence-bar"></div></div>
                    <b>${v}</b>
                </div>
            `).join('');
        }
    } catch (e) {
        console.error('Failed to load dashboard metrics:', e);
    }
}

// =========================================================
// 2. THREAT INTELLIGENCE & INCIDENT ANALYSIS
// =========================================================
async function analyze() {
    const text = document.getElementById('incidentText').value.trim();
    if (!text) return alert('Please enter suspicious text, logs, or an incident description first.');
    
    const box = document.getElementById('analysisResult');
    box.classList.remove('hidden');
    box.innerHTML = '<div class="panel">Running heuristic analysis, IOC extraction &amp; legal mapping…</div>';
    
    try {
        const d = await post('/api/analyze', { text });
        window.currentIncident = d;
        renderAnalysisCard(d, box);
    } catch (e) {
        box.innerHTML = `<div class="panel text-red">Analysis Error: ${e.message}</div>`;
    }
}

function renderAnalysisCard(d, container) {
    const t = d.threat;
    const l = d.legal;
    
    container.innerHTML = `
        <div class="result-wrap">
            <div class="result-grid">
                <!-- Left: Threat & Offence Assessment -->
                <div class="result-card">
                    <div class="panel-header">
                        <h4>SECURITY ASSESSMENT</h4>
                        <span class="badge ${riskClass(d.risk)}">${d.risk.toUpperCase()} RISK</span>
                    </div>
                    
                    <div class="score-display">
                        <div class="score-val ${riskClass(d.risk)}">${d.score}<span>/100</span></div>
                        <div class="bar" style="margin-top:8px;"><i style="width:${d.score}%"></i></div>
                    </div>

                    <div class="info-list">
                        <p><b>Incident ID:</b> <span class="code">${d.incident_id}</span></p>
                        <p><b>Threat Vector:</b> <span>${t.classification}</span></p>
                        <p><b>Cyber Offence:</b> <span>${d.offence}</span></p>
                        <p><b>Severity / Priority:</b> <span class="badge">${d.severity} • ${d.priority}</span></p>
                        <p class="muted small">${d.severity_reason || ''}</p>
                    </div>

                    <h4 style="margin-top:16px;">HEURISTIC EXPLANATION</h4>
                    <ul>
                        ${t.why.map(w => `<li>${w}</li>`).join('')}
                    </ul>

                    <h4 style="margin-top:14px;">TRIGGERED SIGNATURES</h4>
                    <div>
                        ${(t.triggers.length ? t.triggers : ['None'])
                            .map(x => `<span class="tag">${x}</span>`).join('')}
                    </div>

                    <h4 style="margin-top:16px;">EXTRACTED IOCs</h4>
                    <div>
                        ${(d.iocs && d.iocs.length ? d.iocs.map(i => `<span class="tag tag-ioc"><b>${i.type}:</b> ${i.value}</span>`).join('') : '<span class="muted small">No IOCs extracted</span>')}
                    </div>

                    <h4 style="margin-top:16px;">MITRE ATT&amp;CK TACTICS &amp; TECHNIQUES</h4>
                    ${(d.mitre && d.mitre.length ? d.mitre.map(m => `
                        <div class="mitre-item">
                            <b>${m.id} — ${m.name}</b> <span class="badge small">${m.tactic || 'Execution'}</span>
                            <div class="muted small">${m.why}</div>
                        </div>
                    `).join('') : '<span class="muted small">No direct MITRE mapping</span>')}
                </div>

                <!-- Right: Immediate Response, Law & Action -->
                <div class="result-card">
                    <div class="panel-header">
                        <h4>⚡ CONTAINMENT &amp; REMEDIATION</h4>
                        <span class="badge">Playbook</span>
                    </div>
                    
                    <ul class="playbook-steps">
                        ${d.response.map((step, idx) => `
                            <li><b>${idx + 1}.</b> ${step.text || step}</li>
                        `).join('')}
                    </ul>

                    ${l ? `
                        <div class="legal-box" style="margin-top:18px;">
                            <h4>⚖ STATUTORY CYBER LAW MAPPING</h4>
                            <p><b>Information Technology Act:</b> <span class="text-accent">${l.it_act}</span></p>
                            <p><b>BNS 2023 / IPC:</b> <span>${l.bns_ipc || 'N/A'}</span></p>
                            <p><b>DPDP Act 2023:</b> <span class="muted">${l.dpdp_act || 'N/A'}</span></p>
                            <p class="muted small">${l.description}</p>
                            <p class="legal-alert"><b>Reporting Directive:</b> ${l.reporting}</p>
                        </div>
                    ` : ''}

                    <div class="action-buttons" style="margin-top:20px;">
                        <button class="primary" onclick="downloadPdfReport()">📄 DOWNLOAD FORENSIC PDF REPORT</button>
                        <button class="secondary" onclick="openFirWithIncident()">📝 PREPARE POLICE FIR DRAFT</button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Download PDF Report
async function downloadPdfReport() {
    if (!window.currentIncident) return alert('No incident loaded.');
    try {
        const response = await post('/api/report', window.currentIncident, { download: true });
        if (!response.ok) throw new Error('PDF Generation failed');
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `LexGuard_Report_${window.currentIncident.incident_id}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    } catch (e) {
        alert('Failed to generate PDF: ' + e.message);
    }
}

function openFirWithIncident() {
    if (!window.currentIncident) return;
    showPage('legal');
    switchLegalTab('tabFir');
    document.getElementById('firFacts').value = window.currentIncident.input || '';
    if (window.currentIncident.offence) {
        const sel = document.getElementById('firOffence');
        for (let i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value === window.currentIncident.offence) {
                sel.selectedIndex = i;
                break;
            }
        }
    }
}

// =========================================================
// 3. CRYPTOGRAPHIC SUITE
// =========================================================
function switchCryptoTab(tabId) {
    document.querySelectorAll('.crypto-subtab').forEach(t => t.classList.add('hidden'));
    const target = document.getElementById(tabId);
    if (target) target.classList.remove('hidden');
    
    document.querySelectorAll('#crypto .tab-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
}

// AES-256 Multi-mode
async function runAes(action) {
    const text = document.getElementById('aesText').value.trim();
    const passphrase = document.getElementById('aesPass').value.trim();
    const mode = document.getElementById('aesMode').value;
    const out = document.getElementById('aesOut');
    
    if (!passphrase) return alert('Please provide a secret passphrase for key derivation.');
    if (!text) return alert('Please enter text to encrypt or decrypt.');
    
    out.innerHTML = 'Executing AES-256 cryptographic routine...';
    try {
        const res = await post('/api/crypto/aes', { action, text, passphrase, mode });
        if (action === 'encrypt') {
            out.innerHTML = `
                <p><b>Algorithm:</b> <span class="badge">${res.mode}</span></p>
                <p><b>Salt (Hex):</b> <span class="code">${res.salt_hex}</span></p>
                <p><b>IV / Nonce (Hex):</b> <span class="code">${res.iv_hex}</span></p>
                ${res.tag_hex ? `<p><b>GCM Auth Tag:</b> <span class="code">${res.tag_hex}</span></p>` : ''}
                <p><b>Ciphertext (Base64):</b></p>
                <textarea class="code-box" style="height:80px;" readonly>${res.ciphertext_b64}</textarea>
                <p><b>Plaintext SHA-256:</b> <span class="code">${res.sha256_hash}</span></p>
            `;
        } else {
            out.innerHTML = `
                <p><b>Status:</b> <span class="badge green">DECRYPTED SUCCESSFULLY</span></p>
                <p><b>Recovered Plaintext:</b></p>
                <textarea class="code-box" style="height:80px;" readonly>${res.plaintext}</textarea>
                <p><b>Plaintext SHA-256:</b> <span class="code">${res.sha256_hash}</span></p>
            `;
        }
    } catch (e) {
        out.innerHTML = `<span class="text-red">AES Error: ${e.message}</span>`;
    }
}

// RSA Keypair & Signatures
async function generateRsaKeys() {
    const keySize = parseInt(document.getElementById('rsaKeySize').value);
    const pub = document.getElementById('rsaPubKey');
    const priv = document.getElementById('rsaPrivKey');
    
    pub.value = 'Generating cryptographic keypair...';
    priv.value = 'Generating cryptographic keypair...';
    
    try {
        const res = await post('/api/crypto/rsa/generate', { key_size: keySize });
        pub.value = res.public_key_pem;
        priv.value = res.private_key_pem;
        document.getElementById('rsaOut').innerHTML = `<span class="badge green">Generated ${res.key_size}-Bit RSA Keypair (${res.public_key_fingerprint})</span>`;
    } catch (e) {
        alert('RSA Generation error: ' + e.message);
    }
}

async function runRsaSign() {
    const message = document.getElementById('rsaMsg').value.trim();
    const privPem = document.getElementById('rsaPrivKey').value.trim();
    const out = document.getElementById('rsaOut');
    
    if (!message) return alert('Enter a message to sign.');
    if (!privPem) return alert('Generate or paste a Private Key PEM first.');
    
    try {
        const res = await post('/api/crypto/rsa/sign_verify', {
            action: 'sign',
            message: message,
            private_key_pem: privPem
        });
        document.getElementById('rsaSig').value = res.signature_b64;
        out.innerHTML = `<span class="badge green">Signature Generated (${res.algorithm})</span> • SHA-256 Digest: <span class="code">${res.digest_sha256}</span>`;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Signing failed: ${e.message}</span>`;
    }
}

async function runRsaVerify() {
    const message = document.getElementById('rsaMsg').value.trim();
    const pubPem = document.getElementById('rsaPubKey').value.trim();
    const signature = document.getElementById('rsaSig').value.trim();
    const out = document.getElementById('rsaOut');
    
    if (!message || !pubPem || !signature) return alert('Message, Public Key, and Signature are all required for verification.');
    
    try {
        const res = await post('/api/crypto/rsa/sign_verify', {
            action: 'verify',
            message: message,
            public_key_pem: pubPem,
            signature_b64: signature
        });
        out.innerHTML = res.valid ?
            `<div class="badge green">✓ ${res.message}</div>` :
            `<div class="badge red">✗ ${res.message}</div>`;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Verification failed: ${e.message}</span>`;
    }
}

// Steganography
async function embedStego() {
    const fileInput = document.getElementById('stegoImgEmbed');
    const secret = document.getElementById('stegoSecret').value.trim();
    const msg = document.getElementById('stegoEmbedMsg');
    
    if (!fileInput.files.length) return alert('Choose an image file.');
    if (!secret) return alert('Enter a secret message.');
    
    const formData = new FormData();
    formData.append('image', fileInput.files[0]);
    formData.append('secret', secret);
    
    msg.innerHTML = 'Embedding confidential payload into LSB pixels...';
    try {
        const response = await fetch('/api/stego/hide', { method: 'POST', body: formData });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Stego embedding failed');
        }
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'stego_carrier.png';
        document.body.appendChild(a);
        a.click();
        a.remove();
        msg.innerHTML = '<span class="text-green">✓ Payload embedded! Downloaded stego_carrier.png</span>';
    } catch (e) {
        msg.innerHTML = `<span class="text-red">Stego error: ${e.message}</span>`;
    }
}

async function extractStego() {
    const fileInput = document.getElementById('stegoImgExtract');
    const out = document.getElementById('stegoExtractOut');
    
    if (!fileInput.files.length) return alert('Choose a stego carrier image.');
    
    const formData = new FormData();
    formData.append('image', fileInput.files[0]);
    
    out.innerHTML = 'Extracting pixel bitstream...';
    try {
        const res = await fetch('/api/stego/extract', { method: 'POST', body: formData });
        const d = await res.json();
        if (!res.ok) throw new Error(d.error || 'Extraction failed');
        out.innerHTML = `
            <p><b>Status:</b> <span class="badge green">CONCEALED PAYLOAD DETECTED</span></p>
            <p><b>Recovered Secret:</b></p>
            <textarea class="code-box" readonly>${d.secret}</textarea>
            <p><b>Payload Hash (SHA-256):</b> <span class="code">${d.sha256}</span></p>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Extraction failed: ${e.message}</span>`;
    }
}

// Multi-Hash Inspector
async function calculateMultiHash() {
    const text = document.getElementById('hashInput').value;
    const out = document.getElementById('hashOut');
    if (!text) return alert('Enter text to hash.');
    
    try {
        const res = await post('/api/crypto/multihash', { text });
        out.innerHTML = `
            <p><b>Data Size:</b> ${res.length_bytes} Bytes • <b>Shannon Entropy:</b> ${res.entropy_bits} Bits</p>
            <div class="hash-grid">
                ${Object.entries(res.hashes).map(([algo, info]) => `
                    <div class="hash-row">
                        <div class="hash-header">
                            <b>${algo}</b> <span class="badge small">${info.security}</span>
                        </div>
                        <input class="code code-input" readonly value="${info.digest}">
                    </div>
                `).join('')}
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Hash Error: ${e.message}</span>`;
    }
}

// Diffie-Hellman Simulator
async function runDiffieHellman() {
    const out = document.getElementById('dhOut');
    try {
        const res = await post('/api/crypto/dh', {});
        out.innerHTML = `
            <div class="dh-box">
                <p><b>Public Prime Modulus (p):</b> ${res.prime_p} &nbsp;|&nbsp; <b>Generator Base (g):</b> ${res.generator_g}</p>
                <div class="two-col" style="margin-top:10px;">
                    <div class="panel">
                        <h5>👩 Alice's Side</h5>
                        <p>Private Secret (a): <b>${res.alice.private_a}</b></p>
                        <p>Computed Public Value (A = g^a mod p): <b>${res.alice.public_A}</b></p>
                        <p>Shared Key (K = B^a mod p): <b class="text-accent">${res.computed_shared_secret}</b></p>
                    </div>
                    <div class="panel">
                        <h5>👨 Bob's Side</h5>
                        <p>Private Secret (b): <b>${res.bob.private_b}</b></p>
                        <p>Computed Public Value (B = g^b mod p): <b>${res.bob.public_B}</b></p>
                        <p>Shared Key (K = A^b mod p): <b class="text-accent">${res.computed_shared_secret}</b></p>
                    </div>
                </div>
                <p style="margin-top:12px;" class="text-green">✓ ${res.explanation}</p>
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">DH Error: ${e.message}</span>`;
    }
}

// Fernet Operations
async function cryptoAction(action) {
    const text = document.getElementById('cryptoText').value.trim();
    const out = document.getElementById('cryptoOut');
    if (!text) return alert('Enter text or token.');
    try {
        const res = await post('/api/crypto', { action, text });
        out.innerHTML = `
            <p><b>Result:</b></p>
            <textarea class="code-box" readonly>${res.result}</textarea>
            <p><b>SHA-256 Digest:</b> <span class="code">${res.hash}</span></p>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Error: ${e.message}</span>`;
    }
}

async function saveVault() {
    const name = document.getElementById('vaultName').value.trim();
    const note = document.getElementById('vaultNote').value.trim();
    const out = document.getElementById('vaultOut');
    if (!name || !note) return alert('Provide a name and note content.');
    try {
        const res = await post('/api/locker/save', { name, note });
        out.innerHTML = `<span class="text-green">✓ ${res.message}</span> (File: ${res.file})`;
    } catch (e) {
        out.innerHTML = `<span class="text-red">${e.message}</span>`;
    }
}

async function getVault() {
    const name = document.getElementById('vaultName').value.trim();
    const out = document.getElementById('vaultOut');
    if (!name) return alert('Enter the vault note identifier.');
    try {
        const res = await post('/api/locker/get', { name });
        out.innerHTML = `
            <p><b>Decrypted Note:</b></p>
            <textarea class="code-box" readonly>${res.note}</textarea>
            <p><b>Vault File Hash:</b> <span class="code">${res.hash}</span></p>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">${e.message}</span>`;
    }
}

// =========================================================
// 4. DATA LOSS PREVENTION (DLP) & PRIVACY VAULT
// =========================================================
async function runDlpScan() {
    const text = document.getElementById('dlpInput').value.trim();
    const out = document.getElementById('dlpOut');
    if (!text) return alert('Please enter text for DLP scanning.');
    
    out.innerHTML = 'Scanning text for sensitive PII entities...';
    try {
        const res = await post('/api/dlp/scan', { text });
        out.innerHTML = `
            <div class="dlp-summary">
                <p><b>Entities Redacted:</b> <span class="badge ${res.total_redacted > 0 ? 'red' : 'green'}">${res.total_redacted} PII Items Found</span></p>
                <div class="findings-list" style="margin-top:10px;">
                    ${res.findings.map(f => `
                        <div class="finding-card">
                            <b>${f.type}:</b> <code>${f.masked}</code>
                            ${f.valid ? '<span class="badge small green">Checksum Validated</span>' : ''}
                        </div>
                    `).join('')}
                </div>
                <h5 style="margin-top:14px;">Sanitized &amp; Masked Output Text</h5>
                <textarea class="code-box" style="height:120px;" readonly>${res.redacted_text}</textarea>
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">DLP Scan Error: ${e.message}</span>`;
    }
}

async function runShredder() {
    const filename = document.getElementById('shredFilename').value.trim();
    const size_kb = parseInt(document.getElementById('shredSize').value) || 64;
    const passes = parseInt(document.getElementById('shredPasses').value) || 3;
    const out = document.getElementById('shredOut');
    
    out.innerHTML = 'Executing DoD 5220.22-M sanitization passes...';
    try {
        const res = await post('/api/shredder/simulate', { filename, size_kb, passes });
        out.innerHTML = `
            <div class="shred-report">
                <div class="panel-header">
                    <h4>SANITIZATION AUDIT REPORT</h4>
                    <span class="badge green">${res.certificate.verdict}</span>
                </div>
                <p><b>Standard:</b> ${res.standard}</p>
                <p><b>Sanitization Certificate ID:</b> <span class="code">${res.certificate.sanitization_id}</span></p>
                <p><b>Bytes Overwritten:</b> ${res.total_bytes_sanitized} Bytes (${passes} Passes)</p>
                <div class="pass-logs" style="margin-top:10px;">
                    ${res.logs.map(l => `
                        <div class="pass-item">
                            <span><b>Pass ${l.pass}:</b> ${l.pattern}</span>
                            <span>Entropy: ${l.resulting_entropy}</span>
                            <span class="text-green">✓ ${l.status}</span>
                        </div>
                    `).join('')}
                </div>
                <p style="margin-top:10px;" class="muted small">Residual magnetic trace: ${res.residual_magnetic_trace}</p>
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Shredder error: ${e.message}</span>`;
    }
}

// =========================================================
// 5. DIGITAL EVIDENCE VAULT
// =========================================================
async function uploadEvidence() {
    const fileInput = document.getElementById('evidenceFile');
    const incidentId = document.getElementById('evidenceIncident').value.trim();
    const note = document.getElementById('evidenceNote').value.trim();
    const msg = document.getElementById('evidenceMsg');
    
    if (!fileInput.files.length) return alert('Please choose a file to ingest.');
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('incident_id', incidentId);
    formData.append('note', note);
    
    msg.innerHTML = 'Ingesting evidence and generating SHA-256 seal...';
    try {
        const res = await fetch('/api/evidence', { method: 'POST', body: formData });
        const d = await res.json();
        if (!res.ok) throw new Error(d.error || 'Upload failed');
        msg.innerHTML = `<span class="text-green">✓ Evidence secured with ID ${d.evidence_id} (SHA-256: ${d.sha256.substring(0, 16)}...)</span>`;
        loadEvidence();
    } catch (e) {
        msg.innerHTML = `<span class="text-red">Upload failed: ${e.message}</span>`;
    }
}

async function loadEvidence() {
    const list = document.getElementById('evidenceList');
    if (!list) return;
    try {
        const res = await fetch('/api/evidence/list');
        const records = await res.json();
        if (!records.length) {
            list.innerHTML = '<span class="muted">No digital evidence artifacts in vault.</span>';
            return;
        }
        list.innerHTML = records.map(r => `
            <div class="evidence-card">
                <div class="ev-head">
                    <b>${r.evidence_id}</b>
                    <span class="badge small ${r.status === 'VERIFIED INTACT' ? 'green' : 'amber'}">${r.status}</span>
                </div>
                <p><b>File:</b> ${r.filename} (${Math.round(r.size / 1024)} KB)</p>
                <p><b>Incident:</b> <span class="code">${r.incident_id}</span></p>
                <p><b>SHA-256:</b> <span class="code">${r.sha256 || r.original_hash}</span></p>
                <div class="ev-actions" style="margin-top:8px;">
                    <button class="secondary small-btn" onclick="verifyEvidence('${r.incident_id}', '${r.evidence_id}')">VERIFY INTEGRITY</button>
                    <button class="secondary small-btn" onclick="viewCustody('${r.incident_id}')">VIEW CUSTODY</button>
                </div>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = `<span class="text-red">Failed to load evidence: ${e.message}</span>`;
    }
}

async function verifyEvidence(incident_id, evidence_id) {
    try {
        const res = await post('/api/evidence/verify', { incident_id, evidence_id });
        alert(`Integrity Check: ${res.status}\nOriginal: ${res.original}\nCurrent:  ${res.current}`);
        loadEvidence();
    } catch (e) {
        alert('Verification error: ' + e.message);
    }
}

async function viewCustody(incident_id) {
    const panel = document.getElementById('custodyPanel');
    panel.classList.remove('hidden');
    panel.innerHTML = 'Loading chain of custody logs...';
    try {
        const res = await fetch(`/api/evidence/${incident_id}/custody`);
        const entries = await res.json();
        panel.innerHTML = `
            <h4>CHAIN OF CUSTODY AUDIT LOG — ${incident_id}</h4>
            <div class="timeline" style="margin-top:12px;">
                ${entries.map(e => `
                    <div class="timeline-item">
                        <span class="time">${e.timestamp}</span>
                        <b>${e.action}</b>
                        <p class="muted small">${e.description}</p>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (e) {
        panel.innerHTML = `<span class="text-red">Failed to load custody: ${e.message}</span>`;
    }
}

// =========================================================
// 6. CYBER LAW & LEGAL ENFORCEMENT
// =========================================================
function switchLegalTab(tabId) {
    document.querySelectorAll('.legal-subtab').forEach(t => t.classList.add('hidden'));
    const target = document.getElementById(tabId);
    if (target) target.classList.remove('hidden');
    
    document.querySelectorAll('#legal .tab-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
}

async function generateFirDraft() {
    const complainant_name = document.getElementById('firComplainant').value.trim();
    const complainant_contact = document.getElementById('firContact').value.trim();
    const offence = document.getElementById('firOffence').value;
    const financial_loss = document.getElementById('firLoss').value.trim();
    const suspect_info = document.getElementById('firSuspect').value.trim();
    const input = document.getElementById('firFacts').value.trim();
    const out = document.getElementById('firOut');
    
    out.innerText = 'Drafting formal Cyber Crime Police FIR Application...';
    try {
        const res = await post('/api/report/fir', {
            complainant_name,
            complainant_contact,
            offence,
            financial_loss,
            suspect_info,
            input,
            iocs: window.currentIncident ? window.currentIncident.iocs : []
        });
        out.innerText = res.fir_text;
    } catch (e) {
        out.innerText = 'Error generating FIR: ' + e.message;
    }
}

async function generate65bCertificate() {
    const examiner_name = document.getElementById('certExaminer').value.trim();
    const organization = document.getElementById('certOrg').value.trim();
    const incident_id = document.getElementById('certIncident').value.trim() || (window.currentIncident ? window.currentIncident.incident_id : 'LG-CASE-MASTER');
    const out = document.getElementById('certOut');
    
    out.innerText = 'Generating Section 65B Digital Evidence Certificate...';
    try {
        const res = await post('/api/report/section65b', {
            examiner_name,
            organization,
            incident_id,
            evidence: window.currentIncident ? window.currentIncident.evidence : []
        });
        out.innerText = res.certificate_text;
    } catch (e) {
        out.innerText = 'Error generating Certificate: ' + e.message;
    }
}

// =========================================================
// 7. WIRELESS & MOBILE THREAT RADAR
// =========================================================
async function wifi(type) {
    const out = document.getElementById('wifiOut');
    out.innerHTML = 'Evaluating 802.11 security posture...';
    try {
        const res = await post('/api/wifi', { type });
        out.innerHTML = `
            <div class="result-card" style="margin-top:10px;">
                <div class="panel-header">
                    <h4>${res.type} WIRELESS RISK</h4>
                    <span class="badge ${riskClass(res.risk)}">${res.risk.toUpperCase()} RISK (${res.score}/100)</span>
                </div>
                <p>${res.explanation}</p>
                <h5 style="margin-top:10px;">Attack Vector Assessment</h5>
                <ul>
                    ${res.heuristics.map(h => `<li>${h}</li>`).join('')}
                </ul>
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Error: ${e.message}</span>`;
    }
}

async function permissionsCheck() {
    const permissions = document.getElementById('permissions').value.trim();
    const out = document.getElementById('permOut');
    if (!permissions) return alert('Enter permissions to evaluate.');
    
    out.innerHTML = 'Analyzing Android permission matrix...';
    try {
        const res = await post('/api/permissions', { permissions });
        out.innerHTML = `
            <div class="result-card" style="margin-top:10px;">
                <div class="panel-header">
                    <h4>MALWARE RISK RATING</h4>
                    <span class="badge ${riskClass(res.risk)}">${res.risk.toUpperCase()} (${res.score}/100)</span>
                </div>
                <p><b>Sensitive Permissions Identified:</b></p>
                <div>${res.sensitive.map(s => `<span class="tag">${s}</span>`).join('')}</div>
                
                ${res.combos_detected.length ? `
                    <h5 style="margin-top:14px;" class="text-red">Dangerous Permission Combinations Detected!</h5>
                    ${res.combos_detected.map(c => `
                        <div class="mitre-item" style="border-left-color:var(--red);">
                            <b>${c.name}</b> <span class="badge small red">${c.risk}</span>
                            <p class="muted small">${c.description}</p>
                        </div>
                    `).join('')}
                ` : '<p class="text-green" style="margin-top:10px;">✓ No critical surveillance or financial fraud combos identified.</p>'}
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Error: ${e.message}</span>`;
    }
}

// =========================================================
// 8. INCIDENT RESPONSE & SCENARIO WORKFLOWS
// =========================================================
function scenario(type) {
    const out = document.getElementById('scenarioOut');
    out.classList.remove('hidden');
    
    const responses = {
        'Phishing': ['Do not click suspicious links or download attachments.', 'Change compromised passwords immediately from an official device.', 'Enable hardware-token or authenticator app MFA.', 'Preserve raw email headers and screenshot for forensics.', 'Report to cybercrime.gov.in and CERT-In.'],
        'Hacking/Unauthorized Access': ['Terminate all active web/app sessions immediately.', 'Reset master credentials using a secure password generator.', 'Audit authorized OAuth apps and revoke unknown API keys.', 'Inspect server authentication logs.', 'Report under Section 43/66 IT Act.'],
        'Online Fraud': ['Call 1930 Cyber Fraud Helpline within Golden Hour to freeze funds.', 'Inform your bank fraud desk to hotlist cards and block net banking.', 'Preserve UTR, transaction IDs, and timestamps.', 'Register formal complaint on cybercrime.gov.in.', 'Submit dispute form with the bank within 3 days.'],
        'Ransomware': ['Immediately disconnect infected hosts from network/Wi-Fi.', 'Do NOT reboot abruptly if memory dump is needed.', 'Preserve ransom notes and sample encrypted files.', 'Check NoMoreRansom for decryption keys.', 'Notify CERT-In and incident response team.'],
        'Malware-link': ['Disconnect endpoint from corporate/home network.', 'Extract file SHA-256 hash and process execution tree.', 'Run offline antimalware scan in safe mode.', 'Force password reset across associated accounts.', 'Quarantine binary in digital evidence vault.'],
        'Identity Theft': ['File complaint on cybercrime.gov.in for acknowledgement ID.', 'Notify UIDAI / Credit Bureaus to place identity freeze.', 'Request platform takedown for fake impersonating profiles.', 'Keep certified copies of official identity documents.', 'Publish public disclaimer if necessary.'],
        'Cyberstalking': ['Do not engage or negotiate with the stalker.', 'Capture full timestamped screenshots with URLs.', 'Block and report accounts on social media platforms.', 'Inspect personal devices for unauthorized tracking apps.', 'Seek assistance under Women/Child Cybercrime reporting.'],
        'Data Theft': ['Identify data exfiltration channels (Cloud, USB, VPN).', 'Revoke suspect credentials and seal outbound egress ports.', 'Perform forensic imaging of suspect endpoints.', 'Notify CERT-In within 6 hours as per regulatory mandate.', 'Evaluate DPDP Act 2023 compliance liabilities.']
    };
    
    const steps = responses[type] || ['Preserve evidence.', 'Contact cyber cell.'];
    out.innerHTML = `
        <div class="panel">
            <div class="panel-header">
                <h4>IMMEDIATE ACTION PROTOCOL — ${type.toUpperCase()}</h4>
                <span class="badge red">Action Required</span>
            </div>
            <ul class="playbook-steps" style="margin-top:12px;">
                ${steps.map((s, i) => `<li><b>${i + 1}.</b> ${s}</li>`).join('')}
            </ul>
        </div>
    `;
}

// =========================================================
// 9. CASE INVESTIGATION & FORENSICS
// =========================================================
async function loadCases() {
    const q = (document.getElementById('caseSearch') ? document.getElementById('caseSearch').value.trim() : '');
    const list = document.getElementById('caseList');
    if (!list) return;
    
    try {
        const res = await fetch('/api/cases?q=' + encodeURIComponent(q));
        const cases = await res.json();
        if (!cases.length) {
            list.innerHTML = '<span class="muted">No matching cases found in investigation archive.</span>';
            return;
        }
        list.innerHTML = cases.map(c => `
            <div class="case-card" onclick="viewCaseDetail('${c.incident_id}')">
                <div class="case-head">
                    <b>${c.incident_id}</b>
                    <span class="badge small ${riskClass(c.risk)}">${c.risk}</span>
                </div>
                <p><b>Threat:</b> ${c.threat ? c.threat.classification : 'N/A'} • <b>Offence:</b> ${c.offence || 'Unclear'}</p>
                <p class="muted small">${c.timestamp}</p>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = `<span class="text-red">Error loading cases: ${e.message}</span>`;
    }
}

async function viewCaseDetail(incidentId) {
    const out = document.getElementById('caseDetail');
    out.innerHTML = 'Loading case dossier...';
    try {
        const res = await fetch('/api/cases/' + incidentId);
        const c = await res.json();
        
        out.innerHTML = `
            <div class="dossier-box">
                <div class="panel-header">
                    <h4>${c.incident_id} DOSSIER</h4>
                    <span class="badge ${riskClass(c.risk)}">${c.risk.toUpperCase()}</span>
                </div>
                <p><b>Registered:</b> ${c.timestamp}</p>
                <p><b>Threat:</b> ${c.threat ? c.threat.classification : 'N/A'}</p>
                <p><b>Offence:</b> ${c.offence || 'Unclear'}</p>
                <p><b>Status:</b> <span class="badge small">${c.status || 'ACTIVE'}</span></p>
                
                <h5 style="margin-top:14px;">Audit Hash-Chain Verification</h5>
                <p>${c.audit_verification && c.audit_verification.valid ? 
                    '<span class="badge green">✓ Cryptographic Audit Chain Valid</span>' : 
                    '<span class="badge red">✗ Audit Chain Broken</span>'}</p>
                
                <div style="margin-top:16px;">
                    <a href="/api/cases/${c.incident_id}/export" class="primary" style="display:inline-block; text-decoration:none; padding:8px 14px; border-radius:6px; font-weight:600;">📦 EXPORT FORENSIC CASE ZIP</a>
                </div>
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Error: ${e.message}</span>`;
    }
}

async function loadIocs() {
    const list = document.getElementById('iocList');
    const type = document.getElementById('iocType') ? document.getElementById('iocType').value : '';
    const q = document.getElementById('iocSearch') ? document.getElementById('iocSearch').value.trim() : '';
    if (!list) return;
    
    try {
        const res = await fetch(`/api/iocs?type=${encodeURIComponent(type)}&q=${encodeURIComponent(q)}`);
        const iocs = await res.json();
        if (!iocs.length) {
            list.innerHTML = '<span class="muted small">No IOC artifacts logged.</span>';
            return;
        }
        list.innerHTML = iocs.map(i => `
            <div class="ioc-card">
                <b>${i.type}:</b> <code>${i.value}</code>
                <span class="muted small">${i.incident_id}</span>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = `<span class="text-red">${e.message}</span>`;
    }
}

// =========================================================
// 10. SECURITY LAB TOOLS
// =========================================================
async function analyzeUrl() {
    const url = document.getElementById('urlInput').value.trim();
    const out = document.getElementById('urlOut');
    if (!url) return alert('Enter a URL.');
    try {
        const res = await post('/api/url/analyze', { url });
        out.innerHTML = `
            <div class="result-card" style="margin-top:10px;">
                <div class="panel-header">
                    <h4>URL RISK SCORE</h4>
                    <span class="badge ${riskClass(res.risk)}">${res.risk} (${res.score}/100)</span>
                </div>
                <p><b>Domain Host:</b> ${res.domain} &nbsp;|&nbsp; <b>Scheme:</b> ${res.scheme}</p>
                <h5>Structural Anomalies Detected</h5>
                <ul>
                    ${res.indicators.map(i => `<li>${i}</li>`).join('')}
                </ul>
                <p class="legal-alert" style="margin-top:10px;">${res.recommendation}</p>
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Error: ${e.message}</span>`;
    }
}

async function analyzeFile() {
    const fileInput = document.getElementById('labFile');
    const out = document.getElementById('fileOut');
    if (!fileInput.files.length) return alert('Choose a file.');
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    out.innerHTML = 'Computing Shannon entropy & static signatures...';
    try {
        const res = await fetch('/api/file/analyze', { method: 'POST', body: formData });
        const d = await res.json();
        out.innerHTML = `
            <div class="result-card" style="margin-top:10px;">
                <div class="panel-header">
                    <h4>${d.filename}</h4>
                    <span class="badge ${riskClass(d.risk)}">${d.risk}</span>
                </div>
                <p><b>Size:</b> ${d.size} Bytes • <b>Entropy:</b> ${d.entropy} / 8.0</p>
                <p><b>SHA-256:</b> <span class="code">${d.sha256}</span></p>
                <h5>Triage Findings</h5>
                <ul>
                    ${d.indicators.map(i => `<li>${i}</li>`).join('')}
                </ul>
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Error: ${e.message}</span>`;
    }
}

async function analyzePassword() {
    const password = document.getElementById('passwordInput').value;
    const out = document.getElementById('passwordOut');
    try {
        const res = await post('/api/password/analyze', { password });
        out.innerHTML = `
            <div class="result-card" style="margin-top:10px;">
                <div class="panel-header">
                    <h4>PASSWORD STRENGTH</h4>
                    <span class="badge ${res.score >= 65 ? 'green' : 'red'}">${res.strength} (${res.score}/100)</span>
                </div>
                <p><b>Entropy:</b> ${res.entropy_bits} Bits • <b>Character Classes:</b> ${res.classes}/4</p>
                <ul>
                    ${res.warnings.map(w => `<li>${w}</li>`).join('')}
                </ul>
            </div>
        `;
    } catch (e) {
        out.innerHTML = `<span class="text-red">Error: ${e.message}</span>`;
    }
}

// =========================================================
// 11. ATTACK SCENARIO SIMULATOR
// =========================================================
async function runSimulation(scenario) {
    const out = document.getElementById('simulationOut');
    out.classList.remove('hidden');
    out.innerHTML = 'Running live sandbox scenario simulation…';
    
    try {
        const d = await post('/api/simulator', { scenario });
        window.currentIncident = d;
        out.innerHTML = `
            <div class="panel-header" style="margin-bottom:12px;">
                <h4>SIMULATION TELEMETRY: ${scenario.toUpperCase()}</h4>
                <span class="badge blue">CONTROLLED LAB EXECUTION</span>
            </div>
            <div class="sim-input-box">
                <b>Injected Payload Telemetry:</b>
                <p class="code">${d.input}</p>
            </div>
        `;
        const wrap = document.createElement('div');
        renderAnalysisCard(d, wrap);
        out.appendChild(wrap);
    } catch (e) {
        out.innerHTML = `<span class="text-red">Simulation failed: ${e.message}</span>`;
    }
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    loadDashboard();
});
