// =========================================================
// LEXGUARD CYBER DEFENSE PLATFORM — MAIN JS CONTROLLER
// (CM51205 Syllabus Aligned)
// =========================================================

function applyTheme(theme) {
    const light = theme === 'light';
    document.body.classList.toggle('light-theme', light);
    localStorage.setItem('lexguard-theme', light ? 'light' : 'dark');
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (icon) icon.textContent = light ? '☾' : '☀';
    if (label) label.textContent = light ? 'DARK MODE' : 'LIGHT MODE';
}

function toggleTheme() {
    applyTheme(document.body.classList.contains('light-theme') ? 'dark' : 'light');
}

(function initTheme() {
    const saved = localStorage.getItem('lexguard-theme') || 'dark';
    applyTheme(saved);
})();

const pages = {
    dashboard: 'SOC Security Dashboard',
    analyze: 'Threat & Attack Vector Analyzer',
    crypto: 'Cryptography & Ciphers Suite',
    access: 'Authentication & Access Control Lab',
    evidence: 'Digital Evidence Vault & Custody',
    legal: 'Cyber Law & Legal Enforcement Center',
    wireless: 'Wireless & Mobile Threat Radar',
    response: 'Incident Response Center',
    investigate: 'Case Investigation & Archive',
    simulator: 'Attack Scenario Simulator'
};

function showPage(id) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active-page'));
    const target = document.getElementById(id);
    if (target) target.classList.add('active-page');
    
    document.querySelectorAll('.nav').forEach(n => n.classList.toggle('active', n.dataset.page === id));
    document.getElementById('pageTitle').textContent = pages[id] || 'Security Console';
    
    if (id === 'evidence') loadEvidence();
    if (id === 'investigate') loadCases();
    if (id === 'dashboard') loadDashboard();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.querySelectorAll('.nav').forEach(n => {
    n.onclick = () => showPage(n.dataset.page);
});

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

function copyToClipboard(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.innerText || el.value;
    navigator.clipboard.writeText(text).then(() => alert('Copied to clipboard!')).catch(() => alert('Failed to copy.'));
}

// 1. Dashboard
async function loadDashboard() {
    try {
        const res = await fetch('/api/dashboard');
        const d = await res.json();
        document.getElementById('dashIncidents').textContent = d.total_incidents;
        document.getElementById('dashCritical').textContent = d.critical_high;
        document.getElementById('dashEvidence').textContent = d.evidence_count;
    } catch (e) {
        console.error('Dashboard load error:', e);
    }
}

// 2. Threat Analysis
async function analyze() {
    const text = document.getElementById('incidentText').value.trim();
    if (!text) return alert('Enter incident description or message.');
    const box = document.getElementById('analysisResult');
    box.classList.remove('hidden');
    box.innerHTML = '<div class="panel">Running heuristic threat triage &amp; statutory legal mapping...</div>';
    try {
        const d = await post('/api/analyze', { text });
        window.currentIncident = d;
        box.innerHTML = `
            <div class="result-wrap">
                <div class="result-grid">
                    <div class="result-card">
                        <div class="panel-header">
                            <h4>THREAT ASSESSMENT</h4>
                            <span class="badge ${d.risk === 'Critical' || d.risk === 'High' ? 'red' : 'green'}">${d.risk.toUpperCase()} RISK (${d.score}/100)</span>
                        </div>
                        <p><b>Incident ID:</b> <span class="code">${d.incident_id}</span></p>
                        <p><b>Threat Category:</b> <b>${d.threat.classification}</b></p>
                        <p><b>Offence Classification:</b> <b>${d.offence}</b></p>
                        <h5 style="margin-top:12px;">Heuristic Explanation</h5>
                        <ul>${d.threat.why.map(w => `<li>${w}</li>`).join('')}</ul>
                        <h5 style="margin-top:12px;">Triggered Keywords</h5>
                        <div>${d.threat.triggers.map(t => `<span class="tag">${t}</span>`).join('') || '<span class="muted">None</span>'}</div>
                    </div>
                    <div class="result-card">
                        <div class="panel-header">
                            <h4>⚖ STATUTORY IT ACT PROVISIONS</h4>
                            <span class="badge blue">Legal Mapping</span>
                        </div>
                        ${d.legal ? `
                            <p><b>IT Act Section:</b> <span class="text-accent">${d.legal.it_act}</span></p>
                            <p><b>BNS / IPC Provision:</b> ${d.legal.bns_ipc || 'N/A'}</p>
                            <p class="muted small">${d.legal.description}</p>
                            <p class="legal-alert"><b>Reporting:</b> ${d.legal.reporting}</p>
                        ` : '<p class="muted">General cyber security incident protocols apply.</p>'}
                        <h5 style="margin-top:14px;">Recommended Response Steps</h5>
                        <ul class="playbook-steps">
                            ${d.response.map((s, i) => `<li><b>${i+1}.</b> ${s.text || s}</li>`).join('')}
                        </ul>
                        <div style="margin-top:16px;">
                            <button class="primary" onclick="downloadPdf()">📄 DOWNLOAD INCIDENT PDF REPORT</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    } catch (e) {
        box.innerHTML = `<div class="panel text-red">Error: ${e.message}</div>`;
    }
}

async function downloadPdf() {
    if (!window.currentIncident) return;
    try {
        const res = await post('/api/report', window.currentIncident, { download: true });
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Report_${window.currentIncident.incident_id}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (e) {
        alert('PDF error: ' + e.message);
    }
}

// 3. Cryptography Tools
function switchCryptoTab(tabId) {
    document.querySelectorAll('.crypto-subtab').forEach(t => t.classList.add('hidden'));
    const target = document.getElementById(tabId);
    if (target) target.classList.remove('hidden');
    document.querySelectorAll('#crypto .tab-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
}

// Caesar
async function runCaesar(mode) {
    const text = document.getElementById('caesarText').value;
    const shift = parseInt(document.getElementById('caesarShift').value) || 3;
    const out = document.getElementById('caesarOut');
    try {
        const res = await post('/api/crypto/caesar', { text, shift, mode });
        out.innerHTML = `
            <p><b>Mode:</b> ${mode.toUpperCase()} (Shift Key: ${res.shift})</p>
            <p><b>Result:</b></p>
            <textarea class="code-box" readonly>${res.result}</textarea>
            <p><b>SHA-256 Digest:</b> <span class="code">${res.hash}</span></p>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

async function runCaesarBruteforce() {
    const text = document.getElementById('caesarText').value;
    const out = document.getElementById('caesarOut');
    try {
        const res = await post('/api/crypto/caesar/bruteforce', { text });
        out.innerHTML = `
            <h5>Brute-Force Cryptanalysis (All 25 Possible Shifts):</h5>
            <div style="max-height:220px; overflow-y:auto;">
                ${res.results.map(r => `<p style="margin:4px 0;"><b>Shift ${r.shift}:</b> <span class="code">${r.plaintext}</span></p>`).join('')}
            </div>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// Monoalphabetic
async function runMono(mode) {
    const text = document.getElementById('monoText').value;
    const key = document.getElementById('monoKey').value.trim();
    const out = document.getElementById('monoOut');
    try {
        const res = await post('/api/crypto/monoalphabetic', { text, key, mode });
        out.innerHTML = `
            <p><b>Mode:</b> ${mode.toUpperCase()}</p>
            <p><b>Result:</b></p>
            <textarea class="code-box" readonly>${res.result}</textarea>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// Vigenere
async function runVigenere(mode) {
    const text = document.getElementById('vigText').value;
    const key = document.getElementById('vigKey').value.trim();
    const out = document.getElementById('vigOut');
    try {
        const res = await post('/api/crypto/vigenere', { text, key, mode });
        out.innerHTML = `
            <p><b>Mode:</b> ${mode.toUpperCase()} (Key: ${res.key})</p>
            <p><b>Result:</b></p>
            <textarea class="code-box" readonly>${res.result}</textarea>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// Rail Fence
async function runRail(mode) {
    const text = document.getElementById('railText').value;
    const rails = parseInt(document.getElementById('railCount').value) || 3;
    const out = document.getElementById('railOut');
    try {
        const res = await post('/api/crypto/railfence', { text, rails, mode });
        out.innerHTML = `
            <p><b>Transposition Mode:</b> ${mode.toUpperCase()} (Depth: ${res.rails} Rails)</p>
            <p><b>Result:</b></p>
            <textarea class="code-box" readonly>${res.result}</textarea>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// Columnar
async function runColumnar(mode) {
    const text = document.getElementById('colText').value;
    const key = document.getElementById('colKey').value.trim();
    const out = document.getElementById('colOut');
    try {
        const res = await post('/api/crypto/columnar', { text, key, mode });
        out.innerHTML = `
            <p><b>Columnar Transposition:</b> ${mode.toUpperCase()} (Keyword: ${res.key})</p>
            <p><b>Result:</b></p>
            <textarea class="code-box" readonly>${res.result}</textarea>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// Vernam
async function runVernam() {
    const text = document.getElementById('vernamText').value;
    const key = document.getElementById('vernamKey').value;
    const out = document.getElementById('vernamOut');
    try {
        const res = await post('/api/crypto/vernam', { text, key });
        out.innerHTML = `
            <p><b>Vernam XOR Hex:</b> <span class="code">${res.raw_xor_hex}</span></p>
            <p><b>Printable Representation:</b></p>
            <textarea class="code-box" readonly>${res.ascii_printable}</textarea>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// DES vs AES
async function loadDesAesComparison() {
    const out = document.getElementById('desAesOut');
    try {
        const res = await post('/api/crypto/des_aes_compare', {});
        out.innerHTML = `
            <div class="two-col">
                <div class="panel">
                    <h4>${res.DES.name}</h4>
                    <p><b>Key Length:</b> ${res.DES.key_length}</p>
                    <p><b>Block Size:</b> ${res.DES.block_size}</p>
                    <p><b>Structure:</b> ${res.DES.structure}</p>
                    <p><b>Status:</b> <span class="badge red">${res.DES.status}</span></p>
                </div>
                <div class="panel">
                    <h4>${res.AES.name}</h4>
                    <p><b>Key Length:</b> ${res.AES.key_length}</p>
                    <p><b>Block Size:</b> ${res.AES.block_size}</p>
                    <p><b>Structure:</b> ${res.AES.structure}</p>
                    <p><b>Status:</b> <span class="badge green">${res.AES.status}</span></p>
                </div>
            </div>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// RSA
async function generateRsa() {
    try {
        const res = await post('/api/crypto/rsa/generate', {});
        document.getElementById('rsaPub').value = res.public_key_pem;
        document.getElementById('rsaPriv').value = res.private_key_pem;
        document.getElementById('rsaOut').innerHTML = '<span class="badge green">RSA 2048-Bit Keypair Generated</span>';
    } catch (e) { alert(e.message); }
}

async function signRsa() {
    const message = document.getElementById('rsaMsg').value;
    const priv = document.getElementById('rsaPriv').value;
    if (!message || !priv) return alert('Enter message and generate RSA keys first.');
    try {
        const res = await post('/api/crypto/rsa/sign_verify', { action: 'sign', message, private_key_pem: priv });
        document.getElementById('rsaSig').value = res.signature_b64;
        document.getElementById('rsaOut').innerHTML = `<span class="badge green">Digital Signature Generated</span> (SHA-256: ${res.digest_sha256})`;
    } catch (e) { alert(e.message); }
}

async function verifyRsa() {
    const message = document.getElementById('rsaMsg').value;
    const pub = document.getElementById('rsaPub').value;
    const sig = document.getElementById('rsaSig').value;
    if (!message || !pub || !sig) return alert('Message, Public key, and Signature are required.');
    try {
        const res = await post('/api/crypto/rsa/sign_verify', { action: 'verify', message, public_key_pem: pub, signature_b64: sig });
        document.getElementById('rsaOut').innerHTML = res.valid ?
            '<div class="badge green">✓ Digital Signature is VALID &amp; Intact</div>' :
            '<div class="badge red">✗ Signature INVALID</div>';
    } catch (e) { alert(e.message); }
}

// Diffie-Hellman
async function runDiffieHellman() {
    const out = document.getElementById('dhOut');
    try {
        const res = await post('/api/crypto/dh', {});
        out.innerHTML = `
            <p><b>Public Parameters:</b> Prime $p = ${res.prime_p}$, Generator $g = ${res.generator_g}$</p>
            <div class="two-col" style="margin-top:10px;">
                <div class="panel">
                    <h5>Alice</h5>
                    <p>Private Key $a = ${res.alice.private_a}$</p>
                    <p>Calculated $A = g^a \\pmod p = ${res.alice.public_A}$</p>
                    <p>Shared Secret $K = ${res.computed_shared_secret}$</p>
                </div>
                <div class="panel">
                    <h5>Bob</h5>
                    <p>Private Key $b = ${res.bob.private_b}$</p>
                    <p>Calculated $B = g^b \\pmod p = ${res.bob.public_B}$</p>
                    <p>Shared Secret $K = ${res.computed_shared_secret}$</p>
                </div>
            </div>
            <p class="text-green" style="margin-top:10px;">✓ ${res.explanation}</p>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// Multi-Hash
async function runMultiHash() {
    const text = document.getElementById('hashInput').value;
    const out = document.getElementById('hashOut');
    try {
        const res = await post('/api/crypto/multihash', { text });
        out.innerHTML = `
            <div class="hash-row"><b>MD-5 (128-bit):</b> <span class="code">${res.MD5.digest}</span> <span class="badge small red">${res.MD5.status}</span></div>
            <div class="hash-row" style="margin-top:8px;"><b>SHA-1 (160-bit):</b> <span class="code">${res['SHA-1'].digest}</span> <span class="badge small amber">${res['SHA-1'].status}</span></div>
            <div class="hash-row" style="margin-top:8px;"><b>SHA-256 (256-bit):</b> <span class="code">${res['SHA-256'].digest}</span> <span class="badge small green">${res['SHA-256'].status}</span></div>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// 4. Access Controls & Biometrics (Unit 3)
async function evaluateRbac() {
    const role = document.getElementById('accessRole').value;
    const out = document.getElementById('rbacOut');
    try {
        const res = await post('/api/access/rbac_eval', { role });
        out.innerHTML = `
            <p><b>Active Role:</b> <span class="badge">${res.role}</span></p>
            <p><b>Granted Permissions:</b> ${res.granted_permissions.map(p => `<span class="tag">${p}</span>`).join('') || '<span class="muted">No permissions</span>'}</p>
            <h5 style="margin-top:14px;">Access Control Model Definitions:</h5>
            <ul>
                <li><b>DAC:</b> ${res.models['DAC (Discretionary Access Control)']}</li>
                <li><b>MAC:</b> ${res.models['MAC (Mandatory Access Control)']}</li>
                <li><b>RBAC:</b> ${res.models['RBAC (Role-Based Access Control)']}</li>
            </ul>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

async function loadBiometrics() {
    const out = document.getElementById('biometricsOut');
    try {
        const res = await post('/api/access/biometrics_eval', {});
        out.innerHTML = `
            <h5>Biometric Verification Methods:</h5>
            ${res.Biometric_Types.map(b => `
                <div class="statute-card" style="margin-top:6px; padding:10px;">
                    <b>${b.type}</b> (Accuracy: ${b.accuracy})
                    <p class="small" style="margin:2px 0;"><b>Features:</b> ${b.characteristics}</p>
                    <p class="small text-red" style="margin:2px 0;"><b>Attack Vector:</b> ${b.attack_vector}</p>
                </div>
            `).join('')}
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

async function loadPasswordAttacks() {
    const out = document.getElementById('biometricsOut');
    try {
        const res = await post('/api/access/password_attacks', {});
        out.innerHTML = `
            <h5>Password Attacks &amp; Defenses:</h5>
            <p><b>Shoulder Surfing:</b> ${res['Shoulder Surfing']}</p>
            <p><b>Dumpster Diving:</b> ${res['Dumpster Diving']}</p>
            <p><b>Piggybacking:</b> ${res['Piggybacking']}</p>
            <h5>Good Password Construction Rules:</h5>
            <ul>${res['Good Password Construction'].map(r => `<li>${r}</li>`).join('')}</ul>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

// 5. Evidence
async function uploadEvidence() {
    const file = document.getElementById('evidenceFile').files[0];
    const incident_id = document.getElementById('evidenceIncident').value.trim();
    const note = document.getElementById('evidenceNote').value.trim();
    const msg = document.getElementById('evidenceMsg');
    if (!file) return alert('Select a file.');
    const fd = new FormData();
    fd.append('file', file);
    fd.append('incident_id', incident_id);
    fd.append('note', note);
    try {
        const res = await fetch('/api/evidence', { method: 'POST', body: fd });
        const d = await res.json();
        msg.innerHTML = `<span class="text-green">✓ Evidence secured (ID: ${d.evidence_id}, SHA-256: ${d.sha256.substring(0, 16)}...)</span>`;
        loadEvidence();
    } catch (e) { msg.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

async function loadEvidence() {
    const list = document.getElementById('evidenceList');
    if (!list) return;
    try {
        const res = await fetch('/api/evidence/list');
        const items = await res.json();
        if (!items.length) { list.innerHTML = '<span class="muted">No evidence files in vault.</span>'; return; }
        list.innerHTML = items.map(i => `
            <div class="evidence-card">
                <b>${i.evidence_id}</b> (${i.filename})
                <p class="code">${i.sha256}</p>
                <button class="secondary small-btn" onclick="verifyEvidence('${i.incident_id}', '${i.evidence_id}')">VERIFY INTEGRITY</button>
            </div>
        `).join('');
    } catch (e) { list.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

async function verifyEvidence(incident_id, evidence_id) {
    try {
        const res = await post('/api/evidence/verify', { incident_id, evidence_id });
        alert(`Integrity Status: ${res.status}\nCurrent Hash: ${res.current}`);
    } catch (e) { alert(e.message); }
}

// 6. Cyber Law & FIR
async function generateFir() {
    const complainant_name = document.getElementById('firName').value;
    const complainant_contact = document.getElementById('firContact').value;
    const offence = document.getElementById('firOffence').value;
    const financial_loss = document.getElementById('firLoss').value;
    const input = document.getElementById('firFacts').value;
    const out = document.getElementById('legalDocOut');
    try {
        const res = await post('/api/report/fir', { complainant_name, complainant_contact, offence, financial_loss, input });
        out.value = res.fir_text;
    } catch (e) { out.value = 'Error: ' + e.message; }
}

async function generate65b() {
    const examiner_name = document.getElementById('firName').value;
    const out = document.getElementById('legalDocOut');
    try {
        const res = await post('/api/report/section65b', { examiner_name });
        out.value = res.certificate_text;
    } catch (e) { out.value = 'Error: ' + e.message; }
}

// 7. Wireless & Response
async function wifi(type) {
    const out = document.getElementById('wifiOut');
    try {
        const res = await post('/api/wifi', { type });
        out.innerHTML = `
            <p><b>Security Level:</b> <span class="badge ${res.risk === 'High' ? 'red' : 'green'}">${res.risk} (${res.score}/100)</span></p>
            <p class="small">${res.explanation}</p>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

function scenario(type) {
    const out = document.getElementById('scenarioOut');
    out.classList.remove('hidden');
    const steps = {
        'Phishing': ['Do not click suspicious links or enter passwords.', 'Change exposed passwords immediately.', 'Enable Multi-Factor Authentication.', 'Report to cybercrime.gov.in.'],
        'Hacking/Unauthorized Access': ['Terminate active sessions.', 'Reset master password.', 'Revoke unknown API keys.', 'Preserve authentication logs.'],
        'Online Fraud': ['Call 1930 Cyber Fraud Helpline immediately.', 'Block bank cards & net banking.', 'File complaint on cybercrime.gov.in.'],
        'Ransomware': ['Isolate device from network.', 'Do not reboot abruptly.', 'Check NoMoreRansom for decryptors.'],
        'Malware-link': ['Disconnect from internet.', 'Run antimalware scan.', 'Quarantine file in evidence vault.'],
        'Identity Theft': ['File complaint on cybercrime.gov.in.', 'Notify UIDAI / Credit Bureaus to place an identity freeze.']
    };
    out.innerHTML = `
        <div class="panel">
            <h4>CONTAINMENT PLAYBOOK — ${type.toUpperCase()}</h4>
            <ul>${(steps[type] || ['Preserve evidence.']).map(s => `<li>${s}</li>`).join('')}</ul>
        </div>
    `;
}

// 8. Cases & Simulation
async function loadCases() {
    const list = document.getElementById('caseList');
    if (!list) return;
    try {
        const res = await fetch('/api/cases');
        const cases = await res.json();
        list.innerHTML = cases.map(c => `
            <div class="case-card">
                <b>${c.incident_id}</b> — ${c.threat ? c.threat.classification : 'N/A'}
                <span class="muted small">${c.timestamp}</span>
            </div>
        `).join('') || '<span class="muted">No cases registered.</span>';
    } catch (e) { list.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

async function runSimulation(scenario) {
    const out = document.getElementById('simulationOut');
    out.classList.remove('hidden');
    out.innerHTML = 'Executing simulation scenario...';
    try {
        const d = await post('/api/simulator', { scenario });
        window.currentIncident = d;
        out.innerHTML = `
            <div class="panel-header">
                <h4>SCENARIO: ${scenario.toUpperCase()}</h4>
                <span class="badge blue">SIMULATION EXECUTION</span>
            </div>
            <p><b>Injected Payload:</b> <code>${d.input}</code></p>
            <p><b>Threat Identified:</b> <b>${d.threat.classification}</b> &nbsp;|&nbsp; <b>Risk:</b> ${d.risk} (${d.score}/100)</p>
            <p><b>Statutory Section:</b> <span class="text-accent">${d.legal ? d.legal.it_act : 'Section 43/66 IT Act'}</span></p>
        `;
    } catch (e) { out.innerHTML = `<span class="text-red">${e.message}</span>`; }
}

window.addEventListener('DOMContentLoaded', loadDashboard);
