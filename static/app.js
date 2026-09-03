
// =========================================================
// LEXGUARD THEME SWITCHER
// =========================================================
function applyTheme(theme){
    const light = theme === 'light';
    document.body.classList.toggle('light-theme', light);
    localStorage.setItem('lexguard-theme', light ? 'light' : 'dark');
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    const btn = document.getElementById('themeToggle');
    if(icon) icon.textContent = light ? '☾' : '☀';
    if(label) label.textContent = light ? 'DARK MODE' : 'LIGHT MODE';
    if(btn) btn.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
}
function toggleTheme(){
    applyTheme(document.body.classList.contains('light-theme') ? 'dark' : 'light');
}
(function initTheme(){
    const saved = localStorage.getItem('lexguard-theme') || 'dark';
    applyTheme(saved);
})();

const pages={dashboard:'Security Dashboard',analyze:'Analyze Incident',evidence:'Evidence Vault',investigate:'Investigation Center',lab:'Security Lab',crypto:'Crypto Vault',tools:'Security Tools',response:'Response Center',simulator:'Demo Simulator'};
function showPage(id){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active-page'));document.getElementById(id).classList.add('active-page');document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n.dataset.page===id));document.getElementById('pageTitle').textContent=pages[id];if(id==='evidence')loadEvidence();if(id==='investigate'){loadCases();loadIocs();}if(id==='dashboard')loadDashboard();window.scrollTo({top:0,behavior:'smooth'})}
document.querySelectorAll('.nav').forEach(n=>n.onclick=()=>showPage(n.dataset.page));
async function post(url,body,options={}){const r=await fetch(url,{method:'POST',headers:options.headers||{'Content-Type':'application/json'},body:options.raw?body:JSON.stringify(body)});if(options.download)return r;if(!r.ok){const e=await r.json().catch(()=>({error:'Request failed'}));throw new Error(e.error||'Request failed')}return r.json()}
function riskClass(r){return 'risk-'+(r||'').toLowerCase()}
async function analyze() {
    const text = document.getElementById('incidentText').value.trim();

    if (!text) {
        return alert('Paste a message or describe the incident first.');
    }

    const box = document.getElementById('analysisResult');

    box.classList.remove('hidden');

    box.innerHTML = '<div class="panel">Running full analysis…</div>';

    try {
        const d = await post('/api/analyze', { text });

        // Save the latest analysis globally.
        // The PDF button will use this instead of passing
        // the entire JSON object through HTML.
        window.currentIncident = d;

        const t = d.threat;

        box.innerHTML = `
            <div class="result-wrap">

                <div class="result-grid">

                    <!-- INCIDENT ASSESSMENT -->
                    <div class="result-card">

                        <h4>INCIDENT ASSESSMENT</h4>

                        <div class="big-risk ${riskClass(d.risk)}">
                            ${d.risk.toUpperCase()}
                        </div>

                        <div class="muted">
                            Overall risk • ${d.score}/100
                        </div>

                        <div class="bar">
                            <i style="width:${d.score}%"></i>
                        </div>

                        <p>
                            <b>Threat:</b>
                            ${t.classification}
                        </p>

                        <p>
                            <b>Offence:</b>
                            ${d.offence}
                        </p>

                        <p>
                            <b>Incident ID:</b>
                            ${d.incident_id}
                        </p>

                        <h4>WHY WAS THIS FLAGGED?</h4>

                        <ul>
                            ${t.why.map(x => `<li>${x}</li>`).join('')}
                        </ul>

                        <h4 style="margin-top:15px">
                            TRIGGERED INDICATORS
                        </h4>

                        <div>
                            ${
                                (
                                    t.triggers.length
                                        ? t.triggers
                                        : ['None configured']
                                )
                                .map(x => `<span class="tag">${x}</span>`)
                                .join('')
                            }
                        </div>

                        <h4 style="margin-top:15px">SEVERITY & PRIORITY</h4>
                        <p><b>${d.severity}</b> • <b>${d.priority}</b></p>
                        <p class="muted">${d.severity_reason||''}</p>

                        <h4 style="margin-top:15px">INDICATORS OF COMPROMISE</h4>
                        <div>${(d.iocs||[]).map(x=>`<span class="tag">${x.type}: ${x.value}</span>`).join('')||'<span class="muted">None extracted</span>'}</div>

                        <h4 style="margin-top:15px">MITRE ATT&CK</h4>
                        ${(d.mitre||[]).map(x=>`<p><b>${x.id} — ${x.name}</b><br><span class="muted">${x.why}</span></p>`).join('')||'<span class="muted">No configured mapping</span>'}

                    </div>


                    <!-- RESPONSE + REPORT -->
                    <div class="result-card">

                        <h4>⚡ IMMEDIATE RESPONSE</h4>

                        <ul>
                            ${d.response.map(x => `<li>${x}</li>`).join('')}
                        </ul>


                        ${
                            d.legal
                                ? `
                                    <h4 style="margin-top:18px">
                                        ⚖ LEGAL GUIDANCE
                                    </h4>

                                    <p>
                                        <b>${d.legal.section}</b>
                                    </p>

                                    <p class="muted">
                                        ${d.legal.description}
                                    </p>

                                    <p class="muted">
                                        ${d.legal.reporting}
                                    </p>
                                `
                                : ''
                        }


                        <!-- REPORT CENTER -->

                        <div class="report-center">

                            <div class="report-top">

                                <div>
                                    <div class="report-label">
                                        INCIDENT REPORT
                                    </div>

                                    <div class="report-title">
                                        Generate Security Report
                                    </div>

                                    <div class="report-description">
                                        Create a detailed PDF containing
                                        the incident analysis, risk
                                        assessment, detected indicators,
                                        response guidance and legal
                                        information.
                                    </div>
                                </div>

                                <div class="report-document-icon">
                                    📄
                                </div>

                            </div>


                            <button
                                id="generateReportBtn"
                                class="report-download-btn"
                                onclick="downloadReport()"
                            >
                                <span id="reportBtnIcon">↓</span>

                                <span id="reportBtnText">
                                    DOWNLOAD INCIDENT REPORT
                                </span>
                            </button>


                            <div
                                id="reportStatus"
                                class="report-status hidden"
                            >

                                <div
                                    id="reportStatusIcon"
                                    class="report-status-icon"
                                >
                                    ✓
                                </div>

                                <div class="report-status-content">

                                    <strong id="reportStatusTitle">
                                        Download complete
                                    </strong>

                                    <span id="reportStatusMessage">
                                        Your incident report is ready.
                                    </span>

                                    <span
                                        id="reportFileName"
                                        class="report-file-name"
                                    ></span>

                                </div>

                            </div>

                        </div>

                    </div>

                </div>

            </div>
        `;

    } catch (e) {

        box.innerHTML = `
            <div class="panel">
                ${e.message}
            </div>
        `;
    }
}
async function downloadReport() {

    const button = document.getElementById('generateReportBtn');
    const buttonIcon = document.getElementById('reportBtnIcon');
    const buttonText = document.getElementById('reportBtnText');

    const status = document.getElementById('reportStatus');
    const statusIcon = document.getElementById('reportStatusIcon');
    const statusTitle = document.getElementById('reportStatusTitle');
    const statusMessage = document.getElementById('reportStatusMessage');
    const fileName = document.getElementById('reportFileName');


    // Make sure an incident has been analyzed
    if (!window.currentIncident) {
        alert('Please analyze an incident first.');
        return;
    }


    try {

        // ==========================================
        // GENERATING STATE
        // ==========================================

        button.disabled = true;

        buttonIcon.textContent = '⟳';

        buttonText.textContent =
            'GENERATING REPORT...';

        status.classList.remove('hidden');

        statusIcon.textContent = '⟳';

        statusTitle.textContent =
            'Generating incident report...';

        statusMessage.textContent =
            'LexGuard is preparing your security report.';

        fileName.textContent = '';


        // ==========================================
        // SEND DATA TO FLASK
        // ==========================================

        const response = await fetch('/api/report', {

            method: 'POST',

            headers: {
                'Content-Type': 'application/json'
            },

            body: JSON.stringify(
                window.currentIncident
            )
        });


        // ==========================================
        // HANDLE SERVER ERROR
        // ==========================================

        if (!response.ok) {

            let message =
                'Unable to generate the report.';

            try {

                const errorData =
                    await response.json();

                if (errorData.error) {
                    message = errorData.error;
                }

            } catch (e) {
                // Server didn't return JSON
            }

            throw new Error(message);
        }


        // ==========================================
        // RECEIVE PDF
        // ==========================================

        const blob =
            await response.blob();


        // ==========================================
        // GET FILE NAME
        // ==========================================

        let filename =
            'LexGuard_Incident_Report.pdf';

        const disposition =
            response.headers.get(
                'Content-Disposition'
            );

        if (disposition) {

            const match =
                disposition.match(
                    /filename="?([^"]+)"?/
                );

            if (match && match[1]) {
                filename = match[1];
            }
        }


        // ==========================================
        // DOWNLOAD PDF
        // ==========================================

        const url =
            window.URL.createObjectURL(blob);

        const link =
            document.createElement('a');

        link.href = url;

        link.download = filename;

        document.body.appendChild(link);

        link.click();

        link.remove();

        window.URL.revokeObjectURL(url);


        // ==========================================
        // DOWNLOAD COMPLETE
        // ==========================================

        button.disabled = false;

        buttonIcon.textContent = '✓';

        buttonText.textContent =
            'REPORT DOWNLOADED';


        statusIcon.textContent = '✓';

        statusTitle.textContent =
            'Download complete';

        statusMessage.textContent =
            'Your LexGuard incident report has been downloaded.';

        fileName.textContent =
            filename;


        // Return button to normal after 4 seconds

        setTimeout(() => {

            buttonIcon.textContent = '↓';

            buttonText.textContent =
                'DOWNLOAD INCIDENT REPORT';

        }, 4000);


    } catch (error) {

        console.error(
            'Report generation failed:',
            error
        );


        // ==========================================
        // ERROR STATE
        // ==========================================

        button.disabled = false;

        buttonIcon.textContent = '!';

        buttonText.textContent =
            'REPORT GENERATION FAILED';


        status.classList.remove('hidden');

        statusIcon.textContent = '!';

        statusTitle.textContent =
            'Unable to generate report';

        statusMessage.textContent =
            error.message ||
            'An unexpected error occurred.';

        fileName.textContent = '';


        setTimeout(() => {

            buttonIcon.textContent = '↓';

            buttonText.textContent =
                'DOWNLOAD INCIDENT REPORT';

        }, 4000);
    }
}
async function wifi(type){try{const d=await post('/api/wifi',{type});document.getElementById('wifiOut').innerHTML=`<b class="${riskClass(d.risk)}">${d.risk.toUpperCase()}</b> • ${d.score}/100<br><span>${d.explanation}</span>`}catch(e){alert(e.message)}}
async function permissionsCheck(){try{const d=await post('/api/permissions',{permissions:document.getElementById('permissions').value});document.getElementById('permOut').innerHTML=`<b class="${riskClass(d.risk)}">${d.risk.toUpperCase()}</b> • ${d.score}/100<br><span>Sensitive: ${d.sensitive.join(', ')||'None'}</span><br><span>${d.explanation}</span>`}catch(e){alert(e.message)}}
async function cryptoAction(action){const text=document.getElementById('cryptoText').value;try{const d=await post('/api/crypto',{action,text});document.getElementById('cryptoOut').textContent=`Result:\n${d.result}\n\nSHA-256: ${d.hash}`;if(action==='encrypt')document.getElementById('cryptoText').value=d.result}catch(e){document.getElementById('cryptoOut').textContent=e.message}}
async function saveVault(){try{const d=await post('/api/locker/save',{name:document.getElementById('vaultName').value,note:document.getElementById('vaultNote').value});document.getElementById('vaultOut').textContent=`${d.message}\nFile: ${d.file}\nSHA-256: ${d.hash}`}catch(e){document.getElementById('vaultOut').textContent=e.message}}
async function getVault(){try{const d=await post('/api/locker/get',{name:document.getElementById('vaultName').value});document.getElementById('vaultOut').textContent=`Decrypted note:\n${d.note}\n\nVault SHA-256: ${d.hash}`}catch(e){document.getElementById('vaultOut').textContent=e.message}}
async function uploadEvidence(){const f=document.getElementById('evidenceFile').files[0];if(!f)return alert('Choose an evidence file.');const fd=new FormData();fd.append('file',f);fd.append('note',document.getElementById('evidenceNote').value);fd.append('incident_id',document.getElementById('evidenceIncident').value.trim());try{const r=await fetch('/api/evidence',{method:'POST',body:fd});const d=await r.json();if(!r.ok)throw new Error(d.error);document.getElementById('evidenceMsg').innerHTML=`<div class="output"><b>✓ Evidence secured</b><br>Evidence ID: ${d.evidence_id}<br>Incident ID: ${d.incident_id}<br>SHA-256: ${d.sha256}<br>Status: ${d.status}</div>`;document.getElementById('evidenceIncident').value=d.incident_id;loadEvidence();loadCases()}catch(e){document.getElementById('evidenceMsg').textContent=e.message}}
async function loadEvidence(){const r=await fetch('/api/evidence/list');const d=await r.json();document.getElementById('evidenceList').innerHTML=d.length?d.map(x=>`<div class="evidence-item"><b>${x.filename}</b><small>${x.evidence_id||'Legacy'} • ${x.incident_id} • ${x.size} bytes</small><small>SHA-256: ${x.original_hash||x.sha256}</small><span class="status-badge ${x.status==='INTEGRITY FAILED'?'danger':'ok'}">${x.status||'RECORDED'}</span><div class="row"><button class="verify" onclick="verifyEvidence('${x.incident_id}','${x.evidence_id||''}')">VERIFY INTEGRITY</button><button class="secondary" onclick="showCustody('${x.incident_id}')">CHAIN OF CUSTODY</button></div></div>`).join(''):'<span class="muted">No evidence stored yet.</span>'}
async function verifyEvidence(id,eid){try{const d=await post('/api/evidence/verify',{incident_id:id,evidence_id:eid});document.getElementById('evidenceMsg').innerHTML=`<div class="output ${d.match?'':'danger-box'}"><b>${d.match?'✓ VERIFIED — FILE UNMODIFIED':'⚠ INTEGRITY FAILED — FILE MODIFIED'}</b><br>Original: ${d.original}<br>Current: ${d.current}</div>`;loadEvidence();showCustody(id)}catch(e){alert(e.message)}}
async function showCustody(id){const p=document.getElementById('custodyPanel');const d=await fetch('/api/evidence/'+encodeURIComponent(id)+'/custody').then(r=>r.json());p.classList.remove('hidden');p.innerHTML=`<h4>CHAIN OF CUSTODY • ${id}</h4>${d.length?d.map(x=>`<div class="timeline-row"><span>${x.timestamp}</span><b>${x.action}</b><small>${x.evidence_id||''} — ${x.description}</small></div>`).join(''):'<span class="muted">No custody events.</span>'}`}
const scenarios={
'Phishing':['Do not click the suspicious link or attachment.','If credentials were entered, change the password from the official website.','Enable multi-factor authentication.','Preserve the message and screenshots.','Report through the appropriate official channel.'],
'Hacking/Unauthorized Access':['Secure the affected account from a trusted device.','Change the password and enable MFA.','Review active sessions and revoke unknown access.','Preserve login alerts and screenshots.','Report the incident through the appropriate official channel.'],
'Online Fraud':['Contact your bank/payment provider immediately if money is involved.','Preserve transaction IDs and screenshots.','Do not send more money or OTPs.','Secure affected payment accounts.','Report through the appropriate official channel.'],
'Malware-link':['Do not execute the file.','Isolate the device from networks if safe.','Run trusted security scans and update software.','Preserve the suspicious file/URL.','Change credentials if compromise is suspected.'],
'Identity Theft':['Secure affected accounts and identity documents.','Change exposed passwords and enable MFA.','Preserve fake profiles and messages.','Contact affected providers where appropriate.','Report through the appropriate official channel.'],
'Cyberstalking':['Avoid escalating contact.','Block/report the account where appropriate.','Preserve messages, timestamps and URLs.','Tell a trusted person if the situation feels unsafe.','Report through appropriate authorities.'],
'Data Theft':['Restrict further access to affected systems.','Preserve logs and alerts.','Change exposed credentials.','Notify the relevant organisation/admin where applicable.','Report through the appropriate official channel.'],
'Unclear':['Preserve the original evidence.','Avoid links and credential sharing.','Secure important accounts with MFA.','Record screenshots, timestamps and transaction details.','Seek official assistance if serious.']};
function scenario(type){const out=document.getElementById('scenarioOut');out.classList.remove('hidden');out.innerHTML=`<h4>Recommended first response</h4><p class="muted">Scenario: ${type}</p><ol>${scenarios[type].map(x=>`<li>${x}</li>`).join('')}</ol><button class="primary" onclick="showPage('analyze')">RUN FULL ANALYSIS →</button>`}

async function loadDashboard(){try{const d=await fetch('/api/dashboard').then(r=>r.json());['dashIncidents','dashCritical','dashEvidence','dashIocs'].forEach((id,i)=>document.getElementById(id).textContent=[d.total_incidents,d.critical_high,d.evidence_count,d.ioc_count][i]);const renderDist=(obj)=>Object.entries(obj||{}).map(([k,v])=>`<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)"><span>${k}</span><b>${v}</b></div>`).join('')||'<span class="muted">No case data yet.</span>';document.getElementById('threatDistribution').innerHTML=renderDist(d.threat_distribution);document.getElementById('offenceDistribution').innerHTML=renderDist(d.offence_distribution);}catch(e){}}
async function loadCases(){const q=document.getElementById('caseSearch')?.value||'';const d=await fetch('/api/cases?q='+encodeURIComponent(q)).then(r=>r.json());const box=document.getElementById('caseList');if(!box)return;box.innerHTML=d.length?d.map(c=>`<div class="case-row"><div><b>${c.incident_id}</b><small>${c.timestamp||''} • ${(c.threat||{}).classification||'Unknown'} • ${c.offence||'Unclear'}</small></div><div><span class="status-badge">${c.severity||c.risk||'UNKNOWN'}</span><span class="status-badge">${c.priority||'P4'}</span><button class="secondary" onclick="openCase('${c.incident_id}')">OPEN CASE</button></div></div>`).join(''):'<span class="muted">No incidents found.</span>'}
async function openCase(id){const c=await fetch('/api/cases/'+encodeURIComponent(id)).then(r=>r.json());const box=document.getElementById('caseDetail');if(c.error){box.textContent=c.error;return}box.innerHTML=`<div class="case-hero"><b>${c.incident_id}</b><span>${c.severity} • ${c.priority}</span></div><p><b>Threat:</b> ${(c.threat||{}).classification} &nbsp; <b>Offence:</b> ${c.offence}</p><p><b>Risk:</b> ${c.score}/100 &nbsp; <b>Evidence:</b> ${(c.evidence||[]).length} &nbsp; <b>IOCs:</b> ${(c.iocs||[]).length}</p><p><b>MITRE:</b> ${(c.mitre||[]).map(x=>x.id+' '+x.name).join(', ')||'None'}</p><p><b>Response:</b> ${c.response_progress||0}% &nbsp; <b>Status:</b> ${c.status||'ACTIVE'}</p><div class="row"><select onchange="updateCaseStatus('${c.incident_id}',this.value)"><option ${c.status==='ACTIVE'||!c.status?'selected':''}>ACTIVE</option><option ${c.status==='INVESTIGATING'?'selected':''}>INVESTIGATING</option><option ${c.status==='CONTAINED'?'selected':''}>CONTAINED</option><option ${c.status==='RESOLVED'?'selected':''}>RESOLVED</option><option ${c.status==='CLOSED'?'selected':''}>CLOSED</option></select><button class="primary" onclick="exportCase('${c.incident_id}')">EXPORT COMPLETE CASE</button><button class="secondary" onclick="showAudit('${c.incident_id}')">VERIFY AUDIT CHAIN</button></div><h4>Response Playbook</h4>${(c.playbook?.steps||[]).map(s=>`<label class="check-step"><input type="checkbox" ${s.done?'checked':''} onchange="toggleStep('${c.incident_id}',${s.id},this.checked)"><span>${s.text}</span></label>`).join('')}<h4>Timeline</h4>${(c.timeline||[]).slice().reverse().map(x=>`<div class="timeline-row"><span>${x.timestamp}</span><b>${x.action}</b><small>${x.description}</small></div>`).join('')}`}
async function toggleStep(id,step,done){await post('/api/cases/'+encodeURIComponent(id)+'/playbook',{step_id:step,done});openCase(id)}
async function showAudit(id){const c=await fetch('/api/cases/'+encodeURIComponent(id)).then(r=>r.json());alert(c.audit_verification?.valid?'✓ AUDIT CHAIN VERIFIED\nAll recorded events are cryptographically linked.':'⚠ AUDIT CHAIN BROKEN\nAn event failed hash-chain verification.')}
async function loadIocs(){const q=document.getElementById('iocSearch')?.value||'',type=document.getElementById('iocType')?.value||'';const d=await fetch('/api/iocs?q='+encodeURIComponent(q)+'&type='+encodeURIComponent(type)).then(r=>r.json());const box=document.getElementById('iocList');if(!box)return;box.innerHTML=d.length?d.map(x=>`<div class="evidence-item"><b>${x.type}</b><small>${x.value}</small><small>${x.incident_id}</small></div>`).join(''):'<span class="muted">No IOCs extracted yet.</span>'}
async function analyzeUrl(){const url=document.getElementById('urlInput').value.trim();try{const d=await post('/api/url/analyze',{url});document.getElementById('urlOut').innerHTML=`<b class="risk-${d.risk.toLowerCase()}">${d.risk}</b> • ${d.score}/100<br><small>Domain: ${d.domain} • Protocol: ${d.scheme}</small><ul>${d.indicators.map(x=>`<li>${x}</li>`).join('')}</ul><b>Recommendation:</b> ${d.recommendation}`}catch(e){document.getElementById('urlOut').textContent=e.message}}
async function analyzeFile(){const f=document.getElementById('labFile').files[0];if(!f)return alert('Choose a file.');const fd=new FormData();fd.append('file',f);try{const r=await fetch('/api/file/analyze',{method:'POST',body:fd});const d=await r.json();if(!r.ok)throw new Error(d.error);document.getElementById('fileOut').innerHTML=`<b class="risk-${d.risk.toLowerCase()}">${d.risk}</b><br>SHA-256: ${d.sha256}<br>Entropy: ${d.entropy}<ul>${d.indicators.map(x=>`<li>${x}</li>`).join('')}</ul><b>${d.recommendation}</b>`}catch(e){document.getElementById('fileOut').textContent=e.message}}
async function analyzePassword(){const p=document.getElementById('passwordInput').value;try{const d=await post('/api/password/analyze',{password:p});document.getElementById('passwordOut').innerHTML=`<b class="risk-${d.strength==='VERY STRONG'||d.strength==='STRONG'?'low':d.strength==='MEDIUM'?'medium':'high'}">${d.strength}</b> • ${d.score}/100<br>Length: ${d.length} • Entropy: ${d.entropy_bits} bits<br>${d.warnings.map(x=>`<div>⚠ ${x}</div>`).join('')||'No immediate warnings.'}`;document.getElementById('passwordInput').value=''}catch(e){document.getElementById('passwordOut').textContent=e.message}}
async function runSimulation(scenario){const out=document.getElementById('simulationOut');out.classList.remove('hidden');out.innerHTML='Running controlled simulation…';try{const d=await post('/api/simulator',{scenario});window.currentIncident=d;out.innerHTML=`<h4>SIMULATION: ${d.scenario}</h4><div class="result-grid"><div><b>Risk</b><div class="big-risk ${riskClass(d.risk)}">${d.risk} • ${d.score}/100</div><p>Threat: ${d.threat.classification}</p><p>Offence: ${d.offence}</p><p>Incident: ${d.incident_id}</p></div><div><b>IOCS</b><p>${d.iocs.map(x=>`${x.type}: ${x.value}`).join('<br>')||'None'}</p><b>MITRE</b><p>${d.mitre.map(x=>`${x.id} — ${x.name}`).join('<br>')||'None'}</p><button class="primary" onclick="showPage('investigate');loadCases()">OPEN INVESTIGATION CENTER</button></div></div>`}catch(e){out.textContent=e.message}}

async function updateCaseStatus(id,status){await post('/api/cases/'+encodeURIComponent(id)+'/status',{status});openCase(id);loadDashboard()}
async function exportCase(id){const r=await fetch('/api/cases/'+encodeURIComponent(id)+'/export');if(!r.ok){const e=await r.json().catch(()=>({error:'Export failed'}));return alert(e.error)}const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='LexGuard_Case_'+id+'.zip';a.click();URL.revokeObjectURL(a.href)}
