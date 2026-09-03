from flask import Flask, render_template, request, jsonify, send_file
import os, re, json, hashlib, uuid, io, zipfile, mimetypes
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
import os
from datetime import datetime
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, 'lexguard.key')
VAULT_DIR = os.path.join(BASE_DIR, 'vault')
EVIDENCE_DIR = os.path.join(BASE_DIR, 'evidence')
REPORT_DIR = os.path.join(BASE_DIR, 'reports')
CASE_DIR = os.path.join(BASE_DIR, 'cases')
AUDIT_DIR = os.path.join(BASE_DIR, 'audit')
for d in (VAULT_DIR, EVIDENCE_DIR, REPORT_DIR, CASE_DIR, AUDIT_DIR): os.makedirs(d, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

THREAT_RULES = {
    'Phishing': ['verify your account','click here','login','urgent','password','otp','suspended','confirm your account','kyc','verify now'],
    'Ransomware': ['ransom','decrypt','encrypted files','pay bitcoin','bitcoin','files encrypted','decryption key','ransomware'],
    'Malware-link': ['download','attachment','.exe','.apk','malware','trojan','install this app','http://','https://'],
    'Social Engineering': ['send me otp','share otp','impersonating','pretend','secret','gift card','act now','do not tell anyone','urgent call'],
}
OFFENCE_RULES = {
    'Hacking/Unauthorized Access': ['hacked','unauthorized access','accessed my account','broke into','login without permission','password changed'],
    'Identity Theft': ['identity stolen','stolen identity','impersonated me','used my aadhaar','used my pan','fake account in my name','personal details used'],
    'Online Fraud': ['scammed','fraud','upi','bank transfer','otp fraud','money stolen','payment fraud','phishing payment','online scam'],
    'Cyberstalking': ['stalking','repeated messages','threatening messages','harassing me online','online harassment','following me online'],
    'Data Theft': ['stole my data','data stolen','copied files','database stolen','downloaded confidential','leaked data','stolen files'],
}
LAW_MAP = {
    'Hacking/Unauthorized Access': ('Section 43 read with Section 66','Unauthorised access, copying/extraction of data or other computer-related acts; dishonest/fraudulent computer offences may attract Section 66.'),
    'Identity Theft': ('Section 66C','Fraudulent or dishonest use of another person\'s electronic signature, password or other unique identification feature.'),
    'Online Fraud': ('Section 66D','Cheating by personation using a communication device or computer resource.'),
    'Cyberstalking': ('Fact-dependent; Section 67 may apply where obscene electronic content is involved','Section 67 concerns obscene material in electronic form; cyberstalking may also involve other applicable criminal provisions depending on the conduct.'),
    'Data Theft': ('Section 43 read with Section 66','Unauthorised downloading, copying or extraction of data can fall within Section 43; dishonest/fraudulent acts may attract Section 66.'),
}
WIFI_RISK = {
    'Open': ('High',92,'No Wi-Fi encryption is used; traffic and access are more exposed to interception and unauthorised use.'),
    'WEP': ('High',88,'WEP is obsolete and can be broken relatively easily with modern tools.'),
    'WPA': ('Medium',58,'WPA is older and weaker than WPA2/WPA3; upgrade when possible.'),
    'WPA2': ('Low',28,'Generally secure when configured with a strong password and current router settings.'),
    'WPA3': ('Low',15,'Modern Wi-Fi security with stronger protections; use a strong password and updated firmware.'),
}
SENSITIVE_PERMISSIONS = {'camera','microphone','contacts','sms','location','phone','storage','files','call_log','calendar'}

RESPONSE_STEPS = {
    'Phishing':['Do not click the suspicious link or attachment.','If credentials were entered, change the password from the official website.','Enable multi-factor authentication where available.','Preserve the message, sender details and screenshots as evidence.','Report the incident through the appropriate official cybercrime channel.'],
    'Ransomware':['Isolate the affected device from networks if safe to do so.','Do not delete or alter potentially useful evidence.','Disconnect affected shares/devices where appropriate.','Contact your organisation/admin or a qualified incident-response professional.','Preserve ransom notes, filenames, timestamps and logs.'],
    'Malware-link':['Do not open or execute the file.','If already opened, disconnect the device from networks if safe.','Run trusted security scans and update the operating system.','Preserve the suspicious URL/file as evidence.','Change credentials if compromise is suspected.'],
    'Social Engineering':['Stop communicating with the requester.','Do not share OTPs, passwords or recovery codes.','Verify requests through an independent official channel.','Preserve messages and caller/sender information.','Report the account/message if appropriate.'],
    'Hacking/Unauthorized Access':['Secure the affected account and change the password from a trusted device.','Enable MFA and review active sessions/devices.','Preserve login alerts, emails and screenshots.','Review account recovery details and revoke unknown access.','Report the incident through the appropriate official channel.'],
    'Identity Theft':['Secure affected accounts and identity documents.','Change compromised passwords and enable MFA.','Preserve fraudulent profiles, messages and transaction records.','Contact affected service providers or financial institutions if relevant.','Report the incident through the appropriate official channel.'],
    'Online Fraud':['Contact your bank/payment provider immediately if money is involved.','Preserve transaction IDs, UTRs, screenshots and messages.','Do not send additional money or OTPs.','Secure affected accounts and payment apps.','Report through the appropriate official cybercrime channel.'],
    'Cyberstalking':['Do not engage with threats if doing so could increase risk.','Block/report the account where appropriate.','Preserve messages, profiles, timestamps and URLs.','Tell a trusted person and seek local help if there is immediate danger.','Report through appropriate law-enforcement/cybercrime channels.'],
    'Data Theft':['Restrict further access to the affected account/system.','Preserve logs, alerts and copies of relevant evidence.','Change exposed credentials and revoke unknown sessions.','Notify the relevant organisation/admin where applicable.','Report through the appropriate official channel.'],
    'Unclear':['Preserve the original message or evidence.','Avoid clicking links or sharing credentials.','Secure important accounts with strong passwords and MFA.','Gather timestamps, screenshots and transaction details.','Seek official cybercrime/police assistance if the incident is serious.']
}

def get_fernet():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE,'wb') as f: f.write(Fernet.generate_key())
    with open(KEY_FILE,'rb') as f: return Fernet(f.read().strip())

def hash_bytes(data): return hashlib.sha256(data).hexdigest()
def hash_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(65536),b''): h.update(chunk)
    return h.hexdigest()

def match_rules(text, rules):
    lower=text.lower(); scores={}; triggers={}
    for cat, kws in rules.items():
        hits=[kw for kw in kws if kw.lower() in lower]
        if hits: scores[cat]=len(hits); triggers[cat]=hits
    if not scores: return 'Unclear', [], 0
    best_score=max(scores.values()); cat=next(c for c,s in scores.items() if s==best_score)
    total=sum(len(v) for v in rules.values())
    score=min(99, 45 + best_score*14 + max(0, best_score-1)*7)
    return cat, triggers[cat], score

def threat_analyze(text):
    cat,hits,score=match_rules(text,THREAT_RULES)
    if cat=='Unclear':
        return {'classification':'Safe/Unclear','risk':'Low','score':18,'triggers':[],'why':['No configured threat indicators were detected.','This is not proof that the content is safe.'],'response':RESPONSE_STEPS['Unclear']}
    risk='Critical' if score>=85 else 'High' if score>=65 else 'Medium'
    why=[]
    if any(x in hits for x in ['urgent','act now','suspended']): why.append('Urgency or pressure language detected.')
    if any(x in hits for x in ['password','otp','login','verify your account','kyc']): why.append('Credential or identity-verification language detected.')
    if any(x in hits for x in ['http://','https://','click here']): why.append('Link/click-through language detected.')
    if any(x in hits for x in ['.exe','.apk','download','attachment']): why.append('Potentially risky file/download language detected.')
    if any(x in hits for x in ['bitcoin','ransom','encrypted files']): why.append('Ransom/payment-for-decryption language detected.')
    if not why: why=['One or more configured threat indicators matched.']
    return {'classification':cat,'risk':risk,'score:':score,'score':score,'triggers':hits,'why':why,'response':RESPONSE_STEPS.get(cat,RESPONSE_STEPS['Unclear'])}

def offence_analyze(text):
    cat,hits,score=match_rules(text,OFFENCE_RULES)
    if cat=='Unclear': score=22
    risk='Critical' if score>=85 else 'High' if score>=65 else 'Medium' if score>=40 else 'Low'
    return cat,hits,score,risk

def safe_name(name): return re.sub(r'[^A-Za-z0-9_.-]','_',name)[:80]

def legal(category):
    if category not in LAW_MAP: return None
    section,desc=LAW_MAP[category]
    return {'category':category,'section':section,'description':desc,'reporting':'Report through the official cybercrime reporting channel (cybercrime.gov.in) or the nearest police cyber cell. For financial fraud, contact your bank/payment provider immediately.'}

def unified_analysis(text):
    threat=threat_analyze(text)
    offence,hits,oscore,orisk=offence_analyze(text)
    # If threat result is strong, use its score; otherwise blend threat/offence signals.
    score=max(threat['score'], oscore)
    if threat['classification']=='Safe/Unclear' and offence!='Unclear': score=max(45,oscore)
    risk='Critical' if score>=85 else 'High' if score>=65 else 'Medium' if score>=40 else 'Low'
    law=legal(offence) if offence!='Unclear' else None
    incident_id='LG-'+datetime.now().strftime('%Y%m%d')+'-'+uuid.uuid4().hex[:6].upper()
    iocs=extract_iocs(text)
    mitre=map_mitre(threat, offence, iocs, text)
    severity=severity_priority(threat, offence, score, iocs, bool(law), 0)
    playbook=build_playbook(threat['classification'], offence)
    result={'incident_id':incident_id,'timestamp':datetime.now().strftime('%d %b %Y, %I:%M %p'),'input':text,'threat':threat,'offence':offence,'offence_triggers':hits,'risk':risk,'score':score,'severity':severity['severity'],'priority':severity['priority'],'severity_reason':severity['reason'],'legal':law,'response':playbook['steps'],'playbook':playbook,'iocs':iocs,'mitre':mitre,'timeline':[], 'response_progress':0}
    save_case(result, event='Incident Created')
    return result

@app.route('/')
def index(): return render_template('index.html')

@app.post('/api/analyze')
def api_analyze():
    data=request.get_json(silent=True) or {}; text=(data.get('text') or '').strip()
    if not text: return jsonify({'error':'Please enter an incident or suspicious message.'}),400
    return jsonify(unified_analysis(text))

@app.post('/api/threat')
def api_threat():
    text=((request.get_json(silent=True) or {}).get('text') or '').strip()
    if not text: return jsonify({'error':'Text is required.'}),400
    return jsonify(threat_analyze(text))

@app.post('/api/offence')
def api_offence():
    text=((request.get_json(silent=True) or {}).get('text') or '').strip()
    if not text: return jsonify({'error':'Incident description is required.'}),400
    cat,hits,score,risk=offence_analyze(text)
    return jsonify({'classification':cat,'triggers':hits,'score':score,'risk':risk,'legal':legal(cat)})

@app.post('/api/wifi')
def api_wifi():
    data=request.get_json(silent=True) or {}; kind=data.get('type')
    if kind not in WIFI_RISK: return jsonify({'error':'Invalid Wi-Fi type.'}),400
    risk,score,explanation=WIFI_RISK[kind]
    return jsonify({'type':kind,'risk':risk,'score':score,'explanation':explanation})

@app.post('/api/permissions')
def api_permissions():
    raw=(request.get_json(silent=True) or {}).get('permissions','')
    permissions={p.strip().lower().replace(' ','_') for p in raw.split(',') if p.strip()}
    sensitive=sorted(permissions & SENSITIVE_PERMISSIONS); count=len(sensitive)
    score=min(100, count*18 + (10 if 'location' in sensitive else 0) + (10 if 'sms' in sensitive else 0))
    risk='High' if count>=4 else 'Medium' if count>=2 else 'Low'
    return jsonify({'risk':risk,'score':score,'sensitive':sensitive,'explanation':'Risk depends on app purpose; sensitive permissions are not automatically malicious.'})

@app.post('/api/crypto')
def api_crypto():
    data=request.get_json(silent=True) or {}; action=data.get('action'); text=data.get('text','')
    f=get_fernet()
    try:
        if action=='encrypt':
            if not text: raise ValueError('Text is empty.')
            token=f.encrypt(text.encode()).decode(); return jsonify({'result':token,'hash':hash_bytes(text.encode())})
        if action=='decrypt':
            plain=f.decrypt(text.encode()).decode(); return jsonify({'result':plain,'hash':hash_bytes(plain.encode())})
        return jsonify({'error':'Invalid crypto action.'}),400
    except (InvalidToken,UnicodeDecodeError,ValueError) as e: return jsonify({'error':str(e) or 'Invalid encrypted text/key.'}),400

@app.post('/api/locker/save')
def locker_save():
    data=request.get_json(silent=True) or {}; name=safe_name(data.get('name','')); note=data.get('note','')
    if not name or not note: return jsonify({'error':'Name and note are required.'}),400
    path=os.path.join(VAULT_DIR,name+'.vault'); payload=json.dumps({'note':note,'created':datetime.now().isoformat()}).encode()
    with open(path,'wb') as f:f.write(get_fernet().encrypt(payload))
    return jsonify({'message':'Encrypted vault saved.','file':name+'.vault','hash':hash_file(path)})

@app.post('/api/locker/get')
def locker_get():
    name=safe_name((request.get_json(silent=True) or {}).get('name','')); path=os.path.join(VAULT_DIR,name+'.vault')
    if not os.path.isfile(path): return jsonify({'error':'Vault file not found.'}),404
    try:
        with open(path,'rb') as f: data=get_fernet().decrypt(f.read())
        payload=json.loads(data.decode()); return jsonify({'note':payload.get('note',''),'hash':hash_file(path)})
    except Exception: return jsonify({'error':'Could not decrypt this vault.'}),400

@app.route('/api/evidence', methods=['POST'])
def evidence():
    file=request.files.get('file'); note=request.form.get('note','').strip(); incident=safe_name(request.form.get('incident_id','').strip())
    if not file or not file.filename: return jsonify({'error':'Choose an evidence file.'}),400
    if not incident:
        incident='LG-'+datetime.now().strftime('%Y%m%d')+'-'+uuid.uuid4().hex[:6].upper()
    if not re.fullmatch(r'LG-[A-Z0-9_-]+', incident): return jsonify({'error':'Invalid Incident ID.'}),400
    original=safe_name(file.filename)
    if not original: return jsonify({'error':'Invalid filename.'}),400
    folder=os.path.join(EVIDENCE_DIR,incident); os.makedirs(folder,exist_ok=True)
    path=os.path.join(folder,original)
    if os.path.exists(path):
        stem,ext=os.path.splitext(original); original=f'{stem}_{uuid.uuid4().hex[:6]}{ext}'; path=os.path.join(folder,original)
    file.save(path); digest=hash_file(path)
    meta={'evidence_id':'EV-'+uuid.uuid4().hex[:8].upper(),'incident_id':incident,'filename':original,'file_type':mimetypes.guess_type(original)[0] or 'application/octet-stream','sha256':digest,'size':os.path.getsize(path),'created':datetime.now().isoformat(timespec='seconds'),'note':note,'status':'VERIFIED','original_hash':digest}
    meta_path=os.path.join(folder,original+'.metadata.json')
    with open(meta_path,'w',encoding='utf-8') as f: json.dump(meta,f,indent=2)
    # Keep legacy metadata for compatibility.
    with open(os.path.join(folder,'metadata.json'),'w',encoding='utf-8') as f: json.dump(meta,f,indent=2)
    append_custody(meta,'Evidence Added',f'Evidence {meta["evidence_id"]} uploaded as {original}.')
    append_custody(meta,'Hash Generated',f'Original SHA-256 recorded: {digest}.')
    update_case_evidence(incident, meta)
    return jsonify(meta)

@app.post('/api/evidence/verify')
def evidence_verify():
    data=request.get_json(silent=True) or {}; incident=safe_name(data.get('incident_id','')); evidence_id=data.get('evidence_id')
    meta=load_evidence_meta(incident,evidence_id)
    if not meta: return jsonify({'error':'Evidence record not found.'}),404
    path=os.path.join(EVIDENCE_DIR,incident,meta['filename'])
    if not os.path.isfile(path): return jsonify({'error':'Evidence file is missing.','status':'MISSING'}),404
    current=hash_file(path); match=current==meta.get('original_hash',meta.get('sha256'))
    meta['sha256_current']=current; meta['status']='VERIFIED' if match else 'INTEGRITY FAILED'
    if not match: append_custody(meta,'Integrity Verified',f'Integrity failure: current SHA-256 differs from original.')
    else: append_custody(meta,'Integrity Verified','Original and current SHA-256 values match.')
    with open(os.path.join(EVIDENCE_DIR,incident,meta['filename']+'.metadata.json'),'w',encoding='utf-8') as f: json.dump(meta,f,indent=2)
    return jsonify({'match':match,'original':meta.get('original_hash',meta.get('sha256')),'current':current,'filename':meta['filename'],'evidence_id':meta.get('evidence_id'),'status':meta['status']})

@app.get('/api/evidence/list')
def evidence_list():
    records=[]
    if not os.path.isdir(EVIDENCE_DIR): return jsonify(records)
    for incident in sorted(os.listdir(EVIDENCE_DIR),reverse=True):
        folder=os.path.join(EVIDENCE_DIR,incident)
        if not os.path.isdir(folder): continue
        for fn in os.listdir(folder):
            if fn.endswith('.metadata.json') or fn == 'metadata.json':
                try:
                    with open(os.path.join(folder,fn),encoding='utf-8') as f: meta=json.load(f)
                    if fn == 'metadata.json' and not meta.get('evidence_id'):
                        meta['evidence_id']='LEGACY-'+hashlib.sha1((incident+meta.get('filename','')).encode()).hexdigest()[:8].upper()
                        meta.setdefault('original_hash',meta.get('sha256'))
                        meta.setdefault('status','RECORDED')
                        meta.setdefault('file_type',mimetypes.guess_type(meta.get('filename',''))[0] or 'application/octet-stream')
                    records.append(meta)
                except Exception: pass
    return jsonify(records[:50])

@app.get('/api/evidence/<incident>/custody')
def evidence_custody(incident):
    return jsonify(load_custody(safe_name(incident)))

@app.route('/api/report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No incident data received"}), 400

        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak
        )
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.units import mm
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfbase import pdfmetrics

        os.makedirs("reports", exist_ok=True)

        incident_id = data.get(
            "incident_id",
            "LG-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        )

        filename = f"{incident_id}.pdf"
        filepath = os.path.join("reports", filename)

        # ---------------------------------------------------------
        # Extract information
        # ---------------------------------------------------------

        # Threat information is stored inside a dictionary
        threat = data.get("threat", {})

        if isinstance(threat, dict):

           threat_classification = threat.get( "classification","Unknown")

           reasons = threat.get("why",[])

           indicators = threat.get("triggers",[])

        else:

             threat_classification = str(threat)
             reasons = []
             indicators = []


        # Offence
        offence = data.get(
            "offence",
            "Unclear"
        )
        


        # Risk
        risk = data.get(
            "risk",
          data.get("risk_level", "Unknown")
        ) 


        # Risk score
        score = data.get(
           "score",
        data.get("risk_score", "N/A")
        )


        # Recommended response
        recommendations = data.get(
          "recommendations",
          data.get("response", [])
        )


        # Legal guidance
        legal = data.get(
          "legal_guidance",
          data.get("legal", {})
        )

        if isinstance(legal, dict):

            legal_section = legal.get(
                "section",
                "No specific legal section mapped."
            )

            legal_description = legal.get(
               "description",
                "No specific legal description available."
            )

            legal_reporting = legal.get(
                "reporting",
                "Report the incident through the appropriate official cybercrime channel."
             )

        else:

            legal_section = str(legal)
            legal_description = ""
            legal_reporting = ""


        # Original incident text
        original_text = data.get(
            "input",
            data.get("message", "")
        )


        # Make sure lists are actually lists
        if isinstance(reasons, str):
            reasons = [reasons]

        if isinstance(indicators, str):
            indicators = [indicators]

        if isinstance(recommendations, str):
            recommendations = [recommendations]
        # ---------------------------------------------------------
        # Document
        # ---------------------------------------------------------

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=26,
            alignment=TA_CENTER,
            spaceAfter=8
        )

        subtitle_style = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#64748b")
        )

        heading_style = ParagraphStyle(
            "Heading",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            spaceBefore=14,
            spaceAfter=7
        )

        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=14,
            spaceAfter=5
        )

        small_style = ParagraphStyle(
            "Small",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748b")
        )

        # ---------------------------------------------------------
        # Build report
        # ---------------------------------------------------------

        story = []

        # Header
        story.append(
            Paragraph("LEXGUARD", title_style)
        )

        story.append(
            Paragraph(
                "CYBER INCIDENT ANALYSIS & RESPONSE REPORT",
                subtitle_style
            )
        )

        story.append(Spacer(1, 12))

        # Incident information
        incident_data = [
            [
                Paragraph("<b>Incident ID</b>", body_style),
                Paragraph(str(incident_id), body_style)
            ],
            [
                Paragraph("<b>Generated</b>", body_style),
                Paragraph(
                    datetime.now().strftime("%d %B %Y, %I:%M %p"),
                    body_style
                )
            ],
            [
                Paragraph("<b>Threat Classification</b>", body_style),
                Paragraph(str(threat_classification), body_style)
            ],
            [
                Paragraph("<b>Offence Classification</b>", body_style),
                Paragraph(str(offence), body_style)
            ],
            [
                Paragraph("<b>Overall Risk</b>", body_style),
                Paragraph(
                    f"<b>{str(risk).upper()}</b>",
                    body_style
                )
            ],
            [
                Paragraph("<b>Risk Score</b>", body_style),
                Paragraph(f"{score}/100", body_style)
            ]
        ]

        table = Table(
            incident_data,
            colWidths=[55 * mm, 115 * mm]
        )

        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1),
                 colors.HexColor("#e8eef5")),
                ("GRID", (0, 0), (-1, -1), 0.5,
                 colors.HexColor("#b8c2cc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
            ])
        )

        story.append(table)

        # ---------------------------------------------------------
        # Executive Summary
        # ---------------------------------------------------------

        story.append(
            Paragraph("1. EXECUTIVE SUMMARY", heading_style)
        )

        story.append(
            Paragraph(
                f"LexGuard analyzed the submitted incident and classified "
                f"the detected threat as <b>{threat}</b> with an overall "
                f"risk level of <b>{risk}</b> and a risk score of "
                f"<b>{score}/100</b>.",
                body_style
            )
        )

        # ---------------------------------------------------------
        # Why flagged
        # ---------------------------------------------------------

        story.append(
            Paragraph("2. WHY THIS INCIDENT WAS FLAGGED", heading_style)
        )

        if reasons:
            for reason in reasons:
                story.append(
                    Paragraph(
                        f"• {str(reason)}",
                        body_style
                    )
                )
        else:
            story.append(
                Paragraph(
                    "No additional explanation was recorded.",
                    body_style
                )
            )

        # ---------------------------------------------------------
        # Indicators
        # ---------------------------------------------------------

        story.append(
            Paragraph("3. DETECTED INDICATORS", heading_style)
        )

        if indicators:
            indicator_text = "  •  ".join(
                str(x) for x in indicators
            )

            story.append(
                Paragraph(
                    indicator_text,
                    body_style
                )
            )
        else:
            story.append(
                Paragraph(
                    "No specific indicators recorded.",
                    body_style
                )
            )

       # ---------------------------------------------------------
       # Incident Overview
       # ---------------------------------------------------------

        story.append(
        Paragraph(
           "4. INCIDENT OVERVIEW",
           heading_style
            )
        )

        overview_text = (
            f"LexGuard analyzed the submitted incident using its "
            f"rule-based threat detection and cyber-offence classification "
            f"engine. The incident was identified as "
            f"<b>{threat_classification}</b> with an overall risk level of "
            f"<b>{str(risk).upper()}</b> and a risk score of "
            f"<b>{score}/100</b>."
        )

        story.append(
            Paragraph(
            overview_text,
            body_style
            )
        )

        story.append(Spacer(1, 8))

        story.append(
        Paragraph(
            "<b>Assessment:</b> The original incident content has been "
            "excluded from this report to protect sensitive information. "
            "Only the security analysis, detected indicators, recommended "
            "response, and legal guidance are included.",
            body_style
            )
        )
        # ---------------------------------------------------------
        # Response
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "5. RECOMMENDED RESPONSE",
                heading_style
            )
        )

        if recommendations:
            for i, item in enumerate(recommendations, 1):
                story.append(
                    Paragraph(
                        f"<b>{i}.</b> {str(item)}",
                        body_style
                    )
                )
        else:
            story.append(
                Paragraph(
                    "Follow standard cybersecurity incident-response "
                    "procedures and preserve relevant evidence.",
                    body_style
                )
            )

        # ---------------------------------------------------------
        # Legal guidance
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "6. CYBER LAW & REPORTING GUIDANCE",
                heading_style
            )
        )

        safe_legal = (
            str(legal)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br/>")
        )

        story.append(
            Paragraph(
                safe_legal,
                body_style
            )
        )

        story.append(
            Paragraph(
                "For cybercrime reporting, use the official "
                "Indian cybercrime reporting channel or contact "
                "the appropriate cybercrime/police authority.",
                body_style
            )
        )

        # ---------------------------------------------------------
        # LexGuard 2.0 intelligence sections
        # ---------------------------------------------------------
        iocs = data.get("iocs", [])
        mitre = data.get("mitre", [])
        severity = data.get("severity", "N/A")
        priority = data.get("priority", "N/A")
        story.append(Paragraph("7. SEVERITY & PRIORITY", heading_style))
        story.append(Paragraph(f"Severity: <b>{str(severity)}</b> &nbsp;&nbsp; Priority: <b>{str(priority)}</b>", body_style))
        story.append(Paragraph(str(data.get("severity_reason", "Priority is derived from the existing rule-based risk assessment and incident context.")), body_style))
        story.append(Paragraph("8. INDICATORS OF COMPROMISE", heading_style))
        if iocs:
            for i in iocs: story.append(Paragraph(f"<b>{str(i.get('type'))}</b>: {str(i.get('value'))}", body_style))
        else: story.append(Paragraph("No IOCs were extracted from the supplied incident text.", body_style))
        story.append(Paragraph("9. MITRE ATT&CK MAPPING", heading_style))
        if mitre:
            for m in mitre: story.append(Paragraph(f"<b>{str(m.get('id'))} — {str(m.get('name'))}</b><br/>{str(m.get('why'))}", body_style))
        else: story.append(Paragraph("No configured MITRE ATT&CK mapping matched this incident.", body_style))
        story.append(Paragraph("10. RESPONSE PLAYBOOK", heading_style))
        pb=data.get("playbook", {})
        story.append(Paragraph(f"{str(pb.get('name','Incident Response Playbook'))} — Progress: {str(data.get('response_progress',0))}%", body_style))
        for step in pb.get('steps',[]): story.append(Paragraph(f"{'[x]' if step.get('done') else '[ ]'} {str(step.get('text'))}", body_style))
        # ---------------------------------------------------------
        # Evidence
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "11. EVIDENCE & INTEGRITY",
                heading_style
            )
        )

        story.append(
            Paragraph(
                "Preserve suspicious messages, screenshots, files, "
                "transaction information and other relevant evidence. "
                "Where applicable, record SHA-256 hashes to help verify "
                "that stored evidence has not been modified.",
                body_style
            )
        )

        evidence_items = data.get("evidence", [])
        if evidence_items:
            for ev in evidence_items:
                story.append(Paragraph(f"<b>{str(ev.get('evidence_id','Evidence'))}</b> — {str(ev.get('filename',''))} — SHA-256: {str(ev.get('original_hash',ev.get('sha256','N/A')))} — Status: {str(ev.get('status','RECORDED'))}", body_style))
        story.append(Paragraph("12. INCIDENT TIMELINE", heading_style))
        timeline = data.get("timeline", [])
        if timeline:
            for item in timeline: story.append(Paragraph(f"{str(item.get('timestamp'))} — <b>{str(item.get('action'))}</b> — {str(item.get('description'))}", body_style))
        else: story.append(Paragraph("Timeline events are recorded in the Investigation Center when available.", body_style))
        story.append(Paragraph("13. CHAIN-OF-CUSTODY SUMMARY", heading_style))
        custody = load_custody(str(incident_id))
        if custody:
            for item in custody: story.append(Paragraph(f"{str(item.get('timestamp'))} — {str(item.get('action'))} — {str(item.get('evidence_id',''))}", body_style))
        else: story.append(Paragraph("No chain-of-custody events are attached to this report.", body_style))

        # ---------------------------------------------------------
        # Footer / disclaimer
        # ---------------------------------------------------------

        story.append(Spacer(1, 20))

        story.append(
            Paragraph(
                "LEXGUARD • Cyber Threat & Legal Response Platform",
                small_style
            )
        )

        story.append(
            Paragraph(
                "<b>Disclaimer:</b> This report provides educational, "
                "rule-based cybersecurity guidance. Legal applicability "
                "depends on the facts of the incident and the law in force. "
                "This report is not legal advice.",
                small_style
            )
        )

        doc.build(story)

        # Send PDF to browser
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf"
        )

    except Exception as e:
        print("PDF generation error:", e)
        return jsonify({"error": str(e)}), 500


# ========================= LEXGUARD 2.0 UPGRADE =========================
CASE_INDEX=os.path.join(CASE_DIR,'cases.json')

def _read_json(path, default):
    try:
        with open(path,encoding='utf-8') as f: return json.load(f)
    except Exception: return default

def _write_json(path, data):
    tmp=path+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: json.dump(data,f,indent=2,ensure_ascii=False)
    os.replace(tmp,path)

def load_cases(): return _read_json(CASE_INDEX, [])

def save_cases(cases): _write_json(CASE_INDEX,cases)

def append_audit(incident, action, description, evidence_id=None):
    path=os.path.join(AUDIT_DIR,safe_name(incident)+'.json')
    events=_read_json(path, [])
    prev=events[-1]['hash'] if events else 'GENESIS'
    event={'timestamp':datetime.now().isoformat(timespec='seconds'),'action':action,'incident_id':incident,'evidence_id':evidence_id,'description':description,'previous_hash':prev}
    canonical=json.dumps(event,sort_keys=True,separators=(',',':')).encode()
    event['hash']=hashlib.sha256((prev.encode()+canonical)).hexdigest()
    events.append(event); _write_json(path,events); return event

def verify_audit_chain(incident):
    events=_read_json(os.path.join(AUDIT_DIR,safe_name(incident)+'.json'),[]); prev='GENESIS'
    for e in events:
        copy=dict(e); h=copy.pop('hash',None); canonical=json.dumps(copy,sort_keys=True,separators=(',',':')).encode()
        expected=hashlib.sha256((prev.encode()+canonical)).hexdigest()
        if h!=expected or e.get('previous_hash')!=prev: return {'valid':False,'checked':len(events),'broken_at':e.get('timestamp')}
        prev=h
    return {'valid':True,'checked':len(events),'broken_at':None}

def append_custody(meta, action, description):
    incident=meta['incident_id']; path=os.path.join(EVIDENCE_DIR,incident,'chain_of_custody.json')
    entries=_read_json(path,[]); entries.append({'timestamp':datetime.now().isoformat(timespec='seconds'),'action':action,'evidence_id':meta.get('evidence_id'),'incident_id':incident,'description':description})
    _write_json(path,entries); append_audit(incident,action,description,meta.get('evidence_id'))

def load_custody(incident): return _read_json(os.path.join(EVIDENCE_DIR,incident,'chain_of_custody.json'),[])

def load_evidence_meta(incident,evidence_id=None):
    folder=os.path.join(EVIDENCE_DIR,incident)
    if not os.path.isdir(folder): return None
    metas=[]
    for fn in os.listdir(folder):
        if fn.endswith('.metadata.json'):
            try: metas.append(_read_json(os.path.join(folder,fn),{}))
            except Exception: pass
    if evidence_id: return next((m for m in metas if m.get('evidence_id')==evidence_id),None)
    if metas: return metas[0]
    legacy=os.path.join(folder,'metadata.json')
    return _read_json(legacy,None) if os.path.isfile(legacy) else None

def update_case_evidence(incident,meta):
    cases=load_cases(); case=next((c for c in cases if c.get('incident_id')==incident),None)
    if not case:
        case={'incident_id':incident,'timestamp':meta.get('created'),'input':'','threat':{'classification':'Evidence-only'},'offence':'Unclear','risk':'Unknown','score':0,'severity':'LOW','priority':'P4','severity_reason':'Evidence record created without a full incident analysis.','legal':None,'response':RESPONSE_STEPS['Unclear'],'playbook':build_playbook('Unclear','Unclear'),'iocs':[],'mitre':[],'timeline':[],'response_progress':0,'evidence':[]}
        cases.append(case)
    case.setdefault('evidence',[]).append(meta)
    add_timeline(case,'Evidence Added',f'{meta.get("filename")} secured as {meta.get("evidence_id")}.')
    save_cases(cases)
    append_audit(incident,'Evidence Associated With Incident',f'{meta.get("evidence_id")} associated with {incident}.',meta.get('evidence_id'))

def add_timeline(case,action,description):
    case.setdefault('timeline',[]).append({'timestamp':datetime.now().isoformat(timespec='seconds'),'action':action,'description':description})

def extract_iocs(text):
    text=text or ''; found=[]
    patterns=[('IPv4',r'(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])'),('URL',r'\bhttps?://[^\s<>"\']+'),('Email',r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),('SHA-256',r'\b[a-fA-F0-9]{64}\b'),('SHA-1',r'\b[a-fA-F0-9]{40}\b'),('MD5',r'\b[a-fA-F0-9]{32}\b'),('Domain',r'(?<![@\w.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w.-])')]
    seen=set()
    for typ,pat in patterns:
        for val in re.findall(pat,text):
            val=val.rstrip('.,;:)]}')
            key=(typ,val.lower())
            if key not in seen: seen.add(key); found.append({'type':typ,'value':val})
    return found

def map_mitre(threat,offence,iocs,text):
    c=threat.get('classification',''); o=offence or ''; low=(text or '').lower(); out=[]
    def add(tid,name,why): out.append({'id':tid,'name':name,'why':why})
    if c=='Phishing' or any(x in low for x in ['phishing','click here','verify your account']): add('T1566','Phishing','The incident contains phishing/social-engineering indicators.')
    if 'http://' in low or 'https://' in low or any(i['type']=='URL' for i in iocs): add('T1566.002','Phishing: Spearphishing Link','A suspicious link/URL is present.')
    if any(x in low for x in ['password','otp','credential','login']): add('T1056.002','Input Capture: GUI Input Capture','The content requests credentials or authentication information.')
    if c=='Malware-link' or any(x in low for x in ['.exe','.apk','trojan','malware']): add('T1204.002','User Execution: Malicious File','The incident involves a potentially malicious file or executable.')
    if c=='Ransomware' or any(x in low for x in ['ransom','encrypted files','decryption key']): add('T1486','Data Encrypted for Impact','The incident describes encryption/ransom behavior.')
    if o=='Hacking/Unauthorized Access' or any(x in low for x in ['hacked','unauthorized access','login without permission']): add('T1078','Valid Accounts','The incident may involve misuse of an account or credentials.')
    if o=='Data Theft' or any(x in low for x in ['stole my data','copied files','database stolen','leaked data']): add('T1005','Data from Local System','The description indicates possible collection or theft of data.')
    # de-duplicate by id
    return list({x['id']:x for x in out}.values())

def build_playbook(threat,offence):
    key=threat if threat in RESPONSE_STEPS else offence if offence in RESPONSE_STEPS else 'Unclear'
    return {'name':f'{key} Response Playbook','steps':[{'id':i+1,'text':x,'done':False} for i,x in enumerate(RESPONSE_STEPS[key])]}

def severity_priority(threat,offence,score,iocs,has_legal,evidence_count):
    points=score + min(15,len(iocs)*3) + min(10,evidence_count*2) + (8 if threat.get('classification') in ('Ransomware','Malware-link') else 0) + (7 if offence in ('Online Fraud','Hacking/Unauthorized Access','Data Theft') else 0)
    sev='CRITICAL' if points>=100 else 'HIGH' if points>=75 else 'MEDIUM' if points>=45 else 'LOW'
    pri={'CRITICAL':'P1','HIGH':'P2','MEDIUM':'P3','LOW':'P4'}[sev]
    reasons=[]
    if score>=65: reasons.append(f'Base risk score is {score}/100.')
    if iocs: reasons.append(f'{len(iocs)} IOC(s) were extracted.')
    if evidence_count: reasons.append(f'{evidence_count} evidence item(s) are attached.')
    if threat.get('classification') in ('Ransomware','Malware-link'): reasons.append('Malware/impact behavior increases urgency.')
    if offence in ('Online Fraud','Hacking/Unauthorized Access','Data Theft'): reasons.append(f'{offence} can require prompt containment.')
    return {'severity':sev,'priority':pri,'reason':' '.join(reasons) or 'Low-confidence or informational incident indicators.'}

def save_case(result,event=None):
    cases=load_cases(); case=next((c for c in cases if c.get('incident_id')==result.get('incident_id')),None)
    if case: case.update(result)
    else: case=result.copy(); cases.append(case)
    if event: add_timeline(case,event,'LexGuard recorded this incident event.')
    save_cases(cases); append_audit(result['incident_id'],event or 'Case Updated','Case record saved.')

def refresh_case(incident):
    cases=load_cases(); return next((c for c in cases if c.get('incident_id')==incident),None)

def case_stats():
    cases=load_cases(); ev=[]
    for c in cases: ev.extend(c.get('evidence',[]))
    return {'total_incidents':len(cases),'active_incidents':sum(1 for c in cases if c.get('status','ACTIVE') not in ('RESOLVED','CLOSED')),'critical_high':sum(1 for c in cases if c.get('severity') in ('CRITICAL','HIGH')),'resolved':sum(1 for c in cases if c.get('status') in ('RESOLVED','CLOSED')),'evidence_count':len(ev),'verified_evidence':sum(1 for x in ev if x.get('status')=='VERIFIED'),'integrity_failures':sum(1 for x in ev if x.get('status')=='INTEGRITY FAILED'),'ioc_count':sum(len(c.get('iocs',[])) for c in cases),'threat_distribution':dict(__import__('collections').Counter((c.get('threat') or {}).get('classification','Unknown') for c in cases)),'offence_distribution':dict(__import__('collections').Counter(c.get('offence','Unknown') for c in cases))}

@app.get('/api/dashboard')
def api_dashboard(): return jsonify(case_stats())

@app.get('/api/cases')
def api_cases():
    q=(request.args.get('q') or '').lower().strip(); cases=load_cases()
    if q: cases=[c for c in cases if q in json.dumps(c).lower()]
    return jsonify(sorted(cases,key=lambda c:c.get('timestamp',''),reverse=True))

@app.get('/api/cases/<incident_id>')
def api_case(incident_id):
    case=refresh_case(safe_name(incident_id))
    if not case: return jsonify({'error':'Incident not found.'}),404
    case=case.copy(); case['audit']=_read_json(os.path.join(AUDIT_DIR,safe_name(incident_id)+'.json'),[]); case['audit_verification']=verify_audit_chain(incident_id)
    return jsonify(case)

@app.post('/api/cases/<incident_id>/playbook')
def api_playbook(incident_id):
    data=request.get_json(silent=True) or {}; step_id=int(data.get('step_id',0)); done=bool(data.get('done',False)); cases=load_cases(); case=next((c for c in cases if c.get('incident_id')==safe_name(incident_id)),None)
    if not case: return jsonify({'error':'Incident not found.'}),404
    steps=case.setdefault('playbook',{}).setdefault('steps',[]); target=next((x for x in steps if x.get('id')==step_id),None)
    if not target: return jsonify({'error':'Playbook step not found.'}),404
    target['done']=done; completed=sum(1 for x in steps if x.get('done')); case['response_progress']=round(completed*100/len(steps)) if steps else 100
    add_timeline(case,'Response Step Updated',f"{target['text']} — {'completed' if done else 'reopened'}."); append_audit(incident_id,'Response Step Updated',target['text'])
    save_cases(cases); return jsonify({'progress':case['response_progress'],'playbook':case['playbook']})

@app.get('/api/iocs')
def api_iocs():
    q=(request.args.get('q') or '').lower().strip(); typ=(request.args.get('type') or '').lower().strip(); out=[]
    for c in load_cases():
        for i in c.get('iocs',[]):
            x=dict(i); x['incident_id']=c.get('incident_id'); x['timestamp']=c.get('timestamp'); out.append(x)
    if q: out=[x for x in out if q in str(x.get('value','')).lower() or q in str(x.get('incident_id','')).lower()]
    if typ: out=[x for x in out if x.get('type','').lower()==typ]
    return jsonify(out)

@app.post('/api/url/analyze')
def api_url_analyze():
    raw=((request.get_json(silent=True) or {}).get('url') or '').strip(); from urllib.parse import urlparse
    if not raw: return jsonify({'error':'Enter a URL or domain.'}),400
    candidate=raw if re.match(r'^https?://',raw,re.I) else 'http://'+raw
    p=urlparse(candidate); host=p.hostname or ''; indicators=[]; score=0
    if p.scheme!='https': score+=15; indicators.append('No HTTPS')
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$',host): score+=30; indicators.append('IP address used as host')
    if '@' in raw: score+=25; indicators.append('@ symbol can obscure the destination')
    if len(host.split('.'))>3: score+=12; indicators.append('Deep subdomain structure')
    if host.count('-')>=2: score+=8; indicators.append('Multiple hyphens in host')
    if any(x in (host+p.path).lower() for x in ['login','verify','secure','account','update','otp','bank','wallet']): score+=18; indicators.append('Credential/account lure wording')
    if any(x in raw.lower() for x in ['%2f','%40','%2e','xn--']): score+=15; indicators.append('Encoded/punycode pattern')
    risk='CRITICAL' if score>=70 else 'HIGH' if score>=45 else 'MEDIUM' if score>=25 else 'LOW'
    return jsonify({'input':raw,'normalized':candidate,'domain':host,'scheme':p.scheme,'path':p.path or '/','score':min(score,100),'risk':risk,'indicators':indicators or ['No configured suspicious URL indicators matched.'],'recommendation':'Do not enter credentials or payment details unless you independently verify the destination.' if score>=25 else 'Continue with normal caution and verify the destination before entering sensitive information.'})

@app.post('/api/file/analyze')
def api_file_analyze():
    file=request.files.get('file')
    if not file or not file.filename: return jsonify({'error':'Choose a file.'}),400
    name=safe_name(file.filename); data=file.read(); ext=os.path.splitext(name)[1].lower(); size=len(data); digest=hash_bytes(data)
    entropy=0.0
    if data:
        from math import log2
        counts=[0]*256
        for b in data: counts[b]+=1
        entropy=-sum((c/size)*log2(c/size) for c in counts if c)
    risky_ext={'.exe','.dll','.scr','.bat','.cmd','.ps1','.vbs','.js','.apk','.msi','.jar'}
    score=35 if ext in risky_ext else 10
    if entropy>7.5: score+=20
    if size==0: score+=15
    risk='HIGH' if score>=50 else 'MEDIUM' if score>=30 else 'LOW'
    return jsonify({'filename':name,'size':size,'extension':ext or 'none','mime':mimetypes.guess_type(name)[0] or 'unknown','sha256':digest,'entropy':round(entropy,2),'risk':risk,'indicators':(['Executable/scripting file extension'] if ext in risky_ext else [])+(['High byte entropy; this alone is not proof of malware.'] if entropy>7.5 else []),'recommendation':'Do not execute the file; preserve it for analysis.' if score>=30 else 'Treat as untrusted input and verify its source.'})

@app.post('/api/password/analyze')
def api_password_analyze():
    pw=(request.get_json(silent=True) or {}).get('password','')
    import math
    if not isinstance(pw,str): return jsonify({'error':'Invalid password.'}),400
    classes=sum(bool(re.search(p,pw)) for p in [r'[a-z]',r'[A-Z]',r'\d',r'[^A-Za-z0-9]'])
    pool=sum([26 if re.search(r'[a-z]',pw) else 0,26 if re.search(r'[A-Z]',pw) else 0,10 if re.search(r'\d',pw) else 0,32 if re.search(r'[^A-Za-z0-9]',pw) else 0])
    entropy=round(len(pw)*math.log2(pool),1) if pool else 0
    common=bool(re.search(r'(password|123456|qwerty|admin|letmein)',pw,re.I))
    score=min(100, round(entropy*1.25)+len(pw)*2) if pw else 0
    if common: score=min(score,25)
    strength='VERY STRONG' if score>=85 else 'STRONG' if score>=65 else 'MEDIUM' if score>=40 else 'WEAK'
    return jsonify({'length':len(pw),'classes':classes,'entropy_bits':entropy,'score':score,'strength':strength,'warnings':(['Common password pattern detected.'] if common else [])+(['Use at least 12–16 characters for important accounts.'] if len(pw)<12 else [])})

@app.post('/api/simulator')
def api_simulator():
    scenarios={
      'Phishing':'URGENT: Your bank account has been suspended. Click here to verify your password and OTP immediately: http://secure-account.example/verify',
      'Ransomware':'Your files have been encrypted. Pay bitcoin to receive the decryption key. Do not restart the system.',
      'Online Fraud':'I was scammed through UPI. Money was stolen after I shared an OTP with the caller.',
      'Identity Theft':'Someone created a fake account in my name and used my personal details without permission.',
      'Malware':'Download invoice.exe from this link and install it to view the document.'}
    key=(request.get_json(silent=True) or {}).get('scenario'); text=scenarios.get(key)
    if not text: return jsonify({'error':'Unknown simulation scenario.'}),400
    return jsonify(unified_analysis(text)|{'simulation':True,'scenario':key})

@app.get('/api/cases/<incident_id>/export')
def api_export_case(incident_id):
    incident=safe_name(incident_id); case=refresh_case(incident)
    if not case: return jsonify({'error':'Incident not found.'}),404
    memory=io.BytesIO()
    with zipfile.ZipFile(memory,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('Case_Metadata.json',json.dumps({k:v for k,v in case.items() if k!='input'},indent=2,ensure_ascii=False))
        z.writestr('Incident_Input.txt',case.get('input',''))
        z.writestr('IOC_Report.txt','\n'.join(f"{x.get('type')}: {x.get('value')}" for x in case.get('iocs',[])) or 'No IOCs extracted.')
        z.writestr('Timeline.txt','\n'.join(f"{x.get('timestamp')} | {x.get('action')} | {x.get('description')}" for x in case.get('timeline',[])) or 'No timeline events.')
        z.writestr('Chain_of_Custody.txt','\n'.join(f"{x.get('timestamp')} | {x.get('action')} | {x.get('evidence_id')} | {x.get('description')}" for x in load_custody(incident)) or 'No custody events.')
        z.writestr('Evidence_Hashes.txt','\n'.join(f"{x.get('evidence_id')} | {x.get('filename')} | SHA-256: {x.get('original_hash',x.get('sha256'))}" for x in case.get('evidence',[])) or 'No evidence attached.')
        report_path=os.path.join(REPORT_DIR,incident+'.pdf')
        if os.path.isfile(report_path): z.write(report_path,arcname='Incident_Report.pdf')
        for ev in case.get('evidence',[]):
            path=os.path.join(EVIDENCE_DIR,incident,ev.get('filename',''))
            if os.path.isfile(path): z.write(path,arcname=os.path.join('Evidence',ev.get('filename','evidence')))
    memory.seek(0); append_audit(incident,'Evidence Exported','Complete forensic case package generated.')
    return send_file(memory,as_attachment=True,download_name=f'LexGuard_Case_{incident}.zip',mimetype='application/zip')

@app.post('/api/cases/<incident_id>/status')
def api_case_status(incident_id):
    status=(request.get_json(silent=True) or {}).get('status','ACTIVE').upper(); allowed={'ACTIVE','INVESTIGATING','CONTAINED','RESOLVED','CLOSED'}
    if status not in allowed: return jsonify({'error':'Invalid status.'}),400
    cases=load_cases(); case=next((c for c in cases if c.get('incident_id')==safe_name(incident_id)),None)
    if not case: return jsonify({'error':'Incident not found.'}),404
    case['status']=status; add_timeline(case,'Case Status Updated',f'Case status changed to {status}.'); append_audit(incident_id,'Case Status Updated',status); save_cases(cases); return jsonify(case)

@app.get('/api/health')
def health(): return jsonify({'status':'ok','key_exists':os.path.exists(KEY_FILE)})

if __name__=='__main__':
    print('LexGuard Web running at http://127.0.0.1:5000')
    app.run(debug=True)
