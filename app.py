from flask import Flask, render_template, request, jsonify, send_file
import os, re, json, hashlib, uuid, io, zipfile, mimetypes, base64, math, secrets
from datetime import datetime

# Cryptographic libraries
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Image processing for Steganography
from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, 'lexguard.key')
VAULT_DIR = os.path.join(BASE_DIR, 'vault')
EVIDENCE_DIR = os.path.join(BASE_DIR, 'evidence')
REPORT_DIR = os.path.join(BASE_DIR, 'reports')
CASE_DIR = os.path.join(BASE_DIR, 'cases')
AUDIT_DIR = os.path.join(BASE_DIR, 'audit')

for d in (VAULT_DIR, EVIDENCE_DIR, REPORT_DIR, CASE_DIR, AUDIT_DIR):
    os.makedirs(d, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# =========================================================================
# THREAT INTELLIGENCE & HEURISTIC ENGINE (Threat & Attack Vector Detection)
# =========================================================================
THREAT_RULES = {
    'Phishing': [
        'verify your account', 'click here', 'login', 'urgent', 'password', 'otp',
        'suspended', 'confirm your account', 'kyc', 'verify now', 'bank alert',
        'account locked', 'update details', 'reactivate', 'claim prize', 'winner',
        'credential', 'billing error', 'payment declined'
    ],
    'Ransomware': [
        'ransom', 'decrypt', 'encrypted files', 'pay bitcoin', 'bitcoin', 'files encrypted',
        'decryption key', 'ransomware', 'all your data is locked', 'readme.txt',
        'restore your files', 'monero', 'tor browser', '.locked', '.crypto'
    ],
    'Malware-link': [
        'download', 'attachment', '.exe', '.apk', 'malware', 'trojan', 'install this app',
        'http://', 'https://', '.vbs', '.bat', '.scr', '.jar', 'invoice.exe', 'macro enabled',
        'enable content', 'powershell -enc', 'rundll32'
    ],
    'Social Engineering': [
        'send me otp', 'share otp', 'impersonating', 'pretend', 'secret', 'gift card',
        'act now', 'do not tell anyone', 'urgent call', 'help me transfer', 'friend in trouble',
        'customs officer', 'police officer asking money', 'tax refund', 'lottery department'
    ],
    'Web Application Attack': [
        'select * from', 'union select', '<script>', 'onerror=', '1=1', 'or 1=1',
        'drop table', 'exec xp_', '../../etc/passwd', 'eval(', 'document.cookie', 'sql injection',
        'xss', 'directory traversal'
    ],
    'Credential Stuffing/Brute Force': [
        'multiple failed logins', 'brute force', 'dictionary attack', 'unrecognized device login',
        'password spray', 'rapid login attempts', 'ip rotation login', 'auth failure surge'
    ],
    'DDoS/Botnet Activity': [
        'ddos', 'denial of service', 'traffic flood', 'syn flood', 'amplification attack',
        'botnet command', 'high packet rate', 'server unavailable', 'bandwidth exhaustion'
    ]
}

OFFENCE_RULES = {
    'Hacking/Unauthorized Access': [
        'hacked', 'unauthorized access', 'accessed my account', 'broke into',
        'login without permission', 'password changed', 'compromised server',
        'privilege escalation', 'backdoor installed'
    ],
    'Identity Theft': [
        'identity stolen', 'stolen identity', 'impersonated me', 'used my aadhaar',
        'used my pan', 'fake account in my name', 'personal details used', 'forged profile',
        'cloned account', 'synthetic identity'
    ],
    'Online Financial Fraud': [
        'scammed', 'fraud', 'upi', 'bank transfer', 'otp fraud', 'money stolen',
        'payment fraud', 'phishing payment', 'online scam', 'unauthorized transaction',
        'fake investment', 'task scam', 'credit card fraud', 'qr code scam'
    ],
    'Cyberstalking/Harassment': [
        'stalking', 'repeated messages', 'threatening messages', 'harassing me online',
        'online harassment', 'following me online', 'defamation', 'blackmail', 'leaked photos',
        'doxxing', 'morphed photos'
    ],
    'Corporate Data Theft/Exfiltration': [
        'stole my data', 'data stolen', 'copied files', 'database stolen',
        'downloaded confidential', 'leaked data', 'stolen files', 'source code leak',
        'customer data breach', 'data exfiltration', 'trade secret theft'
    ],
    'Cyber Terrorism/Critical Infrastructure': [
        'threat to nation', 'power grid attack', 'government website hacked',
        'cyber terrorism', 'sabotage infrastructure', 'critical information infrastructure',
        'denial of vital services'
    ],
    'SIM Swapping/Telecom Fraud': [
        'sim swapped', 'lost mobile network', 'sim cloning', 'unauthorized sim issued',
        'telecom fraud', 'sms diverted'
    ]
}

# Comprehensive Legal Mappings: IT Act 2000/2008, BNS 2023, DPDP Act 2023
LAW_MAP = {
    'Hacking/Unauthorized Access': {
        'it_act': 'Section 43 read with Section 66 of IT Act, 2000',
        'bns_ipc': 'Section 303 / 308 of BNS 2023 (Theft/Extortion) & Sec 378/424 IPC',
        'description': 'Penalizes unauthorized access, downloading, extraction of data, computer damage, and dishonest or fraudulent computer-related acts. Punishment: Up to 3 years imprisonment and/or fine up to ₹5,00,000.',
        'dpdp_act': 'Section 8 of DPDP Act, 2023 (Breach of Security Safeguards for Personal Data).',
        'reporting': 'File immediately on cybercrime.gov.in and report to CERT-In within 6 hours for critical cyber security incidents.'
    },
    'Identity Theft': {
        'it_act': 'Section 66C of IT Act, 2000',
        'bns_ipc': 'Section 319 of BNS 2023 (Cheating by Personation) & Sec 419 IPC',
        'description': 'Criminalizes fraudulent or dishonest use of electronic signatures, passwords, Aadhaar, PAN, or unique identification features of another person. Punishment: Up to 3 years imprisonment and fine up to ₹1,00,000.',
        'dpdp_act': 'Section 4 & 6 of DPDP Act 2023 (Unauthorized Processing & Identity Misuse).',
        'reporting': 'Report to nearest Cyber Police Station, notify UIDAI/Income Tax if Aadhaar/PAN is compromised, and report on cybercrime.gov.in.'
    },
    'Online Financial Fraud': {
        'it_act': 'Section 66D of IT Act, 2000',
        'bns_ipc': 'Section 318(4) of BNS 2023 (Cheating and Dishonestly Inducing Delivery of Property) & Sec 420 IPC',
        'description': 'Punishes cheating by personation by using computer resources or communication devices. Punishment: Up to 3 years imprisonment and fine up to ₹1,00,000.',
        'dpdp_act': 'Financial data breach liabilities under RBI Cyber Security Framework.',
        'reporting': 'IMMEDIATELY dial National Cyber Crime Helpline 1930 (Golden Hour freeze request), notify bank to freeze transaction/UTR, and file complaint on cybercrime.gov.in.'
    },
    'Cyberstalking/Harassment': {
        'it_act': 'Section 66E (Privacy violation) & Section 67/67A/67B of IT Act, 2000',
        'bns_ipc': 'Section 78 of BNS 2023 (Stalking) & Section 354D IPC',
        'description': 'Addresses electronic stalking, capturing/transmitting private images without consent, or publishing sexually explicit electronic content. Punishment: 3 to 7 years imprisonment depending on recurrence and section.',
        'dpdp_act': 'Protection of sensitive personal data against non-consensual disclosure.',
        'reporting': 'Preserve all screenshots, chat logs, profile URLs; report to National Cybercrime Portal under "Women/Child Crime Reporting" or nearest Cyber Cell.'
    },
    'Corporate Data Theft/Exfiltration': {
        'it_act': 'Section 43(b), Section 66, and Section 72A of IT Act, 2000',
        'bns_ipc': 'Section 316 of BNS 2023 (Criminal Breach of Trust) & Sec 406/420 IPC',
        'description': 'Punishes disclosure of information in breach of lawful contract or unauthorized extraction/copying of databases. Punishment: Up to 3 years imprisonment and/or fine up to ₹5,00,000.',
        'dpdp_act': 'Section 8(6) & Section 33 of DPDP Act 2023 (Data Fiduciary breach penalties up to ₹250 Crores).',
        'reporting': 'Mandatory breach notification to CERT-In (within 6 hours) and Data Protection Board of India under DPDP Act.'
    },
    'Cyber Terrorism/Critical Infrastructure': {
        'it_act': 'Section 66F of IT Act, 2000',
        'bns_ipc': 'Section 113 of BNS 2023 (Terrorist Acts) & UAPA provisions',
        'description': 'Punishes cyber terrorism acts intended to threaten unity, integrity, security of nation, or deny access to authorized personnel to critical infrastructure. Punishment: Life imprisonment.',
        'dpdp_act': 'National security exemptions under Section 17 of DPDP Act.',
        'reporting': 'Urgent escalation to NCIIPC (National Critical Information Infrastructure Protection Centre) and CERT-In.'
    },
    'SIM Swapping/Telecom Fraud': {
        'it_act': 'Section 66C & 66D of IT Act, 2000',
        'bns_ipc': 'Section 318 / 319 of BNS 2023 & Sec 419/420 IPC',
        'description': 'Fraudulent SIM issuance to intercept 2FA OTPs for financial takeover.',
        'dpdp_act': 'Telecom regulatory non-compliance under DoT/TRAI rules.',
        'reporting': 'Immediately contact telecom provider to block SIM, inform banks to deactivate net banking, and register complaint on 1930.'
    }
}

WIFI_RISK = {
    'Open': ('High', 95, 'No Wi-Fi encryption is configured. All unencrypted traffic (HTTP, DNS) is exposed to packet sniffing, ARP spoofing, and Evil Twin Man-In-The-Middle (MITM) attacks.'),
    'WEP': ('High', 90, 'WEP (Wired Equivalent Privacy) uses obsolete RC4 cipher with weak 24-bit IVs. It can be cracked in under 60 seconds using statistical FMS/Korek attacks.'),
    'WPA': ('Medium', 65, 'WPA (TKIP) is deprecated and vulnerable to Beck and Michael MIC attacks. Transition to WPA2/WPA3 immediately.'),
    'WPA2': ('Low', 25, 'WPA2-AES (CCMP) provides strong symmetric protection. Ensure robust passphrases to resist offline dictionary/KRACK attacks.'),
    'WPA3': ('Low', 10, 'WPA3 utilizes SAE (Simultaneous Authentication of Equals) dragonfly handshake and 192-bit cryptographic suite, providing forward secrecy and brute-force resistance.')
}

SENSITIVE_PERMISSIONS = {
    'android.permission.read_sms': 'SMS',
    'android.permission.receive_sms': 'SMS',
    'android.permission.send_sms': 'SMS',
    'android.permission.camera': 'Camera',
    'android.permission.record_audio': 'Microphone',
    'android.permission.access_fine_location': 'Precise Location',
    'android.permission.access_coarse_location': 'Approx Location',
    'android.permission.read_contacts': 'Contacts',
    'android.permission.read_call_log': 'Call Logs',
    'android.permission.read_phone_state': 'Device Phone State / IMEI',
    'android.permission.system_alert_window': 'Screen Overlay (Draw Over Apps)',
    'android.permission.bind_accessibility_service': 'Accessibility Service (Keylogging risk)',
    'android.permission.request_install_packages': 'Unknown Package Installation',
    'android.permission.read_external_storage': 'Storage Access',
    'android.permission.write_external_storage': 'Storage Write',
    'camera': 'Camera',
    'microphone': 'Microphone',
    'sms': 'SMS',
    'location': 'Location',
    'contacts': 'Contacts',
    'call_log': 'Call Logs',
    'phone': 'Phone',
    'storage': 'Storage'
}

DANGEROUS_PERMISSION_COMBOS = [
    {
        'name': 'Financial / OTP Interceptor Vector',
        'required': ['sms', 'storage'],
        'risk': 'CRITICAL',
        'description': 'App can read incoming 2FA SMS tokens and write data secretly, typical of banking trojans.'
    },
    {
        'name': 'Full Surveillance / Spyware Vector',
        'required': ['camera', 'microphone', 'location'],
        'risk': 'CRITICAL',
        'description': 'App can capture ambient audio, photos, and track real-time physical GPS coordinates.'
    },
    {
        'name': 'Screen Overlay & Keylogger Vector',
        'required': ['system_alert_window', 'bind_accessibility_service'],
        'risk': 'CRITICAL',
        'description': 'App can draw fake phishing overlays over banking apps and record all user keystrokes.'
    },
    {
        'name': 'Identity & Social Profiling Vector',
        'required': ['contacts', 'call_log', 'phone'],
        'risk': 'HIGH',
        'description': 'App exfiltrates personal phone book, call history, and device IMEI/Phone number.'
    }
]

RESPONSE_STEPS = {
    'Phishing': [
        'Do not click the suspicious link, download any attachments, or enter passwords.',
        'If credentials were submitted, immediately change passwords from a verified official device.',
        'Enable Hardware Security Key or Authenticator App MFA (avoid SMS MFA where possible).',
        'Preserve raw email headers, SMS screenshots, sender phone/email, and URL for forensics.',
        'Report incident to CERT-In (incident@cert-in.org.in) and cybercrime.gov.in.'
    ],
    'Ransomware': [
        'Instantly isolate the affected host from LAN, Wi-Fi, VPN, and paired cloud storage.',
        'Do NOT reboot or shut down abruptly if RAM dump/memory forensics is feasible.',
        'Identify ransomware extension, preserve the ransom note file and sample encrypted file without altering timestamps.',
        'Assess offline backup integrity; verify if decryption keys are available via NoMoreRansom.',
        'Notify organization Incident Response team and report to cybercrime authorities immediately.'
    ],
    'Malware-link': [
        'Disconnect the infected endpoint from the corporate/home network immediately.',
        'Extract file SHA-256 hash, file path, and process execution tree.',
        'Run offline endpoint detection and antimalware scans in safe mode.',
        'Revoke active session tokens and force password resets across associated accounts.',
        'Submit sample to sandbox/forensics vault for reverse engineering.'
    ],
    'Social Engineering': [
        'Immediately cease communication with the imposter or suspicious caller.',
        'Never disclose OTPs, banking PINs, remote access IDs (AnyDesk/TeamViewer), or passwords.',
        'Perform out-of-band verification through independently obtained official phone numbers.',
        'Preserve call recordings, WhatsApp/Telegram chat logs, and caller IDs.',
        'Report suspicious numbers to Chakshu portal (Sanchar Saathi) and cybercrime.gov.in.'
    ],
    'Hacking/Unauthorized Access': [
        'Terminate all active web/app sessions from account security settings.',
        'Reset account master password using a secure password generator.',
        'Audit authorized OAuth apps, API tokens, and recovery email/phone numbers for persistence.',
        'Inspect server/application access logs and preserve authentication logs.',
        'Report unauthorized breach under Section 43/66 IT Act.'
    ],
    'Identity Theft': [
        'File an emergency cyber complaint on cybercrime.gov.in and obtain acknowledgement number.',
        'Notify UIDAI (for Aadhaar misuse) and Credit Information Bureaus (CIBIL/Experian) to place a credit freeze.',
        'Request takedown of fake impersonating profiles with platform trust & safety teams.',
        'Keep certified copies of original identity documents and formal police GD/FIR.',
        'Publish a disclaimer if corporate/public identity was compromised.'
    ],
    'Online Financial Fraud': [
        'Call 1930 Cyber Fraud Helpline within the Golden Hour to freeze disputed UPI/Bank funds.',
        'Contact your bank\'s 24x7 fraud prevention desk to hotlist cards and freeze net banking.',
        'Document Transaction ID, UTR Number, Beneficiary Account/UPI VPA, and timestamped statements.',
        'Lodge formal complaint with Cyber Cell and obtain Cyber Crime Acknowledgement Number.',
        'Submit dispute form (Chargeback/Fraud Notification) with the bank within 3 working days.'
    ],
    'Cyberstalking/Harassment': [
        'Do not engage, negotiate, or retaliate against the stalker.',
        'Capture full-screen timestamped screenshots including browser URLs and message IDs.',
        'Block and report accounts across platforms after securing forensically sound evidence.',
        'Check personal device for unauthorized tracking apps, MDM profiles, or location sharing.',
        'Seek assistance from National Cybercrime Reporting Portal under Women/Child Protection.'
    ],
    'Corporate Data Theft/Exfiltration': [
        'Identify exfiltration vectors (Cloud storage, USB, Shadow IT, compromised service accounts).',
        'Revoke suspect credentials and restrict outbound data egress channels.',
        'Initiate digital forensics imaging of suspect endpoints and preserve SIEM/firewall logs.',
        'Notify CERT-In within 6 hours as mandated by CERT-In Cyber Security Directions.',
        'Evaluate DPDP Act 2023 compliance breach obligations.'
    ],
    'Unclear': [
        'Preserve all digital artifacts (messages, logs, files, timestamps) in pristine condition.',
        'Avoid clicking unverified links or disclosing credentials/identity information.',
        'Enable Multi-Factor Authentication across all critical email and financial services.',
        'Perform full malware scan using updated signature and heuristic engines.',
        'Seek guidance from authorized cybersecurity professionals or Cyber Cell authorities.'
    ]
}

# =========================================================================
# CORE UTILITY & CRYPTO HELPER FUNCTIONS
# =========================================================================
def get_fernet():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'wb') as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, 'rb') as f:
        return Fernet(f.read().strip())

def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()

def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def safe_name(name):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', str(name))[:80]

def _read_json(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default

def _write_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

# =========================================================================
# AUDIT & CHAIN OF CUSTODY (Cryptographic Hash-Chain)
# =========================================================================
def append_audit(incident, action, description, evidence_id=None):
    path = os.path.join(AUDIT_DIR, safe_name(incident) + '.json')
    events = _read_json(path, [])
    prev = events[-1]['hash'] if events else 'GENESIS'
    event = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'action': action,
        'incident_id': incident,
        'evidence_id': evidence_id,
        'description': description,
        'previous_hash': prev
    }
    canonical = json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
    event['hash'] = hashlib.sha256((prev.encode() + canonical)).hexdigest()
    events.append(event)
    _write_json(path, events)
    return event

def verify_audit_chain(incident):
    events = _read_json(os.path.join(AUDIT_DIR, safe_name(incident) + '.json'), [])
    prev = 'GENESIS'
    for e in events:
        copy = dict(e)
        h = copy.pop('hash', None)
        canonical = json.dumps(copy, sort_keys=True, separators=(',', ':')).encode()
        expected = hashlib.sha256((prev.encode() + canonical)).hexdigest()
        if h != expected or e.get('previous_hash') != prev:
            return {'valid': False, 'checked': len(events), 'broken_at': e.get('timestamp')}
        prev = h
    return {'valid': True, 'checked': len(events), 'broken_at': None}

def append_custody(meta, action, description):
    incident = meta['incident_id']
    folder = os.path.join(EVIDENCE_DIR, incident)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, 'chain_of_custody.json')
    entries = _read_json(path, [])
    entries.append({
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'action': action,
        'evidence_id': meta.get('evidence_id'),
        'incident_id': incident,
        'description': description
    })
    _write_json(path, entries)
    append_audit(incident, action, description, meta.get('evidence_id'))

def load_custody(incident):
    return _read_json(os.path.join(EVIDENCE_DIR, safe_name(incident), 'chain_of_custody.json'), [])

def load_evidence_meta(incident, evidence_id=None):
    folder = os.path.join(EVIDENCE_DIR, incident)
    if not os.path.isdir(folder):
        return None
    metas = []
    for fn in os.listdir(folder):
        if fn.endswith('.metadata.json'):
            try:
                metas.append(_read_json(os.path.join(folder, fn), {}))
            except Exception:
                pass
    if evidence_id:
        return next((m for m in metas if m.get('evidence_id') == evidence_id), None)
    if metas:
        return metas[0]
    legacy = os.path.join(folder, 'metadata.json')
    return _read_json(legacy, None) if os.path.isfile(legacy) else None

# =========================================================================
# CASE MANAGEMENT & IOC EXTRACTION
# =========================================================================
CASE_INDEX = os.path.join(CASE_DIR, 'cases.json')

def load_cases():
    return _read_json(CASE_INDEX, [])

def save_cases(cases):
    _write_json(CASE_INDEX, cases)

def refresh_case(incident):
    cases = load_cases()
    return next((c for c in cases if c.get('incident_id') == incident), None)

def add_timeline(case, action, description):
    case.setdefault('timeline', []).append({
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'action': action,
        'description': description
    })

def update_case_evidence(incident, meta):
    cases = load_cases()
    case = next((c for c in cases if c.get('incident_id') == incident), None)
    if not case:
        case = {
            'incident_id': incident,
            'timestamp': meta.get('created'),
            'input': '',
            'threat': {'classification': 'Evidence Preservation Only'},
            'offence': 'Unclear',
            'risk': 'Low',
            'score': 0,
            'severity': 'LOW',
            'priority': 'P4',
            'severity_reason': 'Direct forensic evidence intake record.',
            'legal': None,
            'response': RESPONSE_STEPS['Unclear'],
            'playbook': build_playbook('Unclear', 'Unclear'),
            'iocs': [],
            'mitre': [],
            'timeline': [],
            'response_progress': 0,
            'evidence': []
        }
        cases.append(case)
    case.setdefault('evidence', []).append(meta)
    add_timeline(case, 'Evidence Added', f"{meta.get('filename')} secured with ID {meta.get('evidence_id')}.")
    save_cases(cases)
    append_audit(incident, 'Evidence Linked', f"Evidence {meta.get('evidence_id')} registered to incident {incident}.", meta.get('evidence_id'))

def extract_iocs(text):
    text = text or ''
    found = []
    patterns = [
        ('IPv4', r'(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])'),
        ('URL', r'\bhttps?://[^\s<>"\']+'),
        ('Email', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        ('Crypto Wallet', r'\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90}|0x[a-fA-F0-9]{40})\b'),
        ('SHA-256', r'\b[a-fA-F0-9]{64}\b'),
        ('SHA-1', r'\b[a-fA-F0-9]{40}\b'),
        ('MD5', r'\b[a-fA-F0-9]{32}\b'),
        ('UPI VPA', r'\b[a-zA-Z0-9.\-_]{2,49}@[a-zA-Z]{2,}\b'),
        ('Domain', r'(?<![@\w.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w.-])')
    ]
    seen = set()
    for typ, pat in patterns:
        for val in re.findall(pat, text):
            val = val.rstrip('.,;:)]}')
            key = (typ, val.lower())
            if key not in seen:
                seen.add(key)
                found.append({'type': typ, 'value': val})
    return found

def map_mitre(threat, offence, iocs, text):
    c = threat.get('classification', '')
    o = offence or ''
    low = (text or '').lower()
    out = []
    def add(tid, name, tactic, why):
        out.append({'id': tid, 'name': name, 'tactic': tactic, 'why': why})
    
    if c == 'Phishing' or any(x in low for x in ['phishing', 'click here', 'verify your account', 'otp']):
        add('T1566', 'Phishing', 'Initial Access', 'Adversary uses targeted messages and fraudulent links to elicit credentials or access.')
    if 'http://' in low or 'https://' in low or any(i['type'] == 'URL' for i in iocs):
        add('T1566.002', 'Spearphishing Link', 'Initial Access', 'Suspicious URL pointing to adversary-controlled lure infrastructure.')
    if any(x in low for x in ['password', 'otp', 'credential', 'login', 'pin', 'aadhaar']):
        add('T1056.002', 'GUI Input Capture / Credential Harvesting', 'Credential Access', 'Adversary prompts victim to input secret authentication tokens or PII.')
    if c == 'Malware-link' or any(x in low for x in ['.exe', '.apk', 'trojan', 'malware', 'invoice.exe']):
        add('T1204.002', 'User Execution: Malicious File', 'Execution', 'Victim tricked into executing malicious payload, script, or installer.')
    if c == 'Ransomware' or any(x in low for x in ['ransom', 'encrypted files', 'decryption key']):
        add('T1486', 'Data Encrypted for Impact', 'Impact', 'Adversary encrypts target filesystem to interrupt availability and extort ransom.')
    if o == 'Hacking/Unauthorized Access' or any(x in low for x in ['hacked', 'unauthorized access', 'broke into']):
        add('T1078', 'Valid Accounts', 'Defense Evasion / Initial Access', 'Adversary leverages compromised user credentials to authenticate without authorization.')
    if o in ('Corporate Data Theft/Exfiltration', 'Hacking/Unauthorized Access') or any(x in low for x in ['stole my data', 'database stolen', 'leaked data']):
        add('T1005', 'Data from Local System', 'Collection', 'Adversary gathers sensitive data files, personal records, or source databases.')
        add('T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration', 'Data extracted from the perimeter to unauthorized third-party infrastructure.')
    if c == 'Web Application Attack' or any(x in low for x in ['select *', '<script>', 'sql injection', 'xss']):
        add('T1190', 'Exploit Public-Facing Application', 'Initial Access', 'Attacker leverages injection vulnerabilities in web endpoints.')
    return list({x['id']: x for x in out}.values())

def build_playbook(threat, offence):
    key = threat if threat in RESPONSE_STEPS else offence if offence in RESPONSE_STEPS else 'Unclear'
    return {
        'name': f"{key} Containment & Remediation Playbook",
        'steps': [{'id': i + 1, 'text': x, 'done': False} for i, x in enumerate(RESPONSE_STEPS.get(key, RESPONSE_STEPS['Unclear']))]
    }

def severity_priority(threat, offence, score, iocs, has_legal, evidence_count):
    points = score + min(15, len(iocs) * 3) + min(10, evidence_count * 2) + \
             (12 if threat.get('classification') in ('Ransomware', 'Malware-link', 'Web Application Attack') else 0) + \
             (10 if offence in ('Online Financial Fraud', 'Hacking/Unauthorized Access', 'Corporate Data Theft/Exfiltration', 'Cyber Terrorism/Critical Infrastructure') else 0)
    
    sev = 'CRITICAL' if points >= 90 else 'HIGH' if points >= 65 else 'MEDIUM' if points >= 40 else 'LOW'
    pri = {'CRITICAL': 'P1 (Immediate Containment)', 'HIGH': 'P2 (Urgent Triage)', 'MEDIUM': 'P3 (Standard Response)', 'LOW': 'P4 (Informational)'}[sev]
    
    reasons = []
    if score >= 65: reasons.append(f"High heuristic threat score ({score}/100).")
    if iocs: reasons.append(f"{len(iocs)} Indicator(s) of Compromise extracted.")
    if evidence_count: reasons.append(f"{evidence_count} digital evidence artifact(s) linked.")
    if threat.get('classification') in ('Ransomware', 'Malware-link'): reasons.append('Destructive malware payload behavior detected.')
    if offence in ('Online Financial Fraud', 'Corporate Data Theft/Exfiltration'): reasons.append(f"Financial or data exposure in {offence} requires rapid containment.")
    return {'severity': sev, 'priority': pri, 'reason': ' '.join(reasons) or 'Informational security incident.'}

def match_rules(text, rules):
    lower = text.lower()
    scores = {}
    triggers = {}
    for cat, kws in rules.items():
        hits = [kw for kw in kws if kw.lower() in lower]
        if hits:
            scores[cat] = len(hits)
            triggers[cat] = hits
    if not scores:
        return 'Unclear', [], 0
    best_score = max(scores.values())
    cat = next(c for c, s in scores.items() if s == best_score)
    score = min(99, 45 + best_score * 15 + max(0, best_score - 1) * 6)
    return cat, triggers[cat], score

def threat_analyze(text):
    cat, hits, score = match_rules(text, THREAT_RULES)
    if cat == 'Unclear':
        return {
            'classification': 'Informational / Low Threat Risk',
            'risk': 'Low',
            'score': 15,
            'triggers': [],
            'why': ['No direct attack signatures or malicious indicators matched standard heuristic rules.', 'Always exercise general caution when handling unsolicited communications.'],
            'response': RESPONSE_STEPS['Unclear']
        }
    risk = 'Critical' if score >= 85 else 'High' if score >= 65 else 'Medium'
    why = []
    if any(x in hits for x in ['urgent', 'act now', 'suspended', 'account locked']):
        why.append('High-pressure urgency or account-coercion psychological trigger detected.')
    if any(x in hits for x in ['password', 'otp', 'login', 'verify your account', 'kyc', 'credential']):
        why.append('Direct credential harvesting or personal identification capture attempt.')
    if any(x in hits for x in ['http://', 'https://', 'click here']):
        why.append('Hyperlink redirection indicator detected.')
    if any(x in hits for x in ['.exe', '.apk', 'download', 'attachment', 'powershell']):
        why.append('Executable payload download or script delivery mechanism identified.')
    if any(x in hits for x in ['bitcoin', 'ransom', 'encrypted files', 'monero']):
        why.append('Extortion / cryptographic ransom payload indicator identified.')
    if not why:
        why = ['Configured threat detection pattern match confirmed.']
    return {
        'classification': cat,
        'risk': risk,
        'score': score,
        'triggers': hits,
        'why': why,
        'response': RESPONSE_STEPS.get(cat, RESPONSE_STEPS['Unclear'])
    }

def offence_analyze(text):
    cat, hits, score = match_rules(text, OFFENCE_RULES)
    if cat == 'Unclear':
        score = 20
    risk = 'Critical' if score >= 85 else 'High' if score >= 65 else 'Medium' if score >= 40 else 'Low'
    return cat, hits, score, risk

def legal_lookup(category):
    if category not in LAW_MAP:
        return None
    info = LAW_MAP[category]
    return {
        'category': category,
        'it_act': info['it_act'],
        'bns_ipc': info['bns_ipc'],
        'dpdp_act': info.get('dpdp_act', 'DPDP Act, 2023 Provisions apply to data fiduciaries.'),
        'description': info['description'],
        'reporting': info['reporting']
    }

def unified_analysis(text):
    threat = threat_analyze(text)
    offence, hits, oscore, orisk = offence_analyze(text)
    score = max(threat['score'], oscore)
    if threat['classification'] == 'Informational / Low Threat Risk' and offence != 'Unclear':
        score = max(48, oscore)
    risk = 'Critical' if score >= 85 else 'High' if score >= 65 else 'Medium' if score >= 40 else 'Low'
    law = legal_lookup(offence) if offence != 'Unclear' else None
    incident_id = 'LG-' + datetime.now().strftime('%Y%m%d') + '-' + uuid.uuid4().hex[:6].upper()
    iocs = extract_iocs(text)
    mitre = map_mitre(threat, offence, iocs, text)
    severity = severity_priority(threat, offence, score, iocs, bool(law), 0)
    playbook = build_playbook(threat['classification'], offence)
    
    result = {
        'incident_id': incident_id,
        'timestamp': datetime.now().strftime('%d %b %Y, %I:%M %p'),
        'input': text,
        'threat': threat,
        'offence': offence,
        'offence_triggers': hits,
        'risk': risk,
        'score': score,
        'severity': severity['severity'],
        'priority': severity['priority'],
        'severity_reason': severity['reason'],
        'legal': law,
        'response': playbook['steps'],
        'playbook': playbook,
        'iocs': iocs,
        'mitre': mitre,
        'timeline': [],
        'response_progress': 0,
        'evidence': []
    }
    save_case(result, event='Incident Analyzed & Registered')
    return result

def save_case(result, event=None):
    cases = load_cases()
    case = next((c for c in cases if c.get('incident_id') == result.get('incident_id')), None)
    if case:
        case.update(result)
    else:
        case = result.copy()
        cases.append(case)
    if event:
        add_timeline(case, event, 'LexGuard Security Engine recorded this incident activity.')
    save_cases(cases)
    append_audit(result['incident_id'], event or 'Case Updated', 'Security case logged and cryptographically sealed.')

# =========================================================================
# DATA LOSS PREVENTION (DLP) & SENSITIVE DATA REDACTION
# =========================================================================
def luhn_verify(number_str):
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0

def verhoeff_check(num_str):
    # Verhoeff check table for Aadhaar validation
    d_table = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]
    p_table = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]
    c = 0
    clean = re.sub(r'\D', '', num_str)
    if len(clean) != 12:
        return False
    for i, item in enumerate(reversed(clean)):
        c = d_table[c][p_table[i % 8][int(item)]]
    return c == 0

def scan_and_redact_pii(text, mask_char='*'):
    if not text:
        return {'redacted_text': '', 'findings': [], 'total_redacted': 0}
    
    redacted = text
    findings = []
    
    # 1. Aadhaar (12 digits, often formatted as 4-4-4)
    aadhaar_matches = re.finditer(r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b', text)
    for m in aadhaar_matches:
        raw = m.group(0)
        clean = re.sub(r'\D', '', raw)
        valid = verhoeff_check(clean)
        masked = raw[:2] + mask_char * (len(raw) - 4) + raw[-2:]
        findings.append({'type': 'Aadhaar Number (UID)', 'raw': raw, 'valid': valid, 'masked': masked})
        redacted = redacted.replace(raw, f"[REDACTED_AADHAAR: {masked}]")

    # 2. Indian PAN Card (5 letters, 4 digits, 1 letter)
    pan_matches = re.finditer(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', redacted, re.I)
    for m in pan_matches:
        raw = m.group(0).upper()
        masked = raw[:2] + mask_char * 5 + raw[-2:]
        findings.append({'type': 'Permanent Account Number (PAN)', 'raw': raw, 'valid': True, 'masked': masked})
        redacted = redacted.replace(raw, f"[REDACTED_PAN: {masked}]")

    # 3. Credit / Debit Cards
    cc_matches = re.finditer(r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b', redacted)
    for m in cc_matches:
        raw = m.group(0)
        clean = re.sub(r'\D', '', raw)
        if luhn_verify(clean):
            masked = clean[:4] + mask_char * (len(clean) - 8) + clean[-4:]
            findings.append({'type': 'Credit/Debit Card (Luhn Validated)', 'raw': raw, 'valid': True, 'masked': masked})
            redacted = redacted.replace(raw, f"[REDACTED_CARD: {masked}]")

    # 4. API Keys & Secrets
    api_patterns = [
        (r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b', 'GitHub Access Token'),
        (r'\bAKIA[0-9A-Z]{16}\b', 'AWS Access Key ID'),
        (r'\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b', 'JWT Bearer Token'),
        (r'(?i)\b(?:api[_-]?key|secret|password|passwd|auth[_-]?token)\s*[:=]\s*["\']?([^\s"\']{6,})', 'Secret / Password Parameter')
    ]
    for pat, label in api_patterns:
        for m in re.finditer(pat, redacted):
            raw = m.group(0)
            masked = raw[:4] + mask_char * max(6, len(raw) - 6)
            findings.append({'type': label, 'raw': raw, 'valid': True, 'masked': masked})
            redacted = redacted.replace(raw, f"[REDACTED_{label.upper().replace(' ', '_')}]")

    # 5. Phone Numbers (Indian 10-digit format)
    phone_matches = re.finditer(r'(?:\+91[\s-]?)?[6-9]\d{9}\b', redacted)
    for m in phone_matches:
        raw = m.group(0)
        masked = raw[:4] + mask_char * 4 + raw[-2:]
        findings.append({'type': 'Phone Number', 'raw': raw, 'valid': True, 'masked': masked})
        redacted = redacted.replace(raw, f"[REDACTED_PHONE: {masked}]")

    return {
        'original_length': len(text),
        'redacted_length': len(redacted),
        'total_redacted': len(findings),
        'findings': findings,
        'redacted_text': redacted
    }

# =========================================================================
# CRYPTOGRAPHY ENGINES: AES-256, RSA-2048, MULTI-HASH & STEGANOGRAPHY
# =========================================================================
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def aes_encrypt(plaintext: str, passphrase: str, mode: str = 'GCM'):
    salt = secrets.token_bytes(16)
    key = derive_key(passphrase, salt)
    data = plaintext.encode('utf-8')
    
    if mode.upper() == 'GCM':
        iv = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        payload = salt + iv + tag + ciphertext
        return {
            'mode': 'AES-256-GCM (Authenticated)',
            'ciphertext_b64': base64.b64encode(payload).decode('utf-8'),
            'salt_hex': salt.hex(),
            'iv_hex': iv.hex(),
            'tag_hex': tag.hex(),
            'sha256_hash': hash_bytes(data)
        }
    else: # CBC with PKCS7
        iv = secrets.token_bytes(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        payload = salt + iv + ciphertext
        return {
            'mode': 'AES-256-CBC (PKCS7)',
            'ciphertext_b64': base64.b64encode(payload).decode('utf-8'),
            'salt_hex': salt.hex(),
            'iv_hex': iv.hex(),
            'sha256_hash': hash_bytes(data)
        }

def aes_decrypt(ciphertext_b64: str, passphrase: str, mode: str = 'GCM'):
    raw = base64.b64decode(ciphertext_b64)
    salt = raw[:16]
    key = derive_key(passphrase, salt)
    
    if mode.upper() == 'GCM':
        iv = raw[16:28]
        tag = raw[28:44]
        ciphertext = raw[44:]
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode('utf-8')
    else:
        iv = raw[16:32]
        ciphertext = raw[32:]
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode('utf-8')

# Steganography Engine (LSB Embedding into PNG)
def stego_embed(img_bytes: bytes, secret_text: str) -> bytes:
    image = Image.open(io.BytesIO(img_bytes)).convert('RGB')
    encoded = image.copy()
    width, height = image.size
    
    # Prefix secret with length delimiter
    secret_data = f"LEXGUARD::{len(secret_text)}::{secret_text}".encode('utf-8')
    binary_secret = ''.join(format(byte, '08b') for byte in secret_data)
    req_pixels = len(binary_secret)
    
    if req_pixels > width * height * 3:
        raise ValueError(f"Image too small. Required capacity: {req_pixels} bits; Available: {width * height * 3} bits.")
    
    data_idx = 0
    pixels = encoded.load()
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            
            if data_idx < len(binary_secret):
                r = (r & ~1) | int(binary_secret[data_idx])
                data_idx += 1
            if data_idx < len(binary_secret):
                g = (g & ~1) | int(binary_secret[data_idx])
                data_idx += 1
            if data_idx < len(binary_secret):
                b = (b & ~1) | int(binary_secret[data_idx])
                data_idx += 1
                
            pixels[x, y] = (r, g, b)
            if data_idx >= len(binary_secret):
                break
        if data_idx >= len(binary_secret):
            break
            
    out_io = io.BytesIO()
    encoded.save(out_io, format='PNG')
    return out_io.getvalue()

def stego_extract(img_bytes: bytes) -> str:
    image = Image.open(io.BytesIO(img_bytes)).convert('RGB')
    width, height = image.size
    pixels = image.load()
    
    bit_str = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bit_str.append(str(r & 1))
            bit_str.append(str(g & 1))
            bit_str.append(str(b & 1))
            if len(bit_str) > 200000: # safety cap
                break
        if len(bit_str) > 200000:
            break
            
    all_bits = ''.join(bit_str)
    all_bytes = bytearray()
    for i in range(0, len(all_bits), 8):
        byte = all_bits[i:i+8]
        if len(byte) == 8:
            all_bytes.append(int(byte, 2))
            
    raw_text = all_bytes.decode('utf-8', errors='ignore')
    if "LEXGUARD::" not in raw_text:
        raise ValueError("No LexGuard steganographic payload detected in image.")
    
    parts = raw_text.split("LEXGUARD::", 1)[1]
    if "::" not in parts:
        raise ValueError("Corrupted steganographic header.")
        
    length_str, rest = parts.split("::", 1)
    secret_len = int(length_str)
    return rest[:secret_len]

# =========================================================================
# FLASK HTTP ROUTES & API ENDPOINTS
# =========================================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.post('/api/analyze')
def api_analyze():
    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Please enter an incident or suspicious message.'}), 400
    return jsonify(unified_analysis(text))

@app.post('/api/threat')
def api_threat():
    text = ((request.get_json(silent=True) or {}).get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Text is required.'}), 400
    return jsonify(threat_analyze(text))

@app.post('/api/offence')
def api_offence():
    text = ((request.get_json(silent=True) or {}).get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Incident description is required.'}), 400
    cat, hits, score, risk = offence_analyze(text)
    return jsonify({'classification': cat, 'triggers': hits, 'score': score, 'risk': risk, 'legal': legal_lookup(cat)})

# --- DLP & Privacy Endpoints ---
@app.post('/api/dlp/scan')
def api_dlp_scan():
    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Please provide text for DLP scanning.'}), 400
    return jsonify(scan_and_redact_pii(text))

@app.post('/api/shredder/simulate')
def api_shredder():
    data = request.get_json(silent=True) or {}
    filename = safe_name(data.get('filename') or 'sensitive_records.dat')
    file_size_kb = min(1024, max(1, int(data.get('size_kb', 64))))
    passes = min(7, max(1, int(data.get('passes', 3))))
    
    # Simulate DoD 5220.22-M 3-pass sanitization
    pass_logs = []
    total_bytes = file_size_kb * 1024
    initial_entropy = 7.82 # random original
    
    for p in range(1, passes + 1):
        if p == 1:
            pattern = '0x00 (All Zeros Overwrite)'
            entropy = 0.0
        elif p == 2:
            pattern = '0xFF (All Ones Overwrite)'
            entropy = 0.0
        elif p == 3:
            pattern = 'Cryptographic Pseudo-Random Byte Stream'
            entropy = 7.99
        else:
            pattern = f"Pass {p} Alternating Bit Complement"
            entropy = 4.0
        
        pass_logs.append({
            'pass': p,
            'pattern': pattern,
            'bytes_overwritten': total_bytes,
            'resulting_entropy': entropy,
            'status': 'VERIFIED WIPED'
        })
        
    return jsonify({
        'filename': filename,
        'standard': 'DoD 5220.22-M (National Industrial Security Program Operating Manual)',
        'passes_completed': passes,
        'total_bytes_sanitized': total_bytes,
        'residual_magnetic_trace': '< 0.0001% (Unrecoverable)',
        'logs': pass_logs,
        'certificate': {
            'sanitization_id': 'SHRED-' + uuid.uuid4().hex[:8].upper(),
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'verdict': 'SECURELY DESTROYED & PURGED'
        }
    })

# --- Cryptography Endpoints ---
@app.post('/api/crypto')
def api_crypto():
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    text = data.get('text', '')
    f = get_fernet()
    try:
        if action == 'encrypt':
            if not text: raise ValueError('Text is empty.')
            token = f.encrypt(text.encode()).decode()
            return jsonify({'result': token, 'hash': hash_bytes(text.encode())})
        if action == 'decrypt':
            plain = f.decrypt(text.encode()).decode()
            return jsonify({'result': plain, 'hash': hash_bytes(plain.encode())})
        return jsonify({'error': 'Invalid crypto action.'}), 400
    except (InvalidToken, UnicodeDecodeError, ValueError) as e:
        return jsonify({'error': str(e) or 'Invalid encrypted text/key.'}), 400

@app.post('/api/crypto/aes')
def api_crypto_aes():
    data = request.get_json(silent=True) or {}
    action = data.get('action', 'encrypt')
    text = data.get('text', '')
    passphrase = data.get('passphrase', '')
    mode = data.get('mode', 'GCM')
    
    if not passphrase:
        return jsonify({'error': 'Secret passphrase is required for AES-256 derivation.'}), 400
    if not text:
        return jsonify({'error': 'Text is required.'}), 400
        
    try:
        if action == 'encrypt':
            res = aes_encrypt(text, passphrase, mode)
            return jsonify(res)
        elif action == 'decrypt':
            decrypted = aes_decrypt(text, passphrase, mode)
            return jsonify({'plaintext': decrypted, 'sha256_hash': hash_bytes(decrypted.encode('utf-8'))})
        return jsonify({'error': 'Invalid action.'}), 400
    except Exception as e:
        return jsonify({'error': f"AES Operation Failed: {str(e)}"}), 400

@app.post('/api/crypto/rsa/generate')
def api_rsa_generate():
    key_size = int((request.get_json(silent=True) or {}).get('key_size', 2048))
    if key_size not in (2048, 3072, 4096):
        key_size = 2048
        
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    fingerprint = hashlib.sha256(pub_pem.encode()).hexdigest()
    return jsonify({
        'key_size': key_size,
        'public_key_pem': pub_pem,
        'private_key_pem': priv_pem,
        'public_key_fingerprint': f"SHA256:{fingerprint[:32]}..."
    })

@app.post('/api/crypto/rsa/sign_verify')
def api_rsa_sign_verify():
    data = request.get_json(silent=True) or {}
    action = data.get('action', 'sign')
    message = data.get('message', '').encode('utf-8')
    
    try:
        if action == 'sign':
            priv_pem = data.get('private_key_pem', '').strip().encode('utf-8')
            private_key = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
            signature = private_key.sign(
                message,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return jsonify({
                'signature_b64': base64.b64encode(signature).decode('utf-8'),
                'algorithm': 'RSA-PSS with SHA-256',
                'digest_sha256': hashlib.sha256(message).hexdigest()
            })
        elif action == 'verify':
            pub_pem = data.get('public_key_pem', '').strip().encode('utf-8')
            sig_b64 = data.get('signature_b64', '').strip()
            public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
            sig_bytes = base64.b64decode(sig_b64)
            
            try:
                public_key.verify(
                    sig_bytes,
                    message,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return jsonify({'valid': True, 'message': 'Cryptographic Digital Signature is VALID & Intact.'})
            except Exception:
                return jsonify({'valid': False, 'message': 'Signature INVALID or document was tampered with.'})
    except Exception as e:
        return jsonify({'error': f"RSA Operation failed: {str(e)}"}), 400

@app.post('/api/crypto/multihash')
def api_multihash():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    raw = text.encode('utf-8')
    
    h_sha256 = hashlib.sha256(raw).hexdigest()
    h_sha512 = hashlib.sha512(raw).hexdigest()
    h_sha3_256 = hashlib.sha3_256(raw).hexdigest()
    h_blake2b = hashlib.blake2b(raw).hexdigest()
    h_md5 = hashlib.md5(raw).hexdigest()
    
    # Entropy calculation
    counts = [0] * 256
    for b in raw: counts[b] += 1
    entropy = 0.0
    if len(raw) > 0:
        entropy = -sum((c / len(raw)) * math.log2(c / len(raw)) for c in counts if c)
        
    return jsonify({
        'length_bytes': len(raw),
        'entropy_bits': round(entropy, 3),
        'hashes': {
            'SHA-256': {'digest': h_sha256, 'security': 'High (Standard NIST)', 'bits': 256},
            'SHA-512': {'digest': h_sha512, 'security': 'Ultra-High', 'bits': 512},
            'SHA3-256 (Keccak)': {'digest': h_sha3_256, 'security': 'Next-Gen Quantum Resistant', 'bits': 256},
            'BLAKE2b': {'digest': h_blake2b, 'security': 'High (Ultra-Fast)', 'bits': 512},
            'MD5 (Legacy)': {'digest': h_md5, 'security': 'BROKEN (Collision Prone - Do NOT use for security)', 'bits': 128}
        }
    })

@app.post('/api/crypto/dh')
def api_diffie_hellman():
    # Demonstrates Diffie-Hellman Key Exchange parameters
    p = 23 # Prime
    g = 5  # Base / Generator
    alice_private = secrets.randbelow(15) + 1
    bob_private = secrets.randbelow(15) + 1
    
    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)
    
    alice_shared = pow(bob_public, alice_private, p)
    bob_shared = pow(alice_public, bob_private, p)
    
    return jsonify({
        'prime_p': p,
        'generator_g': g,
        'alice': {'private_a': alice_private, 'public_A': alice_public},
        'bob': {'private_b': bob_private, 'public_B': bob_public},
        'computed_shared_secret': alice_shared,
        'match': alice_shared == bob_shared,
        'explanation': f"Alice sends A={alice_public} over public wire. Bob sends B={bob_public}. Both compute key K = {alice_shared} without eavesdroppers discovering private keys."
    })

# --- Steganography Endpoints ---
@app.post('/api/stego/hide')
def api_stego_hide():
    file = request.files.get('image')
    secret = request.form.get('secret', '').strip()
    if not file or not secret:
        return jsonify({'error': 'Image file and secret message are required.'}), 400
        
    try:
        img_bytes = file.read()
        stego_png = stego_embed(img_bytes, secret)
        return send_file(
            io.BytesIO(stego_png),
            mimetype='image/png',
            as_attachment=True,
            download_name='stego_carrier.png'
        )
    except Exception as e:
        return jsonify({'error': f"Steganography embedding failed: {str(e)}"}), 400

@app.post('/api/stego/extract')
def api_stego_extract():
    file = request.files.get('image')
    if not file:
        return jsonify({'error': 'Please upload a carrier image.'}), 400
    try:
        secret = stego_extract(file.read())
        return jsonify({'secret': secret, 'status': 'SUCCESS', 'sha256': hash_bytes(secret.encode())})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# --- Wireless & Mobile Security Endpoints ---
@app.post('/api/wifi')
def api_wifi():
    data = request.get_json(silent=True) or {}
    kind = data.get('type')
    if kind not in WIFI_RISK:
        return jsonify({'error': 'Invalid Wi-Fi type.'}), 400
    risk, score, explanation = WIFI_RISK[kind]
    
    # Advanced threat indicators
    heuristics = []
    if kind == 'Open':
        heuristics.append('Active Evil Twin / Wi-Fi Pineapple threat exposure')
        heuristics.append('Vulnerable to DNS hijacking and SSL-Strip credential theft')
    elif kind == 'WEP':
        heuristics.append('Vulnerable to immediate IV collision cracking (aircrack-ng)')
    elif kind == 'WPA':
        heuristics.append('TKIP MIC vulnerability (Beck-Tews attack vector)')
    elif kind == 'WPA2':
        heuristics.append('Secure against eavesdropping; subject to 4-way handshake dictionary attacks if weak PSK')
    elif kind == 'WPA3':
        heuristics.append('Protected by Simultaneous Authentication of Equals (SAE) with forward secrecy')

    return jsonify({
        'type': kind,
        'risk': risk,
        'score': score,
        'explanation': explanation,
        'heuristics': heuristics
    })

@app.post('/api/permissions')
def api_permissions():
    raw = (request.get_json(silent=True) or {}).get('permissions', '')
    raw_list = [p.strip().lower().replace(' ', '_') for p in raw.split(',') if p.strip()]
    
    sensitive = []
    normalized_keys = set()
    for p in raw_list:
        for sk, label in SENSITIVE_PERMISSIONS.items():
            if sk in p or p in sk:
                sensitive.append(label)
                normalized_keys.add(sk.split('.')[-1])
                
    sensitive = sorted(list(set(sensitive)))
    count = len(sensitive)
    
    triggered_combos = []
    for combo in DANGEROUS_PERMISSION_COMBOS:
        req = combo['required']
        if all(any(r in k for k in normalized_keys) for r in req):
            triggered_combos.append(combo)
            
    score = min(100, count * 15 + (len(triggered_combos) * 20))
    risk = 'CRITICAL' if (len(triggered_combos) > 0 or count >= 5) else 'HIGH' if count >= 3 else 'MEDIUM' if count >= 1 else 'LOW'
    
    return jsonify({
        'risk': risk,
        'score': score,
        'sensitive': sensitive,
        'combos_detected': triggered_combos,
        'explanation': 'Evaluated against Android Security Risk Matrix & Dangerous Permission Combinations.'
    })

# --- Locker / Encrypted Notes ---
@app.post('/api/locker/save')
def locker_save():
    data = request.get_json(silent=True) or {}
    name = safe_name(data.get('name', ''))
    note = data.get('note', '')
    if not name or not note:
        return jsonify({'error': 'Name and note are required.'}), 400
    path = os.path.join(VAULT_DIR, name + '.vault')
    payload = json.dumps({'note': note, 'created': datetime.now().isoformat()}).encode()
    with open(path, 'wb') as f:
        f.write(get_fernet().encrypt(payload))
    return jsonify({'message': 'Encrypted zero-knowledge vault saved.', 'file': name + '.vault', 'hash': hash_file(path)})

@app.post('/api/locker/get')
def locker_get():
    name = safe_name((request.get_json(silent=True) or {}).get('name', ''))
    path = os.path.join(VAULT_DIR, name + '.vault')
    if not os.path.isfile(path):
        return jsonify({'error': 'Vault file not found.'}), 404
    try:
        with open(path, 'rb') as f:
            data = get_fernet().decrypt(f.read())
        payload = json.loads(data.decode())
        return jsonify({'note': payload.get('note', ''), 'hash': hash_file(path)})
    except Exception:
        return jsonify({'error': 'Could not decrypt this vault.'}), 400

# --- Evidence Vault & Tamper Verification ---
@app.route('/api/evidence', methods=['POST'])
def evidence():
    file = request.files.get('file')
    note = request.form.get('note', '').strip()
    incident = safe_name(request.form.get('incident_id', '').strip())
    
    if not file or not file.filename:
        return jsonify({'error': 'Choose an evidence file.'}), 400
    if not incident:
        incident = 'LG-' + datetime.now().strftime('%Y%m%d') + '-' + uuid.uuid4().hex[:6].upper()
    if not re.fullmatch(r'LG-[A-Z0-9_-]+', incident):
        return jsonify({'error': 'Invalid Incident ID format.'}), 400
        
    original = safe_name(file.filename)
    folder = os.path.join(EVIDENCE_DIR, incident)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, original)
    if os.path.exists(path):
        stem, ext = os.path.splitext(original)
        original = f"{stem}_{uuid.uuid4().hex[:6]}{ext}"
        path = os.path.join(folder, original)
        
    file.save(path)
    digest = hash_file(path)
    meta = {
        'evidence_id': 'EV-' + uuid.uuid4().hex[:8].upper(),
        'incident_id': incident,
        'filename': original,
        'file_type': mimetypes.guess_type(original)[0] or 'application/octet-stream',
        'sha256': digest,
        'size': os.path.getsize(path),
        'created': datetime.now().isoformat(timespec='seconds'),
        'note': note,
        'status': 'VERIFIED INTACT',
        'original_hash': digest
    }
    meta_path = os.path.join(folder, original + '.metadata.json')
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)
    with open(os.path.join(folder, 'metadata.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)
        
    append_custody(meta, 'Evidence Ingested', f"Evidence secured with SHA-256 seal: {digest}")
    update_case_evidence(incident, meta)
    return jsonify(meta)

@app.post('/api/evidence/verify')
def evidence_verify():
    data = request.get_json(silent=True) or {}
    incident = safe_name(data.get('incident_id', ''))
    evidence_id = data.get('evidence_id')
    meta = load_evidence_meta(incident, evidence_id)
    if not meta:
        return jsonify({'error': 'Evidence record not found.'}), 404
        
    path = os.path.join(EVIDENCE_DIR, incident, meta['filename'])
    if not os.path.isfile(path):
        return jsonify({'error': 'Evidence file is missing on storage.', 'status': 'FILE MISSING'}), 404
        
    current = hash_file(path)
    match = current == meta.get('original_hash', meta.get('sha256'))
    meta['sha256_current'] = current
    meta['status'] = 'VERIFIED INTACT' if match else 'INTEGRITY FAILED - TAMPER DETECTED'
    
    if not match:
        append_custody(meta, 'Integrity Verification Failed', f"Hash mismatch detected! Current: {current} vs Recorded: {meta.get('original_hash')}")
    else:
        append_custody(meta, 'Integrity Verified', f"SHA-256 seal verified matching original ({current}).")
        
    with open(os.path.join(EVIDENCE_DIR, incident, meta['filename'] + '.metadata.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)
        
    return jsonify({
        'match': match,
        'original': meta.get('original_hash', meta.get('sha256')),
        'current': current,
        'filename': meta['filename'],
        'evidence_id': meta.get('evidence_id'),
        'status': meta['status']
    })

@app.get('/api/evidence/list')
def evidence_list():
    records = []
    if not os.path.isdir(EVIDENCE_DIR):
        return jsonify(records)
    for incident in sorted(os.listdir(EVIDENCE_DIR), reverse=True):
        folder = os.path.join(EVIDENCE_DIR, incident)
        if not os.path.isdir(folder):
            continue
        for fn in os.listdir(folder):
            if fn.endswith('.metadata.json') or fn == 'metadata.json':
                try:
                    with open(os.path.join(folder, fn), encoding='utf-8') as f:
                        meta = json.load(f)
                    if fn == 'metadata.json' and not meta.get('evidence_id'):
                        meta['evidence_id'] = 'LEGACY-' + hashlib.sha1((incident + meta.get('filename', '')).encode()).hexdigest()[:8].upper()
                        meta.setdefault('original_hash', meta.get('sha256'))
                        meta.setdefault('status', 'RECORDED')
                    records.append(meta)
                except Exception:
                    pass
    return jsonify(records[:60])

@app.get('/api/evidence/<incident>/custody')
def evidence_custody(incident):
    return jsonify(load_custody(safe_name(incident)))

# =========================================================================
# LEGAL REPORTING & COURT-ADMISSIBLE FORENSIC CERTIFICATES
# =========================================================================
@app.post('/api/report/fir')
def api_generate_fir_text():
    data = request.get_json(silent=True) or {}
    incident_id = data.get('incident_id', 'LG-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    complainant = data.get('complainant_name', '[Complainant / Organization Name]')
    contact = data.get('complainant_contact', '[Phone / Email]')
    suspect_info = data.get('suspect_info', 'Unknown online entity / IP / Phone / VPA')
    financial_loss = data.get('financial_loss', 'N/A')
    offence = data.get('offence', 'Online Financial Fraud')
    threat = data.get('threat', {}).get('classification', 'Phishing / Malware')
    incident_desc = data.get('input', '')
    iocs = data.get('iocs', [])
    law = data.get('legal') or legal_lookup(offence) or {}
    
    it_act_sec = law.get('it_act', 'Section 43 read with Section 66 of Information Technology Act, 2000')
    bns_sec = law.get('bns_ipc', 'Section 318(4) of Bharatiya Nyaya Sanhita (BNS), 2023')
    
    fir_template = f"""================================================================================
FORMAL CYBER CRIME POLICE COMPLAINT / FIR APPLICATION
Under Section 154 / 173 of Code of Criminal Procedure / Bharatiya Nagarik Suraksha Sanhita (BNSS)
To be submitted at: Cyber Crime Police Station / National Cyber Crime Reporting Portal (cybercrime.gov.in)
================================================================================

DATE: {datetime.now().strftime('%d %B %Y')}
COMPLAINT TRACKING REFERENCE: {incident_id}

TO,
THE OFFICER-IN-CHARGE / INSPECTOR OF POLICE,
CYBER CRIME POLICE STATION.

SUBJECT: Formal complaint regarding {offence} under {it_act_sec} and {bns_sec}.

1. COMPLAINANT DETAILS:
   - Name / Organization: {complainant}
   - Contact Number / Email: {contact}

2. NATURE OF CYBER CRIME / OFFENCE:
   - Primary Offence: {offence}
   - Threat Classification: {threat}
   - Applicable Provisions of Law:
     * {it_act_sec}
     * {bns_sec}

3. FINANCIAL LOSS / DAMAGE INVOLVED:
   - Disputed Amount / Loss: {financial_loss}

4. SUMMARY OF INCIDENT & FACTS:
{incident_desc or 'Victim was targeted through electronic communications and malicious lures resulting in unauthorized digital interference.'}

5. TECHNICAL FORENSIC INDICATORS & SUSPECT LEADS (IOCs):
{chr(10).join(f"   * [{ioc.get('type')}]: {ioc.get('value')}" for ioc in iocs) if iocs else '   * Technical logs and sender handles attached in forensic case bundle.'}

6. SUSPECT IDENTIFIERS (IF KNOWN):
   - {suspect_info}

7. PRAYER / RELIEF SOUGHT:
   It is respectfully requested that:
   a) A formal First Information Report (FIR) / Complaint be registered under the aforementioned sections.
   b) Immediate notice under Section 91 CrPC / Section 94 BNSS be served to the relevant intermediary, payment gateway, telecom operator, or domain registrar to freeze the suspect accounts and preserve IP/CDR server logs.
   c) Necessary lawful action be initiated against the culprits.

DECLARATION:
I hereby affirm that the information stated above is true and authentic to the best of my knowledge and electronic records.

Digitally generated via LexGuard Cyber Defense Platform.
Forensic Hash Seal: {hash_bytes((incident_id + incident_desc).encode())}
"""
    return jsonify({'fir_text': fir_template, 'incident_id': incident_id})

@app.post('/api/report/section65b')
def api_generate_65b_certificate():
    data = request.get_json(silent=True) or {}
    incident_id = data.get('incident_id', 'LG-' + datetime.now().strftime('%Y%m%d'))
    examiner = data.get('examiner_name', 'Cyber Defense & Forensics Examiner')
    org = data.get('organization', 'LexGuard Forensics Unit')
    evidence_list = data.get('evidence', [])
    
    cert_text = f"""================================================================================
CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872 /
SECTION 63 OF BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023
(For Admissibility of Electronic Records in Court of Law)
================================================================================

CERTIFICATE ID: CERT65B-{uuid.uuid4().hex[:8].upper()}
INCIDENT CASE REF: {incident_id}
DATE OF ISSUANCE: {datetime.now().strftime('%d %B %Y, %I:%M %p')}

I, {examiner}, designated at {org}, do hereby certify and affirm under solemn declaration that:

1. I am in lawful control and operation of the computer systems, servers, and digital devices through which the electronic records related to Incident Ref: {incident_id} were extracted, processed, and preserved.

2. During the relevant period, the electronic devices and cryptographic preservation systems operated regularly and properly. There was no operational malfunction or tampering that would affect the accuracy or integrity of the electronic output.

3. The electronic records and digital artifacts listed below were hashed at intake using cryptographic standard SHA-256 to ensure absolute chain-of-custody and prevent bit-level alteration:

ELECTRONIC EVIDENCE INVENTORY & INTEGRITY SEALS:
--------------------------------------------------------------------------------
{chr(10).join(f"• ID: {ev.get('evidence_id')} | File: {ev.get('filename')} | Size: {ev.get('size', 0)} Bytes\n  SHA-256: {ev.get('original_hash', ev.get('sha256'))}\n  Verification Status: {ev.get('status', 'VERIFIED INTACT')}" for ev in evidence_list) if evidence_list else '• Case Master Record Hash: ' + hash_bytes(incident_id.encode())}
--------------------------------------------------------------------------------

4. The information contained in this electronic output accurately reproduces the digital evidence in our secure custody.

5. This certificate is executed in compliance with Section 65B(4) of the Indian Evidence Act / Section 63(4) of BSA 2023.

AFFIRMED & CRYPTOGRAPHICALLY SEALED:
Signature & Seal: __________________________
SHA-256 Certificate Seal: {hash_bytes((incident_id + examiner + datetime.now().isoformat()).encode())}
"""
    return jsonify({'certificate_text': cert_text, 'incident_id': incident_id})

# --- PDF Generation Endpoint ---
@app.route('/api/report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "No incident data received"}), 400

        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.lib.units import mm

        incident_id = data.get("incident_id", "LG-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        filename = f"{incident_id}.pdf"
        filepath = os.path.join(REPORT_DIR, filename)

        threat = data.get("threat", {})
        threat_classification = threat.get("classification", "Unknown") if isinstance(threat, dict) else str(threat)
        reasons = threat.get("why", []) if isinstance(threat, dict) else []
        indicators = threat.get("triggers", []) if isinstance(threat, dict) else []
        offence = data.get("offence", "Unclear")
        risk = data.get("risk", "Medium")
        score = data.get("score", 0)
        recommendations = data.get("response", [])
        legal = data.get("legal", {}) or {}
        iocs = data.get("iocs", [])
        mitre = data.get("mitre", [])
        severity = data.get("severity", "MEDIUM")
        priority = data.get("priority", "P3")
        timeline = data.get("timeline", [])
        evidence_items = data.get("evidence", [])

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=14 * mm,
            leftMargin=14 * mm,
            topMargin=14 * mm,
            bottomMargin=14 * mm
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("RTitle", parent=styles["Title"], fontSize=20, leading=24, alignment=TA_CENTER, textColor=colors.HexColor("#0f172a"))
        subtitle_style = ParagraphStyle("RSub", parent=styles["Normal"], fontSize=9, leading=12, alignment=TA_CENTER, textColor=colors.HexColor("#64748b"))
        heading_style = ParagraphStyle("RHead", parent=styles["Heading2"], fontSize=11, leading=14, spaceBefore=10, spaceAfter=5, textColor=colors.HexColor("#1e293b"))
        body_style = ParagraphStyle("RBody", parent=styles["Normal"], fontSize=8.5, leading=12, spaceAfter=4, textColor=colors.HexColor("#334155"))
        code_style = ParagraphStyle("RCode", parent=styles["Normal"], fontSize=7.5, leading=10, fontName="Courier", textColor=colors.HexColor("#0f172a"))
        small_style = ParagraphStyle("RSmall", parent=styles["Normal"], fontSize=7.5, leading=10, textColor=colors.HexColor("#64748b"))

        story = []
        story.append(Paragraph("<b>LEXGUARD CYBER DEFENSE &amp; FORENSICS PLATFORM</b>", title_style))
        story.append(Paragraph("INCIDENT INVESTIGATION, THREAT INTELLIGENCE &amp; LEGAL RESPONSE REPORT", subtitle_style))
        story.append(Spacer(1, 8))

        meta_data = [
            [Paragraph("<b>Incident Identifier</b>", body_style), Paragraph(str(incident_id), code_style), Paragraph("<b>Generation Timestamp</b>", body_style), Paragraph(datetime.now().strftime("%d %b %Y, %I:%M %p"), body_style)],
            [Paragraph("<b>Threat Classification</b>", body_style), Paragraph(f"<b>{threat_classification}</b>", body_style), Paragraph("<b>Offence Category</b>", body_style), Paragraph(f"<b>{offence}</b>", body_style)],
            [Paragraph("<b>Overall Risk Level</b>", body_style), Paragraph(f"<b>{str(risk).upper()} ({score}/100)</b>", body_style), Paragraph("<b>Severity / Priority</b>", body_style), Paragraph(f"<b>{severity} / {priority}</b>", body_style)]
        ]
        t_meta = Table(meta_data, colWidths=[38 * mm, 52 * mm, 42 * mm, 48 * mm])
        t_meta.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_meta)
        story.append(Spacer(1, 8))

        # Threat Assessment
        story.append(Paragraph("<b>1. THREAT INTELLIGENCE &amp; DETECTION ANALYSIS</b>", heading_style))
        if reasons:
            for r in reasons: story.append(Paragraph(f"• {str(r)}", body_style))
        if indicators:
            story.append(Paragraph(f"<b>Triggered Signatures:</b> {', '.join(str(x) for x in indicators)}", body_style))

        # MITRE ATT&CK Matrix
        if mitre:
            story.append(Paragraph("<b>2. MITRE ATT&amp;CK TACTICS &amp; TECHNIQUES</b>", heading_style))
            m_rows = [[Paragraph("<b>Technique ID</b>", body_style), Paragraph("<b>Technique Name</b>", body_style), Paragraph("<b>Tactic</b>", body_style)]]
            for m in mitre:
                m_rows.append([Paragraph(str(m.get("id")), code_style), Paragraph(str(m.get("name")), body_style), Paragraph(str(m.get("tactic", "Execution")), body_style)])
            t_mitre = Table(m_rows, colWidths=[35 * mm, 80 * mm, 65 * mm])
            t_mitre.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_mitre)
            story.append(Spacer(1, 6))

        # IOC Table
        if iocs:
            story.append(Paragraph("<b>3. EXTRACTED INDICATORS OF COMPROMISE (IOCs)</b>", heading_style))
            ioc_rows = [[Paragraph("<b>Artifact Type</b>", body_style), Paragraph("<b>Indicator Value</b>", body_style)]]
            for i in iocs:
                ioc_rows.append([Paragraph(str(i.get("type")), body_style), Paragraph(str(i.get("value")), code_style)])
            t_ioc = Table(ioc_rows, colWidths=[45 * mm, 135 * mm])
            t_ioc.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_ioc)
            story.append(Spacer(1, 6))

        # Legal Provisions
        story.append(Paragraph("<b>4. CYBER LAW &amp; COMPLIANCE DIRECTIVES</b>", heading_style))
        if isinstance(legal, dict) and legal.get("it_act"):
            story.append(Paragraph(f"<b>Information Technology Act, 2000:</b> {legal.get('it_act')}", body_style))
            story.append(Paragraph(f"<b>Bharatiya Nyaya Sanhita (BNS) 2023 / IPC:</b> {legal.get('bns_ipc', 'N/A')}", body_style))
            story.append(Paragraph(f"<b>DPDP Act 2023 / Regulatory Mandate:</b> {legal.get('dpdp_act', 'N/A')}", body_style))
            story.append(Paragraph(f"<b>Legal Details:</b> {legal.get('description', '')}", body_style))
            story.append(Paragraph(f"<b>Mandatory Reporting:</b> {legal.get('reporting', '')}", body_style))
        else:
            story.append(Paragraph("Standard IT Act general provisions apply. Report suspicious cyber activities to cybercrime.gov.in.", body_style))

        # Incident Response Checklist
        story.append(Paragraph("<b>5. INCIDENT RESPONSE &amp; CONTAINMENT PLAYBOOK</b>", heading_style))
        if recommendations:
            for idx, step in enumerate(recommendations, 1):
                txt = step if isinstance(step, str) else step.get('text', '')
                story.append(Paragraph(f"<b>{idx}.</b> {txt}", body_style))

        # Evidence & Hash Table
        if evidence_items:
            story.append(Paragraph("<b>6. FORENSIC EVIDENCE &amp; INTEGRITY SEALS (Sec 65B)</b>", heading_style))
            ev_rows = [[Paragraph("<b>Evidence ID</b>", body_style), Paragraph("<b>Filename</b>", body_style), Paragraph("<b>SHA-256 Integrity Seal</b>", body_style)]]
            for ev in evidence_items:
                ev_rows.append([Paragraph(str(ev.get("evidence_id")), code_style), Paragraph(str(ev.get("filename")), body_style), Paragraph(str(ev.get("original_hash", ev.get("sha256"))), code_style)])
            t_ev = Table(ev_rows, colWidths=[35 * mm, 50 * mm, 95 * mm])
            t_ev.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_ev)

        story.append(Spacer(1, 14))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=6))
        story.append(Paragraph("<b>LEXGUARD PLATFORM</b> • Cryptographically Verified Forensic Document • Generated under strict digital chain-of-custody protocols.", small_style))

        doc.build(story)
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype="application/pdf")
    except Exception as e:
        print("PDF generation error:", e)
        return jsonify({"error": str(e)}), 500

# --- General System Endpoints ---
@app.get('/api/dashboard')
def api_dashboard():
    cases = load_cases()
    ev = []
    for c in cases:
        ev.extend(c.get('evidence', []))
    from collections import Counter
    return jsonify({
        'total_incidents': len(cases),
        'active_incidents': sum(1 for c in cases if c.get('status', 'ACTIVE') not in ('RESOLVED', 'CLOSED')),
        'critical_high': sum(1 for c in cases if c.get('severity') in ('CRITICAL', 'HIGH')),
        'resolved': sum(1 for c in cases if c.get('status') in ('RESOLVED', 'CLOSED')),
        'evidence_count': len(ev),
        'verified_evidence': sum(1 for x in ev if x.get('status') == 'VERIFIED INTACT'),
        'integrity_failures': sum(1 for x in ev if 'FAILED' in x.get('status', '')),
        'ioc_count': sum(len(c.get('iocs', [])) for c in cases),
        'threat_distribution': dict(Counter((c.get('threat') or {}).get('classification', 'Unknown') for c in cases)),
        'offence_distribution': dict(Counter(c.get('offence', 'Unknown') for c in cases))
    })

@app.get('/api/cases')
def api_cases():
    q = (request.args.get('q') or '').lower().strip()
    cases = load_cases()
    if q:
        cases = [c for c in cases if q in json.dumps(c).lower()]
    return jsonify(sorted(cases, key=lambda c: c.get('timestamp', ''), reverse=True))

@app.get('/api/cases/<incident_id>')
def api_case(incident_id):
    case = refresh_case(safe_name(incident_id))
    if not case:
        return jsonify({'error': 'Incident not found.'}), 404
    case = case.copy()
    case['audit'] = _read_json(os.path.join(AUDIT_DIR, safe_name(incident_id) + '.json'), [])
    case['audit_verification'] = verify_audit_chain(incident_id)
    return jsonify(case)

@app.post('/api/cases/<incident_id>/playbook')
def api_playbook(incident_id):
    data = request.get_json(silent=True) or {}
    step_id = int(data.get('step_id', 0))
    done = bool(data.get('done', False))
    cases = load_cases()
    case = next((c for c in cases if c.get('incident_id') == safe_name(incident_id)), None)
    if not case:
        return jsonify({'error': 'Incident not found.'}), 404
    steps = case.setdefault('playbook', {}).setdefault('steps', [])
    target = next((x for x in steps if x.get('id') == step_id), None)
    if not target:
        return jsonify({'error': 'Playbook step not found.'}), 404
    target['done'] = done
    completed = sum(1 for x in steps if x.get('done'))
    case['response_progress'] = round(completed * 100 / len(steps)) if steps else 100
    add_timeline(case, 'Playbook Step Completed' if done else 'Playbook Step Reopened', target['text'])
    append_audit(incident_id, 'Playbook Step Updated', target['text'])
    save_cases(cases)
    return jsonify({'progress': case['response_progress'], 'playbook': case['playbook']})

@app.get('/api/cases/<incident_id>/export')
def api_export_case(incident_id):
    incident = safe_name(incident_id)
    case = refresh_case(incident)
    if not case:
        return jsonify({'error': 'Incident not found.'}), 404
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('Case_Metadata.json', json.dumps({k: v for k, v in case.items() if k != 'input'}, indent=2, ensure_ascii=False))
        z.writestr('Incident_Input.txt', case.get('input', ''))
        z.writestr('IOC_Report.txt', '\n'.join(f"{x.get('type')}: {x.get('value')}" for x in case.get('iocs', [])) or 'No IOCs extracted.')
        z.writestr('Timeline.txt', '\n'.join(f"{x.get('timestamp')} | {x.get('action')} | {x.get('description')}" for x in case.get('timeline', [])) or 'No timeline events.')
        z.writestr('Chain_of_Custody.txt', '\n'.join(f"{x.get('timestamp')} | {x.get('action')} | {x.get('evidence_id')} | {x.get('description')}" for x in load_custody(incident)) or 'No custody events.')
        z.writestr('Evidence_Hashes.txt', '\n'.join(f"{x.get('evidence_id')} | {x.get('filename')} | SHA-256: {x.get('original_hash', x.get('sha256'))}" for x in case.get('evidence', [])) or 'No evidence attached.')
        
        # Add generated PDF report if present
        report_path = os.path.join(REPORT_DIR, incident + '.pdf')
        if os.path.isfile(report_path):
            z.write(report_path, arcname='Incident_Forensic_Report.pdf')
        for ev in case.get('evidence', []):
            path = os.path.join(EVIDENCE_DIR, incident, ev.get('filename', ''))
            if os.path.isfile(path):
                z.write(path, arcname=os.path.join('Evidence_Files', ev.get('filename', 'evidence')))
    memory.seek(0)
    append_audit(incident, 'Forensic Package Exported', 'Full case zip archive exported.')
    return send_file(memory, as_attachment=True, download_name=f"LexGuard_Forensics_{incident}.zip", mimetype='application/zip')

@app.post('/api/cases/<incident_id>/status')
def api_case_status(incident_id):
    status = (request.get_json(silent=True) or {}).get('status', 'ACTIVE').upper()
    allowed = {'ACTIVE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'}
    if status not in allowed:
        return jsonify({'error': 'Invalid status.'}), 400
    cases = load_cases()
    case = next((c for c in cases if c.get('incident_id') == safe_name(incident_id)), None)
    if not case:
        return jsonify({'error': 'Incident not found.'}), 404
    case['status'] = status
    add_timeline(case, 'Case Status Updated', f"Status set to {status}.")
    append_audit(incident_id, 'Case Status Updated', status)
    save_cases(cases)
    return jsonify(case)

@app.get('/api/iocs')
def api_iocs():
    q = (request.args.get('q') or '').lower().strip()
    typ = (request.args.get('type') or '').lower().strip()
    out = []
    for c in load_cases():
        for i in c.get('iocs', []):
            x = dict(i)
            x['incident_id'] = c.get('incident_id')
            x['timestamp'] = c.get('timestamp')
            out.append(x)
    if q:
        out = [x for x in out if q in str(x.get('value', '')).lower() or q in str(x.get('incident_id', '')).lower()]
    if typ:
        out = [x for x in out if x.get('type', '').lower() == typ]
    return jsonify(out)

@app.post('/api/url/analyze')
def api_url_analyze():
    raw = ((request.get_json(silent=True) or {}).get('url') or '').strip()
    from urllib.parse import urlparse
    if not raw:
        return jsonify({'error': 'Enter a URL or domain.'}), 400
    candidate = raw if re.match(r'^https?://', raw, re.I) else 'http://' + raw
    p = urlparse(candidate)
    host = p.hostname or ''
    indicators = []
    score = 0
    if p.scheme != 'https':
        score += 20
        indicators.append('Insecure plain HTTP protocol (No TLS encryption)')
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', host):
        score += 35
        indicators.append('Raw IP address used instead of legitimate domain hostname')
    if '@' in raw:
        score += 30
        indicators.append('@ symbol used to obfuscate true destination')
    if len(host.split('.')) > 3:
        score += 15
        indicators.append('Deep multi-level subdomain masquerading')
    if host.count('-') >= 2:
        score += 10
        indicators.append('Excessive hyphens in hostname (typosquatting marker)')
    if any(x in (host + p.path).lower() for x in ['login', 'verify', 'secure', 'account', 'update', 'otp', 'bank', 'wallet', 'kyc']):
        score += 25
        indicators.append('High-risk credential harvesting or financial lure keywords in URI path')
    if any(x in raw.lower() for x in ['%2f', '%40', '%2e', 'xn--']):
        score += 20
        indicators.append('Hex URL encoding or Punycode homograph attack indicator')
        
    risk = 'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW'
    return jsonify({
        'input': raw,
        'normalized': candidate,
        'domain': host,
        'scheme': p.scheme,
        'path': p.path or '/',
        'score': min(score, 100),
        'risk': risk,
        'indicators': indicators or ['No suspicious URL structural indicators identified.'],
        'recommendation': 'DO NOT visit or enter credentials. Isolate URL in threat intelligence database.' if score >= 25 else 'Proceed with standard vigilance. Destination appears structurally nominal.'
    })

@app.post('/api/file/analyze')
def api_file_analyze():
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'Choose a file.'}), 400
    name = safe_name(file.filename)
    data = file.read()
    ext = os.path.splitext(name)[1].lower()
    size = len(data)
    digest = hash_bytes(data)
    
    entropy = 0.0
    if data:
        counts = [0] * 256
        for b in data: counts[b] += 1
        entropy = -sum((c / size) * math.log2(c / size) for c in counts if c)
        
    risky_ext = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.apk', '.msi', '.jar', '.hta', '.iso'}
    score = 40 if ext in risky_ext else 10
    if entropy > 7.5:
        score += 25
    if size == 0:
        score += 15
        
    risk = 'HIGH' if score >= 50 else 'MEDIUM' if score >= 30 else 'LOW'
    indicators = []
    if ext in risky_ext:
        indicators.append(f"High-risk executable or script extension ({ext})")
    if entropy > 7.5:
        indicators.append(f"High byte entropy ({round(entropy, 2)} / 8.0) indicating packing, encryption, or compression")
        
    return jsonify({
        'filename': name,
        'size': size,
        'extension': ext or 'none',
        'mime': mimetypes.guess_type(name)[0] or 'unknown',
        'sha256': digest,
        'entropy': round(entropy, 2),
        'risk': risk,
        'indicators': indicators or ['Standard binary/text profile without overt anomalies.'],
        'recommendation': 'Do not execute. Quarantine in digital evidence vault.' if score >= 30 else 'Standard input profile.'
    })

@app.post('/api/password/analyze')
def api_password_analyze():
    pw = (request.get_json(silent=True) or {}).get('password', '')
    if not isinstance(pw, str):
        return jsonify({'error': 'Invalid password.'}), 400
        
    classes = sum(bool(re.search(p, pw)) for p in [r'[a-z]', r'[A-Z]', r'\d', r'[^A-Za-z0-9]'])
    pool = sum([26 if re.search(r'[a-z]', pw) else 0, 26 if re.search(r'[A-Z]', pw) else 0, 10 if re.search(r'\d', pw) else 0, 32 if re.search(r'[^A-Za-z0-9]', pw) else 0])
    entropy = round(len(pw) * math.log2(pool), 1) if pool else 0
    common = bool(re.search(r'(password|123456|qwerty|admin|letmein|welcome|iloveyou|pass123)', pw, re.I))
    
    score = min(100, round(entropy * 1.2) + len(pw) * 2) if pw else 0
    if common:
        score = min(score, 20)
        
    strength = 'VERY STRONG' if score >= 85 else 'STRONG' if score >= 65 else 'MEDIUM' if score >= 40 else 'WEAK'
    warnings = []
    if common: warnings.append('Known common password / dictionary pattern detected.')
    if len(pw) < 12: warnings.append('Length under 12 characters is susceptible to GPU-accelerated brute force.')
    if classes < 3: warnings.append('Incorporate mixed case, numbers, and special symbols.')
    
    return jsonify({
        'length': len(pw),
        'classes': classes,
        'entropy_bits': entropy,
        'score': score,
        'strength': strength,
        'warnings': warnings or ['Strong password complexity and entropy.']
    })

@app.post('/api/simulator')
def api_simulator():
    scenarios = {
        'Phishing': 'URGENT: Your State Bank account has been suspended due to pending KYC. Click here immediately to verify your Aadhaar and OTP: http://sbi-kyc-verify-portal.in/login.php',
        'Ransomware': 'ATTENTION: All your company databases and documents have been encrypted with AES-256. Pay 0.5 Bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to obtain your decryption key. Decryptor contact: lockdata@darkmail.onion',
        'Financial Fraud': 'I was scammed out of ₹85,000 through a fake electricity bill SMS. The caller instructed me to install AnyDesk and transfer ₹10 via UPI, following which multiple unauthorized debits occurred.',
        'Identity Theft': 'Someone created a fake Instagram profile using my photographs and personal Aadhaar details, sending threatening messages and demanding money from my contacts.',
        'Malware': 'Please find attached invoice_sep2026.pdf.exe. Run this program with administrative privileges to unlock your purchase receipt.',
        'Web Attack': 'Attacker submitted input payload: "admin\' OR \'1\'=\'1\' UNION SELECT username, password_hash, credit_card FROM users --" causing database exfiltration.',
        'SIM Swap': 'My mobile SIM network suddenly showed No Service. Within 30 minutes, ₹2,00,000 was transferred from my net banking using redirected 2FA SMS tokens.'
    }
    key = (request.get_json(silent=True) or {}).get('scenario')
    text = scenarios.get(key)
    if not text:
        return jsonify({'error': 'Unknown simulation scenario.'}), 400
    res = unified_analysis(text)
    res.update({'simulation': True, 'scenario': key})
    return jsonify(res)

@app.get('/api/health')
def health():
    return jsonify({
        'status': 'HEALTHY & ONLINE',
        'engine': 'LexGuard Cyber Defense & Legal Forensics Suite',
        'key_status': 'LOCAL MASTER FERNET KEY ACTIVE' if os.path.exists(KEY_FILE) else 'AUTO-GENERATED'
    })

if __name__ == '__main__':
    print('=================================================================')
    print('  LEXGUARD CYBER DEFENSE & LEGAL FORENSICS PLATFORM')
    print('  Local Security Server online at http://127.0.0.1:5000')
    print('=================================================================')
    app.run(debug=True, port=5000)
