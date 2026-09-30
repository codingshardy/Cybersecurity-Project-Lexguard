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
# UNIT 1 & UNIT 4: THREAT INTELLIGENCE & ATTACK TAXONOMY
# (Foundations, Threats, Active vs Passive Attacks, Social Engineering)
# =========================================================================
SECURITY_PILLARS = {
    'Confidentiality': 'Ensures sensitive information is not disclosed to unauthorized individuals or entities. Protected by encryption (AES, DES, Caesar) and access control (DAC, MAC, RBAC).',
    'Integrity': 'Guarantees that data has not been altered, modified, or deleted by unauthorized parties. Maintained via Cryptographic Hashing (MD-5, SHA-256) and Digital Signatures.',
    'Availability': 'Ensures systems, networks, and applications are accessible to authorized users when needed. Defended against DoS and DDoS attacks.',
    'Accountability': 'Actions of an entity can be traced uniquely to that entity through audit logs and chain-of-custody tracking.',
    'Non-repudiation': 'Prevents an individual from denying the authenticity of a sent message or transaction. Achieved using Asymmetric Digital Signatures (RSA) and PKI.',
    'Reliability': 'Consistent and dependable performance of security mechanisms under all operating conditions.',
    'Authentication': 'Verification of the claimed identity of a user, process, or device using Passwords, Biometrics, or Kerberos tickets.'
}

ATTACK_TAXONOMY = {
    'Passive Attacks': {
        'description': 'Attacks that monitor or eavesdrop on data transmissions without modifying system resources.',
        'types': [
            {'name': 'Packet Sniffing / Eavesdropping', 'desc': 'Capturing unencrypted packets over a network.'},
            {'name': 'Traffic Analysis', 'desc': 'Observing message frequency, location, and length to deduce patterns.'},
            {'name': 'Shoulder Surfing', 'desc': 'Direct observation of user entering passwords or PINs.'},
            {'name': 'Dumpster Diving', 'desc': 'Retrieving discarded sensitive printouts or media.'}
        ]
    },
    'Active Attacks': {
        'description': 'Attacks that attempt to alter system resources or affect their operation.',
        'types': [
            {'name': 'Denial of Service (DoS / DDoS)', 'desc': 'Flooding server bandwidth or resources to disrupt availability.'},
            {'name': 'Phishing & Spoofing', 'desc': 'Forging sender identities or fake web portals to harvest credentials.'},
            {'name': 'Man-in-the-Middle (MitM)', 'desc': 'Interception and unauthorized alteration of communication between two parties.'},
            {'name': 'Replay Attack', 'desc': 'Capturing valid transmission packets and re-transmitting them later.'},
            {'name': 'Data Diddling & Tampering', 'desc': 'Unauthorized modification of data before or during entry.'},
            {'name': 'Web Defacement', 'desc': 'Altering visual appearance of web pages via server compromise.'},
            {'name': 'Backdoors & Trapdoors', 'desc': 'Hidden entry points bypassing normal authentication mechanisms.'}
        ]
    }
}

THREAT_RULES = {
    'Phishing': ['verify your account', 'click here', 'login', 'urgent', 'password', 'otp', 'suspended', 'confirm your account', 'kyc', 'verify now', 'bank alert', 'account locked'],
    'Ransomware': ['ransom', 'decrypt', 'encrypted files', 'pay bitcoin', 'bitcoin', 'files encrypted', 'decryption key', 'ransomware', 'readme.txt', '.locked', '.crypto'],
    'Malware-link': ['download', 'attachment', '.exe', '.apk', 'malware', 'trojan', 'install this app', 'http://', 'https://', '.bat', '.scr', 'invoice.exe'],
    'Social Engineering': ['send me otp', 'share otp', 'impersonating', 'pretend', 'secret', 'gift card', 'act now', 'do not tell anyone', 'urgent call', 'help me transfer'],
    'Web Application Attack': ['select * from', 'union select', '<script>', 'onerror=', '1=1', 'or 1=1', 'drop table', 'sql injection', 'xss'],
    'DoS/DDoS Attack': ['ddos', 'denial of service', 'syn flood', 'traffic flood', 'bandwidth exhaustion', 'server unavailable', 'botnet attack']
}

OFFENCE_RULES = {
    'Hacking/Unauthorized Access': ['hacked', 'unauthorized access', 'accessed my account', 'broke into', 'login without permission', 'password changed', 'backdoor'],
    'Identity Theft': ['identity stolen', 'stolen identity', 'impersonated me', 'used my aadhaar', 'used my pan', 'fake account in my name', 'forged profile'],
    'Online Financial Fraud': ['scammed', 'fraud', 'upi', 'bank transfer', 'otp fraud', 'money stolen', 'payment fraud', 'phishing payment', 'credit card fraud'],
    'Cyberstalking/Harassment': ['stalking', 'repeated messages', 'threatening messages', 'harassing me online', 'online harassment', 'following me online', 'blackmail'],
    'Data Theft/Exfiltration': ['stole my data', 'data stolen', 'copied files', 'database stolen', 'downloaded confidential', 'leaked data', 'data diddling']
}

# Indian IT Act 2000 & 2008 Statutory Mapping
LAW_MAP = {
    'Hacking/Unauthorized Access': {
        'it_act': 'Section 43 read with Section 66 of Information Technology Act, 2000',
        'bns_ipc': 'Section 303 / 308 of BNS 2023 & Sec 378/424 IPC',
        'description': 'Penalizes unauthorized access, downloading, extraction of data, and dishonest or fraudulent computer damage. Punishment: Up to 3 years imprisonment and/or fine up to ₹5,00,000.',
        'reporting': 'Report through cybercrime.gov.in or nearest Cyber Crime Police Station.'
    },
    'Identity Theft': {
        'it_act': 'Section 66C of Information Technology Act, 2000',
        'bns_ipc': 'Section 319 of BNS 2023 (Cheating by Personation) & Sec 419 IPC',
        'description': 'Criminalizes fraudulent or dishonest use of electronic signature, password, Aadhaar, PAN, or unique identification feature. Punishment: Up to 3 years imprisonment and fine up to ₹1,00,000.',
        'reporting': 'Report to Cyber Police Station and notify UIDAI / Income Tax Department if credentials are compromised.'
    },
    'Online Financial Fraud': {
        'it_act': 'Section 66D of Information Technology Act, 2000',
        'bns_ipc': 'Section 318(4) of BNS 2023 (Cheating) & Sec 420 IPC',
        'description': 'Punishes cheating by personation by using computer resources or communication devices. Punishment: Up to 3 years imprisonment and fine up to ₹1,00,000.',
        'reporting': 'Immediately dial National Cybercrime Helpline 1930 (Golden Hour freeze request) and file on cybercrime.gov.in.'
    },
    'Cyberstalking/Harassment': {
        'it_act': 'Section 66E & Section 67 / 67A of Information Technology Act, 2000',
        'bns_ipc': 'Section 78 of BNS 2023 (Stalking) & Section 354D IPC',
        'description': 'Addresses privacy violation, electronic stalking, capturing/transmitting private images, or publishing obscene material. Punishment: 3 to 7 years imprisonment.',
        'reporting': 'Preserve screenshots and chat logs; report on cybercrime.gov.in under Women/Child Protection.'
    },
    'Data Theft/Exfiltration': {
        'it_act': 'Section 43(b), Section 66, and Section 72A of Information Technology Act, 2000',
        'bns_ipc': 'Section 316 of BNS 2023 (Criminal Breach of Trust) & Sec 406 IPC',
        'description': 'Punishes unauthorized downloading, copying, or disclosure of confidential electronic data in breach of contract. Punishment: Up to 3 years imprisonment and fine up to ₹5,00,000.',
        'reporting': 'File complaint with Cyber Cell and notify Certifying Authority / CERT-In.'
    }
}

RESPONSE_STEPS = {
    'Phishing': [
        'Do not click suspicious links or enter login credentials/passwords.',
        'If credentials were entered, immediately change password from a verified device.',
        'Enable Multi-Factor Authentication (MFA) on all critical accounts.',
        'Preserve raw email headers, SMS screenshots, and URL for forensics.',
        'Report the incident to cybercrime.gov.in and your organization security team.'
    ],
    'Ransomware': [
        'Immediately isolate infected computer from Wi-Fi, LAN, and cloud storage.',
        'Do not reboot abruptly if RAM/memory forensics is feasible.',
        'Preserve ransom note and encrypted sample file without altering timestamps.',
        'Check NoMoreRansom database for available public decryptor tools.',
        'Report incident to CERT-In and nearest Cyber Cell.'
    ],
    'Malware-link': [
        'Disconnect the infected machine from network to stop lateral spread.',
        'Record file SHA-256 hash and process execution tree.',
        'Run an updated antimalware scan in safe mode.',
        'Revoke active session tokens and force password reset.',
        'Quarantine suspect file in digital evidence vault.'
    ],
    'Social Engineering': [
        'Immediately stop communicating with the imposter.',
        'Never share OTPs, PINs, passwords, or remote access IDs (AnyDesk/TeamViewer).',
        'Verify caller credentials through an independently verified official telephone number.',
        'Preserve call recordings and chat logs.',
        'Report suspicious phone numbers to cybercrime authorities.'
    ],
    'Hacking/Unauthorized Access': [
        'Terminate all active sessions from account security settings.',
        'Reset password using a strong 12+ character mixed passphrase.',
        'Audit authorized OAuth apps and revoke unknown API keys.',
        'Preserve server authentication and access logs.',
        'Lodge formal complaint under Section 43/66 IT Act.'
    ],
    'Identity Theft': [
        'File complaint on cybercrime.gov.in to obtain an official acknowledgement ID.',
        'Notify UIDAI / Credit Bureaus to place an identity freeze if Aadhaar/PAN is exposed.',
        'Request takedown of fake impersonating profiles.',
        'Preserve copies of fraudulent profiles and transaction receipts.',
        'Publish disclaimer if public identity was compromised.'
    ],
    'Online Financial Fraud': [
        'Call 1930 Cyber Fraud Helpline immediately within the Golden Hour to freeze disputed funds.',
        'Contact bank 24x7 helpline to block debit/credit cards and net banking.',
        'Preserve UTR number, transaction IDs, SMS alerts, and bank statements.',
        'File complaint on cybercrime.gov.in.',
        'Submit written fraud dispute form to bank branch within 3 working days.'
    ],
    'Cyberstalking/Harassment': [
        'Do not engage or negotiate with the stalker.',
        'Capture timestamped screenshots including browser URLs and message headers.',
        'Block and report accounts across social platforms.',
        'Check personal phone for unauthorized tracking apps or MDM profiles.',
        'Seek assistance under National Cybercrime Portal Women/Child Protection section.'
    ],
    'Data Theft/Exfiltration': [
        'Restrict further access to the affected database/storage.',
        'Revoke suspect employee/user credentials.',
        'Preserve system audit logs and data access records.',
        'Notify organization administration and CERT-In.',
        'Report under Section 43/66/72A IT Act.'
    ],
    'Unclear': [
        'Preserve all digital artifacts (messages, files, timestamps) securely.',
        'Avoid clicking unverified links or sharing authentication codes.',
        'Enable Multi-Factor Authentication on all important accounts.',
        'Perform antivirus scan and verify account activity logs.',
        'Seek guidance from authorized cybersecurity professionals.'
    ]
}

# =========================================================================
# UNIT 2: CRYPTOGRAPHY (SYLLABUS CIPHERS & ALGORITHMS)
# Caesar, Monoalphabetic, Vigenère, Rail Fence, Columnar, Vernam OTP, DES/AES, RSA, Diffie-Hellman, MD5, SHA
# =========================================================================

# 1. Caesar Cipher (Substitution)
def caesar_cipher(text: str, shift: int, mode: str = 'encrypt'):
    if mode == 'decrypt':
        shift = -shift
    res = []
    for ch in text:
        if ch.isupper():
            res.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        elif ch.islower():
            res.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        else:
            res.append(ch)
    return ''.join(res)

def caesar_bruteforce(ciphertext: str):
    results = []
    for s in range(1, 26):
        results.append({'shift': s, 'plaintext': caesar_cipher(ciphertext, s, 'decrypt')})
    return results

# 2. Monoalphabetic Cipher (Substitution)
STANDARD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def monoalphabetic_cipher(text: str, key_alphabet: str, mode: str = 'encrypt'):
    key_alpha = key_alphabet.upper()
    if len(key_alpha) != 26 or len(set(key_alpha)) != 26:
        raise ValueError("Monoalphabetic key must contain all 26 unique letters of the alphabet.")
    
    if mode == 'encrypt':
        trans = str.maketrans(STANDARD_ALPHA + STANDARD_ALPHA.lower(), key_alpha + key_alpha.lower())
    else:
        trans = str.maketrans(key_alpha + key_alpha.lower(), STANDARD_ALPHA + STANDARD_ALPHA.lower())
    return text.translate(trans)

# 3. Vigenère Cipher (Polyalphabetic Substitution)
def vigenere_cipher(text: str, key: str, mode: str = 'encrypt'):
    if not key:
        raise ValueError("Vigenère key cannot be empty.")
    key = re.sub(r'[^A-Za-z]', '', key).upper()
    if not key:
        raise ValueError("Vigenère key must contain alphabetic characters.")
    
    res = []
    k_idx = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[k_idx % len(key)]) - 65
            if mode == 'decrypt':
                shift = -shift
            if ch.isupper():
                res.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            else:
                res.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            k_idx += 1
        else:
            res.append(ch)
    return ''.join(res)

# 4. Rail Fence Cipher (Transposition Technique)
def rail_fence_encrypt(text: str, rails: int):
    if rails <= 1:
        return text
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for ch in text:
        fence[rail].append(ch)
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(cipher: str, rails: int):
    if rails <= 1:
        return cipher
    # Determine positions in fence
    pattern = [[None] * len(cipher) for _ in range(rails)]
    rail = 0
    direction = 1
    for i in range(len(cipher)):
        pattern[rail][i] = '*'
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1
    
    # Fill in cipher characters
    idx = 0
    for r in range(rails):
        for c in range(len(cipher)):
            if pattern[r][c] == '*' and idx < len(cipher):
                pattern[r][c] = cipher[idx]
                idx += 1
                
    # Read in zigzag
    res = []
    rail = 0
    direction = 1
    for i in range(len(cipher)):
        res.append(pattern[rail][i])
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1
    return ''.join(res)

# 5. Simple Columnar Transposition
def columnar_encrypt(text: str, key: str):
    clean_text = text.replace(' ', '_')
    key_order = sorted(list(enumerate(key)), key=lambda x: x[1])
    num_cols = len(key)
    num_rows = math.ceil(len(clean_text) / num_cols)
    padded_text = clean_text.ljust(num_rows * num_cols, 'X')
    
    grid = [padded_text[i * num_cols : (i + 1) * num_cols] for i in range(num_rows)]
    ciphertext = []
    for orig_idx, _ in key_order:
        ciphertext.append(''.join(grid[r][orig_idx] for r in range(num_rows)))
    return ''.join(ciphertext)

def columnar_decrypt(cipher: str, key: str):
    num_cols = len(key)
    num_rows = math.ceil(len(cipher) / num_cols)
    key_order = sorted(list(enumerate(key)), key=lambda x: x[1])
    
    grid = [[''] * num_cols for _ in range(num_rows)]
    idx = 0
    for orig_idx, _ in key_order:
        for r in range(num_rows):
            if idx < len(cipher):
                grid[r][orig_idx] = cipher[idx]
                idx += 1
                
    plaintext = ''.join(''.join(row) for row in grid)
    return plaintext.replace('_', ' ').rstrip('X')

# 6. Vernam Cipher (One-Time Pad / XOR)
def vernam_cipher(text: str, key: str):
    if len(key) < len(text):
        raise ValueError(f"Vernam One-Time Pad key must be at least as long as plaintext ({len(text)} chars).")
    res = []
    for t_ch, k_ch in zip(text, key):
        res.append(chr(ord(t_ch) ^ ord(k_ch)))
    raw_str = ''.join(res)
    return {
        'raw_xor_hex': raw_str.encode('utf-8', errors='surrogateescape').hex(),
        'ascii_printable': ''.join(c if 32 <= ord(c) <= 126 else f"\\x{ord(c):02x}" for c in raw_str)
    }

# =========================================================================
# CORE HELPER FUNCTIONS & STORAGE
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

# Audit chain
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

# Cases
CASE_INDEX = os.path.join(CASE_DIR, 'cases.json')
def load_cases(): return _read_json(CASE_INDEX, [])
def save_cases(cases): _write_json(CASE_INDEX, cases)
def refresh_case(incident): return next((c for c in load_cases() if c.get('incident_id') == incident), None)

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
    add_timeline(case, 'Evidence Ingested', f"{meta.get('filename')} secured with ID {meta.get('evidence_id')}.")
    save_cases(cases)
    append_audit(incident, 'Evidence Registered', f"Evidence {meta.get('evidence_id')} saved.", meta.get('evidence_id'))

def extract_iocs(text):
    text = text or ''
    found = []
    patterns = [
        ('IPv4', r'(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])'),
        ('URL', r'\bhttps?://[^\s<>"\']+'),
        ('Email', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        ('Crypto Wallet', r'\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90}|0x[a-fA-F0-9]{40})\b'),
        ('SHA-256', r'\b[a-fA-F0-9]{64}\b'),
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
    
    if c == 'Phishing' or any(x in low for x in ['phishing', 'click here', 'verify your account']):
        add('T1566', 'Phishing', 'Initial Access', 'Adversary uses targeted messages and fraudulent links to elicit credentials.')
    if 'http://' in low or 'https://' in low or any(i['type'] == 'URL' for i in iocs):
        add('T1566.002', 'Spearphishing Link', 'Initial Access', 'Suspicious URL pointing to adversary-controlled lure infrastructure.')
    if any(x in low for x in ['password', 'otp', 'credential', 'login', 'pin']):
        add('T1056.002', 'Input Capture / Credential Harvesting', 'Credential Access', 'Adversary prompts victim to input secret authentication tokens.')
    if c == 'Malware-link' or any(x in low for x in ['.exe', '.apk', 'trojan', 'malware']):
        add('T1204.002', 'User Execution: Malicious File', 'Execution', 'Victim tricked into executing malicious payload or script.')
    if c == 'Ransomware' or any(x in low for x in ['ransom', 'encrypted files', 'decryption key']):
        add('T1486', 'Data Encrypted for Impact', 'Impact', 'Adversary encrypts target filesystem to interrupt availability.')
    if o == 'Hacking/Unauthorized Access' or any(x in low for x in ['hacked', 'unauthorized access']):
        add('T1078', 'Valid Accounts', 'Defense Evasion', 'Misuse of valid credentials to gain unauthorized access.')
    return list({x['id']: x for x in out}.values())

def build_playbook(threat, offence):
    key = threat if threat in RESPONSE_STEPS else offence if offence in RESPONSE_STEPS else 'Unclear'
    return {
        'name': f"{key} Containment Playbook",
        'steps': [{'id': i + 1, 'text': x, 'done': False} for i, x in enumerate(RESPONSE_STEPS.get(key, RESPONSE_STEPS['Unclear']))]
    }

def match_rules(text, rules):
    lower = text.lower()
    scores, triggers = {}, {}
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
            'why': ['No direct attack signatures or malicious indicators matched standard heuristic rules.'],
            'response': RESPONSE_STEPS['Unclear']
        }
    risk = 'Critical' if score >= 85 else 'High' if score >= 65 else 'Medium'
    why = []
    if any(x in hits for x in ['urgent', 'act now', 'suspended', 'account locked']):
        why.append('High-pressure urgency or psychological coercion indicator detected.')
    if any(x in hits for x in ['password', 'otp', 'login', 'verify your account', 'kyc']):
        why.append('Direct credential harvesting or identity verification trap detected.')
    if any(x in hits for x in ['http://', 'https://', 'click here']):
        why.append('External hyperlink redirection indicator detected.')
    if any(x in hits for x in ['.exe', '.apk', 'download', 'attachment']):
        why.append('Executable payload download delivery mechanism identified.')
    if any(x in hits for x in ['bitcoin', 'ransom', 'encrypted files']):
        why.append('Ransomware extortion payload indicator identified.')
    if not why:
        why = ['Configured threat signature matched.']
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
    if cat == 'Unclear': score = 20
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
        'severity': 'HIGH' if score >= 65 else 'MEDIUM' if score >= 40 else 'LOW',
        'priority': 'P1' if score >= 85 else 'P2' if score >= 65 else 'P3',
        'severity_reason': f"Calculated from heuristic score ({score}/100) and {len(iocs)} extracted IOC(s).",
        'legal': law,
        'response': playbook['steps'],
        'playbook': playbook,
        'iocs': iocs,
        'mitre': mitre,
        'timeline': [],
        'response_progress': 0,
        'evidence': []
    }
    save_case(result, event='Incident Registered & Analyzed')
    return result

def save_case(result, event=None):
    cases = load_cases()
    case = next((c for c in cases if c.get('incident_id') == result.get('incident_id')), None)
    if case: case.update(result)
    else: case = result.copy(); cases.append(case)
    if event: add_timeline(case, event, 'LexGuard recorded this security event.')
    save_cases(cases)
    append_audit(result['incident_id'], event or 'Case Updated', 'Incident cryptographically sealed.')

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
        return jsonify({'error': 'Please enter text or an incident description.'}), 400
    return jsonify(unified_analysis(text))

# --- Syllabus Classical Ciphers Endpoints (Unit 2) ---
@app.post('/api/crypto/caesar')
def api_caesar():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    shift = int(data.get('shift', 3))
    mode = data.get('mode', 'encrypt')
    if not text: return jsonify({'error': 'Text is required.'}), 400
    res = caesar_cipher(text, shift, mode)
    return jsonify({'result': res, 'shift': shift, 'mode': mode, 'hash': hashlib.sha256(res.encode()).hexdigest()})

@app.post('/api/crypto/caesar/bruteforce')
def api_caesar_bruteforce():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    if not text: return jsonify({'error': 'Ciphertext required for cryptanalysis.'}), 400
    return jsonify({'results': caesar_bruteforce(text)})

@app.post('/api/crypto/monoalphabetic')
def api_monoalphabetic():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key = data.get('key', 'QWERTYUIOPASDFGHJKLZXCVBNM')
    mode = data.get('mode', 'encrypt')
    try:
        res = monoalphabetic_cipher(text, key, mode)
        return jsonify({'result': res, 'key': key, 'mode': mode})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.post('/api/crypto/vigenere')
def api_vigenere():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key = data.get('key', 'SECURITY')
    mode = data.get('mode', 'encrypt')
    try:
        res = vigenere_cipher(text, key, mode)
        return jsonify({'result': res, 'key': key, 'mode': mode})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.post('/api/crypto/railfence')
def api_railfence():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    rails = int(data.get('rails', 3))
    mode = data.get('mode', 'encrypt')
    if rails < 2: return jsonify({'error': 'Rails must be at least 2.'}), 400
    res = rail_fence_encrypt(text, rails) if mode == 'encrypt' else rail_fence_decrypt(text, rails)
    return jsonify({'result': res, 'rails': rails, 'mode': mode})

@app.post('/api/crypto/columnar')
def api_columnar():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key = data.get('key', 'HACK')
    mode = data.get('mode', 'encrypt')
    if not key: return jsonify({'error': 'Keyword required.'}), 400
    res = columnar_encrypt(text, key) if mode == 'encrypt' else columnar_decrypt(text, key)
    return jsonify({'result': res, 'key': key, 'mode': mode})

@app.post('/api/crypto/vernam')
def api_vernam():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key = data.get('key', '')
    if not text or not key: return jsonify({'error': 'Text and One-Time Pad key required.'}), 400
    try:
        res = vernam_cipher(text, key)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# --- Unit 2: Modern Symmetric & Asymmetric (DES/AES, RSA, Diffie-Hellman, MD5/SHA) ---
@app.post('/api/crypto/des_aes_compare')
def api_des_aes_compare():
    return jsonify({
        'DES': {
            'name': 'Data Encryption Standard (DES)',
            'key_length': '56 Bits (Obsolete)',
            'block_size': '64 Bits',
            'structure': 'Feistel Cipher (16 Rounds)',
            'security': 'Vulnerable to brute-force (cracked in hours)',
            'status': 'Deprecated (Replaced by AES)'
        },
        'AES': {
            'name': 'Advanced Encryption Standard (AES / Rijndael)',
            'key_length': '128, 192, or 256 Bits',
            'block_size': '128 Bits',
            'structure': 'Substitution-Permutation Network (SPN)',
            'security': 'Computationally secure against modern brute force',
            'status': 'Global NIST Standard'
        }
    })

@app.post('/api/crypto/aes')
def api_crypto_aes():
    data = request.get_json(silent=True) or {}
    action = data.get('action', 'encrypt')
    text = data.get('text', '')
    passphrase = data.get('passphrase', 'SecretKey')
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(passphrase.encode())
    
    try:
        if action == 'encrypt':
            iv = secrets.token_bytes(12)
            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
            ct = encryptor.update(text.encode()) + encryptor.finalize()
            payload = salt + iv + encryptor.tag + ct
            return jsonify({'mode': 'AES-256-GCM', 'ciphertext_b64': base64.b64encode(payload).decode(), 'sha256': hashlib.sha256(text.encode()).hexdigest()})
        else:
            raw = base64.b64decode(text)
            salt, iv, tag, ct = raw[:16], raw[16:28], raw[28:44], raw[44:]
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
            decryptor = Cipher(algorithms.AES(kdf.derive(passphrase.encode())), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            pt = decryptor.update(ct) + decryptor.finalize()
            return jsonify({'plaintext': pt.decode(), 'sha256': hashlib.sha256(pt).hexdigest()})
    except Exception as e:
        return jsonify({'error': f"AES Operation failed: {str(e)}"}), 400

@app.post('/api/crypto/rsa/generate')
def api_rsa_generate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pub = key.public_key()
    return jsonify({
        'public_key_pem': pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        'private_key_pem': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
        'key_size': 2048
    })

@app.post('/api/crypto/rsa/sign_verify')
def api_rsa_sign_verify():
    data = request.get_json(silent=True) or {}
    action = data.get('action', 'sign')
    msg = data.get('message', '').encode()
    try:
        if action == 'sign':
            priv_pem = data.get('private_key_pem', '').encode()
            priv = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
            sig = priv.sign(msg, asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
            return jsonify({'signature_b64': base64.b64encode(sig).decode(), 'digest_sha256': hashlib.sha256(msg).hexdigest()})
        else:
            pub_pem = data.get('public_key_pem', '').encode()
            sig = base64.b64decode(data.get('signature_b64', ''))
            pub = serialization.load_pem_public_key(pub_pem, backend=default_backend())
            pub.verify(sig, msg, asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
            return jsonify({'valid': True, 'message': 'Digital Signature is mathematically valid.'})
    except Exception as e:
        return jsonify({'valid': False, 'message': f"Verification failed: {str(e)}"}), 400

@app.post('/api/crypto/dh')
def api_diffie_hellman():
    p, g = 23, 5
    a, b = secrets.randbelow(15) + 1, secrets.randbelow(15) + 1
    A, B = pow(g, a, p), pow(g, b, p)
    K1, K2 = pow(B, a, p), pow(A, b, p)
    return jsonify({
        'prime_p': p, 'generator_g': g,
        'alice': {'private_a': a, 'public_A': A},
        'bob': {'private_b': b, 'public_B': B},
        'computed_shared_secret': K1,
        'match': K1 == K2,
        'explanation': f"Alice sends A={A}. Bob sends B={B}. Both calculate shared key K={K1} without revealing secrets a and b."
    })

@app.post('/api/crypto/multihash')
def api_multihash():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    raw = text.encode()
    return jsonify({
        'MD5': {'digest': hashlib.md5(raw).hexdigest(), 'bits': 128, 'status': 'Vulnerable to Collision Attacks'},
        'SHA-1': {'digest': hashlib.sha1(raw).hexdigest(), 'bits': 160, 'status': 'Legacy / Deprecated'},
        'SHA-256': {'digest': hashlib.sha256(raw).hexdigest(), 'bits': 256, 'status': 'Standard Secure Hash'}
    })

# --- Unit 3: Identification, Authentication, Biometrics & Access Control (DAC, MAC, RBAC) ---
@app.post('/api/access/rbac_eval')
def api_rbac_eval():
    data = request.get_json(silent=True) or {}
    role = data.get('role', 'User').capitalize()
    resource = data.get('resource', 'Report')
    
    rbac_matrix = {
        'Admin': ['Read', 'Write', 'Delete', 'Execute', 'Audit Logs', 'Export Evidence'],
        'Analyst': ['Read', 'Write', 'Execute'],
        'User': ['Read'],
        'Guest': []
    }
    permissions = rbac_matrix.get(role, [])
    return jsonify({
        'role': role,
        'resource': resource,
        'granted_permissions': permissions,
        'models': {
            'DAC (Discretionary Access Control)': 'Owner sets permissions at their discretion.',
            'MAC (Mandatory Access Control)': 'Central authority enforces clearance levels (Top Secret, Secret, Confidential).',
            'RBAC (Role-Based Access Control)': 'Permissions are assigned strictly based on organizational roles (Admin, Analyst, User).'
        }
    })

@app.post('/api/access/biometrics_eval')
def api_biometrics_eval():
    return jsonify({
        'Biometric_Types': [
            {'type': 'Fingerprint', 'characteristics': 'Ridge patterns, minutiae points', 'accuracy': 'High', 'attack_vector': 'Silicone fake prints'},
            {'type': 'Retina / Iris Scan', 'characteristics': 'Blood vessel patterns in eye', 'accuracy': 'Very High', 'attack_vector': 'High-resolution photo spoofing'},
            {'type': 'Voice Pattern', 'characteristics': 'Vocal frequency, cadence', 'accuracy': 'Medium', 'attack_vector': 'Deepfake voice cloning'},
            {'type': 'Keystroke Dynamics', 'characteristics': 'Typing rhythm, dwell and flight time', 'accuracy': 'Medium-High', 'attack_vector': 'Behavioral replay'},
            {'type': 'Signature Dynamics', 'characteristics': 'Stroke speed, pen pressure', 'accuracy': 'Medium', 'attack_vector': 'Handwriting forgery'}
        ]
    })

@app.post('/api/access/password_attacks')
def api_password_attacks():
    return jsonify({
        'Shoulder Surfing': 'Direct physical observation of user typing credentials.',
        'Dumpster Diving': 'Searching discarded documents/storage media for passwords or network diagrams.',
        'Piggybacking': 'Unauthorized individual following authorized personnel into secure facilities.',
        'Brute Force / Dictionary': 'Automated attempts trying wordlists and combinations.',
        'Good Password Construction': [
            'Minimum 12-16 characters',
            'Combination of uppercase, lowercase, numbers, and symbols',
            'No personal dictionary words (names, birthdates, sequential numbers)',
            'Unique password per critical service'
        ]
    })

# --- Unit 5: Wireless & Mobile Devices ---
@app.post('/api/wifi')
def api_wifi():
    data = request.get_json(silent=True) or {}
    kind = data.get('type', 'Open')
    risk_data = {
        'Open': ('High', 95, 'No encryption. Exposed to packet sniffing, Evil Twin, and ARP spoofing.'),
        'WEP': ('High', 90, 'Uses weak RC4 24-bit IVs. Easily cracked via FMS attack.'),
        'WPA': ('Medium', 65, 'TKIP protocol is vulnerable to MIC attacks.'),
        'WPA2': ('Low', 25, 'CCMP/AES symmetric encryption. Strong against eavesdropping.'),
        'WPA3': ('Low', 10, 'Uses SAE dragonfly handshake; forward secrecy enabled.')
    }
    risk, score, explanation = risk_data.get(kind, ('Low', 20, 'Standard profile.'))
    return jsonify({'type': kind, 'risk': risk, 'score': score, 'explanation': explanation})

# --- Unit 6: Legal Reporting, FIR & Section 65B ---
@app.post('/api/report/fir')
def api_generate_fir():
    data = request.get_json(silent=True) or {}
    incident_id = data.get('incident_id', 'LG-' + datetime.now().strftime('%Y%m%d'))
    complainant = data.get('complainant_name', 'Complainant')
    contact = data.get('complainant_contact', '+91-XXXXXXXXXX')
    offence = data.get('offence', 'Online Financial Fraud')
    loss = data.get('financial_loss', 'N/A')
    facts = data.get('input', '')
    law = legal_lookup(offence) or {}
    
    fir_template = f"""================================================================================
FORMAL CYBER CRIME POLICE COMPLAINT / FIR APPLICATION
Under Code of Criminal Procedure / Information Technology Act, 2000
Submitted To: Cyber Crime Police Station / cybercrime.gov.in
================================================================================
DATE: {datetime.now().strftime('%d %B %Y')}
COMPLAINT TRACKING REF: {incident_id}

TO,
THE OFFICER-IN-CHARGE,
CYBER CRIME POLICE STATION.

SUBJECT: Complaint regarding {offence} under {law.get('it_act', 'Section 43/66 IT Act')}.

1. COMPLAINANT: {complainant} (Contact: {contact})
2. ACCUSED / SUSPECT DETAILS: Online perpetrators / Unknown
3. FINANCIAL LOSS / DISPUTED AMOUNT: {loss}
4. APPLICABLE STATUTORY SECTIONS:
   - {law.get('it_act', 'Section 43 read with Section 66 IT Act, 2000')}
   - {law.get('bns_ipc', 'Relevant Sections of BNS / IPC')}

5. SUMMARY OF FACTS:
{facts or 'Complainant was targeted through electronic communications and malicious fraud.'}

6. PRAYER:
   It is requested to register a formal FIR, issue preservation notices to intermediaries,
   and initiate lawful investigation under the Information Technology Act.

Digitally Sealed by LexGuard Platform.
Cryptographic Hash: {hashlib.sha256((incident_id + facts).encode()).hexdigest()}
================================================================================
"""
    return jsonify({'fir_text': fir_template, 'incident_id': incident_id})

@app.post('/api/report/section65b')
def api_generate_65b():
    data = request.get_json(silent=True) or {}
    incident_id = data.get('incident_id', 'LG-' + datetime.now().strftime('%Y%m%d'))
    examiner = data.get('examiner_name', 'Cyber Defense Examiner')
    
    cert = f"""================================================================================
CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872 /
SECTION 63 OF BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023
(For Admissibility of Electronic Records in Court)
================================================================================
CERTIFICATE ID: CERT65B-{uuid.uuid4().hex[:8].upper()}
CASE REF: {incident_id}
DATE: {datetime.now().strftime('%d %B %Y')}

I, {examiner}, hereby certify that:
1. I am in lawful control and operation of the computer device producing this electronic output.
2. The computer system operated normally and properly during the extraction of digital evidence.
3. The electronic record output has been preserved with cryptographic SHA-256 integrity hashing.
4. No tampering or alteration has occurred during custody.

AFFIRMED & CRYPTOGRAPHICALLY SEALED:
SHA-256 Master Hash Seal: {hashlib.sha256(incident_id.encode()).hexdigest()}
================================================================================
"""
    return jsonify({'certificate_text': cert, 'incident_id': incident_id})

# --- PDF Report ---
@app.route('/api/report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json(silent=True) or {}
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.units import mm

        incident_id = data.get("incident_id", "LG-" + datetime.now().strftime("%Y%m%d"))
        filename = f"{incident_id}.pdf"
        filepath = os.path.join(REPORT_DIR, filename)

        doc = SimpleDocTemplate(filepath, pagesize=A4, rightMargin=14*mm, leftMargin=14*mm, topMargin=14*mm, bottomMargin=14*mm)
        styles = getSampleStyleSheet()
        t_style = ParagraphStyle("T", parent=styles["Title"], fontSize=18, leading=22, alignment=TA_CENTER)
        sub_style = ParagraphStyle("S", parent=styles["Normal"], fontSize=9, leading=12, alignment=TA_CENTER, textColor=colors.HexColor("#64748b"))
        h_style = ParagraphStyle("H", parent=styles["Heading2"], fontSize=11, leading=14, spaceBefore=8, spaceAfter=4)
        b_style = ParagraphStyle("B", parent=styles["Normal"], fontSize=8.5, leading=12)

        story = [
            Paragraph("<b>LEXGUARD CYBER DEFENSE &amp; LEGAL FORENSICS</b>", t_style),
            Paragraph("INCIDENT INVESTIGATION &amp; STATUTORY LEGAL REPORT", sub_style),
            Spacer(1, 10),
            Paragraph("<b>1. INCIDENT ASSESSMENT</b>", h_style),
            Paragraph(f"<b>Incident ID:</b> {incident_id} &nbsp;|&nbsp; <b>Threat:</b> {data.get('threat',{}).get('classification','N/A')} &nbsp;|&nbsp; <b>Risk:</b> {data.get('risk','N/A')}", b_style),
            Spacer(1, 6),
            Paragraph("<b>2. STATUTORY IT ACT PROVISIONS</b>", h_style),
            Paragraph(f"<b>Information Technology Act:</b> {data.get('legal',{}).get('it_act','Section 43/66 IT Act')}", b_style),
            Paragraph(f"<b>Legal Details:</b> {data.get('legal',{}).get('description','')}", b_style),
            Spacer(1, 6),
            Paragraph("<b>3. RECOMMENDED CONTAINMENT STEPS</b>", h_style)
        ]
        for step in data.get('response', []):
            txt = step if isinstance(step, str) else step.get('text', '')
            story.append(Paragraph(f"• {txt}", b_style))
        
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=6))
        story.append(Paragraph("<b>LEXGUARD PLATFORM</b> • Generated under digital forensics standards.", sub_style))

        doc.build(story)
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype="application/pdf")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Evidence & General Endpoints ---
@app.route('/api/evidence', methods=['POST'])
def evidence():
    file = request.files.get('file')
    note = request.form.get('note', '').strip()
    incident = safe_name(request.form.get('incident_id', '').strip()) or ('LG-' + datetime.now().strftime('%Y%m%d') + '-' + uuid.uuid4().hex[:6].upper())
    if not file or not file.filename: return jsonify({'error': 'Choose a file.'}), 400
    
    original = safe_name(file.filename)
    folder = os.path.join(EVIDENCE_DIR, incident)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, original)
    file.save(path)
    digest = hash_file(path)
    
    meta = {
        'evidence_id': 'EV-' + uuid.uuid4().hex[:8].upper(),
        'incident_id': incident,
        'filename': original,
        'sha256': digest,
        'size': os.path.getsize(path),
        'created': datetime.now().isoformat(timespec='seconds'),
        'note': note,
        'status': 'VERIFIED INTACT',
        'original_hash': digest
    }
    with open(os.path.join(folder, original + '.metadata.json'), 'w') as f: json.dump(meta, f)
    append_custody(meta, 'Evidence Ingested', f"SHA-256 seal: {digest}")
    update_case_evidence(incident, meta)
    return jsonify(meta)

@app.get('/api/evidence/list')
def evidence_list():
    records = []
    if not os.path.isdir(EVIDENCE_DIR): return jsonify(records)
    for incident in sorted(os.listdir(EVIDENCE_DIR), reverse=True):
        folder = os.path.join(EVIDENCE_DIR, incident)
        if not os.path.isdir(folder): continue
        for fn in os.listdir(folder):
            if fn.endswith('.metadata.json'):
                try:
                    with open(os.path.join(folder, fn)) as f: records.append(json.load(f))
                except Exception: pass
    return jsonify(records[:50])

@app.post('/api/evidence/verify')
def evidence_verify():
    data = request.get_json(silent=True) or {}
    incident, evidence_id = safe_name(data.get('incident_id', '')), data.get('evidence_id')
    meta = load_evidence_meta(incident, evidence_id)
    if not meta: return jsonify({'error': 'Evidence record not found.'}), 404
    path = os.path.join(EVIDENCE_DIR, incident, meta['filename'])
    if not os.path.isfile(path): return jsonify({'error': 'Evidence file missing.'}), 404
    current = hash_file(path)
    match = current == meta.get('original_hash', meta.get('sha256'))
    return jsonify({'match': match, 'original': meta.get('original_hash'), 'current': current, 'status': 'VERIFIED INTACT' if match else 'TAMPER DETECTED'})

@app.get('/api/evidence/<incident>/custody')
def evidence_custody(incident):
    return jsonify(load_custody(safe_name(incident)))

@app.get('/api/dashboard')
def api_dashboard():
    cases = load_cases()
    from collections import Counter
    return jsonify({
        'total_incidents': len(cases),
        'active_incidents': sum(1 for c in cases if c.get('status', 'ACTIVE') != 'CLOSED'),
        'critical_high': sum(1 for c in cases if c.get('severity') in ('CRITICAL', 'HIGH')),
        'evidence_count': sum(len(c.get('evidence', [])) for c in cases),
        'threat_distribution': dict(Counter((c.get('threat') or {}).get('classification', 'Unknown') for c in cases)),
        'offence_distribution': dict(Counter(c.get('offence', 'Unknown') for c in cases))
    })

@app.get('/api/cases')
def api_cases():
    return jsonify(sorted(load_cases(), key=lambda c: c.get('timestamp', ''), reverse=True))

@app.get('/api/cases/<incident_id>')
def api_case(incident_id):
    c = refresh_case(safe_name(incident_id))
    if not c: return jsonify({'error': 'Incident not found.'}), 404
    c = c.copy()
    c['audit_verification'] = verify_audit_chain(incident_id)
    return jsonify(c)

@app.post('/api/cases/<incident_id>/playbook')
def api_playbook(incident_id):
    data = request.get_json(silent=True) or {}
    step_id = int(data.get('step_id', 0))
    done = bool(data.get('done', False))
    cases = load_cases()
    case = next((c for c in cases if c.get('incident_id') == safe_name(incident_id)), None)
    if not case: return jsonify({'error': 'Incident not found.'}), 404
    steps = case.setdefault('playbook', {}).setdefault('steps', [])
    target = next((x for x in steps if x.get('id') == step_id), None)
    if target: target['done'] = done
    save_cases(cases)
    return jsonify({'playbook': case['playbook']})

@app.get('/api/cases/<incident_id>/export')
def api_export_case(incident_id):
    incident = safe_name(incident_id)
    case = refresh_case(incident)
    if not case: return jsonify({'error': 'Incident not found.'}), 404
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('Case_Metadata.json', json.dumps(case, indent=2))
        z.writestr('Timeline.txt', '\n'.join(f"{x.get('timestamp')} | {x.get('action')}" for x in case.get('timeline', [])))
    memory.seek(0)
    return send_file(memory, as_attachment=True, download_name=f"LexGuard_{incident}.zip", mimetype='application/zip')

@app.post('/api/simulator')
def api_simulator():
    scenarios = {
        'Phishing': 'URGENT: Your State Bank account is suspended. Click here: http://sbi-kyc.in to verify your password and OTP.',
        'Ransomware': 'All your files have been encrypted. Pay bitcoin to obtain the decryption key.',
        'Financial Fraud': 'I was scammed through UPI after sharing an OTP with a caller pretending to be from my bank.',
        'Identity Theft': 'Someone used my Aadhaar and created a fake account in my name without permission.',
        'Malware': 'Please download invoice.exe from this link and execute the file.',
        'DoS Attack': 'Server is unresponsive due to high SYN flood traffic from a botnet.'
    }
    key = (request.get_json(silent=True) or {}).get('scenario')
    text = scenarios.get(key)
    if not text: return jsonify({'error': 'Unknown scenario.'}), 400
    res = unified_analysis(text)
    res.update({'simulation': True, 'scenario': key})
    return jsonify(res)

@app.get('/api/health')
def health():
    return jsonify({'status': 'HEALTHY & ONLINE', 'course_code': 'CM51205'})

if __name__ == '__main__':
    print('=================================================================')
    print('  LEXGUARD CYBER DEFENSE PLATFORM (MSBTE CM51205 SYLLABUS ALIGNED)')
    print('  Running at http://127.0.0.1:5000')
    print('=================================================================')
    app.run(debug=True, port=5000)
