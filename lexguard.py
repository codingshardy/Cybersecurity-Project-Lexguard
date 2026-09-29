"""
LexGuard — Unified Cyber Defense & Legal Forensics Platform.
Interactive Command Line Interface (CLI) Engine.
"""
import hashlib
import json
import os
import re
import secrets
import base64
import math
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, "lexguard.key")
VAULT_DIR = os.path.join(BASE_DIR, "vault")

# ANSI Color codes for clean terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

THREAT_RULES = {
    "Phishing": ["verify your account", "click here", "login", "urgent", "password", "otp", "suspended", "confirm your account", "kyc", "verify now"],
    "Ransomware": ["ransom", "decrypt", "encrypted files", "pay bitcoin", "bitcoin", "files encrypted", "decryption key", "monero"],
    "Malware-link": ["download", "attachment", ".exe", ".apk", "malware", "trojan", "install this app", "http://", "https://", ".bat", ".scr"],
    "Social Engineering": ["send me otp", "share otp", "impersonating", "pretend", "secret", "gift card", "act now", "do not tell anyone", "urgent call"],
    "Web Application Attack": ["select * from", "union select", "<script>", "1=1", "or 1=1", "drop table", "sql injection", "xss"],
}

OFFENCE_RULES = {
    "Hacking/Unauthorized Access": ["hacked", "unauthorized access", "accessed my account", "broke into", "login without permission", "password changed"],
    "Identity Theft": ["identity stolen", "stolen identity", "impersonated me", "used my aadhaar", "used my pan", "fake account in my name", "personal details used"],
    "Online Financial Fraud": ["scammed", "fraud", "upi", "bank transfer", "otp fraud", "money stolen", "payment fraud", "phishing payment", "online scam"],
    "Cyberstalking/Harassment": ["stalking", "repeated messages", "threatening messages", "harassing me online", "online harassment", "following me online"],
    "Corporate Data Theft/Exfiltration": ["stole my data", "data stolen", "copied files", "database stolen", "downloaded confidential", "leaked data", "stolen files"],
}

LAW_MAP = {
    "Hacking/Unauthorized Access": ("Section 43 read with Section 66 of IT Act, 2000", "Section 303 / 308 of BNS 2023", "Unauthorised computer access, downloading/extraction of data. Punishment: Up to 3 years and/or fine up to ₹5,00,000."),
    "Identity Theft": ("Section 66C of IT Act, 2000", "Section 319 of BNS 2023", "Fraudulent use of another person's password, electronic signature, Aadhaar or PAN. Punishment: Up to 3 years and fine up to ₹1,00,000."),
    "Online Financial Fraud": ("Section 66D of IT Act, 2000", "Section 318(4) of BNS 2023", "Cheating by personation using communication device or computer resource. Punishment: Up to 3 years and fine up to ₹1,00,000."),
    "Cyberstalking/Harassment": ("Section 66E / 67 of IT Act, 2000", "Section 78 of BNS 2023", "Privacy violation, cyberstalking, publishing obscene electronic material. Punishment: 3 to 7 years imprisonment."),
    "Corporate Data Theft/Exfiltration": ("Section 43(b) / 66 / 72A of IT Act, 2000", "Section 316 of BNS 2023", "Breach of lawful contract & unauthorized extraction of corporate databases. Punishment: Up to 3 years or civil penalties up to ₹250 Crores under DPDP Act."),
}

def ensure_dirs():
    os.makedirs(VAULT_DIR, exist_ok=True)

def get_fernet():
    ensure_dirs()
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return Fernet(f.read().strip())

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def read_multiline(prompt="Enter text (press Enter on an empty line to submit):"):
    print(f"{YELLOW}{prompt}{RESET}")
    lines = []
    while True:
        try:
            line = input()
            if not line:
                break
            lines.append(line)
        except EOFError:
            break
    return "\n".join(lines).strip()

def threat_identifier():
    print(f"\n{BOLD}{CYAN}=== 1. THREAT INTELLIGENCE & ATTACK IDENTIFIER ==={RESET}")
    text = read_multiline()
    if not text:
        print(f"{RED}[!] No input provided.{RESET}")
        return

    lower = text.lower()
    scores, triggers = {}, {}
    for cat, kws in THREAT_RULES.items():
        hits = [kw for kw in kws if kw.lower() in lower]
        if hits:
            scores[cat] = len(hits)
            triggers[cat] = hits

    if not scores:
        print(f"{GREEN}[✓] Classification: Informational / Safe Profile{RESET}")
        print("Reason: No overt heuristic attack indicators detected.")
        return

    best_score = max(scores.values())
    cat = next(c for c, s in scores.items() if s == best_score)
    print(f"\n{BOLD}Threat Classification: {RED}{cat}{RESET}")
    print(f"Triggered Signatures: {YELLOW}{', '.join(triggers[cat])}{RESET}")
    print(f"Calculated Threat Confidence: {BOLD}{min(99, 45 + best_score * 15)}/100{RESET}")

def crypto_suite():
    print(f"\n{BOLD}{CYAN}=== 2. CRYPTOGRAPHIC SECURITY SUITE ==={RESET}")
    print("1. AES-256 Symmetric Encryption (GCM Mode)")
    print("2. AES-256 Symmetric Decryption")
    print("3. RSA-2048 Keypair Generator & Digital Signer")
    print("4. Multi-Algorithm Hash Inspector (SHA-256, SHA-512, MD5)")
    print("5. Fernet Token Vault")
    choice = input(f"{BOLD}Select Option: {RESET}").strip()

    if choice == "1":
        text = input("Enter plaintext to encrypt: ").strip()
        passphrase = input("Enter encryption passphrase: ").strip()
        if not text or not passphrase: return
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(passphrase.encode())
        iv = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
        payload = salt + iv + encryptor.tag + ciphertext
        print(f"\n{GREEN}[✓] AES-256-GCM Ciphertext (Base64):{RESET}")
        print(base64.b64encode(payload).decode())

    elif choice == "2":
        b64_data = input("Paste Base64 ciphertext payload: ").strip()
        passphrase = input("Enter decryption passphrase: ").strip()
        try:
            raw = base64.b64decode(b64_data)
            salt, iv, tag, ct = raw[:16], raw[16:28], raw[28:44], raw[44:]
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
            key = kdf.derive(passphrase.encode())
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            pt = decryptor.update(ct) + decryptor.finalize()
            print(f"\n{GREEN}[✓] Decrypted Plaintext:{RESET} {pt.decode()}")
        except Exception as e:
            print(f"{RED}[!] Decryption Failed: {e}{RESET}")

    elif choice == "3":
        print(f"{YELLOW}Generating RSA-2048 Keypair...{RESET}")
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pub = priv.public_key()
        pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        print(f"{GREEN}[✓] Public Key Generated:{RESET}\n{pub_pem}")
        msg = input("Enter string to digitally sign: ").encode()
        sig = priv.sign(msg, asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
        print(f"{GREEN}[✓] Cryptographic Digital Signature (Base64):{RESET}\n{base64.b64encode(sig).decode()}")

    elif choice == "4":
        text = input("Enter string to compute cryptographic digests: ")
        raw = text.encode()
        print(f"\nSHA-256:  {BOLD}{hashlib.sha256(raw).hexdigest()}{RESET}")
        print(f"SHA-512:  {BOLD}{hashlib.sha512(raw).hexdigest()}{RESET}")
        print(f"BLAKE2b:  {BOLD}{hashlib.blake2b(raw).hexdigest()}{RESET}")
        print(f"MD5:      {RED}{hashlib.md5(raw).hexdigest()} (Insecure/Legacy){RESET}")

    elif choice == "5":
        f = get_fernet()
        text = input("Enter text to encrypt with Master Fernet Key: ")
        tok = f.encrypt(text.encode()).decode()
        print(f"{GREEN}Fernet Token:{RESET} {tok}")

def dlp_pii_scanner():
    print(f"\n{BOLD}{CYAN}=== 3. DATA LOSS PREVENTION (DLP) & PII REDACTOR ==={RESET}")
    text = read_multiline("Paste text to scan and redact PII:")
    if not text: return

    redacted = text
    found = 0
    # Aadhaar
    for m in re.finditer(r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b', text):
        raw = m.group(0)
        masked = raw[:2] + "****" + raw[-2:]
        redacted = redacted.replace(raw, f"[REDACTED_AADHAAR: {masked}]")
        found += 1
    # PAN
    for m in re.finditer(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', redacted, re.I):
        raw = m.group(0).upper()
        masked = raw[:2] + "*****" + raw[-2:]
        redacted = redacted.replace(raw, f"[REDACTED_PAN: {masked}]")
        found += 1

    print(f"\n{BOLD}DLP Inspection Summary:{RESET} {GREEN if found==0 else RED}{found} Sensitive PII Item(s) Redacted{RESET}")
    print(f"\n{BOLD}Sanitized Output:{RESET}\n{redacted}")

def offence_and_law():
    print(f"\n{BOLD}{CYAN}=== 4. CYBER OFFENCE CLASSIFICATION & LEGAL MAPPING ==={RESET}")
    text = read_multiline("Describe cyber incident facts:")
    if not text: return

    lower = text.lower()
    scores, triggers = {}, {}
    for cat, kws in OFFENCE_RULES.items():
        hits = [kw for kw in kws if kw.lower() in lower]
        if hits:
            scores[cat] = len(hits)
            triggers[cat] = hits

    if not scores:
        print(f"{YELLOW}[!] Offence classification unclear from description.{RESET}")
        return

    best_score = max(scores.values())
    cat = next(c for c, s in scores.items() if s == best_score)
    print(f"\n{BOLD}Identified Offence: {RED}{cat}{RESET}")
    if cat in LAW_MAP:
        it_act, bns, desc = LAW_MAP[cat]
        print(f"{BOLD}Applicable IT Act Provision: {CYAN}{it_act}{RESET}")
        print(f"{BOLD}Applicable BNS (IPC) Provision: {CYAN}{bns}{RESET}")
        print(f"{BOLD}Legal Analysis: {RESET}{desc}")

def fir_generator():
    print(f"\n{BOLD}{CYAN}=== 5. FORMAL CYBER CRIME POLICE FIR APPLICATION GENERATOR ==={RESET}")
    name = input("Complainant Full Name: ").strip() or "Concerned Citizen"
    contact = input("Contact Phone/Email: ").strip() or "+91-XXXXXXXXXX"
    loss = input("Financial Loss (if applicable): ").strip() or "N/A"
    facts = input("Summary of Incident: ").strip()
    
    fir = f"""
================================================================================
FORMAL CYBER CRIME POLICE COMPLAINT / FIR APPLICATION
================================================================================
DATE: {datetime.now().strftime('%d %B %Y')}
TO: THE OFFICER-IN-CHARGE, CYBER CRIME POLICE STATION.

1. COMPLAINANT: {name} (Contact: {contact})
2. FINANCIAL LOSS: {loss}
3. INCIDENT FACTS:
   {facts}
4. LEGAL SECTIONS: Section 43/66/66D of Information Technology Act, 2000 & BNS 2023.
5. PRAYER: Register formal FIR and issue preservation order under Sec 91 CrPC.

Digital Verification Seal: {sha256_text(name + facts)}
================================================================================
"""
    print(f"{GREEN}{fir}{RESET}")

def main():
    while True:
        print(f"\n{BOLD}{CYAN}======================================================={RESET}")
        print(f"{BOLD}{CYAN}  LEXGUARD CYBER DEFENSE & LEGAL FORENSICS SUITE (CLI) {RESET}")
        print(f"{BOLD}{CYAN}======================================================={RESET}")
        print("1. Threat Intelligence & Attack Identifier")
        print("2. Cryptographic Security Suite (AES / RSA / Multi-Hash)")
        print("3. Data Loss Prevention (DLP) & PII Redactor")
        print("4. Cyber Offence Classification & Statutory Law")
        print("5. Formal Cyber Crime Police FIR Application Generator")
        print("6. Exit")
        choice = input(f"\n{BOLD}Select Module (1-6): {RESET}").strip()

        if choice == "1": threat_identifier()
        elif choice == "2": crypto_suite()
        elif choice == "3": dlp_pii_scanner()
        elif choice == "4": offence_and_law()
        elif choice == "5": fir_generator()
        elif choice == "6":
            print(f"{GREEN}Exiting LexGuard. Security session closed.{RESET}")
            break
        else:
            print(f"{RED}Invalid selection.{RESET}")

if __name__ == "__main__":
    main()
