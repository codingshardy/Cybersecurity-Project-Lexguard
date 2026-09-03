"""LexGuard - Cyber Threat Identification & Legal Response Advisor.
Diploma in Computer Engineering - Cyber Security Microproject.
"""
import hashlib
import json
import os
import re

from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, "lexguard.key")
VAULT_DIR = os.path.join(BASE_DIR, "vault")

THREAT_RULES = {
    "Phishing": ["verify your account", "click here", "login", "urgent", "password", "otp", "suspended", "confirm your account"],
    "Ransomware": ["ransom", "decrypt", "encrypted files", "pay bitcoin", "bitcoin", "files encrypted", "decryption key"],
    "Malware-link": ["download", "attachment", ".exe", ".apk", "malware", "trojan", "install this app", "http://", "https://"],
    "Social Engineering": ["send me otp", "share otp", "impersonating", "pretend", "secret", "gift card", "act now", "do not tell anyone"],
}

OFFENCE_RULES = {
    "Hacking/Unauthorized Access": ["hacked", "unauthorized access", "accessed my account", "broke into", "login without permission", "password changed"],
    "Identity Theft": ["identity stolen", "stolen identity", "impersonated me", "used my aadhaar", "used my pan", "fake account in my name", "personal details used"],
    "Online Fraud": ["scammed", "fraud", "upi", "bank transfer", "otp fraud", "money stolen", "payment fraud", "phishing payment", "online scam"],
    "Cyberstalking": ["stalking", "repeated messages", "threatening messages", "harassing me online", "online harassment", "following me online"],
    "Data Theft": ["stole my data", "data stolen", "copied files", "database stolen", "downloaded confidential", "leaked data", "stolen files"],
}

# Educational mapping; legal applicability depends on facts and current law.
LAW_MAP = {
    "Hacking/Unauthorized Access": ("Section 43 read with Section 66", "Unauthorised access, copying/extraction of data or other computer-related acts; dishonest/fraudulent computer offences may attract Section 66.", "Report through cybercrime.gov.in or the nearest police cyber cell."),
    "Identity Theft": ("Section 66C", "Fraudulent or dishonest use of another person's electronic signature, password or other unique identification feature.", "Report through cybercrime.gov.in or the nearest police cyber cell."),
    "Online Fraud": ("Section 66D", "Cheating by personation using a communication device or computer resource.", "Report through cybercrime.gov.in or the nearest police cyber cell. For financial fraud, report to your bank/payment provider immediately too."),
    "Cyberstalking": ("Section 67 (where obscene/sexually explicit electronic content is involved); other laws may apply", "Section 67 concerns obscene material in electronic form; cyberstalking itself may involve other applicable criminal provisions depending on the conduct.", "Report through cybercrime.gov.in or the nearest police cyber cell."),
    "Data Theft": ("Section 43 read with Section 66", "Unauthorised downloading, copying or extraction of data can fall within Section 43; dishonest/fraudulent acts may attract Section 66.", "Report through cybercrime.gov.in or the nearest police cyber cell."),
}

WIFI_RISK = {
    "Open": ("High", "No Wi-Fi encryption is used; traffic and access are more exposed to interception and unauthorised use."),
    "WEP": ("High", "WEP is obsolete and can be broken relatively easily with modern tools."),
    "WPA": ("Medium", "WPA is older and weaker than WPA2/WPA3; upgrade when possible."),
    "WPA2": ("Low", "Generally secure when configured with a strong password and current router settings."),
    "WPA3": ("Low", "Modern Wi-Fi security with stronger protections; use a strong password and updated firmware."),
}

SENSITIVE_PERMISSIONS = {"camera", "microphone", "contacts", "sms", "location", "phone", "storage", "files", "call_log", "calendar", "contacts"}


def ensure_dirs():
    os.makedirs(VAULT_DIR, exist_ok=True)


def get_fernet():
    """Create/load the project's Fernet key."""
    ensure_dirs()
    try:
        if not os.path.exists(KEY_FILE):
            with open(KEY_FILE, "wb") as f:
                f.write(Fernet.generate_key())
            print("[+] New encryption key generated: lexguard.key")
        with open(KEY_FILE, "rb") as f:
            key = f.read().strip()
        return Fernet(key)
    except (OSError, ValueError) as exc:
        print(f"[!] Could not load encryption key: {exc}")
        return None


def sha256_file(path):
    """Return SHA-256 for a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_multiline(prompt="Enter text (press Enter on an empty line to finish):"):
    print(prompt)
    lines = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    return "\n".join(lines).strip()


def threat_identifier():
    print("\n=== 1. THREAT IDENTIFIER ===")
    text = read_multiline()
    if not text:
        print("[!] Please enter some text.")
        return

    lower = text.lower()
    scores = {}
    triggers = {}
    for category, keywords in THREAT_RULES.items():
        hits = [kw for kw in keywords if kw.lower() in lower]
        if hits:
            scores[category] = len(hits)
            triggers[category] = hits

    if not scores:
        print("Classification: Safe/Unclear")
        print("Reason: No configured threat keywords were detected. This is not a guarantee that the message is safe.")
        return

    best_score = max(scores.values())
    best = [cat for cat, score in scores.items() if score == best_score]
    category = best[0]
    print(f"Classification: {category}")
    print("Triggered keywords:", ", ".join(triggers[category]))
    if len(best) > 1:
        print("Note: Multiple categories matched; the first highest-scoring category is displayed.")
    print("Disclaimer: This is a rule-based educational detector, not a malware/phishing scanner.")


def crypto_vault():
    print("\n=== 2. CRYPTO VAULT ===")
    fernet = get_fernet()
    if not fernet:
        return
    print("1. Encrypt text note")
    print("2. Decrypt text note")
    print("3. Encrypt file")
    print("4. Decrypt file")
    choice = input("Choose an option: ").strip()

    if choice == "1":
        text = input("Enter text to encrypt: ")
        if not text:
            print("[!] Empty text.")
            return
        token = fernet.encrypt(text.encode()).decode()
        print("Encrypted text:")
        print(token)
    elif choice == "2":
        token = input("Paste Fernet token: ").strip()
        try:
            print("Decrypted text:")
            print(fernet.decrypt(token.encode()).decode())
        except (InvalidToken, UnicodeDecodeError):
            print("[!] Invalid key/token or corrupted encrypted text.")
    elif choice in {"3", "4"}:
        path = input("Enter file path: ").strip().strip('"')
        if not os.path.isfile(path):
            print("[!] File not found.")
            return
        try:
            before = sha256_file(path)
            with open(path, "rb") as f:
                data = f.read()
            if choice == "3":
                out = path + ".enc"
                result = fernet.encrypt(data)
            else:
                if not path.endswith(".enc"):
                    print("[!] Decryption expects a file ending in .enc created by this module.")
                    return
                out = path[:-4] + ".dec"
                result = fernet.decrypt(data)
            with open(out, "wb") as f:
                f.write(result)
            after = sha256_file(out)
            print(f"Output: {out}")
            print(f"SHA-256 input:  {before}")
            print(f"SHA-256 output: {after}")
            if choice == "4":
                print("[+] Decryption completed. Compare the decrypted-file hash with the original file's saved hash if available.")
        except (OSError, InvalidToken) as exc:
            print(f"[!] Operation failed: {exc}")
    else:
        print("[!] Invalid option.")


def data_protection_locker():
    print("\n=== 3. DATA PROTECTION LOCKER ===")
    fernet = get_fernet()
    if not fernet:
        return
    print("1. Save encrypted note")
    print("2. Retrieve encrypted note")
    choice = input("Choose an option: ").strip()
    if choice == "1":
        name = input("Vault filename (without .vault): ").strip()
        note = input("Enter sensitive note: ")
        if not name or not note:
            print("[!] Filename and note are required.")
            return
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        path = os.path.join(VAULT_DIR, safe_name + ".vault")
        try:
            payload = {"note": note}
            with open(path, "wb") as f:
                f.write(fernet.encrypt(json.dumps(payload).encode()))
            print(f"[+] Encrypted vault saved: {path}")
        except OSError as exc:
            print(f"[!] Could not save vault: {exc}")
    elif choice == "2":
        name = input("Vault filename (without .vault): ").strip()
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        path = os.path.join(VAULT_DIR, safe_name + ".vault")
        if not os.path.isfile(path):
            print("[!] Vault file not found.")
            return
        try:
            with open(path, "rb") as f:
                payload = json.loads(fernet.decrypt(f.read()).decode())
            print("Decrypted note:", payload.get("note", ""))
        except (OSError, InvalidToken, json.JSONDecodeError, UnicodeDecodeError):
            print("[!] Could not decrypt this vault. The key may be wrong or the file may be damaged.")
    else:
        print("[!] Invalid option.")


def classify_offence(text):
    lower = text.lower()
    scores = {}
    triggers = {}
    for category, keywords in OFFENCE_RULES.items():
        hits = [kw for kw in keywords if kw.lower() in lower]
        if hits:
            scores[category] = len(hits)
            triggers[category] = hits
    if not scores:
        return "Unclear", []
    best_score = max(scores.values())
    category = next(cat for cat, score in scores.items() if score == best_score)
    return category, triggers[category]


def cyber_law_mapper(category=None):
    print("\n=== 6. CYBER LAW MAPPER ===")
    if category not in LAW_MAP:
        categories = list(LAW_MAP.keys())
        for i, item in enumerate(categories, 1):
            print(f"{i}. {item}")
        try:
            selected = int(input("Select offence category: ").strip())
            category = categories[selected - 1]
        except (ValueError, IndexError):
            print("[!] Invalid category.")
            return

    section, description, report = LAW_MAP[category]
    print(f"Category: {category}")
    print(f"Relevant provision: {section}")
    print(f"Description: {description}")
    print(f"Reporting: {report}")
    print("Important: This mapping is for educational guidance; exact legal sections depend on the facts and current law.")


def offence_classifier():
    print("\n=== 4. OFFENCE CLASSIFIER ===")
    text = input("Describe the incident in one line: ").strip()
    if not text:
        print("[!] Please enter an incident description.")
        return
    category, hits = classify_offence(text)
    print(f"Classification: {category}")
    if hits:
        print("Triggered keywords:", ", ".join(hits))
    else:
        print("No configured offence keywords were detected.")
    if category in LAW_MAP:
        cyber_law_mapper(category)
    else:
        print("No automatic legal mapping available for Unclear classification.")


def wireless_mobile_checker():
    print("\n=== 5. WIRELESS & MOBILE RISK CHECKER ===")
    print("1. Check Wi-Fi encryption")
    print("2. Check app permissions")
    choice = input("Choose an option: ").strip()
    if choice == "1":
        options = list(WIFI_RISK.keys())
        for i, item in enumerate(options, 1):
            print(f"{i}. {item}")
        try:
            selected = int(input("Select Wi-Fi type: ").strip())
            kind = options[selected - 1]
        except (ValueError, IndexError):
            print("[!] Invalid selection.")
            return
        risk, explanation = WIFI_RISK[kind]
        print(f"Risk: {risk}")
        print(explanation)
    elif choice == "2":
        raw = input("Enter comma-separated permissions: ").strip()
        if not raw:
            print("[!] Please enter permissions.")
            return
        permissions = {p.strip().lower().replace(" ", "_") for p in raw.split(",") if p.strip()}
        sensitive = sorted(permissions & SENSITIVE_PERMISSIONS)
        count = len(sensitive)
        risk = "Low" if count <= 1 else "Medium" if count <= 3 else "High"
        print(f"Risk: {risk}")
        print(f"Sensitive permissions detected ({count}): {', '.join(sensitive) if sensitive else 'None'}")
        print("Note: Risk depends on context and whether the app legitimately needs each permission.")
    else:
        print("[!] Invalid option.")


def main():
    ensure_dirs()
    while True:
        print("\n" + "=" * 62)
        print("LEXGUARD - Cyber Threat Identification & Legal Response Advisor")
        print("=" * 62)
        print("1. Threat Identifier (CO1)")
        print("2. Crypto Vault (CO2)")
        print("3. Data Protection Locker (CO3)")
        print("4. Offence Classifier (CO4) + Cyber Law Mapper")
        print("5. Wireless & Mobile Risk Checker (CO5)")
        print("6. Cyber Law Mapper (CO6)")
        print("0. Exit")
        choice = input("\nEnter choice: ").strip()
        if choice == "1":
            threat_identifier()
        elif choice == "2":
            crypto_vault()
        elif choice == "3":
            data_protection_locker()
        elif choice == "4":
            offence_classifier()
        elif choice == "5":
            wireless_mobile_checker()
        elif choice == "6":
            cyber_law_mapper()
        elif choice == "0":
            print("Goodbye! Stay cyber-safe.")
            break
        else:
            print("[!] Invalid choice. Select 0-6.")


if __name__ == "__main__":
    main()
