# LexGuard – Cyber Threat Identification & Legal Response Advisor

A Python CLI microproject for Diploma in Computer Engineering – Cyber Security. LexGuard combines rule-based cyber-threat identification, symmetric encryption, data protection, cyber-offence classification, wireless/mobile risk scoring, and educational cyber-law guidance in one offline application.

## Course Outcome Mapping

| Module | Feature | CO |
|---|---|---|
| 1 | Threat Identifier – keyword-based phishing/ransomware/malware/social-engineering detection | CO1 – Identify software threats and attacks |
| 2 | Crypto Vault – Fernet encryption/decryption + SHA-256 hashing | CO2 – Apply cryptographic algorithms |
| 3 | Data Protection Locker – encrypted `.vault` notes | CO3 – Apply data protection techniques |
| 4 | Offence Classifier – hacking, identity theft, fraud, cyberstalking, data theft | CO4 – Analyze types of cyber offences |
| 5 | Wireless & Mobile Risk Checker – Wi-Fi and app-permission risk | CO5 – Cybercrime on wireless/mobile devices |
| 6 | Cyber Law Mapper – educational IT Act mapping and reporting guidance | CO6 – Apply cyber law to a given issue |

## Features

1. **Threat Identifier:** Paste suspicious email/SMS text. The rule engine reports the highest-scoring category and matching keywords.
2. **Crypto Vault:** Encrypt/decrypt text or files with a locally stored Fernet key. File operations also show SHA-256 hashes.
3. **Data Protection Locker:** Stores sensitive notes as encrypted `.vault` files in `vault/`.
4. **Offence Classifier:** Classifies an incident description and automatically launches the legal mapping.
5. **Wireless & Mobile Risk Checker:** Scores Wi-Fi encryption or a list of app permissions.
6. **Cyber Law Mapper:** Provides educational legal guidance and directs users to the National Cyber Crime Reporting Portal / nearest cyber cell.

## Requirements

- Python 3.10 or newer
- `cryptography`
- Internet is **not required** for the program itself.

## Windows Installation

Open Command Prompt or PowerShell in this folder:

```powershell
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python lexguard.py
```

If `python` is not recognized, try `py`:

```powershell
py -m venv venv
venv\Scripts\activate
py -m pip install -r requirements.txt
py lexguard.py
```

## First Run

The application creates:

- `lexguard.key` – the Fernet encryption key. **Do not delete or share it if you need to decrypt existing vaults/files.**
- `vault/` – encrypted notes created by Module 3.

## Demo Flow

For a smooth viva/demo:

1. Select **1**, paste a phishing sample, and show the triggered keywords.
2. Select **2 → 1**, encrypt a short note and show the Fernet token.
3. Select **2 → 2**, paste the token and show the original text.
4. Select **3 → 1**, save a fake demo password/ID; then retrieve it with **3 → 2**.
5. Select **4**, paste an online-fraud incident and show the automatic legal mapping.
6. Select **5**, demonstrate Open/WEP vs WPA2/WPA3 and then app permissions.
7. Select **6**, manually choose another offence category.

## Important Legal Note

The legal mapping is intentionally educational and rule-based. A cyber incident may involve multiple provisions, and the correct legal provisions depend on the facts, evidence, jurisdiction, and law in force at the time. Do not present the tool as a substitute for legal advice.

## Security Note

This is a classroom demonstration, not a production password manager. The project stores its Fernet key locally, so anyone who obtains both the key and encrypted files can decrypt them. Use only fictional/demo secrets during presentations.


## LexGuard 2.0 Upgrades

The existing modules remain intact. The web application now additionally provides:

- Digital Evidence Vault with Evidence IDs, metadata and incident association
- SHA-256 original/current integrity verification
- Digital chain-of-custody history
- Tamper-evident hash-chain audit log
- Local IOC extraction for IPv4, URLs, domains, email addresses and MD5/SHA hashes
- Local MITRE ATT&CK technique mapping
- Structured incident response playbooks with completion progress
- Incident timeline and case/history investigation center
- Severity (Critical/High/Medium/Low) and P1-P4 priority
- SOC dashboard metrics
- Local URL analyzer, static file triage and password security lab
- Controlled cyber-attack demo simulator
- One-click forensic case ZIP export

### Web Application

```powershell
python app.py
```
Then open `http://127.0.0.1:5000`. The project remains local/offline; no external threat-intelligence API is required for the new analysis modules.

### Recommended 5-minute demo

1. Run **Demo Simulator → Phishing Attack**.
2. Show risk score, offence, extracted IOCs and MITRE ATT&CK mapping.
3. Open **Investigation Center** and inspect the incident timeline.
4. Upload a screenshot/text file in **Evidence Vault**, show SHA-256 and chain of custody.
5. Verify evidence integrity; demonstrate the verified status.
6. Mark response-playbook steps complete and show progress.
7. Open **Security Lab → URL Analyzer** and analyze a suspicious URL.
8. Export the complete forensic case ZIP and show its structured contents.
