# LexGuard — Enterprise Cyber Defense & Legal Forensics Platform

An offline, local-first cybersecurity suite combining heuristic threat intelligence, multi-cipher cryptography, automated data loss prevention (DLP), digital evidence chain of custody, and court-admissible cyber law enforcement tools.

---

## Key Modules & Capabilities

### 1. Threat Intelligence & Incident Analysis
- **Multi-Vector Heuristic Engine**: Real-time identification of Phishing, Ransomware, Trojan payloads, Social Engineering, and Web Application Attacks (SQLi/XSS).
- **MITRE ATT&CK Matrix Mapping**: Automatic tagging of adversary Tactics & Techniques (e.g., T1566 Phishing, T1486 Data Encrypted for Impact, T1056 Credential Harvesting, T1190 Exploit Public Facing App).
- **Automated IOC Extraction**: Extracts and catalogs IPv4 addresses, URLs, domains, email addresses, crypto wallets, UPI VPAs, and MD5/SHA hashes.
- **Dynamic Containment Playbooks**: Step-by-step incident response checklists.

### 2. Cryptographic Security Suite
- **AES-256 Symmetric Encryption**: Multi-mode AES (AES-256-GCM authenticated encryption and AES-256-CBC) with PBKDF2 100,000-iteration key derivation, random salts, and initialization vectors.
- **RSA-2048 Asymmetric Cryptography**: Standard 2048/3072/4096-bit RSA keypair generation, public key distribution, and RSA-PSS with SHA-256 digital signature creation and tamper verification.
- **Multi-Algorithm Hash Inspector**: Simultaneous computation of SHA-256, SHA-512, SHA3-256 (Keccak), BLAKE2b, and MD5 with Shannon entropy metrics.
- **Image Steganography Studio**: Conceals secret payloads into the Least Significant Bits (LSB) of PNG image pixel matrices and extracts them intact.
- **Diffie-Hellman Key Exchange Simulator**: Mathematical step-by-step demonstration of secure asynchronous shared secret derivation.
- **Zero-Knowledge Encrypted Vault**: Master Fernet encrypted locker for credentials and secure notes.

### 3. Data Loss Prevention (DLP) & Privacy Vault
- **Automated PII Redactor**: Inspects and sanitizes text containing:
  - **Aadhaar Numbers** (with Verhoeff checksum validation)
  - **PAN Cards** (Indian Income Tax identifier pattern)
  - **Credit / Debit Cards** (with Luhn algorithm validation)
  - **API Keys / Secrets** (GitHub tokens, AWS keys, JWT Bearer tokens)
  - **Phone Numbers & Emails**
- **DoD 5220.22-M Secure File Sanitizer (Shredder)**: Simulates 3-pass and 7-pass military-grade cryptographic data purging to render file magnetic traces unrecoverable.

### 4. Digital Evidence Vault & Chain of Custody
- **Cryptographic Preservation**: Ingests digital evidence artifacts and registers irreversible SHA-256 fingerprints.
- **Real-Time Tamper Verification**: Compares live byte streams against stored genesis hashes to detect any unauthorized alterations.
- **Tamper-Evident Hash Chain Audit Log**: Cryptographically links all audit actions using a blockchain-like previous-hash verification chain.

### 5. Cyber Law Enforcement & Court-Admissible Reporting
- **Statutory Framework Mapping**: Direct mapping of offences to:
  - **Information Technology Act, 2000 / 2008** (Sections 43, 66, 66C, 66D, 66E, 66F, 67, 72A)
  - **Bharatiya Nyaya Sanhita (BNS), 2023** (Sections 318, 319, 78, 303, 316) / IPC
  - **Digital Personal Data Protection (DPDP) Act, 2023**
- **Formal Cyber Crime Police FIR Application Generator**: Produces ready-to-file legal complaint documents with evidence seals, timeline, financial loss breakdown, and statutory citations.
- **Section 65B (IEA) / Section 63 (BSA) Digital Evidence Certificate**: Generates legal affidavits required for court admissibility of electronic records in India.
- **Forensic PDF Investigation Reports**: Generates detailed, professional PDF case dossiers.

### 6. Wireless & Mobile Threat Radar
- **802.11 Wi-Fi Protocol Risk Evaluator**: Analyzes Open, WEP, WPA, WPA2, and WPA3 security profiles against Evil Twin, Deauthentication, and packet interception threats.
- **Android Permission & Malware Profiler**: Detects dangerous permission combinations such as *SMS + Storage* (OTP Theft), *Camera + Mic + Location* (Spyware), and *Overlay + Accessibility* (Keylogging/Banking Trojan).

---

## Installation & Running

### Prerequisites
- Python 3.10+
- Dependencies: `Flask`, `cryptography`, `reportlab`, `Pillow`

### Quick Start (Web SOC Interface)
```powershell
# In project folder:
venv\Scripts\activate
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

### Terminal CLI Interface
```powershell
python lexguard.py
```

---

## 5-Minute Demonstration Guide for Evaluators

1. **SOC Dashboard (`/`)**:
   - Show real-time telemetry, threat distribution, and system status.
   - Switch between **Dark Mode** and **Light Mode**.
2. **Threat Intelligence (`Analyze Incident`)**:
   - Ingest a phishing or financial fraud sample (or click **Attack Simulator → Phishing Attack**).
   - Point out the **Risk Score**, **Extracted IOCs**, **MITRE ATT&CK Tactics (T1566, T1056)**, and **IT Act / BNS Statutory Provisions**.
   - Click **Download Forensic PDF Report**.
3. **Cryptographic Suite (`Cryptographic Security Suite`)**:
   - **AES-256 Tab**: Encrypt a secret text in GCM mode; decrypt with master passphrase.
   - **RSA-2048 Tab**: Click *Generate Keypair*; enter a message and generate a digital signature; click *Verify Signature*.
   - **Steganography Lab**: Upload an image and embed a secret message; download the stego PNG and extract the hidden payload.
   - **Multi-Hash Tab**: Enter text and show SHA-256, SHA-512, SHA3-256, and BLAKE2b side-by-side with entropy.
4. **Data Loss Prevention (`Data Loss Prevention`)**:
   - Run the **PII Redactor** on text containing Aadhaar, PAN, and Credit Card numbers to show automated masking.
   - Run the **DoD 5220.22-M File Shredder** to demonstrate multi-pass sanitization.
5. **Cyber Law & FIR Suite (`Cyber Law & Legal Enforcement`)**:
   - Click **Formal Cyber Crime FIR Generator** to generate a court-ready police complaint.
   - Click **Section 65B Certificate** to produce an electronic evidence affidavit.
6. **Digital Evidence Vault (`Evidence Vault`)**:
   - Ingest an evidence file, view the SHA-256 fingerprint, and run **Verify Integrity** to demonstrate tamper detection.
