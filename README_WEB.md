# LexGuard Web Dashboard

LexGuard is now available as a local Flask website on top of the existing Python security engine.

## Features added

1. Professional dark cybersecurity dashboard
2. Unified **Analyze Incident** workflow
3. Explainable rule-match reasoning (why it was flagged)
4. Dynamic overall risk score
5. Incident ID and timestamp
6. Guided incident-response recommendations
7. Evidence Locker with SHA-256 integrity recording and verification
8. Fernet Crypto Vault + Data Protection Locker
9. Educational cyber-law mapping and reporting guidance
10. PDF incident report generation
11. “I think I've been hacked” guided response mode
12. Wi-Fi and mobile permission risk tools

## Run on Windows

Open PowerShell in `D:\LexGuard` (or wherever you extracted the project):

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe app.py
```

If PowerShell blocks activation, **do not worry**. Activation is optional; the commands above use the virtual environment's Python directly.

Then open:

`http://127.0.0.1:5000`

## Important files

- `lexguard.py` — original CLI application
- `app.py` — Flask web backend
- `templates/index.html` — website UI
- `static/style.css` — dark cybersecurity UI styling
- `static/app.js` — frontend logic
- `vault/` — encrypted vault records
- `evidence/` — uploaded evidence + recorded SHA-256 metadata
- `reports/` — generated PDF reports
- `lexguard.key` — encryption key created on first use; keep it safe

## Legal disclaimer

LexGuard's legal mapping is educational guidance only. Exact legal provisions depend on the facts and current law. The website should not be presented as a substitute for legal advice or official law-enforcement guidance.
