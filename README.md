# CRU Bank Version 2 — secure multi-user starter

This is a **server-backed application starter**, not certified production core-banking software. It is designed to be deployed on a server with HTTPS and a managed PostgreSQL database.

## Features in this starter

- Individual staff accounts; administrator can create, edit, disable, rename, change usernames, roles and reset passwords (including own profile).
- Password hashes use Werkzeug's scrypt password hashing.
- Role-protected routes (Administrator, Branch Manager, Assistant Manager, Teller, Customer Service, Field Officer, Accountant).
- CSRF protection on forms.
- Customer directory and account opening workflow.
- Account opening requires 3 document files (Aadhaar, PAN, address proof), their document references, passport-size photo and signature specimen.
- Document files are encrypted at rest with Fernet; identity document numbers are encrypted at rest; list views show masked numbers.
- KYC maker-checker review: submitter cannot approve their own KYC.
- Transaction requests, withdrawal signature-check attestation and separate approval step.
- Audit events for login/logout, staff changes, document views, KYC decisions and transaction actions.
- Admin-configurable global idle screen lock; each staff member unlocks with their own password.
- Subtle UI animations.

## Run locally (development)

1. Install Python 3.11+.
2. Create and activate a virtual environment.
3. Install dependencies: `pip install -r requirements.txt`
4. Copy `.env.example` to `.env` and set secrets (see below).
5. Set environment variables from `.env` in your shell, or use your hosting provider's secret manager.
6. Run `python run.py`.
7. Visit `http://127.0.0.1:5000`.

For a local-only quick test, the app creates an initial administrator if none exists:
- Username: `admin`
- Password: `ChangeThisImmediately!2026`

**Change this immediately.** Prefer setting `BOOTSTRAP_ADMIN_USERNAME` and `BOOTSTRAP_ADMIN_PASSWORD` before the first run. Do not use the default on an internet-facing server.

## Generate keys

Generate a Flask secret:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Generate the document encryption key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put both in your hosting provider's secret manager or `.env` file. Keep backups of `DOCUMENT_ENCRYPTION_KEY`; if it is lost, encrypted uploads cannot be recovered. Never commit `.env` or keys to Git.

## Internet deployment outline

1. Provision a private application host and managed PostgreSQL database.
2. Set `DATABASE_URL` to the provider's PostgreSQL connection string.
3. Set `FLASK_SECRET_KEY`, `DOCUMENT_ENCRYPTION_KEY`, and a strong bootstrap admin password.
4. Set `COOKIE_SECURE=true`.
5. Run behind a TLS reverse proxy / managed HTTPS service using:
   `gunicorn --workers 2 --bind 0.0.0.0:8000 run:app`
6. Restrict database and encrypted-document storage to the application service account.
7. Configure encrypted backups, monitoring, security alerts, patching, rate limits/WAF, and a documented incident-response process.
8. Perform independent security testing and legal/regulatory review before any live customer use.

## Important limitations / required production work

This is **not ready for real banking operations**. It does not connect to CRU Bank's core banking platform, RBI, NPCI, UPI, NEFT, RTGS, cheque clearing or any settlement network. Transaction approval only records a demo status; it does not debit or credit balances. It does not perform official Aadhaar/PAN authentication or government KYC checks. Document-number format checks are not authenticity checks. Signature verification is a staff attestation only, not biometric/signature-forensic verification.

Before collecting real customer data, CRU Bank must obtain qualified legal/compliance advice on applicable Indian banking, KYC/AML, privacy and data-protection requirements, consent, purpose limitation, retention/deletion, access logging and approved identity-verification channels. Do not upload live Aadhaar/PAN or customer documents to this starter until it has undergone professional security and compliance review.

Additional work for a real production system includes database migrations, account-number allocation rules, branch-level data scoping, MFA, login throttling/lockout, password-reset workflow, session re-authentication lock overlay, security headers/CSP, malware scanning/CDR for PDFs, document retention policy, encrypted backups/key rotation, tamper-evident audit storage, dual control for all financial postings, reconciliation, limits, sanctions/fraud checks, dispute handling, disaster recovery, penetration testing and integration certification.

## Internet deployment (Render)

This repository includes `render.yaml` for a Render Blueprint deployment. It is **not already online**; you must deploy it from your own GitHub account and configure the secrets.

1. Create a private GitHub repository and upload the contents of this folder.
2. Create an account at Render and choose **New → Blueprint**, then connect that repository.
3. Before deploying, generate a Fernet key on a trusted computer by running:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
4. In the Render Blueprint environment prompt, enter a long unique `BOOTSTRAP_ADMIN_PASSWORD` and the generated `DOCUMENT_ENCRYPTION_KEY`. Keep both private and store them in a password manager.
5. Deploy. Render will provide an HTTPS `onrender.com` address after a successful deployment. Bookmark that address to open the app from your browser.
6. Sign in with username `admin` and the bootstrap password you supplied. Immediately change the password and create separate staff accounts.

**Important deployment notes:** The Blueprint provisions paid Render resources (a starter web service, persistent disk, and basic PostgreSQL database); pricing can change, so check the current estimate before approving. Never use real customer Aadhaar/PAN, photographs, signatures, or money until a qualified security team has completed a production security, privacy, regulatory, backup, and disaster-recovery review. This project is a workflow prototype: it does not connect to banking rails or move/settle funds.
