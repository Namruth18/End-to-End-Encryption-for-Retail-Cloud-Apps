================================================================================
  SECURECLOUD — End-to-End Encrypted Messaging Platform
  Yenepoya University | Project 2026
================================================================================

OVERVIEW
--------
SecureCloud is a web-based, end-to-end encrypted (E2EE) secure messaging and
file-sharing platform built for internal organizational use. It features
role-based access control, encrypted message storage, file encryption,
group messaging, a full audit trail, and optional two-factor authentication (2FA).

The system is designed so that no plaintext data is ever stored in the database.
All messages and files are encrypted at rest using Fernet (AES-128-CBC + HMAC).


PROJECT STRUCTURE
-----------------
  app.py              — Flask backend (REST API, encryption logic, DB management)
  index.html          — Frontend UI (single-page application)
  script.js           — Frontend JavaScript (AJAX calls, UI logic)
  style.css           — Stylesheet (dark cyberpunk theme)
  requirements.txt    — Python dependencies
  launch.json         — VS Code debug configuration (Chrome, port 8080)
  server.key          — Server key file
  audit.json          — Sample audit log export
  messages.json       — Sample encrypted messages export
  users.json          — Sample user data export


TECH STACK
----------
  Backend  : Python 3, Flask 3.0, Flask-CORS 4.0
  Database : SQLite (WAL mode, foreign keys enabled)
  Crypto   : cryptography 41.0.7 (Fernet AES-128-CBC, PBKDF2HMAC, HMAC-SHA256)
  2FA      : TOTP (Time-Based One-Time Password, RFC 6238)
  Frontend : Vanilla HTML/CSS/JS, JetBrains Mono + Orbitron fonts, QRCode.js


FEATURES
--------
  [*] End-to-end encrypted messages (Fernet AES-128-CBC + HMAC integrity check)
  [*] Encrypted file upload, storage, and download
  [*] Role-based access control — Admin, Cashier, Customer Support
  [*] Message categories per role:
        Admin            -> billing, transaction, customer, general
        Cashier          -> billing, transaction
        Customer Support -> customer, general
  [*] Group messaging with per-group encryption keys
  [*] Automatic key rotation when a group member is removed or leaves
  [*] Admin-initiated global encryption key rotation
  [*] TOTP-based 2FA (QR code setup via authenticator app)
  [*] Session token management with expiry
  [*] PBKDF2 password hashing with per-user salt
  [*] Full audit / activity log with HMAC integrity hashes
  [*] Real-time message polling via AJAX
  [*] Key sharing simulation between users
  [*] Attachment support in messages (up to 10 MB, encrypted)


INSTALLATION
------------
  Prerequisites: Python 3.9 or higher

  1. Clone or download the project files into a folder.

  2. (Recommended) Create a virtual environment:
        python -m venv venv
        source venv/bin/activate        # Linux / macOS
        venv\Scripts\activate           # Windows

  3. Install dependencies:
        pip install -r requirements.txt

  4. Run the backend server:
        python app.py

  5. Open your browser and navigate to:
        http://localhost:8000


DEFAULT CREDENTIALS
-------------------
  Username : admin
  Password : admin123
  Role     : Admin

  (Change this immediately in a real deployment!)


USER ROLES
----------
  admin
    - Full access to all message categories
    - Can register new users and assign roles
    - Can rotate encryption keys
    - Can view the full audit log
    - Can manage all groups

  cashier
    - Access to billing and transaction message categories
    - Can send/receive messages and files within allowed categories
    - Can create and participate in groups

  customer_support
    - Access to customer and general message categories


DATABASE SCHEMA (SQLite)
------------------------
  users          — Credentials, role, TOTP secret, login timestamps
  enc_keys       — Encryption keys (active/rotated), creator, timestamps
  messages       — Encrypted messages, HMAC tags, read status, attachments
  files          — Encrypted uploaded files, HMAC tags, owner
  shared_keys    — Key sharing records between users
  groups         — Group metadata (name, creator)
  group_members  — Group membership records
  group_keys     — Per-group Fernet encryption keys
  group_messages — Encrypted group messages with HMAC tags
  sessions       — Active session tokens with expiry
  audit          — Tamper-evident action log (each entry has an integrity hash)

  Database file location: securecloud_db/securecloud.db
  Encrypted files folder: securecloud_db/encrypted_files/


API ENDPOINTS (Selected)
------------------------
  POST /api/login               — Authenticate user, returns session token
  POST /api/register            — Register a new user
  POST /api/logout              — Invalidate session token
  GET  /api/messages            — Fetch inbox (decrypted on server, sent to client)
  POST /api/messages/send       — Send an encrypted message
  GET  /api/audit               — Retrieve audit log (admin only)
  POST /api/keys/rotate         — Rotate global encryption key (admin only)
  POST /api/2fa/setup           — Set up TOTP 2FA for an account
  POST /api/files/upload        — Upload and encrypt a file
  GET  /api/files/download/<id> — Download and decrypt a file
  POST /api/groups/create       — Create a new group
  POST /api/groups/<id>/send    — Send a message to a group
  POST /api/groups/<id>/members/add    — Add a group member (admin/creator)
  POST /api/groups/<id>/members/remove — Remove a member + rotate group key


SECURITY NOTES
--------------
  - Passwords are never stored in plaintext; they are hashed with PBKDF2-HMAC-SHA256
    using a unique random salt per user.
  - Message content is encrypted with Fernet before being written to the database.
  - Each message also carries an HMAC tag for tamper detection (integrity: PASS/FAIL).
  - Audit log entries include an HMAC hash to detect log tampering.
  - When a user is removed from a group, the group encryption key is automatically
    rotated so the removed user cannot decrypt future messages.
  - Session tokens expire and are validated on every request.

  WARNING: This is a university project. Before deploying in any production
  environment, conduct a full security audit. In particular:
    - Enforce HTTPS (TLS) in production.
    - Store the server key securely (e.g., environment variable or secrets manager).
    - Replace the default admin credentials immediately.
    - Enable proper input sanitization and rate limiting.


VS CODE DEBUGGING
-----------------
  The included launch.json is configured for Chrome debugging against
  http://localhost:8080. Make sure the backend is running on port 8000
  and adjust if needed.


DEPENDENCIES (requirements.txt)
--------------------------------
  flask==3.0.0
  flask-cors==4.0.0
  cryptography==41.0.7


AUTHORS / CREDITS
-----------------
  Yenepoya University — Project 2026
  SecureCloud E2EE Platform

================================================================================