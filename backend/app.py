# ═══════════════════════════════════════════════════════════════════════
#  SecureCloud E2EE  |  Yenepoya University Project 2026
#  app.py  —  FULL FEATURE BACKEND
#
#  Features:
#   ✅ Fernet AES-128 symmetric encryption (encrypt + decrypt same key)
#   ✅ Key rotation (admin can rotate the active encryption key)
#   ✅ SQLite database (users, messages, files, keys, audit, sessions)
#   ✅ Secure file upload/encrypt/download/decrypt
#   ✅ Message integrity check via HMAC hash
#   ✅ Timestamp on every message
#   ✅ Chat history per conversation
#   ✅ Role-based access control (admin / cashier / customer_support)
#   ✅ No plaintext ever stored in DB
#   ✅ TOTP-based 2FA (time-based one-time password)
#   ✅ Key sharing simulation between users
#   ✅ Session token management
#   ✅ Full audit / activity log
#   ✅ Real-time AJAX polling endpoint
# ═══════════════════════════════════════════════════════════════════════

from flask import Flask, request, jsonify, send_file, abort, send_from_directory
from flask_cors import CORS
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import sqlite3, base64, os, io, hashlib, hmac as stdlib_hmac
import datetime, time, struct, secrets, json
from pathlib import Path
from functools import wraps

app = Flask(__name__)

FRONTEND_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "frontend"
)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR     = Path("securecloud_db")
BASE_DIR.mkdir(exist_ok=True)
DB_PATH      = BASE_DIR / "securecloud.db"
FILES_DIR    = BASE_DIR / "encrypted_files"
FILES_DIR.mkdir(exist_ok=True)

ROLE_CATEGORIES = {
    "admin":            ["billing", "transaction", "customer", "general"],
    "cashier":          ["billing", "transaction"],
    "customer_support": ["customer", "general"],
    "user":             ["billing", "transaction", "customer", "general"],
}

# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username    TEXT PRIMARY KEY,
            pass_hash   TEXT NOT NULL,
            salt        TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'cashier',
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            created_at  TEXT NOT NULL,
            last_login  TEXT
        );

        CREATE TABLE IF NOT EXISTS enc_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name    TEXT NOT NULL,
            key_data    TEXT NOT NULL,          -- base64 Fernet key
            is_active   INTEGER DEFAULT 0,
            created_at  TEXT NOT NULL,
            created_by  TEXT NOT NULL,
            rotated_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS messages (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            sender         TEXT NOT NULL,
            recipient      TEXT NOT NULL,
            ciphertext     TEXT NOT NULL,
            hmac_tag       TEXT NOT NULL,         -- integrity check
            category       TEXT NOT NULL DEFAULT 'general',
            key_id         INTEGER NOT NULL,
            is_read        INTEGER DEFAULT 0,
            read_at        TEXT,
            sent_at        TEXT NOT NULL,
            has_attachment INTEGER DEFAULT 0,
            attach_name    TEXT,
            attach_mime    TEXT,
            attach_data    TEXT,                  -- base64 encrypted attachment bytes
            FOREIGN KEY(key_id) REFERENCES enc_keys(id)
        );

        CREATE TABLE IF NOT EXISTS files (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            owner        TEXT NOT NULL,
            orig_name    TEXT NOT NULL,
            stored_name  TEXT NOT NULL,
            mime_type    TEXT,
            file_size    INTEGER,
            key_id       INTEGER NOT NULL,
            hmac_tag     TEXT NOT NULL,
            uploaded_at  TEXT NOT NULL,
            FOREIGN KEY(key_id) REFERENCES enc_keys(id)
        );

        CREATE TABLE IF NOT EXISTS shared_keys (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user    TEXT NOT NULL,
            to_user      TEXT NOT NULL,
            key_data     TEXT NOT NULL,         -- encrypted with recipient's public salt
            key_name     TEXT NOT NULL,
            shared_at    TEXT NOT NULL,
            accepted     INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS groups (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name   TEXT NOT NULL,
            created_by   TEXT NOT NULL,
            created_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS group_members (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL,
            username   TEXT NOT NULL,
            joined_at  TEXT NOT NULL,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        );

        CREATE TABLE IF NOT EXISTS group_keys (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL UNIQUE,
            key_data   TEXT NOT NULL,      -- base64 Fernet key
            rotated_at TEXT,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        );

        CREATE TABLE IF NOT EXISTS group_messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL,
            sender     TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            hmac_tag   TEXT NOT NULL,
            sent_at    TEXT NOT NULL,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            username    TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            expires_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT NOT NULL,
            username    TEXT NOT NULL,
            details     TEXT,
            ip_addr     TEXT,
            logged_at   TEXT NOT NULL,
            integrity   TEXT NOT NULL
        );
        """)

        # Create default admin if not exists
        row = db.execute("SELECT username FROM users WHERE username='admin'").fetchone()
        if not row:
            salt = os.urandom(16)
            ph   = _hash_password("admin123", salt)
            now  = _now()
            db.execute("""INSERT INTO users(username,pass_hash,salt,role,created_at)
                          VALUES(?,?,?,?,?)""",
                       ("admin", ph, base64.b64encode(salt).decode(), "admin", now))

        # Create first encryption key if none exist
        row = db.execute("SELECT id FROM enc_keys WHERE is_active=1").fetchone()
        if not row:
            key = Fernet.generate_key()
            db.execute("""INSERT INTO enc_keys(key_name,key_data,is_active,created_at,created_by)
                          VALUES(?,?,1,?,?)""",
                       ("key-v1", base64.b64encode(key).decode(), _now(), "system"))
        db.commit()

# ── Helpers ────────────────────────────────────────────────────────────────────
def _now():
    return datetime.datetime.utcnow().isoformat()

def _hash_password(password: str, salt: bytes) -> str:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000,
                     backend=default_backend())
    return base64.b64encode(kdf.derive(password.encode())).decode()

def _get_active_fernet() -> tuple:
    """Return (Fernet instance, key_id) for the currently active key."""
    with get_db() as db:
        row = db.execute("SELECT id, key_data FROM enc_keys WHERE is_active=1 ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        raise RuntimeError("No active encryption key found.")
    raw = base64.b64decode(row["key_data"])
    return Fernet(raw), row["id"]

def _fernet_for_key_id(key_id: int) -> Fernet:
    """Return Fernet instance for a specific historical key (needed for decryption)."""
    with get_db() as db:
        row = db.execute("SELECT key_data FROM enc_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        raise ValueError(f"Key id={key_id} not found.")
    return Fernet(base64.b64decode(row["key_data"]))

def _compute_hmac(ciphertext: str, key_id: int) -> str:
    """Compute HMAC-SHA256 for message integrity verification."""
    with get_db() as db:
        row = db.execute("SELECT key_data FROM enc_keys WHERE id=?", (key_id,)).fetchone()
    raw_key = base64.b64decode(row["key_data"])
    h = stdlib_hmac.new(raw_key, ciphertext.encode(), hashlib.sha256)
    return h.hexdigest()

def _verify_hmac(ciphertext: str, tag: str, key_id: int) -> bool:
    expected = _compute_hmac(ciphertext, key_id)
    return stdlib_hmac.compare_digest(expected, tag)

def _audit(action: str, username: str, details: str = ""):
    try:
        ip = request.remote_addr
    except RuntimeError:
        ip = "system"
    payload = f"{action}|{username}|{details}|{_now()}"
    integrity = hashlib.sha256(payload.encode()).hexdigest()[:20]
    with get_db() as db:
        db.execute("""INSERT INTO audit(action,username,details,ip_addr,logged_at,integrity)
                      VALUES(?,?,?,?,?,?)""",
                   (action, username, details, ip, _now(), integrity))
        db.commit()

# ── TOTP (Time-based One-Time Password) ───────────────────────────────────────
def _totp_generate_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode()

def _totp_code(secret: str) -> str:
    """Generate current 6-digit TOTP code (30-second window)."""
    key    = base64.b32decode(secret.upper())
    counter = struct.pack(">Q", int(time.time()) // 30)
    h = stdlib_hmac.new(key, counter, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)

def _totp_verify(secret: str, code: str) -> bool:
    """Verify TOTP code (checks ±1 window for clock skew)."""
    key = base64.b32decode(secret.upper())
    for drift in (-1, 0, 1):
        counter = struct.pack(">Q", int(time.time()) // 30 + drift)
        h = stdlib_hmac.new(key, counter, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        expected = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
        if str(expected % 1_000_000).zfill(6) == str(code).zfill(6):
            return True
    return False

# ── Session tokens ─────────────────────────────────────────────────────────────
def _create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    exp   = (datetime.datetime.utcnow() + datetime.timedelta(hours=12)).isoformat()
    with get_db() as db:
        db.execute("INSERT INTO sessions(token,username,created_at,expires_at) VALUES(?,?,?,?)",
                   (token, username, _now(), exp))
        db.commit()
    return token

def _validate_session(token: str):
    with get_db() as db:
        row = db.execute("SELECT username, expires_at FROM sessions WHERE token=?", (token,)).fetchone()
    if not row:
        return None
    if row["expires_at"] < _now():
        return None
    return row["username"]

init_db()

# ── DB MIGRATION: add attachment columns if upgrading from older version ──
def _migrate_db():
    with get_db() as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(messages)").fetchall()]
        for col, defn in [("has_attachment","INTEGER DEFAULT 0"),("attach_name","TEXT"),
                          ("attach_mime","TEXT"),("attach_data","TEXT")]:
            if col not in cols:
                db.execute(f"ALTER TABLE messages ADD COLUMN {col} {defn}")
        db.commit()

# ── DB MIGRATION: create group tables if upgrading ────────────────────────
def _migrate_groups():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS groups (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name   TEXT NOT NULL,
            created_by   TEXT NOT NULL,
            created_at   TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS group_members (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL,
            username   TEXT NOT NULL,
            joined_at  TEXT NOT NULL,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        );
        CREATE TABLE IF NOT EXISTS group_keys (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL UNIQUE,
            key_data   TEXT NOT NULL,
            rotated_at TEXT,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        );
        CREATE TABLE IF NOT EXISTS group_messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id        INTEGER NOT NULL,
            sender          TEXT NOT NULL,
            ciphertext      TEXT NOT NULL,
            hmac_tag        TEXT NOT NULL,
            sent_at         TEXT NOT NULL,
            has_attachment  INTEGER DEFAULT 0,
            attach_name     TEXT,
            attach_mime     TEXT,
            attach_data     TEXT,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        );
        """)
        # Migrate attachment columns onto existing group_messages table
        cols = [r[1] for r in db.execute("PRAGMA table_info(group_messages)").fetchall()]
        for col, defn in [("has_attachment","INTEGER DEFAULT 0"),("attach_name","TEXT"),
                          ("attach_mime","TEXT"),("attach_data","TEXT")]:
            if col not in cols:
                db.execute(f"ALTER TABLE group_messages ADD COLUMN {col} {defn}")
        db.commit()

_migrate_groups()
_migrate_db()


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

# Serve CSS, JS and other assets.  Two URL patterns so both old (/frontend/...)
# and new bare (/style.css) references work without any catch-all that could
# shadow /api/* routes.
_ALLOWED_EXTS = {'.css', '.js', '.ico', '.png', '.jpg', '.svg', '.woff', '.woff2', '.ttf'}

@app.route('/frontend/<path:filename>')
def frontend_static(filename):
    return send_from_directory(FRONTEND_DIR, filename)

# ── REGISTER ──────────────────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    d        = request.json or {}
    username = d.get("username", "").strip()
    password = d.get("password", "").strip()
    # Everyone who self-registers gets 'user' role — only admin is special
    role     = "user"

    if not username or not password:
        return jsonify({"success": False, "message": "All fields required."}), 400
    if len(username) < 3:
        return jsonify({"success": False, "message": "Username must be at least 3 characters."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400
    if not username.replace("_","").isalnum():
        return jsonify({"success": False, "message": "Username: letters, numbers and _ only."}), 400

    with get_db() as db:
        if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            return jsonify({"success": False, "message": "Username already taken."}), 409
        salt = os.urandom(16)
        ph   = _hash_password(password, salt)
        db.execute("""INSERT INTO users(username,pass_hash,salt,role,created_at)
                      VALUES(?,?,?,?,?)""",
                   (username, ph, base64.b64encode(salt).decode(), role, _now()))
        db.commit()

    _audit("REGISTER", username, "New user registered")
    return jsonify({"success": True, "message": "Account created! You can now sign in."})

# ── LOGIN ──────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    d        = request.json or {}
    username = d.get("username", "").strip()
    password = d.get("password", "")
    totp_code= d.get("totp_code", "").strip()

    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    if not row:
        _audit("LOGIN_FAIL", username or "unknown", "User not found")
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    salt = base64.b64decode(row["salt"])
    if _hash_password(password, salt) != row["pass_hash"]:
        _audit("LOGIN_FAIL", username, "Wrong password")
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    # 2FA check
    if row["totp_enabled"] and row["totp_secret"]:
        if not totp_code:
            return jsonify({"success": False, "needs_2fa": True,
                            "message": "2FA code required."}), 200
        if not _totp_verify(row["totp_secret"], totp_code):
            _audit("2FA_FAIL", username, "Wrong TOTP")
            return jsonify({"success": False, "message": "Invalid 2FA code."}), 401

    token = _create_session(username)
    with get_db() as db:
        db.execute("UPDATE users SET last_login=? WHERE username=?", (_now(), username))
        db.commit()

    _audit("LOGIN", username, "Success")
    return jsonify({
        "success":  True,
        "username": username,
        "role":     row["role"],
        "token":    token,
        "totp_enabled": bool(row["totp_enabled"])
    })

# ── LOGOUT ────────────────────────────────────────────────────────────────────
@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.json.get("token","") if request.json else ""
    username = _validate_session(token)
    if token:
        with get_db() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (token,))
            db.commit()
    if username: _audit("LOGOUT", username, "Session ended")
    return jsonify({"success": True})

# ── USERS ──────────────────────────────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
def get_users():
    with get_db() as db:
        rows = db.execute("SELECT username, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

# ── CATEGORIES: allowed per role ──────────────────────────────────────────────
@app.route("/api/categories", methods=["GET"])
def get_categories():
    username = request.args.get("username","")
    with get_db() as db:
        row = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    role = row["role"] if row else "user"
    return jsonify({"role": role, "categories": ROLE_CATEGORIES.get(role, ["general"])})

# ── MESSAGES: SEND ─────────────────────────────────────────────────────────────
@app.route("/api/messages/send", methods=["POST"])
def send_message():
    d          = request.json or {}
    from_user  = d.get("from","").strip()
    to_user    = d.get("to","").strip()
    content    = d.get("content","").strip()
    category   = d.get("category","general").strip().lower()
    attachment = d.get("attachment")   # optional: {name, mime, data_b64}

    if not from_user or not to_user or not content:
        return jsonify({"error": "Missing required fields."}), 400

    # Verify sender exists and get role for category validation
    with get_db() as db:
        row = db.execute("SELECT role FROM users WHERE username=?", (from_user,)).fetchone()
    if not row:
        return jsonify({"error": "Sender not found."}), 404

    # Validate category against sender's role
    allowed_cats = ROLE_CATEGORIES.get(row["role"], ["general"])
    if category not in allowed_cats:
        return jsonify({"error": f"Category '{category}' not allowed for your role. Allowed: {', '.join(allowed_cats)}"}), 403

    # Verify recipient exists
    with get_db() as db:
        row2 = db.execute("SELECT 1 FROM users WHERE username=?", (to_user,)).fetchone()
    if not row2:
        return jsonify({"error": "Recipient not found."}), 404

    # Encrypt message with the active Fernet key before storage
    f, key_id  = _get_active_fernet()
    sent_at    = _now()
    payload    = f"{content}|||{sent_at}"
    ciphertext = f.encrypt(payload.encode()).decode()   # AES-128 encrypted
    hmac_tag   = _compute_hmac(ciphertext, key_id)      # HMAC-SHA256 integrity tag

    # ── Handle optional file/photo attachment ───────────────────────────────
    has_att  = 0; att_name = None; att_mime = None; att_enc = None
    if attachment:
        try:
            raw_att = base64.b64decode(attachment.get("data_b64",""))
            if len(raw_att) > 5 * 1024 * 1024:
                return jsonify({"error": "Attachment too large (max 5 MB)."}), 400
            att_enc  = base64.b64encode(f.encrypt(raw_att)).decode()
            has_att  = 1
            att_name = attachment.get("name","file")
            att_mime = attachment.get("mime","application/octet-stream")
        except Exception as ex:
            return jsonify({"error": f"Attachment error: {ex}"}), 400

    with get_db() as db:
        db.execute("""INSERT INTO messages(sender,recipient,ciphertext,hmac_tag,category,key_id,sent_at,
                                           has_attachment,attach_name,attach_mime,attach_data)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                   (from_user, to_user, ciphertext, hmac_tag, category, key_id, sent_at,
                    has_att, att_name, att_mime, att_enc))
        msg_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.commit()

    _audit("MSG_SENT", from_user, f"to={to_user} id={msg_id} attach={has_att}")
    return jsonify({"success": True, "message_id": msg_id, "sent_at": sent_at})

# ── MESSAGES: INBOX ────────────────────────────────────────────────────────────
@app.route("/api/messages", methods=["GET"])
def get_messages():
    username = request.args.get("username","")
    with get_db() as db:
        rows = db.execute("""SELECT id,sender,recipient,category,is_read,sent_at,read_at,
                                    ciphertext,hmac_tag,key_id,has_attachment,attach_name,attach_mime
                             FROM messages WHERE recipient=? ORDER BY id DESC""",
                          (username,)).fetchall()
    return jsonify([dict(r) for r in rows])

# ── MESSAGES: DECRYPT ──────────────────────────────────────────────────────────
@app.route("/api/messages/decrypt", methods=["POST"])
def decrypt_message():
    d          = request.json or {}
    message_id = d.get("message_id")
    username   = d.get("username","")

    with get_db() as db:
        msg = db.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
        if not msg:
            return jsonify({"error": "Message not found."}), 404
        row = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        role = row["role"] if row else "cashier"

    if msg["recipient"] != username and role != "admin":
        _audit("DECRYPT_DENIED", username, f"msg_id={message_id}")
        return jsonify({"error": "Access denied."}), 403

    # ── Integrity check ──────────────────────────────────────────────────────
    intact = _verify_hmac(msg["ciphertext"], msg["hmac_tag"], msg["key_id"])
    if not intact:
        _audit("INTEGRITY_FAIL", username, f"msg_id={message_id} TAMPERED")
        return jsonify({"error": "Message integrity check failed! Data may have been tampered."}), 400

    # ── Decrypt with the key that was active when message was sent ────────────
    try:
        f         = _fernet_for_key_id(msg["key_id"])
        raw       = f.decrypt(msg["ciphertext"].encode()).decode()
        plaintext, sent_at = raw.rsplit("|||", 1)
    except InvalidToken:
        return jsonify({"error": "Decryption failed — invalid token."}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption error: {e}"}), 400

    # Mark read
    with get_db() as db:
        db.execute("UPDATE messages SET is_read=1, read_at=? WHERE id=?", (_now(), message_id))
        db.commit()

    # ── Decrypt attachment if present ────────────────────────────────────────
    att_result = None
    if msg["has_attachment"] and msg["attach_data"]:
        try:
            raw_att = f.decrypt(base64.b64decode(msg["attach_data"]))
            att_result = {
                "name":     msg["attach_name"],
                "mime":     msg["attach_mime"],
                "data_b64": base64.b64encode(raw_att).decode()
            }
        except Exception as ex:
            att_result = {"error": str(ex)}

    _audit("MSG_READ", username, f"msg_id={message_id} integrity=OK")
    return jsonify({
        "plaintext":  plaintext,
        "from":       msg["sender"],
        "category":   msg["category"],
        "sent_at":    msg["sent_at"],
        "verified":   True,
        "integrity":  "PASS — HMAC-SHA256 verified",
        "key_id":     msg["key_id"],
        "attachment": att_result
    })

# ── MESSAGES: HISTORY (chat between two users) ────────────────────────────────
@app.route("/api/messages/history", methods=["GET"])
def chat_history():
    me    = request.args.get("me","")
    other = request.args.get("other","")
    with get_db() as db:
        rows = db.execute("""SELECT id,sender,recipient,category,is_read,sent_at,ciphertext
                             FROM messages
                             WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
                             ORDER BY id ASC""",
                          (me, other, other, me)).fetchall()
    return jsonify([dict(r) for r in rows])

# ── MESSAGES: POLL (real-time AJAX) ───────────────────────────────────────────
@app.route("/api/messages/poll", methods=["GET"])
def poll_messages():
    """Return count of new unread messages — called every 5s by frontend."""
    username = request.args.get("username","")
    since    = request.args.get("since","")
    with get_db() as db:
        count = db.execute("""SELECT COUNT(*) FROM messages
                              WHERE recipient=? AND is_read=0 AND sent_at>?""",
                           (username, since)).fetchone()[0]
    return jsonify({"new_count": count})

# ── FILES: UPLOAD & ENCRYPT ────────────────────────────────────────────────────
@app.route("/api/files/upload", methods=["POST"])
def upload_file():
    username = request.form.get("username","")
    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    f_obj     = request.files["file"]
    orig_name = f_obj.filename
    mime_type = f_obj.content_type
    raw_bytes = f_obj.read()
    file_size = len(raw_bytes)

    if file_size > 10 * 1024 * 1024:      # 10 MB cap
        return jsonify({"error": "File too large (max 10 MB)."}), 400

    fernet_obj, key_id = _get_active_fernet()
    encrypted_bytes    = fernet_obj.encrypt(raw_bytes)
    stored_name        = secrets.token_hex(16) + ".enc"
    stored_path        = FILES_DIR / stored_name
    stored_path.write_bytes(encrypted_bytes)

    hmac_tag = _compute_hmac(base64.b64encode(encrypted_bytes).decode(), key_id)

    with get_db() as db:
        db.execute("""INSERT INTO files(owner,orig_name,stored_name,mime_type,file_size,key_id,hmac_tag,uploaded_at)
                      VALUES(?,?,?,?,?,?,?,?)""",
                   (username, orig_name, stored_name, mime_type, file_size, key_id, hmac_tag, _now()))
        fid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.commit()

    _audit("FILE_UPLOAD", username, f"file={orig_name} size={file_size} id={fid}")
    return jsonify({"success": True, "file_id": fid, "original_name": orig_name})

# ── FILES: LIST ────────────────────────────────────────────────────────────────
@app.route("/api/files", methods=["GET"])
def list_files():
    username = request.args.get("username","")
    with get_db() as db:
        row  = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        role = row["role"] if row else "cashier"
        if role == "admin":
            rows = db.execute("SELECT id,owner,orig_name,mime_type,file_size,uploaded_at FROM files ORDER BY id DESC").fetchall()
        else:
            rows = db.execute("SELECT id,owner,orig_name,mime_type,file_size,uploaded_at FROM files WHERE owner=? ORDER BY id DESC",
                              (username,)).fetchall()
    return jsonify([dict(r) for r in rows])

# ── FILES: DOWNLOAD & DECRYPT ──────────────────────────────────────────────────
@app.route("/api/files/download/<int:file_id>", methods=["GET"])
def download_file(file_id):
    username = request.args.get("username","")
    with get_db() as db:
        row  = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        role = row["role"] if row else "cashier"
        f    = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()

    if not f:
        return jsonify({"error": "File not found."}), 404
    if f["owner"] != username and role != "admin":
        _audit("FILE_DENY", username, f"file_id={file_id}")
        return jsonify({"error": "Access denied."}), 403

    stored_path = FILES_DIR / f["stored_name"]
    if not stored_path.exists():
        return jsonify({"error": "Encrypted file missing from server."}), 500

    enc_bytes = stored_path.read_bytes()
    fernet_obj = _fernet_for_key_id(f["key_id"])
    try:
        decrypted = fernet_obj.decrypt(enc_bytes)
    except InvalidToken:
        return jsonify({"error": "File decryption failed."}), 400

    _audit("FILE_DOWNLOAD", username, f"file_id={file_id} name={f['orig_name']}")
    return send_file(
        io.BytesIO(decrypted),
        mimetype=f["mime_type"] or "application/octet-stream",
        as_attachment=True,
        download_name=f["orig_name"]
    )

# ── MESSAGES: SENT (outbox) ────────────────────────────────────────────────────
@app.route("/api/messages/sent", methods=["GET"])
def get_sent_messages():
    username = request.args.get("username","")
    with get_db() as db:
        rows = db.execute("""SELECT id,sender,recipient,category,is_read,sent_at,
                                    ciphertext,hmac_tag,key_id,has_attachment,attach_name,attach_mime
                             FROM messages WHERE sender=? ORDER BY id DESC""",
                          (username,)).fetchall()
    return jsonify([dict(r) for r in rows])

# ── MESSAGES: DELETE ───────────────────────────────────────────────────────────
@app.route("/api/messages/delete", methods=["POST"])
def delete_message():
    d          = request.json or {}
    message_id = d.get("message_id")
    username   = d.get("username","")
    with get_db() as db:
        msg = db.execute("SELECT sender,recipient FROM messages WHERE id=?", (message_id,)).fetchone()
        row = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    if not msg:
        return jsonify({"error": "Message not found."}), 404
    role = row["role"] if row else "user"
    if msg["sender"] != username and msg["recipient"] != username and role != "admin":
        return jsonify({"error": "Access denied."}), 403
    with get_db() as db:
        db.execute("DELETE FROM messages WHERE id=?", (message_id,))
        db.commit()
    _audit("MSG_DELETED", username, f"msg_id={message_id}")
    return jsonify({"success": True})

# ── USER MANAGEMENT (Admin only) ───────────────────────────────────────────────
@app.route("/api/users/all", methods=["GET"])
def get_all_users_detail():
    with get_db() as db:
        rows = db.execute("SELECT username,role,totp_enabled,created_at,last_login FROM users ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/users/role", methods=["POST"])
def change_user_role():
    d        = request.json or {}
    admin    = d.get("admin","")
    target   = d.get("username","")
    new_role = d.get("role","")
    with get_db() as db:
        row = db.execute("SELECT role FROM users WHERE username=?", (admin,)).fetchone()
    if not row or row["role"] != "admin":
        return jsonify({"error": "Admin only."}), 403
    if new_role not in ("admin","cashier","customer_support","user"):
        return jsonify({"error": "Invalid role."}), 400
    with get_db() as db:
        db.execute("UPDATE users SET role=? WHERE username=?", (new_role, target))
        db.commit()
    _audit("ROLE_CHANGED", admin, f"target={target} new_role={new_role}")
    return jsonify({"success": True})

@app.route("/api/users/delete", methods=["POST"])
def delete_user():
    d      = request.json or {}
    admin  = d.get("admin","")
    target = d.get("username","")
    with get_db() as db:
        row = db.execute("SELECT role FROM users WHERE username=?", (admin,)).fetchone()
    if not row or row["role"] != "admin":
        return jsonify({"error": "Admin only."}), 403
    if target == "admin":
        return jsonify({"error": "Cannot delete default admin."}), 400
    with get_db() as db:
        db.execute("DELETE FROM users WHERE username=?", (target,))
        db.commit()
    _audit("USER_DELETED", admin, f"target={target}")
    return jsonify({"success": True})

# ── KEY MANAGEMENT ─────────────────────────────────────────────────────────────
@app.route("/api/keys", methods=["GET"])
def list_keys():
    """Admin only — list all encryption keys."""
    with get_db() as db:
        rows = db.execute("SELECT id,key_name,is_active,created_at,created_by,rotated_at FROM enc_keys ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/keys/rotate", methods=["POST"])
def rotate_key():
    """Generate a new Fernet key and make it active. Old key kept for decryption."""
    d        = request.json or {}
    username = d.get("username","")
    key_name = d.get("key_name", f"key-v{int(time.time())}")

    with get_db() as db:
        row = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    if not row or row["role"] != "admin":
        return jsonify({"error": "Admin only."}), 403

    new_key = Fernet.generate_key()
    with get_db() as db:
        db.execute("UPDATE enc_keys SET is_active=0, rotated_at=? WHERE is_active=1", (_now(),))
        db.execute("""INSERT INTO enc_keys(key_name,key_data,is_active,created_at,created_by)
                      VALUES(?,?,1,?,?)""",
                   (key_name, base64.b64encode(new_key).decode(), _now(), username))
        new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.commit()

    _audit("KEY_ROTATED", username, f"new_key_id={new_id} name={key_name}")
    return jsonify({"success": True, "new_key_id": new_id,
                    "message": "Key rotated. Old keys kept for historical decryption."})

@app.route("/api/keys/generate", methods=["POST"])
def generate_personal_key():
    """Generate a one-time display key for the user to copy (key sharing)."""
    d        = request.json or {}
    username = d.get("username","")
    new_key  = Fernet.generate_key()
    _audit("KEY_GENERATED", username, "Personal key generated")
    return jsonify({"key": new_key.decode(), "note": "Copy and share this key securely."})

# ── KEY SHARING ────────────────────────────────────────────────────────────────
@app.route("/api/keys/share", methods=["POST"])
def share_key():
    d         = request.json or {}
    from_user = d.get("from_user","")
    to_user   = d.get("to_user","")
    key_data  = d.get("key_data","")
    key_name  = d.get("key_name","shared-key")
    enc_key_id= d.get("enc_key_id")  # optional: admin shares a system enc_key by id

    if not from_user or not to_user:
        return jsonify({"error": "Missing fields."}), 400

    # Verify both users exist
    with get_db() as db:
        sender_row = db.execute("SELECT role FROM users WHERE username=?", (from_user,)).fetchone()
        recv_row   = db.execute("SELECT username FROM users WHERE username=?", (to_user,)).fetchone()
    if not sender_row:
        return jsonify({"error": "Sender not found."}), 404
    if not recv_row:
        return jsonify({"error": "Recipient not found."}), 404

    # Sharing a system key by id (admin only)
    if enc_key_id:
        if sender_row["role"] != "admin":
            return jsonify({"error": "Only admin can share system encryption keys."}), 403
        with get_db() as db:
            krow = db.execute("SELECT key_data, key_name FROM enc_keys WHERE id=?", (enc_key_id,)).fetchone()
        if not krow:
            return jsonify({"error": "Encryption key not found."}), 404
        # enc_keys stores key_data as base64.b64encode(fernet_key).decode()
        # i.e. double-encoded. Unwrap one layer so shared_keys always holds
        # a valid Fernet key string (URL-safe base64, 44 chars).
        key_data = base64.b64decode(krow["key_data"]).decode()
        key_name = krow["key_name"]
    elif not key_data:
        return jsonify({"error": "Missing key_data or enc_key_id."}), 400

    with get_db() as db:
        db.execute("""INSERT INTO shared_keys(from_user,to_user,key_data,key_name,shared_at)
                      VALUES(?,?,?,?,?)""",
                   (from_user, to_user, key_data, key_name, _now()))
        db.commit()

    _audit("KEY_SHARED", from_user, f"to={to_user} key={key_name}")
    return jsonify({"success": True, "message": f"Key '{key_name}' shared with {to_user}."})

@app.route("/api/keys/shared", methods=["GET"])
def get_shared_keys():
    username = request.args.get("username","")
    with get_db() as db:
        rows = db.execute("""SELECT id,from_user,key_name,shared_at,accepted
                             FROM shared_keys WHERE to_user=? ORDER BY id DESC""",
                          (username,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/keys/shared/accept", methods=["POST"])
def accept_shared_key():
    d        = request.json or {}
    sid      = d.get("share_id")
    username = d.get("username", "")
    with get_db() as db:
        row = db.execute("SELECT key_name, from_user FROM shared_keys WHERE id=? AND to_user=?", (sid, username)).fetchone()
        if not row:
            return jsonify({"error": "Share record not found or access denied."}), 404
        db.execute("UPDATE shared_keys SET accepted=1 WHERE id=?", (sid,))
        db.commit()
    _audit("KEY_ACCEPTED", username, f"share_id={sid} key={row['key_name']} from={row['from_user']}")
    return jsonify({"success": True, "message": f"Key '{row['key_name']}' accepted successfully."})

@app.route("/api/keys/shared/decrypt", methods=["POST"])
def decrypt_with_shared_key():
    """Decrypt a message using a shared key that the user has accepted.

    Two modes:
    1. message_id provided (coming from Inbox via USE SHARED KEY button):
       - Look up which system key (key_id) actually encrypted the message
       - Use that system key to decrypt — the shared_key acts as the access credential
    2. Manual ciphertext paste (no message_id):
       - Try to decrypt using the shared key itself directly
    """
    d          = request.json or {}
    username   = d.get("username", "")
    share_id   = d.get("share_id")
    ciphertext = d.get("ciphertext", "").strip()
    message_id = d.get("message_id")

    if not username or not share_id or not ciphertext:
        return jsonify({"error": "Missing fields."}), 400

    with get_db() as db:
        sk = db.execute("""SELECT key_data, key_name, from_user, accepted
                           FROM shared_keys WHERE id=? AND to_user=?""",
                        (share_id, username)).fetchone()

    if not sk:
        return jsonify({"error": "Shared key not found or access denied."}), 404
    if not sk["accepted"]:
        return jsonify({"error": "You must accept this shared key before using it."}), 403

    try:
        plaintext = None

        # ── Mode 1: message_id known → decrypt with the actual system key ─────────
        if message_id:
            with get_db() as db:
                msg = db.execute(
                    "SELECT ciphertext, key_id, sender FROM messages WHERE id=?", (message_id,)
                ).fetchone()
            if not msg:
                return jsonify({"error": "Message not found."}), 404

            # ENFORCE: only allow decryption if the message was sent by the key sharer.
            # user1 shares key with user2 → user2 can ONLY decrypt messages FROM user1.
            if msg["sender"] != sk["from_user"]:
                return jsonify({
                    "error": f"Access denied — this key was shared by '{sk['from_user']}' "
                             f"but this message is from '{msg['sender']}'. "
                             f"You may only use this key to decrypt messages from '{sk['from_user']}'."
                }), 403

            with get_db() as db:
                sys_key_row = db.execute(
                    "SELECT key_data FROM enc_keys WHERE id=?", (msg["key_id"],)
                ).fetchone()
            if not sys_key_row:
                return jsonify({"error": f"System key id={msg['key_id']} not found."}), 404

            # enc_keys.key_data = base64.b64encode(fernet_key).decode() → unwrap one layer
            fernet_key_bytes = base64.b64decode(sys_key_row["key_data"])
            f = Fernet(fernet_key_bytes)
            raw_plain = f.decrypt(msg["ciphertext"].encode()).decode()
            plaintext = raw_plain.rsplit("|||", 1)[0] if "|||" in raw_plain else raw_plain

        # ── Mode 2: manual ciphertext paste → try the shared key directly ─────────
        else:
            key_str = sk["key_data"].strip() if isinstance(sk["key_data"], str) else sk["key_data"].decode().strip()
            key_bytes = key_str.encode()
            # Shared key is stored as a proper Fernet key (44-char URL-safe b64).
            # Try it directly; if it fails try unwrapping one more b64 layer (legacy rows).
            try:
                f = Fernet(key_bytes)
                raw_plain = f.decrypt(ciphertext.encode()).decode()
            except Exception:
                inner = base64.b64decode(key_bytes)   # legacy double-encoded
                f = Fernet(inner)
                raw_plain = f.decrypt(ciphertext.encode()).decode()
            plaintext = raw_plain.rsplit("|||", 1)[0] if "|||" in raw_plain else raw_plain

        _audit("SHARED_KEY_DECRYPT", username, f"share_id={share_id} key={sk['key_name']}")
        return jsonify({"success": True, "plaintext": plaintext, "key_name": sk["key_name"]})

    except InvalidToken:
        return jsonify({"error": "Decryption failed — wrong key for this ciphertext."}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

@app.route("/api/keys/shared/outgoing", methods=["GET"])
def get_outgoing_shared_keys():
    """Get keys that the current user has shared with others."""
    username = request.args.get("username", "")
    with get_db() as db:
        rows = db.execute("""SELECT id, to_user, key_name, shared_at, accepted
                             FROM shared_keys WHERE from_user=? ORDER BY id DESC""",
                          (username,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/keys/shared/delete", methods=["POST"])
def delete_shared_key():
    """Delete a shared key record. Both the sender and recipient can delete their side."""
    d        = request.json or {}
    share_id = d.get("share_id")
    username = d.get("username", "")
    if not share_id or not username:
        return jsonify({"error": "Missing fields."}), 400
    with get_db() as db:
        row = db.execute(
            "SELECT from_user, to_user, key_name FROM shared_keys WHERE id=?", (share_id,)
        ).fetchone()
    if not row:
        return jsonify({"error": "Shared key not found."}), 404
    if username not in (row["from_user"], row["to_user"]):
        return jsonify({"error": "Access denied."}), 403
    with get_db() as db:
        db.execute("DELETE FROM shared_keys WHERE id=?", (share_id,))
        db.commit()
    _audit("KEY_SHARE_DELETED", username, f"share_id={share_id} key={row['key_name']}")
    return jsonify({"success": True})

# ── 2FA SETUP ──────────────────────────────────────────────────────────────────
@app.route("/api/2fa/setup", methods=["POST"])
def setup_2fa():
    """Generate a TOTP secret and return standards-compliant otpauth:// URI for QR rendering."""
    from urllib.parse import quote
    d        = request.json or {}
    username = d.get("username", "").strip()
    if not username:
        return jsonify({"error": "Username required."}), 400
    with get_db() as db:
        row = db.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "User not found."}), 404

    secret = _totp_generate_secret()   # base32-encoded, 20-byte random key
    with get_db() as db:
        db.execute("UPDATE users SET totp_secret=?, totp_enabled=0 WHERE username=?",
                   (secret, username))
        db.commit()

    # RFC 6238 / Google Authenticator compatible URI
    label   = quote(f"SecureCloud:{username}", safe="")
    otpauth = (
        f"otpauth://totp/{label}"
        f"?secret={secret}"
        f"&issuer=SecureCloud"
        f"&algorithm=SHA1"
        f"&digits=6"
        f"&period=30"
    )
    _audit("2FA_SETUP", username, "TOTP secret generated — QR URL issued")
    return jsonify({
        "secret":   secret,
        "otpauth":  otpauth,      # QR is rendered client-side from this URI
        "username": username,
        "issuer":   "SecureCloud"
    })

@app.route("/api/2fa/verify", methods=["POST"])
def verify_2fa():
    d        = request.json or {}
    username = d.get("username","")
    code     = d.get("code","")
    with get_db() as db:
        row = db.execute("SELECT totp_secret FROM users WHERE username=?", (username,)).fetchone()
    if not row or not row["totp_secret"]:
        return jsonify({"success": False, "message": "2FA not set up."}), 400
    if _totp_verify(row["totp_secret"], code):
        with get_db() as db:
            db.execute("UPDATE users SET totp_enabled=1 WHERE username=?", (username,))
            db.commit()
        _audit("2FA_ENABLED", username, "TOTP verified and enabled")
        return jsonify({"success": True, "message": "2FA enabled successfully!"})
    return jsonify({"success": False, "message": "Invalid code. Try again."}), 400

@app.route("/api/2fa/disable", methods=["POST"])
def disable_2fa():
    d        = request.json or {}
    username = d.get("username","")
    with get_db() as db:
        db.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE username=?", (username,))
        db.commit()
    _audit("2FA_DISABLED", username, "TOTP disabled")
    return jsonify({"success": True})

# ── AUDIT LOG ──────────────────────────────────────────────────────────────────
@app.route("/api/audit", methods=["GET"])
def get_audit():
    with get_db() as db:
        rows = db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

# ── STATS ──────────────────────────────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def get_stats():
    username = request.args.get("username","")
    with get_db() as db:
        row  = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        role = row["role"] if row else "user"

        # All users see all their unread messages — no role filter
        unread      = db.execute("SELECT COUNT(*) FROM messages WHERE recipient=? AND is_read=0",
                                  (username,)).fetchone()[0]
        total_sent  = db.execute("SELECT COUNT(*) FROM messages WHERE sender=?",
                                  (username,)).fetchone()[0]
        total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_files = db.execute("SELECT COUNT(*) FROM files WHERE owner=?",
                                  (username,)).fetchone()[0]
        if role == "admin":
            total_files = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]

        totp_row    = db.execute("SELECT totp_enabled FROM users WHERE username=?",
                                  (username,)).fetchone()

    return jsonify({
        "unread": unread, "total_sent": total_sent,
        "total_users": total_users, "total_files": total_files,
        "totp_enabled": bool(totp_row["totp_enabled"]) if totp_row else False
    })


# ══════════════════════════════════════════════════════════════════════════════
#  GROUPS — Encrypted Group Messaging
# ══════════════════════════════════════════════════════════════════════════════

def _group_fernet(group_id: int) -> Fernet:
    """Return Fernet instance for a group's current encryption key."""
    with get_db() as db:
        row = db.execute("SELECT key_data FROM group_keys WHERE group_id=?", (group_id,)).fetchone()
    if not row:
        raise ValueError(f"No encryption key for group {group_id}.")
    return Fernet(base64.b64decode(row["key_data"]))

def _group_hmac(ciphertext: str, group_id: int) -> str:
    with get_db() as db:
        row = db.execute("SELECT key_data FROM group_keys WHERE group_id=?", (group_id,)).fetchone()
    raw = base64.b64decode(row["key_data"])
    h = stdlib_hmac.new(raw, ciphertext.encode(), hashlib.sha256)
    return h.hexdigest()

def _is_group_member(group_id: int, username: str) -> bool:
    with get_db() as db:
        row = db.execute("SELECT 1 FROM group_members WHERE group_id=? AND username=?",
                         (group_id, username)).fetchone()
    return bool(row)

@app.route("/api/groups/create", methods=["POST"])
def create_group():
    d          = request.json or {}
    creator    = d.get("username", "").strip()
    group_name = d.get("group_name", "").strip()
    members    = d.get("members", [])   # list of usernames (excluding creator)

    if not creator or not group_name:
        return jsonify({"error": "Missing fields."}), 400

    # Verify creator exists AND is admin
    with get_db() as db:
        urow = db.execute("SELECT role FROM users WHERE username=?", (creator,)).fetchone()
    if not urow:
        return jsonify({"error": "Creator not found."}), 404
    if urow["role"] != "admin":
        return jsonify({"error": "Only admins can create groups."}), 403

    # Verify all members exist
    for m in members:
        with get_db() as db:
            if not db.execute("SELECT 1 FROM users WHERE username=?", (m,)).fetchone():
                return jsonify({"error": f"User '{m}' not found."}), 404

    now = _now()
    with get_db() as db:
        db.execute("INSERT INTO groups(group_name,created_by,created_at) VALUES(?,?,?)",
                   (group_name, creator, now))
        group_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Generate unique group encryption key
        gkey = Fernet.generate_key()
        db.execute("INSERT INTO group_keys(group_id,key_data) VALUES(?,?)",
                   (group_id, base64.b64encode(gkey).decode()))

        # Add creator + members
        all_members = list({creator} | set(members))
        for u in all_members:
            db.execute("INSERT INTO group_members(group_id,username,joined_at) VALUES(?,?,?)",
                       (group_id, u, now))
        db.commit()

    _audit("GROUP_CREATED", creator, f"group_id={group_id} name={group_name} members={len(all_members)}")
    return jsonify({"success": True, "group_id": group_id, "group_name": group_name})

@app.route("/api/groups", methods=["GET"])
def list_groups():
    """Return all groups the requesting user belongs to."""
    username = request.args.get("username", "")
    with get_db() as db:
        rows = db.execute("""
            SELECT g.id, g.group_name, g.created_by, g.created_at,
                   (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) AS member_count,
                   (SELECT COUNT(*) FROM group_messages WHERE group_id=g.id) AS message_count
            FROM groups g
            JOIN group_members gm ON gm.group_id=g.id
            WHERE gm.username=?
            ORDER BY g.id DESC
        """, (username,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/groups/<int:group_id>", methods=["GET"])
def get_group(group_id):
    """Return group details + members (must be a member)."""
    username = request.args.get("username", "")
    if not _is_group_member(group_id, username):
        return jsonify({"error": "Access denied — not a member."}), 403
    with get_db() as db:
        g = db.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()
        members = db.execute("SELECT username, joined_at FROM group_members WHERE group_id=? ORDER BY joined_at",
                             (group_id,)).fetchall()
    if not g:
        return jsonify({"error": "Group not found."}), 404
    return jsonify({"group": dict(g), "members": [dict(m) for m in members]})

@app.route("/api/groups/<int:group_id>/messages", methods=["GET"])
def get_group_messages(group_id):
    """Return decrypted messages for a group (must be a member)."""
    username = request.args.get("username", "")
    if not _is_group_member(group_id, username):
        return jsonify({"error": "Access denied — not a member."}), 403

    with get_db() as db:
        msgs = db.execute("""SELECT id,sender,ciphertext,hmac_tag,sent_at,
                                    has_attachment,attach_name,attach_mime,attach_data
                             FROM group_messages WHERE group_id=? ORDER BY id ASC""",
                          (group_id,)).fetchall()

    f = _group_fernet(group_id)
    result = []
    for m in msgs:
        # Verify HMAC integrity
        expected = _group_hmac(m["ciphertext"], group_id)
        intact   = stdlib_hmac.compare_digest(expected, m["hmac_tag"])
        try:
            raw       = f.decrypt(m["ciphertext"].encode()).decode()
            plaintext = raw.rsplit("|||", 1)[0] if "|||" in raw else raw
        except Exception:
            plaintext = "[DECRYPTION FAILED]"
            intact    = False
        att_result = None
        if m["has_attachment"] and m["attach_data"]:
            try:
                raw_att = f.decrypt(base64.b64decode(m["attach_data"]))
                att_result = {
                    "name":     m["attach_name"],
                    "mime":     m["attach_mime"],
                    "data_b64": base64.b64encode(raw_att).decode()
                }
            except Exception as ex:
                att_result = {"error": str(ex)}
        result.append({
            "id":            m["id"],
            "sender":        m["sender"],
            "plaintext":     plaintext,
            "sent_at":       m["sent_at"],
            "integrity":     "PASS" if intact else "FAIL",
            "has_attachment": bool(m["has_attachment"]),
            "attachment":    att_result
        })
    return jsonify(result)

@app.route("/api/groups/<int:group_id>/send", methods=["POST"])
def send_group_message(group_id):
    """Encrypt and store a message in a group."""
    d          = request.json or {}
    sender     = d.get("username", "").strip()
    content    = d.get("content", "").strip()
    attachment = d.get("attachment")   # optional: {name, mime, data_b64}

    if not sender or not content:
        return jsonify({"error": "Missing fields."}), 400
    if not _is_group_member(group_id, sender):
        return jsonify({"error": "Access denied — not a member."}), 403

    f          = _group_fernet(group_id)
    sent_at    = _now()
    payload    = f"{content}|||{sent_at}"
    ciphertext = f.encrypt(payload.encode()).decode()
    hmac_tag   = _group_hmac(ciphertext, group_id)

    # ── Handle optional file/photo/document attachment ──────────────────────
    has_att = 0; att_name = None; att_mime = None; att_enc = None
    if attachment:
        try:
            raw_att = base64.b64decode(attachment.get("data_b64", ""))
            if len(raw_att) > 10 * 1024 * 1024:
                return jsonify({"error": "Attachment too large (max 10 MB)."}), 400
            att_enc  = base64.b64encode(f.encrypt(raw_att)).decode()
            has_att  = 1
            att_name = attachment.get("name", "file")
            att_mime = attachment.get("mime", "application/octet-stream")
        except Exception as ex:
            return jsonify({"error": f"Attachment error: {ex}"}), 400

    with get_db() as db:
        db.execute("""INSERT INTO group_messages
                      (group_id,sender,ciphertext,hmac_tag,sent_at,has_attachment,attach_name,attach_mime,attach_data)
                      VALUES(?,?,?,?,?,?,?,?,?)""",
                   (group_id, sender, ciphertext, hmac_tag, sent_at, has_att, att_name, att_mime, att_enc))
        db.commit()

    _audit("GROUP_MSG_SENT", sender, f"group_id={group_id} attach={has_att}")
    return jsonify({"success": True, "sent_at": sent_at})

@app.route("/api/groups/<int:group_id>/members/add", methods=["POST"])
def add_group_member(group_id):
    """Add a new member to a group (creator or admin only)."""
    d         = request.json or {}
    requester = d.get("username", "").strip()
    new_user  = d.get("new_member", "").strip()

    with get_db() as db:
        g    = db.execute("SELECT created_by FROM groups WHERE id=?", (group_id,)).fetchone()
        urow = db.execute("SELECT role FROM users WHERE username=?", (requester,)).fetchone()
    if not g:
        return jsonify({"error": "Group not found."}), 404
    if g["created_by"] != requester and (not urow or urow["role"] != "admin"):
        return jsonify({"error": "Only the group creator or admin can add members."}), 403
    with get_db() as db:
        if not db.execute("SELECT 1 FROM users WHERE username=?", (new_user,)).fetchone():
            return jsonify({"error": f"User '{new_user}' not found."}), 404
        if db.execute("SELECT 1 FROM group_members WHERE group_id=? AND username=?",
                      (group_id, new_user)).fetchone():
            return jsonify({"error": f"'{new_user}' is already a member."}), 409
        db.execute("INSERT INTO group_members(group_id,username,joined_at) VALUES(?,?,?)",
                   (group_id, new_user, _now()))
        db.commit()
    _audit("GROUP_MEMBER_ADDED", requester, f"group_id={group_id} new_member={new_user}")
    return jsonify({"success": True})

@app.route("/api/groups/<int:group_id>/members/remove", methods=["POST"])
def remove_group_member(group_id):
    """Remove a member and rotate the group encryption key."""
    d          = request.json or {}
    requester  = d.get("username", "").strip()
    target     = d.get("remove_member", "").strip()

    with get_db() as db:
        g    = db.execute("SELECT created_by FROM groups WHERE id=?", (group_id,)).fetchone()
        urow = db.execute("SELECT role FROM users WHERE username=?", (requester,)).fetchone()
    if not g:
        return jsonify({"error": "Group not found."}), 404
    if g["created_by"] != requester and (not urow or urow["role"] != "admin"):
        return jsonify({"error": "Only the group creator or admin can remove members."}), 403
    if target == g["created_by"]:
        return jsonify({"error": "Cannot remove the group creator."}), 400

    with get_db() as db:
        db.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (group_id, target))
        # KEY ROTATION — generate a new key so removed user can't decrypt future messages
        new_key = Fernet.generate_key()
        db.execute("UPDATE group_keys SET key_data=?, rotated_at=? WHERE group_id=?",
                   (base64.b64encode(new_key).decode(), _now(), group_id))
        db.commit()

    _audit("GROUP_MEMBER_REMOVED", requester, f"group_id={group_id} removed={target} KEY_ROTATED")
    return jsonify({"success": True, "key_rotated": True})

@app.route("/api/groups/<int:group_id>/delete", methods=["POST"])
def delete_group(group_id):
    """Delete a group entirely (creator or admin only)."""
    d         = request.json or {}
    requester = d.get("username", "").strip()
    with get_db() as db:
        g    = db.execute("SELECT created_by FROM groups WHERE id=?", (group_id,)).fetchone()
        urow = db.execute("SELECT role FROM users WHERE username=?", (requester,)).fetchone()
    if not g:
        return jsonify({"error": "Group not found."}), 404
    if g["created_by"] != requester and (not urow or urow["role"] != "admin"):
        return jsonify({"error": "Only the group creator or admin can delete groups."}), 403
    with get_db() as db:
        db.execute("DELETE FROM group_messages WHERE group_id=?", (group_id,))
        db.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
        db.execute("DELETE FROM group_keys WHERE group_id=?", (group_id,))
        db.execute("DELETE FROM groups WHERE id=?", (group_id,))
        db.commit()
    _audit("GROUP_DELETED", requester, f"group_id={group_id}")
    return jsonify({"success": True})

@app.route("/api/groups/<int:group_id>/leave", methods=["POST"])
def leave_group(group_id):
    """Leave a group (non-creator members only)."""
    d        = request.json or {}
    username = d.get("username", "").strip()
    with get_db() as db:
        g = db.execute("SELECT created_by FROM groups WHERE id=?", (group_id,)).fetchone()
    if not g:
        return jsonify({"error": "Group not found."}), 404
    if g["created_by"] == username:
        return jsonify({"error": "Creator cannot leave — delete the group instead."}), 400
    if not _is_group_member(group_id, username):
        return jsonify({"error": "You are not a member of this group."}), 404
    with get_db() as db:
        db.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (group_id, username))
        # Rotate key so leaving user can't decrypt future messages
        new_key = Fernet.generate_key()
        db.execute("UPDATE group_keys SET key_data=?, rotated_at=? WHERE group_id=?",
                   (base64.b64encode(new_key).decode(), _now(), group_id))
        db.commit()
    _audit("GROUP_LEFT", username, f"group_id={group_id} KEY_ROTATED")
    return jsonify({"success": True})

@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(FRONTEND_DIR, path)

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  SecureCloud E2EE  |  Yenepoya University 2026          ║")
    print("║  SQLite · Fernet AES-128 · Key Rotation · 2FA · Files   ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print("🌐  Open  http://localhost:8000  in your browser")
    app.run(debug=True, host="0.0.0.0", port=8000)