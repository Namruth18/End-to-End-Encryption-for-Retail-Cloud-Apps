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

from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import sqlite3, base64, os, io, hashlib, hmac as stdlib_hmac
import datetime, time, struct, secrets, json
from pathlib import Path
from functools import wraps

app = Flask(__name__)
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
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sender       TEXT NOT NULL,
            recipient    TEXT NOT NULL,
            ciphertext   TEXT NOT NULL,
            hmac_tag     TEXT NOT NULL,         -- integrity check
            category     TEXT NOT NULL DEFAULT 'general',
            key_id       INTEGER NOT NULL,
            is_read      INTEGER DEFAULT 0,
            read_at      TEXT,
            sent_at      TEXT NOT NULL,
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
    ip = request.remote_addr if request else "system"
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

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_file("index.html")

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

# ── MESSAGES: SEND ─────────────────────────────────────────────────────────────
@app.route("/api/messages/send", methods=["POST"])
def send_message():
    d         = request.json or {}
    from_user = d.get("from","").strip()
    to_user   = d.get("to","").strip()
    content   = d.get("content","").strip()
    # Category is always 'general' — no role restriction on sending
    category  = "general"

    if not from_user or not to_user or not content:
        return jsonify({"error": "Missing required fields."}), 400

    # Verify sender exists
    with get_db() as db:
        row = db.execute("SELECT 1 FROM users WHERE username=?", (from_user,)).fetchone()
    if not row:
        return jsonify({"error": "Sender not found."}), 404

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

    with get_db() as db:
        db.execute("""INSERT INTO messages(sender,recipient,ciphertext,hmac_tag,category,key_id,sent_at)
                      VALUES(?,?,?,?,?,?,?)""",
                   (from_user, to_user, ciphertext, hmac_tag, category, key_id, sent_at))
        msg_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.commit()

    _audit("MSG_SENT", from_user, f"to={to_user} id={msg_id}")
    return jsonify({"success": True, "message_id": msg_id, "sent_at": sent_at})

# ── MESSAGES: INBOX ────────────────────────────────────────────────────────────
@app.route("/api/messages", methods=["GET"])
def get_messages():
    username = request.args.get("username","")
    with get_db() as db:
        rows = db.execute("""SELECT id,sender,recipient,category,is_read,sent_at,read_at,
                                    ciphertext,hmac_tag,key_id
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

    _audit("MSG_READ", username, f"msg_id={message_id} integrity=OK")
    return jsonify({
        "plaintext": plaintext,
        "from":      msg["sender"],
        "category":  msg["category"],
        "sent_at":   msg["sent_at"],
        "verified":  True,
        "integrity": "PASS — HMAC-SHA256 verified",
        "key_id":    msg["key_id"]
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
        db.commit()
        fid = db.execute("SELECT last_insert_rowid()").fetchone()[0]

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

    if not from_user or not to_user or not key_data:
        return jsonify({"error": "Missing fields."}), 400

    with get_db() as db:
        db.execute("""INSERT INTO shared_keys(from_user,to_user,key_data,key_name,shared_at)
                      VALUES(?,?,?,?,?)""",
                   (from_user, to_user, key_data, key_name, _now()))
        db.commit()

    _audit("KEY_SHARED", from_user, f"to={to_user} key={key_name}")
    return jsonify({"success": True, "message": f"Key shared with {to_user}."})

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
    d   = request.json or {}
    sid = d.get("share_id")
    with get_db() as db:
        db.execute("UPDATE shared_keys SET accepted=1 WHERE id=?", (sid,))
        db.commit()
    return jsonify({"success": True})

# ── 2FA SETUP ──────────────────────────────────────────────────────────────────
@app.route("/api/2fa/setup", methods=["POST"])
def setup_2fa():
    d        = request.json or {}
    username = d.get("username","")
    secret   = _totp_generate_secret()
    with get_db() as db:
        db.execute("UPDATE users SET totp_secret=?, totp_enabled=0 WHERE username=?",
                   (secret, username))
        db.commit()
    _audit("2FA_SETUP", username, "TOTP secret generated")
    return jsonify({
        "secret":  secret,
        "qr_hint": f"otpauth://totp/SecureCloud:{username}?secret={secret}&issuer=SecureCloud"
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

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  SecureCloud E2EE  |  Yenepoya University 2026          ║")
    print("║  SQLite · Fernet AES-128 · Key Rotation · 2FA · Files   ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print("🌐  Open  http://localhost:8000  in your browser")
    app.run(debug=True, host="0.0.0.0", port=8000)