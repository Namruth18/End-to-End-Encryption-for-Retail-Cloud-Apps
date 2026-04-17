# app.py  –  SecureCloud E2EE  |  Yenepoya University Project 2026
# Roles: admin | cashier | customer_support  (per LLD Section 5)

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64, os, json, hashlib, datetime
from pathlib import Path

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Storage ────────────────────────────────────────────────────────────────────
DATA_DIR      = Path("secure_cloud_data")
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE    = DATA_DIR / "users.json"
MESSAGES_FILE = DATA_DIR / "messages.json"
AUDIT_FILE    = DATA_DIR / "audit.json"

# ── Stable server-side Fernet key ─────────────────────────────────────────────
_KEY_FILE = DATA_DIR / "server.key"
if _KEY_FILE.exists():
    SERVER_KEY = _KEY_FILE.read_bytes()
else:
    SERVER_KEY = Fernet.generate_key()
    _KEY_FILE.write_bytes(SERVER_KEY)
server_fernet = Fernet(SERVER_KEY)

# ── Role → allowed message categories (LLD Section 5) ─────────────────────────
#  admin            → all categories + audit log
#  cashier          → billing, transaction  (no customer/support messages)
#  customer_support → customer, general     (no billing/financial data)
ROLE_CATEGORIES = {
    "admin":            ["billing", "transaction", "customer", "general"],
    "cashier":          ["billing", "transaction"],
    "customer_support": ["customer", "general"],
}

# ── Data helpers ───────────────────────────────────────────────────────────────
def init_data():
    if not USERS_FILE.exists():
        with open(USERS_FILE, "w") as f:
            json.dump({
                "admin": {
                    "password": "admin123",
                    "role":     "admin",
                    "salt":     base64.b64encode(os.urandom(16)).decode(),
                    "created":  datetime.datetime.now().isoformat()
                }
            }, f, indent=2)
    for fp in (MESSAGES_FILE, AUDIT_FILE):
        if not fp.exists():
            with open(fp, "w") as f:
                json.dump([], f)

def load_data():
    with open(USERS_FILE)    as f: users    = json.load(f)
    with open(MESSAGES_FILE) as f: messages = json.load(f)
    with open(AUDIT_FILE)    as f: audit    = json.load(f)
    return users, messages, audit

def save_data(users, messages, audit):
    with open(USERS_FILE,    "w") as f: json.dump(users,    f, indent=2)
    with open(MESSAGES_FILE, "w") as f: json.dump(messages, f, indent=2)
    with open(AUDIT_FILE,    "w") as f: json.dump(audit,    f, indent=2)

def add_audit_log(action, user, details):
    users, messages, audit = load_data()
    audit.append({
        "id":        len(audit) + 1,
        "timestamp": datetime.datetime.now().isoformat(),
        "action":    action,
        "user":      user,
        "details":   details,
        "hash":      hashlib.sha256(f"{action}{user}{details}".encode()).hexdigest()[:16]
    })
    save_data(users, messages, audit)

class EncryptionEngine:
    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode())), salt

init_data()

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_file("index.html")

# ── REGISTER ──────────────────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role     = data.get("role", "").strip()

    if not username or not password or not role:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(username) < 3:
        return jsonify({"success": False, "message": "Username must be at least 3 characters."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400
    if not username.replace("_", "").isalnum():
        return jsonify({"success": False, "message": "Username: letters, numbers, underscore only."}), 400
    if role not in ("cashier", "customer_support"):
        return jsonify({"success": False, "message": "Select a valid role: Cashier or Customer Support."}), 400

    users, messages, audit = load_data()
    if username in users:
        return jsonify({"success": False, "message": "Username already taken."}), 409

    salt = os.urandom(16)
    users[username] = {
        "password": password,
        "role":     role,
        "salt":     base64.b64encode(salt).decode(),
        "created":  datetime.datetime.now().isoformat()
    }
    save_data(users, messages, audit)
    add_audit_log("REGISTER", username, f"New {role} registered")
    return jsonify({"success": True, "message": "Account created! You can now sign in."})

# ── LOGIN ──────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    users, _, _ = load_data()

    if username in users and users[username]["password"] == password:
        ud     = users[username]
        salt   = base64.b64decode(ud["salt"])
        key, _ = EncryptionEngine.generate_key_from_password(password, salt)
        add_audit_log("LOGIN", username, "Successful authentication")
        return jsonify({"success": True, "username": username, "role": ud["role"], "key": key.decode()})

    add_audit_log("LOGIN_FAIL", username or "unknown", "Bad credentials")
    return jsonify({"success": False, "message": "Invalid username or password."}), 401

# ── USERS ──────────────────────────────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
def get_users():
    users, _, _ = load_data()
    return jsonify([{"username": k, "role": v["role"]} for k, v in users.items()])

# ── SEND MESSAGE ───────────────────────────────────────────────────────────────
@app.route("/api/messages/send", methods=["POST"])
def send_message():
    data      = request.json or {}
    from_user = data.get("from", "").strip()
    to_user   = data.get("to",   "").strip()
    content   = data.get("content", "").strip()
    category  = data.get("category", "general").strip()

    if not from_user or not to_user or not content:
        return jsonify({"error": "Missing required fields."}), 400

    users, _, _ = load_data()
    sender_role = users.get(from_user, {}).get("role", "cashier")
    allowed     = ROLE_CATEGORIES.get(sender_role, ["general"])

    if category not in allowed:
        return jsonify({"error": f"Your role ({sender_role}) cannot send '{category}' messages."}), 403

    timestamp  = datetime.datetime.now().isoformat()
    ciphertext = server_fernet.encrypt(f"{content}|{timestamp}".encode()).decode()
    encrypted  = {"ciphertext": ciphertext, "timestamp": timestamp,
                  "algorithm": "Fernet-AES128-CBC-HMAC", "category": category}

    users, messages, audit = load_data()
    record = {
        "id": len(messages) + 1, "from": from_user, "to": to_user,
        "category": category, "encrypted_data": encrypted,
        "read": False, "read_at": None
    }
    messages.append(record)
    save_data(users, messages, audit)
    add_audit_log("MESSAGE_SENT", from_user, f"To:{to_user} Cat:{category} ID:{record['id']}")
    return jsonify({"success": True, "message_id": record["id"]})

# ── GET MESSAGES (role-filtered inbox) ────────────────────────────────────────
@app.route("/api/messages", methods=["GET"])
def get_messages():
    username = request.args.get("username", "")
    users, messages, _ = load_data()
    role    = users.get(username, {}).get("role", "cashier")
    allowed = ROLE_CATEGORIES.get(role, ["general"])

    inbox = [m for m in messages if m["to"] == username and
             (role == "admin" or m.get("category", "general") in allowed)]
    inbox.reverse()
    return jsonify(inbox)

# ── DECRYPT MESSAGE ────────────────────────────────────────────────────────────
@app.route("/api/messages/decrypt", methods=["POST"])
def decrypt_message():
    data       = request.json or {}
    message_id = data.get("message_id")
    username   = data.get("username", "")

    users, messages, audit = load_data()
    msg = next((m for m in messages if m["id"] == message_id), None)
    if not msg:
        return jsonify({"error": "Message not found."}), 404

    role = users.get(username, {}).get("role", "cashier")
    if msg["to"] != username and role != "admin":
        add_audit_log("DECRYPT_DENIED", username, f"Attempted access to message {message_id}")
        return jsonify({"error": "Access denied."}), 403

    try:
        raw       = server_fernet.decrypt(msg["encrypted_data"]["ciphertext"].encode())
        plaintext, _ = raw.decode().rsplit("|", 1)
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {e}"}), 400

    msg["read"] = True
    msg["read_at"] = datetime.datetime.now().isoformat()
    save_data(users, messages, audit)
    add_audit_log("MESSAGE_READ", username, f"Message ID:{message_id}")

    return jsonify({
        "plaintext": plaintext, "from": msg["from"],
        "category":  msg.get("category", "general"),
        "timestamp": msg["encrypted_data"]["timestamp"],
        "verified":  True
    })

# ── AUDIT (admin only) ─────────────────────────────────────────────────────────
@app.route("/api/audit", methods=["GET"])
def get_audit():
    _, _, audit = load_data()
    return jsonify(list(reversed(audit[-50:])))

# ── STATS ──────────────────────────────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def get_stats():
    username = request.args.get("username", "")
    users, messages, _ = load_data()
    role    = users.get(username, {}).get("role", "cashier")
    allowed = ROLE_CATEGORIES.get(role, ["general"])

    unread     = len([m for m in messages if m["to"] == username and not m.get("read") and
                      (role == "admin" or m.get("category", "general") in allowed)])
    total_sent = len([m for m in messages if m["from"] == username])
    total_users = len(users)
    return jsonify({"unread": unread, "total_sent": total_sent, "total_users": total_users})

if __name__ == "__main__":
    print("🔒 SecureCloud E2EE  |  Yenepoya University Project 2026")
    print("🌐  Open http://localhost:8000 in your browser")
    app.run(debug=True, host="0.0.0.0", port=8000)