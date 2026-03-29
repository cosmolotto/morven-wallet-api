"""
MorvenWallet API — Flask backend
Endpoints: /health, /auth/popup, /api/auth/login, /api/auth/callback,
           /api/wallet/balance, /api/payments/pay, /api/airdrop
Deploy: Render (free tier) — push to cosmolotto/morven-wallet-api
"""
import os, uuid, jwt as pyjwt, hashlib, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

try:
    import psycopg2, psycopg2.extras
    DB_TYPE = 'postgres'
except ImportError:
    import sqlite3
    DB_TYPE = 'sqlite'

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

JWT_SECRET  = os.environ.get('JWT_SECRET', 'morven-dev-secret-change-in-prod')
JWT_EXPIRY  = int(os.environ.get('JWT_EXPIRY_HOURS', 72))
DATABASE_URL = os.environ.get('DATABASE_URL', 'morven_wallet.db')
AIRDROP_KEY  = os.environ.get('AIRDROP_API_KEY', 'airdrop-dev-key')

# ── DB helpers ─────────────────────────────────────────────────────────────

def get_db():
    if DB_TYPE == 'postgres':
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    else:
        conn = sqlite3.connect(DATABASE_URL)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    if DB_TYPE == 'postgres':
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT,
                wallet_id TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS wallets (
                id TEXT PRIMARY KEY,
                user_id TEXT REFERENCES users(id),
                asset TEXT NOT NULL,
                balance NUMERIC(28,8) DEFAULT 0,
                UNIQUE(user_id, asset)
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                from_user_id TEXT,
                to_user_id TEXT,
                asset TEXT NOT NULL,
                amount NUMERIC(28,8) NOT NULL,
                reason TEXT,
                tx_type TEXT DEFAULT 'transfer',
                created_at TIMESTAMP DEFAULT NOW()
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS oauth_states (
                state TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT NOW()
            )""")
    else:
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT,
                wallet_id TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS wallets (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                asset TEXT NOT NULL,
                balance REAL DEFAULT 0,
                UNIQUE(user_id, asset)
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                from_user_id TEXT,
                to_user_id TEXT,
                asset TEXT NOT NULL,
                amount REAL NOT NULL,
                reason TEXT,
                tx_type TEXT DEFAULT 'transfer',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS oauth_states (
                state TEXT PRIMARY KEY,
                created_at TEXT DEFAULT (datetime('now'))
            );
        """)
    conn.commit()
    conn.close()

# ── Auth helpers ───────────────────────────────────────────────────────────

def make_jwt(user_id, email, wallet_id, display_name):
    payload = {
        'sub'         : user_id,
        'email'       : email,
        'wallet_id'   : wallet_id,
        'display_name': display_name,
        'iat'         : datetime.utcnow(),
        'exp'         : datetime.utcnow() + timedelta(hours=JWT_EXPIRY)
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')

def require_jwt(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        token = auth[7:]
        try:
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.jwt_payload = payload
        except pyjwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return wrapper

def wallet_id_for(user_id):
    return 'MRV-' + user_id[:5].upper()

def get_or_create_user(email, display_name=None):
    conn = get_db()
    cur  = conn.cursor()
    try:
        if DB_TYPE == 'postgres':
            cur.execute("SELECT id, email, display_name, wallet_id FROM users WHERE email=%s", (email,))
        else:
            cur.execute("SELECT id, email, display_name, wallet_id FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if row:
            if DB_TYPE == 'postgres':
                return dict(row)
            return dict(row)

        uid       = str(uuid.uuid4())
        wid       = wallet_id_for(uid)
        dname     = display_name or email.split('@')[0]
        if DB_TYPE == 'postgres':
            cur.execute(
                "INSERT INTO users (id,email,display_name,wallet_id) VALUES (%s,%s,%s,%s)",
                (uid, email, dname, wid)
            )
            # Give 50 MRV welcome bonus
            cur.execute(
                "INSERT INTO wallets (id,user_id,asset,balance) VALUES (%s,%s,'MRV',50) ON CONFLICT DO NOTHING",
                (str(uuid.uuid4()), uid)
            )
        else:
            cur.execute(
                "INSERT INTO users (id,email,display_name,wallet_id) VALUES (?,?,?,?)",
                (uid, email, dname, wid)
            )
            cur.execute(
                "INSERT OR IGNORE INTO wallets (id,user_id,asset,balance) VALUES (?,?,'MRV',50)",
                (str(uuid.uuid4()), uid)
            )
        conn.commit()
        return {'id': uid, 'email': email, 'display_name': dname, 'wallet_id': wid}
    finally:
        conn.close()

def get_balance(user_id, asset='MRV'):
    conn = get_db()
    cur  = conn.cursor()
    try:
        if DB_TYPE == 'postgres':
            cur.execute("SELECT balance FROM wallets WHERE user_id=%s AND asset=%s", (user_id, asset))
        else:
            cur.execute("SELECT balance FROM wallets WHERE user_id=? AND asset=?", (user_id, asset))
        row = cur.fetchone()
        return float(row[0]) if row else 0.0
    finally:
        conn.close()

# ── Routes ─────────────────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0', 'db': DB_TYPE})

@app.route('/auth/popup')
def auth_popup():
    """OAuth popup login page — renders inline HTML form"""
    state = secrets.token_urlsafe(16)
    return render_template_string(AUTH_POPUP_HTML, state=state)

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    """Simple email-based login (no password in demo — link-style)"""
    data  = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    name  = data.get('display_name', '')
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400

    user  = get_or_create_user(email, name)
    token = make_jwt(user['id'], user['email'], user['wallet_id'], user['display_name'])
    return jsonify({
        'jwt'  : token,
        'user' : {
            'id'          : user['id'],
            'email'       : user['email'],
            'wallet_id'   : user['wallet_id'],
            'display_name': user['display_name']
        }
    })

@app.route('/api/wallet/balance')
@require_jwt
def wallet_balance():
    uid = request.jwt_payload['sub']
    mrv_bal  = get_balance(uid, 'MRV')
    usdt_bal = get_balance(uid, 'USDT')
    return jsonify({
        'wallet_id': request.jwt_payload.get('wallet_id'),
        'mrv'      : mrv_bal,
        'usdt'     : usdt_bal,
        'usd_value': mrv_bal * 0.05 + usdt_bal  # rough MRV price estimate
    })

@app.route('/api/payments/pay', methods=['POST'])
@require_jwt
def pay():
    data       = request.get_json(silent=True) or {}
    amount     = float(data.get('amount', 0))
    product_id = data.get('product_id', 'unknown')

    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    uid     = request.jwt_payload['sub']
    balance = get_balance(uid, 'MRV')

    if balance < amount:
        return jsonify({'error': 'Insufficient MRV balance', 'balance': balance}), 402

    conn = get_db()
    cur  = conn.cursor()
    try:
        tx_id = str(uuid.uuid4())
        if DB_TYPE == 'postgres':
            cur.execute(
                "UPDATE wallets SET balance = balance - %s WHERE user_id=%s AND asset='MRV'",
                (amount, uid)
            )
            cur.execute(
                "INSERT INTO transactions (id,from_user_id,asset,amount,reason,tx_type) VALUES (%s,%s,'MRV',%s,%s,'payment')",
                (tx_id, uid, amount, product_id)
            )
        else:
            cur.execute(
                "UPDATE wallets SET balance = balance - ? WHERE user_id=? AND asset='MRV'",
                (amount, uid)
            )
            cur.execute(
                "INSERT INTO transactions (id,from_user_id,asset,amount,reason,tx_type) VALUES (?,'MRV',?,?,'payment')",
                (tx_id, uid, amount, product_id)
            )
        conn.commit()
        new_balance = get_balance(uid, 'MRV')
        return jsonify({
            'success'     : True,
            'tx_id'       : tx_id,
            'amount'      : amount,
            'product_id'  : product_id,
            'new_balance' : new_balance
        })
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/airdrop', methods=['POST'])
def airdrop():
    """Server-side airdrop — called by AlphaBot, AidDrop, Arcade Vault etc."""
    api_key = request.headers.get('X-Airdrop-Key', '')
    if api_key != AIRDROP_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

    data      = request.get_json(silent=True) or {}
    to_wallet = data.get('to')       # MRV-XXXXX or user email
    amount    = float(data.get('amount', 0))
    reason    = data.get('reason', 'airdrop')

    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    conn = get_db()
    cur  = conn.cursor()
    try:
        # Find user by wallet_id or email
        if DB_TYPE == 'postgres':
            cur.execute(
                "SELECT id FROM users WHERE wallet_id=%s OR email=%s",
                (to_wallet, to_wallet)
            )
        else:
            cur.execute(
                "SELECT id FROM users WHERE wallet_id=? OR email=?",
                (to_wallet, to_wallet)
            )
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'User not found'}), 404

        uid   = row[0]
        tx_id = str(uuid.uuid4())

        if DB_TYPE == 'postgres':
            cur.execute(
                "INSERT INTO wallets (id,user_id,asset,balance) VALUES (%s,%s,'MRV',%s) "
                "ON CONFLICT (user_id,asset) DO UPDATE SET balance = wallets.balance + EXCLUDED.balance",
                (str(uuid.uuid4()), uid, amount)
            )
            cur.execute(
                "INSERT INTO transactions (id,to_user_id,asset,amount,reason,tx_type) VALUES (%s,%s,'MRV',%s,%s,'airdrop')",
                (tx_id, uid, amount, reason)
            )
        else:
            cur.execute(
                "INSERT OR IGNORE INTO wallets (id,user_id,asset,balance) VALUES (?,?,'MRV',0)",
                (str(uuid.uuid4()), uid)
            )
            cur.execute(
                "UPDATE wallets SET balance = balance + ? WHERE user_id=? AND asset='MRV'",
                (amount, uid)
            )
            cur.execute(
                "INSERT INTO transactions (id,to_user_id,asset,amount,reason,tx_type) VALUES (?,'MRV',?,?,'airdrop')",
                (tx_id, uid, amount, reason)
            )
        conn.commit()
        return jsonify({'success': True, 'tx_id': tx_id, 'amount': amount, 'reason': reason})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ── Popup HTML ─────────────────────────────────────────────────────────────

AUTH_POPUP_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MorvenWallet Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d0d1a;
    color: #e8e8f0;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 20px;
  }
  .card {
    background: #15152a;
    border: 1px solid #2a2a45;
    border-radius: 16px;
    padding: 40px 32px;
    width: 100%; max-width: 380px;
    text-align: center;
  }
  .logo { font-size: 40px; margin-bottom: 12px; }
  h1 { font-size: 22px; font-weight: 700; color: #e0c875; margin-bottom: 6px; }
  p  { font-size: 13px; color: #888; margin-bottom: 28px; }
  input {
    width: 100%; padding: 12px 16px;
    background: #1e1e35; border: 1px solid #2a2a45;
    border-radius: 8px; color: #fff; font-size: 14px;
    margin-bottom: 12px; outline: none;
  }
  input:focus { border-color: #e0c875; }
  button {
    width: 100%; padding: 13px;
    background: #e0c875; color: #0d0d1a;
    border: none; border-radius: 8px;
    font-size: 15px; font-weight: 700; cursor: pointer;
    transition: opacity .2s;
  }
  button:hover { opacity: .9; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .err { color: #ff6b6b; font-size: 13px; margin-top: 10px; display: none; }
  .ok  { color: #4caf50; font-size: 13px; margin-top: 10px; display: none; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">◈</div>
  <h1>MorvenWallet</h1>
  <p>Sign in to access your MRV balance across the Morven Empire</p>
  <input type="email" id="email" placeholder="Email address" autocomplete="email">
  <input type="text"  id="name"  placeholder="Display name (optional)">
  <button id="btn" onclick="doLogin()">Continue →</button>
  <div class="err" id="err"></div>
  <div class="ok"  id="ok">Logged in! Closing...</div>
</div>
<script>
async function doLogin() {
  const email = document.getElementById('email').value.trim();
  const name  = document.getElementById('name').value.trim();
  const btn   = document.getElementById('btn');
  const err   = document.getElementById('err');
  const ok    = document.getElementById('ok');

  if (!email || !email.includes('@')) {
    err.textContent = 'Please enter a valid email';
    err.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in...';
  err.style.display = 'none';

  try {
    const res = await fetch(window.location.origin + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, display_name: name })
    });
    const data = await res.json();
    if (!res.ok || data.error) throw new Error(data.error || 'Login failed');

    ok.style.display = 'block';
    // Post message to opener
    if (window.opener) {
      window.opener.postMessage(
        { type: 'MORVEN_AUTH_SUCCESS', jwt: data.jwt, user: data.user },
        '*'
      );
    }
    setTimeout(() => window.close(), 800);
  } catch(e) {
    err.textContent = e.message;
    err.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Continue →';
  }
}
document.getElementById('email').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});
</script>
</body>
</html>"""

# ── Boot ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=False)
