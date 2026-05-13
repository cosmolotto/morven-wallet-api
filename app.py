"""
MorvenWallet API — Flask backend
Endpoints: /health, /auth/popup, /api/auth/login, /api/auth/callback,
           /api/wallet/balance, /api/payments/pay, /api/airdrop,
           /checkout (GET + POST — used by native apps like VEIL)
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

# ── Checkout (native apps: VEIL etc.) ──────────────────────────────────────

def _validate_checkout(product_id, amount):
    """Mock validation. Replace with real on-chain MRV verification once token is deployed."""
    if not product_id or amount <= 0:
        return False, 'Invalid product_id or amount'
    if amount > 10000:
        return False, 'Amount exceeds mock checkout limit'
    return True, None

def _append_query(url, params):
    """Append ?k=v&... to a URL, preserving existing query string."""
    if not url:
        return url
    sep = '&' if '?' in url else '?'
    parts = []
    for k, v in params.items():
        if v is None:
            continue
        parts.append('{}={}'.format(k, str(v).replace(' ', '%20')))
    return url + sep + '&'.join(parts) if parts else url

@app.route('/checkout', methods=['POST'])
def checkout_post():
    """Programmatic checkout — apps call this after collecting consent.
    Body: { product_id, amount, return_url }
    """
    data        = request.get_json(silent=True) or request.form.to_dict() or {}
    product_id  = (data.get('product_id') or '').strip()
    return_url  = (data.get('return_url') or '').strip() or None
    try:
        amount = float(data.get('amount', 0))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'amount must be numeric'}), 400

    ok, err = _validate_checkout(product_id, amount)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    tx_hash = 'mock_' + uuid.uuid4().hex[:10]
    redirect_url = _append_query(return_url, {
        'tx_hash'    : tx_hash,
        'product'    : product_id,
        'amount'     : amount,
        'status'     : 'success',
    }) if return_url else None

    return jsonify({
        'success'  : True,
        'tx_hash'  : tx_hash,
        'amount'   : amount,
        'product_id': product_id,
        'redirect' : redirect_url,
        'mock'     : True,
    })

@app.route('/checkout', methods=['GET'])
def checkout_get():
    """Web-friendly checkout — used when a native app opens this URL in WebBrowser.
    Query: ?product_id=...&amount=...&return_url=...
    Renders a small confirm page; clicking Confirm triggers redirect with tx_hash.
    """
    product_id = (request.args.get('product_id') or request.args.get('product') or '').strip()
    return_url = (request.args.get('return_url') or request.args.get('return') or '').strip() or None
    try:
        amount = float(request.args.get('amount', 0))
    except (TypeError, ValueError):
        amount = 0

    ok, err = _validate_checkout(product_id, amount)
    if not ok:
        return render_template_string(CHECKOUT_HTML, error=err, product_id=product_id,
                                      amount=amount, return_url=return_url or '', success=False,
                                      tx_hash=None, redirect_url=None), 400

    # auto-confirm flag — useful when called from inside an already-trusted in-app browser
    auto = request.args.get('auto') == '1'
    if auto:
        tx_hash = 'mock_' + uuid.uuid4().hex[:10]
        redirect_url = _append_query(return_url, {
            'tx_hash'  : tx_hash,
            'product'  : product_id,
            'amount'   : amount,
            'status'   : 'success',
        }) if return_url else None
        return render_template_string(CHECKOUT_HTML, error=None, product_id=product_id,
                                      amount=amount, return_url=return_url or '', success=True,
                                      tx_hash=tx_hash, redirect_url=redirect_url)

    return render_template_string(CHECKOUT_HTML, error=None, product_id=product_id,
                                  amount=amount, return_url=return_url or '', success=False,
                                  tx_hash=None, redirect_url=None)

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

CHECKOUT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MorvenWallet Checkout</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d0d1a; color: #e8e8f0;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 20px;
  }
  .card {
    background: #15152a; border: 1px solid #2a2a45;
    border-radius: 16px; padding: 32px 28px;
    width: 100%; max-width: 380px;
  }
  .logo { font-size: 36px; text-align: center; margin-bottom: 8px; color: #e0c875; }
  h1 { font-size: 18px; font-weight: 700; color: #e0c875; margin-bottom: 4px; text-align: center; }
  .sub { font-size: 12px; color: #888; text-align: center; margin-bottom: 22px; }
  .row { display: flex; justify-content: space-between; align-items: center; padding: 11px 0; border-bottom: 1px solid #2a2a45; font-size: 13px; }
  .row strong { color: #fff; }
  .total { padding-top: 14px; font-size: 17px; }
  .total strong { color: #e0c875; }
  button {
    width: 100%; padding: 12px; margin-top: 20px;
    background: #e0c875; color: #0d0d1a;
    border: none; border-radius: 8px;
    font-size: 14px; font-weight: 700; cursor: pointer;
  }
  button.cancel { background: transparent; color: #888; border: 1px solid #2a2a45; margin-top: 10px; font-weight: 500; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .err { color: #ff6b6b; font-size: 13px; margin-top: 10px; text-align: center; }
  .ok  { color: #4caf50; font-size: 13px; margin-top: 14px; text-align: center; line-height: 1.5; }
  .mock { font-size: 10px; color: #666; text-align: center; margin-top: 14px; letter-spacing: 1px; text-transform: uppercase; }
</style>
</head>
<body>
<div class="card" id="checkout-card">
  <div class="logo">◈</div>
  <h1>MorvenWallet</h1>
  <p class="sub">Confirm payment</p>

  {% if error %}
    <p class="err">{{ error }}</p>
  {% elif success %}
    <p class="ok">
      ✓ Payment successful<br>
      <span style="font-family:monospace;font-size:12px;color:#888">{{ tx_hash }}</span>
    </p>
    {% if redirect_url %}
      <button onclick="window.location.href='{{ redirect_url }}'">Return to app →</button>
      <script>setTimeout(function(){ window.location.href='{{ redirect_url }}'; }, 1500);</script>
    {% else %}
      <button onclick="window.close()">Close</button>
    {% endif %}
  {% else %}
    <div class="row"><span>Product</span><strong>{{ product_id }}</strong></div>
    <div class="row"><span>Amount</span><strong>◈ {{ amount }} MRV</strong></div>
    <div class="row total"><span>Total</span><strong>{{ amount }} MRV</strong></div>
    <button id="confirm-btn" onclick="confirmPay()">Confirm payment</button>
    <button class="cancel" onclick="cancelPay()">Cancel</button>
    <p class="mock">Mock checkout · on-chain verification coming with token launch</p>
  {% endif %}
</div>
<script>
function renderSuccess(txHash) {
  var card = document.getElementById('checkout-card');
  while (card.firstChild) card.removeChild(card.firstChild);
  var logo = document.createElement('div'); logo.className = 'logo'; logo.textContent = '✓';
  var h1 = document.createElement('h1'); h1.textContent = 'Payment successful';
  var sub = document.createElement('p'); sub.className = 'sub';
  sub.style.fontFamily = 'monospace';
  sub.textContent = txHash;
  card.appendChild(logo); card.appendChild(h1); card.appendChild(sub);
}
async function confirmPay() {
  var btn = document.getElementById('confirm-btn');
  btn.disabled = true;
  btn.textContent = 'Processing...';
  try {
    var r = await fetch('/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        product_id: {{ product_id|tojson }},
        amount: {{ amount }},
        return_url: {{ return_url|tojson }}
      })
    });
    var data = await r.json();
    if (data.success) {
      if (data.redirect) {
        window.location.href = data.redirect;
      } else {
        renderSuccess(data.tx_hash);
      }
    } else {
      btn.disabled = false;
      btn.textContent = 'Confirm payment';
      alert(data.error || 'Payment failed');
    }
  } catch(e) {
    btn.disabled = false;
    btn.textContent = 'Confirm payment';
    alert('Network error: ' + e.message);
  }
}
function cancelPay() {
  var ret = {{ return_url|tojson }};
  if (ret) window.location.href = ret + (ret.indexOf('?')>=0?'&':'?') + 'status=cancelled';
  else window.close();
}
</script>
</body>
</html>"""

# ── Boot ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=False)
