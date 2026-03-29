/**
 * morven.js — MorvenWallet Auth SDK v1.0
 * Drop-in <script> tag for any Morven Empire frontend
 * Usage: morvenWallet.login() | .getBalance(jwt) | .pay(jwt, amount, productId)
 */
(function (global) {
  'use strict';

  const SDK_VERSION = '1.0.0';
  const DEFAULT_API_URL = 'https://morven-wallet-api.onrender.com';
  const POPUP_W = 480, POPUP_H = 640;

  /* ─── Config ─────────────────────────────────────────────────── */
  let _apiUrl = (typeof MORVEN_API_URL !== 'undefined' ? MORVEN_API_URL : DEFAULT_API_URL);
  let _mockMode = false;          // auto-enabled if API unreachable
  let _cachedJwt = null;

  /* ─── Mock data (used when API is offline / demo) ─────────────── */
  const MOCK_USER = {
    id: 'mock-001',
    wallet_id: 'MRV-DEMO1',
    display_name: 'Demo User',
    email: 'demo@morvenempire.com'
  };
  const MOCK_BALANCE = { mrv: 250.0, usdt: 12.50, usd_value: 262.50 };

  /* ─── Helpers ─────────────────────────────────────────────────── */
  function _popupCenter(url, title) {
    const left = (screen.width - POPUP_W) / 2;
    const top  = (screen.height - POPUP_H) / 2;
    return window.open(
      url, title,
      `width=${POPUP_W},height=${POPUP_H},left=${left},top=${top},` +
      'toolbar=no,menubar=no,scrollbars=yes,resizable=yes'
    );
  }

  function _post(endpoint, data, jwt) {
    const headers = { 'Content-Type': 'application/json' };
    if (jwt) headers['Authorization'] = 'Bearer ' + jwt;
    return fetch(_apiUrl + endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(data)
    }).then(r => r.json());
  }

  function _get(endpoint, jwt) {
    const headers = { 'Content-Type': 'application/json' };
    if (jwt) headers['Authorization'] = 'Bearer ' + jwt;
    return fetch(_apiUrl + endpoint, { headers }).then(r => r.json());
  }

  function _storeJwt(jwt) {
    _cachedJwt = jwt;
    try { localStorage.setItem('mrv_jwt', jwt); } catch(e) {}
  }

  function _loadJwt() {
    if (_cachedJwt) return _cachedJwt;
    try { return localStorage.getItem('mrv_jwt'); } catch(e) { return null; }
  }

  function _clearJwt() {
    _cachedJwt = null;
    try { localStorage.removeItem('mrv_jwt'); } catch(e) {}
  }

  /* ─── Mock JWT ────────────────────────────────────────────────── */
  function _mockJwt(user) {
    const header  = btoa(JSON.stringify({ alg: 'mock', typ: 'JWT' }));
    const payload = btoa(JSON.stringify({ ...user, iat: Date.now(), mock: true }));
    return `${header}.${payload}.mocksig`;
  }

  function _decodeMockJwt(jwt) {
    try {
      const payload = jwt.split('.')[1];
      return JSON.parse(atob(payload));
    } catch(e) { return null; }
  }

  /* ─── Popup Auth flow ─────────────────────────────────────────── */
  function _popupLogin() {
    return new Promise((resolve, reject) => {
      const popup = _popupCenter(_apiUrl + '/auth/popup', 'Login with MorvenWallet');

      if (!popup) {
        reject(new Error('Popup blocked. Please allow popups for this site.'));
        return;
      }

      const timer = setInterval(() => {
        if (popup.closed) {
          clearInterval(timer);
          window.removeEventListener('message', handler);
          reject(new Error('Login cancelled'));
        }
      }, 500);

      function handler(event) {
        if (event.data && event.data.type === 'MORVEN_AUTH_SUCCESS') {
          clearInterval(timer);
          window.removeEventListener('message', handler);
          popup.close();
          resolve(event.data);
        }
        if (event.data && event.data.type === 'MORVEN_AUTH_ERROR') {
          clearInterval(timer);
          window.removeEventListener('message', handler);
          popup.close();
          reject(new Error(event.data.message || 'Auth failed'));
        }
      }

      window.addEventListener('message', handler);
    });
  }

  /* ─── Public API ──────────────────────────────────────────────── */
  const morvenWallet = {
    version: SDK_VERSION,

    /**
     * Configure SDK
     * @param {Object} opts - { apiUrl, mockMode }
     */
    configure(opts = {}) {
      if (opts.apiUrl)    _apiUrl   = opts.apiUrl;
      if (opts.mockMode !== undefined) _mockMode = opts.mockMode;
    },

    /**
     * Get stored JWT (returns null if not logged in)
     */
    getJwt() {
      return _loadJwt();
    },

    /**
     * Check if user is logged in
     */
    isLoggedIn() {
      const jwt = _loadJwt();
      if (!jwt) return false;
      // Check expiry for real JWTs
      try {
        const payload = JSON.parse(atob(jwt.split('.')[1]));
        if (payload.mock) return true;
        return payload.exp > Date.now() / 1000;
      } catch(e) { return true; }
    },

    /**
     * Login with MorvenWallet — opens OAuth popup, returns { jwt, user }
     */
    async login() {
      // Return existing session if valid
      if (this.isLoggedIn()) {
        const jwt = _loadJwt();
        const user = _decodeMockJwt(jwt) || {};
        return { jwt, user, cached: true };
      }

      // Mock mode or API unreachable
      if (_mockMode) {
        const jwt = _mockJwt(MOCK_USER);
        _storeJwt(jwt);
        return { jwt, user: MOCK_USER, mock: true };
      }

      // Check if API is reachable
      try {
        const probe = await fetch(_apiUrl + '/health', { mode: 'cors' })
          .then(r => r.ok).catch(() => false);

        if (!probe) {
          console.warn('[morven.js] API unreachable — using mock mode');
          const jwt = _mockJwt(MOCK_USER);
          _storeJwt(jwt);
          return { jwt, user: MOCK_USER, mock: true };
        }
      } catch(e) {
        const jwt = _mockJwt(MOCK_USER);
        _storeJwt(jwt);
        return { jwt, user: MOCK_USER, mock: true };
      }

      // Real popup login
      const result = await _popupLogin();
      _storeJwt(result.jwt);
      return result;
    },

    /**
     * Get MRV balance for logged-in user
     * @param {string} jwt - JWT token (optional, uses stored if omitted)
     */
    async getBalance(jwt) {
      const token = jwt || _loadJwt();
      if (!token) throw new Error('Not logged in');

      // Mock mode
      if (_mockMode || (token && _decodeMockJwt(token)?.mock)) {
        return MOCK_BALANCE;
      }

      const data = await _get('/api/wallet/balance', token);
      if (data.error) throw new Error(data.error);
      return data;
    },

    /**
     * Pay with MRV
     * @param {string} jwt       - JWT token
     * @param {number} amount    - MRV amount
     * @param {string} productId - Product/service identifier
     */
    async pay(jwt, amount, productId) {
      const token = jwt || _loadJwt();
      if (!token) throw new Error('Not logged in');
      if (!amount || amount <= 0) throw new Error('Invalid amount');

      // Mock mode
      if (_mockMode || (token && _decodeMockJwt(token)?.mock)) {
        return {
          success: true,
          tx_id: 'mock-tx-' + Math.random().toString(36).substr(2, 9),
          amount,
          product_id: productId,
          new_balance: Math.max(0, MOCK_BALANCE.mrv - amount),
          mock: true
        };
      }

      const data = await _post('/api/payments/pay', { amount, product_id: productId }, token);
      if (data.error) throw new Error(data.error);
      return data;
    },

    /**
     * Airdrop MRV to a user (called by platform after rewarded actions)
     * @param {string} toWalletId - Target wallet ID (MRV-XXXXX)
     * @param {number} amount     - MRV amount to airdrop
     * @param {string} reason     - e.g. "game_win", "alphabot_profit"
     * @param {string} apiKey     - Server-side API key
     */
    async airdrop(toWalletId, amount, reason, apiKey) {
      if (_mockMode) {
        return { success: true, tx_id: 'mock-airdrop-' + Date.now(), mock: true };
      }
      return _post('/api/airdrop', { to: toWalletId, amount, reason }, null)
        .then(data => {
          if (data.error) throw new Error(data.error);
          return data;
        });
    },

    /**
     * Logout — clears stored JWT
     */
    logout() {
      _clearJwt();
      window.dispatchEvent(new CustomEvent('morven:logout'));
    },

    /**
     * Render a "Login with MorvenWallet" button into a container
     * @param {string|Element} container - CSS selector or DOM element
     * @param {Object} opts - { onLogin, onError, label, theme }
     */
    renderButton(container, opts = {}) {
      const el = typeof container === 'string'
        ? document.querySelector(container)
        : container;
      if (!el) return;

      const label = opts.label || 'Login with MorvenWallet';
      const theme = opts.theme || 'dark';
      const btn   = document.createElement('button');
      btn.className = 'mrv-btn mrv-btn--' + theme;
      btn.style.cssText = [
        'display:inline-flex;align-items:center;gap:8px;',
        'padding:10px 20px;border-radius:8px;border:none;cursor:pointer;',
        'font-family:inherit;font-size:14px;font-weight:600;',
        theme === 'dark'
          ? 'background:#1a1a2e;color:#e0c875;border:1px solid #e0c875;'
          : 'background:#e0c875;color:#1a1a2e;'
      ].join('');

      const icon = document.createElement('span');
      icon.textContent = '◈';
      icon.style.fontSize = '16px';
      btn.appendChild(icon);
      btn.appendChild(document.createTextNode(' ' + label));

      btn.addEventListener('click', async () => {
        btn.disabled = true;
        btn.style.opacity = '0.7';
        try {
          const result = await morvenWallet.login();
          window.dispatchEvent(new CustomEvent('morven:login', { detail: result }));
          if (opts.onLogin) opts.onLogin(result);
          btn.textContent = '◈ ' + (result.user?.display_name || 'Connected');
          btn.style.background = '#1a6b3a';
          btn.style.color = '#fff';
          btn.style.borderColor = '#1a6b3a';
        } catch(e) {
          if (opts.onError) opts.onError(e);
          console.error('[morven.js]', e.message);
          btn.disabled = false;
          btn.style.opacity = '1';
        }
      });

      el.appendChild(btn);
      return btn;
    }
  };

  /* ─── Auto-restore session ────────────────────────────────────── */
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      if (morvenWallet.isLoggedIn()) {
        const jwt = _loadJwt();
        window.dispatchEvent(new CustomEvent('morven:ready', {
          detail: { jwt, loggedIn: true }
        }));
      }
    });
  }

  /* ─── Export ──────────────────────────────────────────────────── */
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = morvenWallet;
  } else {
    global.morvenWallet = morvenWallet;
  }

})(typeof window !== 'undefined' ? window : global);
