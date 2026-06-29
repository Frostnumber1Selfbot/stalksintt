/**
 * StalkSint — Express Server
 * ─────────────────────────────────────────────────────────────
 * Serves the frontend and proxies all API calls so your API keys
 * stay on the server (never exposed in the browser).
 *
 * Run:  node server.js   (or: npm start)
 * Dev:  npm run dev      (auto-restarts on file changes with nodemon)
 * ─────────────────────────────────────────────────────────────
 */

require('dotenv').config();
const express  = require('express');
const axios    = require('axios');
const path     = require('path');
const crypto   = require('crypto');
const rateLimit = require('express-rate-limit');
const pool     = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Security headers ───────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.removeHeader('X-Powered-By');
  next();
});

// ── Middleware ────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend
app.use(express.static(path.join(__dirname, 'public')));

// Basic rate limiter — 200 requests per 15 minutes per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' }
});
app.use('/api', limiter);

// ── Config endpoint (sends non-secret config to frontend) ────
app.get('/config.js', (req, res) => {
  // We expose ONLY what the frontend needs. Keys stay on server.
  res.type('application/javascript').send(`
    window.__STALKSINT_CONFIG__ = {
      apiBase: '/proxy',
      GITHUB_TOKEN: ${JSON.stringify(process.env.GITHUB_TOKEN || '')},
      ETHERSCAN_KEY: ${JSON.stringify(process.env.ETHERSCAN_KEY || '')}
    };
  `);
});

// ── Auth helpers ────────────────────────────────────────────────
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ── Auth routes ─────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const { rows } = await pool.query(
      `SELECT id, email, role, password_hash FROM admin_users WHERE email = $1 AND role = 'admin'`,
      [email]
    );
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const admin = rows[0];
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    if (admin.password_hash !== hash) return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken();
    await pool.query(
      `INSERT INTO user_sessions (user_id, user_type, session_token, ip_address, expires_at)
       VALUES ($1, 'admin', $2, $3, NOW() + INTERVAL '24 hours')`,
      [admin.id, token, req.ip]
    );
    await pool.query(`UPDATE admin_users SET last_login = NOW() WHERE id = $1`, [admin.id]);

    res.json({ token, email: admin.email, role: admin.role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/validate-key', async (req, res) => {
  const { key, email } = req.body;
  if (!key) return res.status(400).json({ error: 'License key required' });

  try {
    const { rows } = await pool.query(
      `SELECT id, status, owner_email, ip_lock, max_users, expires_at
       FROM license_keys WHERE key = $1`,
      [key]
    );
    if (rows.length === 0) return res.status(404).json({ valid: false, error: 'Key not found' });

    const lic = rows[0];
    if (lic.status !== 'active') return res.status(403).json({ valid: false, error: `Key is ${lic.status}` });
    if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
      await pool.query(`UPDATE license_keys SET status = 'expired' WHERE id = $1`, [lic.id]);
      return res.status(403).json({ valid: false, error: 'Key has expired' });
    }
    if (lic.ip_lock && lic.ip_lock !== req.ip) return res.status(403).json({ valid: false, error: 'IP locked to different address' });
    if (email && lic.owner_email && lic.owner_email !== email) return res.status(403).json({ valid: false, error: 'Email does not match key owner' });

    res.json({ valid: true, key_id: lic.id, max_users: lic.max_users, expires_at: lic.expires_at });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/key-login', async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'License key required' });

  try {
    const { rows } = await pool.query(
      `SELECT id, key, status, owner_email, ip_lock, max_users, expires_at
       FROM license_keys WHERE key = $1`,
      [key]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Key not found' });

    const lic = rows[0];
    if (lic.status !== 'active') return res.status(403).json({ error: `Key is ${lic.status}` });
    if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
      await pool.query(`UPDATE license_keys SET status = 'expired' WHERE id = $1`, [lic.id]);
      return res.status(403).json({ error: 'Key has expired' });
    }

    const token = generateToken();
    await pool.query(
      `INSERT INTO user_sessions (user_id, user_type, session_token, ip_address, expires_at)
       VALUES ($1, 'key', $2, $3, NOW() + INTERVAL '24 hours')`,
      [lic.id, token, req.ip]
    );

    await pool.query(
      `INSERT INTO key_events (license_key_id, action, detail, ip_address, performed_by)
       VALUES ($1, 'login', $2, $3, 'key-login')`,
      [lic.id, `Key login from ${req.ip}`, req.ip]
    );

    res.json({
      token,
      key: lic.key,
      key_id: lic.id,
      valid: true,
      max_users: lic.max_users,
      expires_at: lic.expires_at,
      plan: lic.max_users >= 10 ? 'enterprise' : lic.max_users >= 3 ? 'team' : 'basic'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password, license_key } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    if (license_key) {
      const { rows } = await pool.query(
        `SELECT id, status, expires_at FROM license_keys WHERE key = $1`,
        [license_key]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'License key not found' });
      const lic = rows[0];
      if (lic.status !== 'active') return res.status(403).json({ error: `Key is ${lic.status}` });
      if (lic.expires_at && new Date(lic.expires_at) < new Date()) return res.status(403).json({ error: 'Key expired' });
    }

    const hash = crypto.createHash('sha256').update(password).digest('hex');
    const { rows } = await pool.query(
      `INSERT INTO app_users (email, password_hash, license_key_id, ip_address)
       VALUES ($1, $2, (SELECT id FROM license_keys WHERE key = $3), $4)
       RETURNING id, email, created_at`,
      [email, hash, license_key || null, req.ip]
    );
    res.status(201).json({ user: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: err.message });
  }
});

// ── Search logging middleware ───────────────────────────────────
async function logSearch(searchType, query, endpoint, statusCode, responseSize, ip) {
  try {
    await pool.query(
      `INSERT INTO search_logs (search_type, query, endpoint, status_code, response_size, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [searchType, query, endpoint, statusCode, responseSize || 0, ip]
    );
  } catch { /* silent */ }
}

// ── Admin session middleware ────────────────────────────────────
async function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const { rows } = await pool.query(
      `SELECT s.user_id, a.email, a.role FROM user_sessions s
       JOIN admin_users a ON a.id = s.user_id
       WHERE s.session_token = $1 AND s.expires_at > NOW() AND s.user_type = 'admin'`,
      [auth.slice(7)]
    );
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid or expired session' });
    req.admin = rows[0];
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// ── Admin key management routes ────────────────────────────────
app.post('/api/admin/generate-key', requireAdmin, async (req, res) => {
  const { owner_email, ip_lock, max_users, expires_in_days } = req.body;

  try {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const rnd = n => Array.from({length:n}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    const key = `STLK-${rnd(4)}-${rnd(4)}-${rnd(4)}`;

    const { rows } = await pool.query(
      `INSERT INTO license_keys (key, status, owner_email, ip_lock, max_users, expires_at)
       VALUES ($1, 'active', $2, $3, $4, NOW() + ($5 || ' days')::INTERVAL)
       RETURNING id, key, status, owner_email, expires_at, created_at`,
      [key, owner_email || null, ip_lock || null, max_users || 1, expires_in_days || 365]
    );

    await pool.query(
      `INSERT INTO key_events (license_key_id, action, detail, ip_address, performed_by)
       VALUES ($1, 'generated', $2, $3, $4)`,
      [rows[0].id, `Generated by ${req.admin.email}`, req.ip, req.admin.email]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/keys', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT lk.*, (SELECT COUNT(*) FROM app_users WHERE license_key_id = lk.id) AS user_count
       FROM license_keys lk ORDER BY lk.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/keys/:id', requireAdmin, async (req, res) => {
  const { status, owner_email, ip_lock, max_users } = req.body;

  try {
    const sets = []; const vals = []; let i = 1;
    if (status !== undefined) { sets.push(`status = $${i++}`); vals.push(status); }
    if (owner_email !== undefined) { sets.push(`owner_email = $${i++}`); vals.push(owner_email); }
    if (ip_lock !== undefined) { sets.push(`ip_lock = $${i++}`); vals.push(ip_lock); }
    if (max_users !== undefined) { sets.push(`max_users = $${i++}`); vals.push(max_users); }
    sets.push(`updated_at = NOW()`);
    vals.push(req.params.id);

    const { rows } = await pool.query(
      `UPDATE license_keys SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`,
      vals
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Key not found' });

    if (status) {
      await pool.query(
        `INSERT INTO key_events (license_key_id, action, detail, ip_address, performed_by)
         VALUES ($1, $2, $3, $4, $5)`,
        [rows[0].id, `status_${status}`, `Set by ${req.admin.email}`, req.ip, req.admin.email]
      );
    }

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/keys/:id', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, key FROM license_keys WHERE id = $1`, [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Key not found' });

    await pool.query(
      `INSERT INTO key_events (license_key_id, action, detail, ip_address, performed_by)
       VALUES ($1, 'deleted', $2, $3, $4)`,
      [rows[0].id, `Deleted by ${req.admin.email}`, req.ip, req.admin.email]
    );

    await pool.query(`DELETE FROM license_keys WHERE id = $1`, [req.params.id]);

    res.json({ deleted: true, key: rows[0].key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/key-events', requireAdmin, async (req, res) => {
  const { limit, offset } = req.query;
  try {
    const { rows } = await pool.query(
      `SELECT ke.*, lk.key FROM key_events ke
       LEFT JOIN license_keys lk ON lk.id = ke.license_key_id
       ORDER BY ke.created_at DESC LIMIT $1 OFFSET $2`,
      [Math.min(parseInt(limit) || 100, 500), parseInt(offset) || 0]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const { limit, offset, type } = req.query;
  try {
    let sql = `FROM search_logs WHERE 1=1`; const vals = [];
    if (type) { vals.push(type); sql += ` AND search_type = $${vals.length}`; }
    const count = await pool.query(`SELECT COUNT(*) ${sql}`, vals);
    const { rows } = await pool.query(
      `SELECT * ${sql} ORDER BY created_at DESC LIMIT $${vals.length + 1} OFFSET $${vals.length + 2}`,
      [...vals, Math.min(parseInt(limit) || 100, 500), parseInt(offset) || 0]
    );
    res.json({ logs: rows, total: parseInt(count.rows[0].count) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── OSINTdog proxy ────────────────────────────────────────────
const OSINTDOG_BASE = 'https://osintdog.com';

async function osintdogRequest(method, urlPath, body, res, req) {
  const key = process.env.OSINTDOG_KEY;
  if (!key) return res.status(500).json({ error: 'OSINTDOG_KEY not set in .env' });

  try {
    const response = await axios({
      method,
      url: OSINTDOG_BASE + urlPath,
      headers: {
        'Accept':       'application/json',
        'Content-Type': 'application/json',
        'X-API-Key':    key,
        'Authorization': `Bearer ${key}`,
        'User-Agent':   'StalkSint/1.0'
      },
      data: body || undefined,
      timeout: 30000,
      validateStatus: () => true
    });

    const searchType = urlPath.split('/').pop().split('?')[0] || 'unknown';
    const query = body ? JSON.stringify(body).substring(0, 200) : req?.url || urlPath;
    logSearch(searchType, query, '/proxy' + urlPath, response.status, JSON.stringify(response.data).length, req?.ip);

    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// Forward GET  /proxy/* → OSINTdog
app.get('/proxy/*', async (req, res) => {
  const urlPath = '/' + req.params[0] + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
  await osintdogRequest('GET', urlPath, null, res, req);
});

// Forward POST /proxy/* → OSINTdog
app.post('/proxy/*', async (req, res) => {
  const urlPath = '/' + req.params[0];
  await osintdogRequest('POST', urlPath, req.body, res, req);
});

// ── CSINTDuck proxy ────────────────────────────────────────────
const CSINTDUCK_BASE = 'https://csintduck.cc/api';

async function csintduckRequest(endpoint, params, res) {
  const key = process.env.CSINTDUCK_KEY;
  if (!key) return res.status(500).json({ error: 'CSINTDUCK_KEY not set in .env' });

  try {
    const response = await axios({
      method: 'GET',
      url: `${CSINTDUCK_BASE}/${endpoint}`,
      params,
      headers: {
        'X-API-Key': key,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'StalkSint/1.0'
      },
      timeout: 30000,
      validateStatus: () => true
    });
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

app.get('/api/csintduck/inf0sec', async (req, res) => {
  const { module, query, q } = req.query;
  const queryVal = query || q;
  if (!module) return res.status(400).json({ error: 'module required (leaks, npd, cfx, hlr, github)' });
  await csintduckRequest('inf0sec', { module, query: queryVal || '' }, res);
});

app.get('/api/csintduck/hackcheck', async (req, res) => {
  const { term, category } = req.query;
  if (!term) return res.status(400).json({ error: 'term required' });
  await csintduckRequest('hackcheck', { term, category: category || 'email' }, res);
});

app.get('/api/csintduck/wentyn', async (req, res) => {
  const { query, type } = req.query;
  if (!query) return res.status(400).json({ error: 'query required' });
  await csintduckRequest('wentyn', { query, type: type || 'email' }, res);
});

app.get('/api/csintduck/akula', async (req, res) => {
  const { term, category } = req.query;
  if (!term) return res.status(400).json({ error: 'term required' });
  await csintduckRequest('akula', { term, category: category || 'email' }, res);
});

app.get('/api/csintduck/hudsonrock', async (req, res) => {
  const { query } = req.query;
  if (!query) return res.status(400).json({ error: 'query required' });
  await csintduckRequest('hudsonrock/search', { query }, res);
});

app.get('/api/csintduck/leaksight', async (req, res) => {
  const { query, type } = req.query;
  if (!query) return res.status(400).json({ error: 'query required' });
  await csintduckRequest('leaksight', { query, type: type || 'ip' }, res);
});

app.get('/api/csintduck/stats', async (req, res) => {
  const key = process.env.CSINTDUCK_KEY;
  res.json({
    key_configured: !!key,
    key_prefix: key ? key.substring(0, 8) + '...' : null,
    endpoints: ['inf0sec', 'hackcheck', 'wentyn', 'akula', 'hudsonrock', 'leaksight']
  });
});

// ── GitHub proxy ──────────────────────────────────────────────
app.get('/api/github/:username', async (req, res) => {
  try {
    const headers = { 'Accept': 'application/vnd.github+json' };
    if (process.env.GITHUB_TOKEN) headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;

    const [profile, repos] = await Promise.allSettled([
      axios.get(`https://api.github.com/users/${req.params.username}`, { headers }),
      axios.get(`https://api.github.com/users/${req.params.username}/repos?per_page=30&sort=updated`, { headers })
    ]);

    res.json({
      profile: profile.status === 'fulfilled' ? profile.value.data : null,
      repos:   repos.status   === 'fulfilled' ? repos.value.data   : []
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── IP lookup proxy (ip-api.com) ──────────────────────────────
app.get('/api/ip/:ip', async (req, res) => {
  try {
    const r = await axios.get(
      `http://ip-api.com/json/${req.params.ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`,
      { timeout: 10000 }
    );
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Blockchain.com (BTC) proxy ────────────────────────────────
app.get('/api/btc/:address', async (req, res) => {
  try {
    const r = await axios.get(`https://blockchain.info/rawaddr/${req.params.address}`, { timeout: 15000 });
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Etherscan (ETH) proxy ─────────────────────────────────────
app.get('/api/eth/:address', async (req, res) => {
  const key = process.env.ETHERSCAN_KEY;
  if (!key || key === 'YOUR_ETHERSCAN_KEY') {
    return res.status(400).json({ error: 'ETHERSCAN_KEY not configured in .env' });
  }
  try {
    const r = await axios.get(
      `https://api.etherscan.io/api?module=account&action=balance&address=${req.params.address}&tag=latest&apikey=${key}`,
      { timeout: 10000 }
    );
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Mojang (Minecraft) proxy ──────────────────────────────────
app.get('/api/minecraft/:username', async (req, res) => {
  try {
    const profile = await axios.get(`https://api.mojang.com/users/profiles/minecraft/${req.params.username}`, { timeout: 10000 });
    const uuid    = profile.data.id;
    const session = await axios.get(`https://sessionserver.mojang.com/session/minecraft/profile/${uuid}`, { timeout: 10000 });
    res.json({ profile: profile.data, session: session.data });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

// ── Health check ───────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  let db = false;
  try {
    await pool.query('SELECT 1');
    db = true;
  } catch { /* silent */ }

  const { rows } = await pool.query(
    `SELECT (SELECT COUNT(*) FROM license_keys) AS keys,
            (SELECT COUNT(*) FROM app_users) AS users,
            (SELECT COUNT(*) FROM search_logs) AS searches,
            (SELECT COUNT(*) FROM admin_users) AS admins,
            (SELECT COUNT(*) FROM key_events) AS key_events`
  ).catch(() => ({ rows: [{ keys: 0, users: 0, searches: 0, admins: 0, key_events: 0 }] }));

  res.json({
    status: 'ok',
    db,
    stats: rows[0],
    osintdog: !!process.env.OSINTDOG_KEY,
    github:   !!process.env.GITHUB_TOKEN,
    etherscan: !!(process.env.ETHERSCAN_KEY && process.env.ETHERSCAN_KEY !== 'YOUR_ETHERSCAN_KEY')
  });
});

// ── Fallback → index.html ─────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, async () => {
  let dbOk = false;
  try {
    await pool.query('SELECT 1');
    dbOk = true;
  } catch { /* silent */ }

  console.log(`\n  ✅  StalkSint running at http://localhost:${PORT}`);
  console.log(`  🗄️   PostgreSQL:  ${dbOk ? '✓ connected' : '✗ not connected'}`);
  console.log(`  🔑  OSINTdog key: ${process.env.OSINTDOG_KEY ? '✓ loaded' : '✗ MISSING — set in .env'}`);
  console.log(`  🐙  GitHub token: ${process.env.GITHUB_TOKEN ? '✓ loaded' : '(none — 60 req/hr)'}`);
  console.log(`  💰  Etherscan key: ${process.env.ETHERSCAN_KEY && process.env.ETHERSCAN_KEY !== 'YOUR_ETHERSCAN_KEY' ? '✓ loaded' : '(not set)'}`);
  console.log(`  🦆  CSINTDuck key: ${process.env.CSINTDUCK_KEY ? '✓ loaded' : '(not set)'}\n`);
});
