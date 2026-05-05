/**
 * Sõidupäeviku API
 *
 * Endpoints:
 *   POST   /api/auth/register   { email, password, display_name? }
 *   POST   /api/auth/login      { email, password }
 *   POST   /api/auth/logout
 *   GET    /api/auth/me
 *
 *   GET    /api/settings
 *   PUT    /api/settings        { key: value, ... }
 *
 *   GET    /api/reports
 *   POST   /api/reports         { year, month, ... }
 *   GET    /api/reports/:id
 *   PUT    /api/reports/:id
 *   DELETE /api/reports/:id
 *
 * Auth via httpOnly cookie 'session'. Frontend sends credentials: 'include'.
 */

// ============================================================
// Helpers
// ============================================================
const SESSION_DAYS = 30;

function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init.headers || {}),
    },
  });
}

function corsHeaders(origin) {
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-credentials': 'true',
    'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '86400',
  };
}

function withCors(response, origin) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(origin))) {
    headers.set(k, v);
  }
  return new Response(response.body, { status: response.status, headers });
}

// Hash password with PBKDF2 (Web Crypto API; bcrypt isn't available in Workers)
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hash = new Uint8Array(bits);
  // Format: pbkdf2$100000$<salt-base64>$<hash-base64>
  return `pbkdf2$100000$${btoa(String.fromCharCode(...salt))}$${btoa(String.fromCharCode(...hash))}`;
}

async function verifyPassword(password, stored) {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[1]);
  const salt = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0));
  const expectedHash = parts[3];
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hash = new Uint8Array(bits);
  const hashBase64 = btoa(String.fromCharCode(...hash));
  return hashBase64 === expectedHash;
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function parseCookies(req) {
  const header = req.headers.get('cookie') || '';
  const cookies = {};
  for (const part of header.split(';')) {
    const [k, v] = part.trim().split('=');
    if (k) cookies[k] = decodeURIComponent(v || '');
  }
  return cookies;
}

async function getUserFromSession(req, env) {
  const cookies = parseCookies(req);
  const token = cookies.session;
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.email, u.display_name, u.is_admin FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > datetime('now')`
  ).bind(token).first();
  return row || null;
}

function setSessionCookie(token, maxAgeSeconds) {
  return `session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${maxAgeSeconds}`;
}

// ============================================================
// Route handlers
// ============================================================
async function handleRegister(req, env) {
  const body = await req.json().catch(() => ({}));
  const { email, password, display_name } = body;
  if (!email || !password || password.length < 8) {
    return json({ error: 'E-post ja vähemalt 8-tähemärgine parool nõutud' }, { status: 400 });
  }
  const emailLc = email.toLowerCase().trim();
  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(emailLc).first();
  if (existing) return json({ error: 'See e-post on juba kasutusel' }, { status: 409 });

  const hash = await hashPassword(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?)'
  ).bind(emailLc, hash, display_name || null).run();
  const userId = result.meta.last_row_id;

  const token = randomToken();
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400 * 1000).toISOString();
  await env.DB.prepare(
    'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
  ).bind(token, userId, expiresAt).run();

  return json(
    { id: userId, email: emailLc, display_name: display_name || null, is_admin: false },
    { headers: { 'set-cookie': setSessionCookie(token, SESSION_DAYS * 86400) } }
  );
}

async function handleLogin(req, env) {
  const body = await req.json().catch(() => ({}));
  const { email, password } = body;
  if (!email || !password) return json({ error: 'E-post ja parool nõutud' }, { status: 400 });
  const emailLc = email.toLowerCase().trim();
  const user = await env.DB.prepare(
    'SELECT id, email, password_hash, display_name FROM users WHERE email = ?'
  ).bind(emailLc).first();
  if (!user) return json({ error: 'Vale e-post või parool' }, { status: 401 });

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return json({ error: 'Vale e-post või parool' }, { status: 401 });

  // Update last login
  await env.DB.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").bind(user.id).run();

  const token = randomToken();
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400 * 1000).toISOString();
  await env.DB.prepare(
    'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
  ).bind(token, user.id, expiresAt).run();

  return json(
    { id: user.id, email: user.email, display_name: user.display_name, is_admin: user.is_admin === 1 },
    { headers: { 'set-cookie': setSessionCookie(token, SESSION_DAYS * 86400) } }
  );
}

async function handleLogout(req, env) {
  const cookies = parseCookies(req);
  if (cookies.session) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(cookies.session).run();
  }
  return json({ ok: true }, { headers: { 'set-cookie': setSessionCookie('', 0) } });
}

async function handleMe(req, env) {
  const user = await getUserFromSession(req, env);
  if (!user) return json({ error: 'Pole sisse logitud' }, { status: 401 });
  return json({
    id: user.id,
    email: user.email,
    display_name: user.display_name,
    is_admin: user.is_admin === 1,
  });
}

async function handleGetSettings(user, env) {
  const result = await env.DB.prepare('SELECT key, value FROM settings WHERE user_id = ?').bind(user.id).all();
  const obj = {};
  for (const row of result.results) obj[row.key] = row.value;
  return json(obj);
}

async function handlePutSettings(req, user, env) {
  const body = await req.json().catch(() => ({}));
  const stmts = [];
  for (const [key, value] of Object.entries(body)) {
    stmts.push(
      env.DB.prepare(
        'INSERT INTO settings (user_id, key, value) VALUES (?, ?, ?) ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value'
      ).bind(user.id, key, String(value))
    );
  }
  if (stmts.length) await env.DB.batch(stmts);
  return json({ ok: true });
}

async function handleListReports(user, env) {
  const result = await env.DB.prepare(
    `SELECT r.*, COUNT(t.id) AS trip_count
     FROM reports r LEFT JOIN trips t ON t.report_id = r.id
     WHERE r.user_id = ?
     GROUP BY r.id
     ORDER BY r.year DESC, r.month DESC`
  ).bind(user.id).all();
  return json(result.results || []);
}

async function handleGetReport(id, user, env) {
  const report = await env.DB.prepare('SELECT * FROM reports WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!report) return json({ error: 'Aruannet ei leitud' }, { status: 404 });
  const trips = await env.DB.prepare('SELECT date FROM trips WHERE report_id = ? ORDER BY date').bind(id).all();
  return json({ ...report, trips: (trips.results || []).map(t => t.date) });
}

async function handleCreateReport(req, user, env) {
  const body = await req.json().catch(() => ({}));
  const { year, month, employee_name, plate, employer, prev_speedo, end_speedo, trip_distance, route, purpose, trips } = body;
  if (!year || !month) return json({ error: 'Aasta ja kuu nõutud' }, { status: 400 });

  const existing = await env.DB.prepare(
    'SELECT id FROM reports WHERE user_id = ? AND year = ? AND month = ?'
  ).bind(user.id, year, month).first();
  if (existing) return json({ error: 'Selle kuu aruanne on juba olemas', existing_id: existing.id }, { status: 409 });

  const result = await env.DB.prepare(
    `INSERT INTO reports
     (user_id, year, month, employee_name, plate, employer, prev_speedo, end_speedo, trip_distance, route, purpose, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
  ).bind(user.id, year, month, employee_name || null, plate || null, employer || null,
         prev_speedo || 0, end_speedo || 0, trip_distance || 100, route || null, purpose || null).run();
  const reportId = result.meta.last_row_id;

  if (Array.isArray(trips) && trips.length) {
    const stmts = trips.map(date =>
      env.DB.prepare('INSERT INTO trips (report_id, date) VALUES (?, ?)').bind(reportId, date)
    );
    await env.DB.batch(stmts);
  }

  return json({ id: reportId });
}

async function handleUpdateReport(id, req, user, env) {
  const body = await req.json().catch(() => ({}));
  const { year, month, employee_name, plate, employer, prev_speedo, end_speedo, trip_distance, route, purpose, trips } = body;

  const owned = await env.DB.prepare('SELECT id FROM reports WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!owned) return json({ error: 'Aruannet ei leitud' }, { status: 404 });

  await env.DB.prepare(
    `UPDATE reports SET year=?, month=?, employee_name=?, plate=?, employer=?,
     prev_speedo=?, end_speedo=?, trip_distance=?, route=?, purpose=?, updated_at=datetime('now')
     WHERE id = ?`
  ).bind(year, month, employee_name || null, plate || null, employer || null,
         prev_speedo || 0, end_speedo || 0, trip_distance || 100, route || null, purpose || null, id).run();

  if (Array.isArray(trips)) {
    await env.DB.prepare('DELETE FROM trips WHERE report_id = ?').bind(id).run();
    if (trips.length) {
      const stmts = trips.map(date =>
        env.DB.prepare('INSERT INTO trips (report_id, date) VALUES (?, ?)').bind(id, date)
      );
      await env.DB.batch(stmts);
    }
  }

  return json({ ok: true });
}

async function handleDeleteReport(id, user, env) {
  const owned = await env.DB.prepare('SELECT id FROM reports WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!owned) return json({ error: 'Aruannet ei leitud' }, { status: 404 });
  await env.DB.prepare('DELETE FROM reports WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ============================================================
// Admin endpoints
// ============================================================
async function handleAdminListUsers(user, env) {
  if (user.is_admin !== 1) return json({ error: 'Pole õigust' }, { status: 403 });
  const result = await env.DB.prepare(
    `SELECT
       u.id, u.email, u.display_name, u.is_admin, u.created_at, u.last_login_at,
       COUNT(DISTINCT r.id) AS report_count,
       COUNT(DISTINCT t.id) AS trip_count,
       MAX(r.updated_at) AS last_activity_at
     FROM users u
     LEFT JOIN reports r ON r.user_id = u.id
     LEFT JOIN trips t ON t.report_id = r.id
     GROUP BY u.id
     ORDER BY u.created_at DESC`
  ).all();
  return json(result.results || []);
}

async function handleAdminDeleteUser(id, user, env) {
  if (user.is_admin !== 1) return json({ error: 'Pole õigust' }, { status: 403 });
  if (id === user.id) return json({ error: 'Iseennast kustutada ei saa' }, { status: 400 });
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ============================================================
// Router
// ============================================================
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = env.ALLOWED_ORIGIN || '*';

    // Preflight
    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    let response;
    try {
      response = await route(req, url, env);
    } catch (e) {
      console.error('Worker error:', e);
      response = json({ error: 'Serveri viga: ' + e.message }, { status: 500 });
    }
    return withCors(response, origin);
  },
};

async function route(req, url, env) {
  const path = url.pathname;
  const method = req.method;

  // Public health check
  if (path === '/' || path === '/api') {
    return json({ ok: true, message: 'Sõidupäeviku API' });
  }

  // Auth endpoints (public)
  if (path === '/api/auth/register' && method === 'POST') return handleRegister(req, env);
  if (path === '/api/auth/login' && method === 'POST') return handleLogin(req, env);
  if (path === '/api/auth/logout' && method === 'POST') return handleLogout(req, env);
  if (path === '/api/auth/me' && method === 'GET') return handleMe(req, env);

  // Everything below requires auth
  const user = await getUserFromSession(req, env);
  if (!user) return json({ error: 'Pole sisse logitud' }, { status: 401 });

  if (path === '/api/settings' && method === 'GET') return handleGetSettings(user, env);
  if (path === '/api/settings' && method === 'PUT') return handlePutSettings(req, user, env);

  if (path === '/api/reports' && method === 'GET') return handleListReports(user, env);
  if (path === '/api/reports' && method === 'POST') return handleCreateReport(req, user, env);

  const reportMatch = path.match(/^\/api\/reports\/(\d+)$/);
  if (reportMatch) {
    const id = parseInt(reportMatch[1]);
    if (method === 'GET') return handleGetReport(id, user, env);
    if (method === 'PUT') return handleUpdateReport(id, req, user, env);
    if (method === 'DELETE') return handleDeleteReport(id, user, env);
  }

  // Admin routes
  if (path === '/api/admin/users' && method === 'GET') return handleAdminListUsers(user, env);
  const adminUserMatch = path.match(/^\/api\/admin\/users\/(\d+)$/);
  if (adminUserMatch && method === 'DELETE') {
    return handleAdminDeleteUser(parseInt(adminUserMatch[1]), user, env);
  }

  return json({ error: 'Ei leitud' }, { status: 404 });
}
