/**
 * Sõidupäeviku API — JWT autentimine
 *
 * Auth: JWT Bearer token (Authorization: Bearer <token>)
 * Token tagastatakse login/register vastuses JSON-is: { token, ...user }
 * Frontend salvestab tokeni localStorage-i
 *
 * Endpoints:
 *   POST   /api/auth/register   { email, password, display_name? }
 *   POST   /api/auth/login      { email, password }
 *   POST   /api/auth/logout     (klient kustutab tokeni ise)
 *   POST   /api/auth/password    { current_password, new_password }
 *   PUT    /api/auth/me          { display_name }
 *   GET    /api/auth/me
 *
 *   GET    /api/settings
 *   PUT    /api/settings
 *
 *   GET    /api/vehicles
 *   POST   /api/vehicles
 *   PUT    /api/vehicles/:id
 *   DELETE /api/vehicles/:id
 *
 *   GET    /api/reports
 *   POST   /api/reports
 *   GET    /api/reports/:id
 *   PUT    /api/reports/:id
 *   DELETE /api/reports/:id
 *
 *   GET    /api/admin/users
 *   DELETE /api/admin/users/:id
 *
 *   GET    /api/fuel-prices          (public — Estonia national-average 95 & diesel)
 *   PUT    /api/fuel-prices          (admin — manual override / clear)
 *
 * Cron (wrangler.toml [triggers]): daily refresh of fuel prices from
 * globalpetrolprices.com, unless an admin override is active.
 */

const JWT_EXPIRY_DAYS = 30;

// ============================================================
// JWT (HS256, Web Crypto)
// ============================================================
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64urlStr(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64urlDecode(str) {
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
}

async function signJWT(payload, secret) {
  const header = b64urlStr(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = b64urlStr(JSON.stringify(payload));
  const data   = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${b64url(sig)}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, sigB64] = parts;
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const sigBytes = Uint8Array.from(b64urlDecode(sigB64), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data));
  if (!valid) return null;
  try {
    const payload = JSON.parse(b64urlDecode(body));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function makeToken(userId, email, secret) {
  const exp = Math.floor(Date.now() / 1000) + JWT_EXPIRY_DAYS * 86400;
  return signJWT({ sub: userId, email, exp }, secret);
}

// JWT_SECRET must be configured (wrangler secret). Never fall back to a known
// default — that would let anyone forge tokens for any user. Throw instead so
// the request fails loudly (500) rather than silently signing with a weak key.
function requireSecret(env) {
  if (!env.JWT_SECRET) throw new Error('JWT_SECRET is not configured');
  return env.JWT_SECRET;
}

// ============================================================
// Helpers
// ============================================================
function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: { 'content-type': 'application/json', ...(init.headers || {}) },
  });
}

function corsHeaders(origin) {
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-credentials': 'true',
    'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'access-control-allow-headers': 'Authorization, Content-Type',
    'access-control-max-age': '86400',
  };
}

function withCors(response, origin) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(origin))) headers.set(k, v);
  return new Response(response.body, { status: response.status, headers });
}

async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256
  );
  const hash = new Uint8Array(bits);
  return `pbkdf2$100000$${btoa(String.fromCharCode(...salt))}$${btoa(String.fromCharCode(...hash))}`;
}

async function verifyPassword(password, stored) {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[1]);
  const salt = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits))) === parts[3];
}

// Read JWT from Authorization: Bearer header
async function getUserFromRequest(req, env) {
  const auth = req.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7).trim();
  const secret = requireSecret(env);
  const payload = await verifyJWT(token, secret);
  if (!payload || !payload.sub) return null;
  const user = await env.DB.prepare(
    'SELECT id, email, display_name, is_admin FROM users WHERE id = ?'
  ).bind(payload.sub).first();
  return user || null;
}

// ============================================================
// Auth handlers
// ============================================================
async function handleRegister(req, env) {
  const body = await req.json().catch(() => ({}));
  const { email, password, display_name } = body;
  if (!email || !password || password.length < 8)
    return json({ error: 'E-post ja vähemalt 8-tähemärgine parool nõutud' }, { status: 400 });

  const emailLc = email.toLowerCase().trim();
  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(emailLc).first();
  if (existing) return json({ error: 'See e-post on juba kasutusel' }, { status: 409 });

  const hash = await hashPassword(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?)'
  ).bind(emailLc, hash, display_name || null).run();
  const userId = result.meta.last_row_id;

  const secret = requireSecret(env);
  const token = await makeToken(userId, emailLc, secret);

  return json({ token, id: userId, email: emailLc, display_name: display_name || null, is_admin: false });
}

async function handleLogin(req, env) {
  const body = await req.json().catch(() => ({}));
  const { email, password } = body;
  if (!email || !password) return json({ error: 'E-post ja parool nõutud' }, { status: 400 });

  const emailLc = email.toLowerCase().trim();
  const user = await env.DB.prepare(
    'SELECT id, email, password_hash, display_name, is_admin FROM users WHERE email = ?'
  ).bind(emailLc).first();
  if (!user) return json({ error: 'Vale e-post või parool' }, { status: 401 });

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return json({ error: 'Vale e-post või parool' }, { status: 401 });

  await env.DB.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").bind(user.id).run();

  const secret = requireSecret(env);
  const token = await makeToken(user.id, user.email, secret);

  return json({
    token,
    id: user.id, email: user.email,
    display_name: user.display_name,
    is_admin: user.is_admin === 1,
  });
}

async function handleLogout() {
  // JWT on stateless — klient kustutab tokeni ise
  return json({ ok: true });
}

// Change own password. Requires the current one, so a token alone can't lock
// the owner out of the account. Tokens are stateless: sessions already issued
// to other devices keep working until they expire — only the password changes.
async function handleChangePassword(req, user, env) {
  const body = await req.json().catch(() => ({}));
  const { current_password, new_password } = body;
  if (!current_password || !new_password)
    return json({ error: 'Praegune ja uus parool nõutud' }, { status: 400 });
  if (new_password.length < 8)
    return json({ error: 'Uus parool peab olema vähemalt 8 tähemärki' }, { status: 400 });

  const row = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?').bind(user.id).first();
  if (!row) return json({ error: 'Kasutajat ei leitud' }, { status: 404 });
  if (!(await verifyPassword(current_password, row.password_hash)))
    return json({ error: 'Praegune parool on vale' }, { status: 403 });

  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .bind(await hashPassword(new_password), user.id).run();

  // Hand back a fresh token so the device that made the change stays signed in.
  const token = await makeToken(user.id, user.email, requireSecret(env));
  return json({ ok: true, token });
}

// Update the account's own profile. Only display_name is editable — the
// e-mail identifies the account, so changing it would need a verification
// flow we don't have.
async function handleUpdateMe(req, user, env) {
  const body = await req.json().catch(() => ({}));
  if (!('display_name' in body)) return json({ error: 'Midagi muuta pole' }, { status: 400 });
  const name = (body.display_name == null ? '' : String(body.display_name)).trim();
  if (name.length > 100) return json({ error: 'Nimi võib olla kuni 100 tähemärki' }, { status: 400 });

  await env.DB.prepare('UPDATE users SET display_name = ? WHERE id = ?').bind(name || null, user.id).run();
  return json({ ok: true, id: user.id, email: user.email, display_name: name || null, is_admin: user.is_admin === 1 });
}

async function handleMe(req, env) {
  const user = await getUserFromRequest(req, env);
  if (!user) return json({ error: 'Pole sisse logitud' }, { status: 401 });
  return json({
    id: user.id, email: user.email,
    display_name: user.display_name,
    is_admin: user.is_admin === 1,
  });
}

// ============================================================
// Settings
// ============================================================
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
    stmts.push(env.DB.prepare(
      'INSERT INTO settings (user_id, key, value) VALUES (?, ?, ?) ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value'
    ).bind(user.id, key, String(value)));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return json({ ok: true });
}

// ============================================================
// Reports
// ============================================================
async function handleListReports(user, env) {
  const result = await env.DB.prepare(
    `SELECT r.*,
       COUNT(t.id) AS trip_count,
       SUM(CASE WHEN t.trip_type = 'T' THEN COALESCE(t.km, 0) ELSE 0 END) AS work_km
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

  const mode = report.mode || 'simple';
  if (mode === 'detail') {
    const trips = await env.DB.prepare(
      'SELECT id, date, route, km, plate, odom_start, odom_end, trip_type, notes FROM trips WHERE report_id = ? ORDER BY date, odom_start'
    ).bind(id).all();
    return json({ ...report, mode, trips: trips.results || [] });
  } else {
    const trips = await env.DB.prepare('SELECT date FROM trips WHERE report_id = ? ORDER BY date').bind(id).all();
    return json({ ...report, mode, trips: (trips.results || []).map(t => t.date) });
  }
}

async function handleCreateReport(req, user, env) {
  const body = await req.json().catch(() => ({}));
  const { year, month, mode = 'simple', employee_name, plate, employer,
          prev_speedo, end_speedo, trip_distance, route, purpose, trips } = body;
  if (!year || !month) return json({ error: 'Aasta ja kuu nõutud' }, { status: 400 });
  if (mode !== 'simple' && mode !== 'detail')
    return json({ error: 'Mode peab olema simple või detail' }, { status: 400 });

  // Backwards-compat: a client that doesn't send vehicle_id falls back to the
  // user's default vehicle, so old frontends keep working after this migration.
  const vehicleId = body.vehicle_id != null ? body.vehicle_id : await resolveDefaultVehicleId(user, env);

  const existing = await env.DB.prepare(
    'SELECT id FROM reports WHERE user_id = ? AND year = ? AND month = ? AND vehicle_id IS ?'
  ).bind(user.id, year, month, vehicleId).first();
  if (existing) return json({ error: 'Selle kuu aruanne on juba olemas', existing_id: existing.id }, { status: 409 });

  const fuelPrice = await resolveFuelPriceForVehicle(vehicleId, user, env);

  const result = await env.DB.prepare(
    `INSERT INTO reports
     (user_id, vehicle_id, year, month, mode, employee_name, plate, employer, prev_speedo, end_speedo, trip_distance, route, purpose, fuel_price, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
  ).bind(user.id, vehicleId, year, month, mode, employee_name || null, plate || null, employer || null,
         prev_speedo || 0, end_speedo || 0, trip_distance || 100, route || null, purpose || null, fuelPrice).run();
  const reportId = result.meta.last_row_id;

  if (Array.isArray(trips) && trips.length) await insertTrips(env, reportId, mode, trips, year, month);
  return json({ id: reportId });
}

async function handleUpdateReport(id, req, user, env) {
  const body = await req.json().catch(() => ({}));
  const { year, month, mode, employee_name, plate, employer,
          prev_speedo, end_speedo, trip_distance, route, purpose, trips } = body;

  const owned = await env.DB.prepare('SELECT id, mode, vehicle_id FROM reports WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!owned) return json({ error: 'Aruannet ei leitud' }, { status: 404 });

  // Keep the existing vehicle_id when the client omits it (older frontends).
  const vehicleId = body.vehicle_id !== undefined ? body.vehicle_id : owned.vehicle_id;
  const effectiveMode = mode || owned.mode || 'simple';
  // Re-snapshot the fuel price on save (a save reflects the price at that time).
  const fuelPrice = await resolveFuelPriceForVehicle(vehicleId, user, env);
  await env.DB.prepare(
    `UPDATE reports SET vehicle_id=?, year=?, month=?, mode=?, employee_name=?, plate=?, employer=?,
     prev_speedo=?, end_speedo=?, trip_distance=?, route=?, purpose=?, fuel_price=?, updated_at=datetime('now')
     WHERE id = ?`
  ).bind(vehicleId, year, month, effectiveMode, employee_name || null, plate || null, employer || null,
         prev_speedo || 0, end_speedo || 0, trip_distance || 100, route || null, purpose || null, fuelPrice, id).run();

  if (Array.isArray(trips)) {
    await env.DB.prepare('DELETE FROM trips WHERE report_id = ?').bind(id).run();
    if (trips.length) await insertTrips(env, id, effectiveMode, trips, year, month);
  }
  return json({ ok: true });
}

// A monthly report may only hold that month's trips. The client prunes dates
// that fall outside the report month, but filter here too so a stale client (or
// a report whose month was switched after the days were picked) can't write
// another month's trips into this one.
function tripsInMonth(trips, mode, year, month) {
  if (!year || !month) return trips;
  const prefix = `${year}-${String(month).padStart(2, '0')}-`;
  return trips.filter(t => {
    const date = mode === 'detail' ? (t && t.date) : t;
    return typeof date === 'string' && date.startsWith(prefix);
  });
}

async function insertTrips(env, reportId, mode, trips, year, month) {
  trips = tripsInMonth(trips, mode, year, month);
  if (!trips.length) return;
  if (mode === 'detail') {
    const stmts = trips.map(t => env.DB.prepare(
      `INSERT INTO trips (report_id, date, route, km, plate, odom_start, odom_end, trip_type, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(reportId, t.date, t.route || null, t.km || null, t.plate || null,
           t.odom_start || null, t.odom_end || null, t.trip_type || 'T', t.notes || null));
    await env.DB.batch(stmts);
  } else {
    const stmts = trips.map(date =>
      env.DB.prepare('INSERT INTO trips (report_id, date) VALUES (?, ?)').bind(reportId, date)
    );
    await env.DB.batch(stmts);
  }
}

async function handleDeleteReport(id, user, env) {
  const owned = await env.DB.prepare('SELECT id FROM reports WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!owned) return json({ error: 'Aruannet ei leitud' }, { status: 404 });
  await env.DB.prepare('DELETE FROM reports WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ============================================================
// Vehicles
// ============================================================
// Resolve the user's default vehicle id (for backwards-compat when the
// client does not send a vehicle_id). Falls back to any vehicle the user has.
async function resolveDefaultVehicleId(user, env) {
  const def = await env.DB.prepare(
    'SELECT id FROM vehicles WHERE user_id = ? ORDER BY is_default DESC, archived ASC, id ASC LIMIT 1'
  ).bind(user.id).first();
  return def ? def.id : null;
}

// Snapshot the current fuel price for a vehicle's fuel type, stored on the
// report at save time. Returns €/liter, or null if the vehicle has no fuel
// type set or no price is available yet.
async function resolveFuelPriceForVehicle(vehicleId, user, env) {
  if (!vehicleId) return null;
  const veh = await env.DB.prepare(
    'SELECT fuel_type FROM vehicles WHERE id = ? AND user_id = ?'
  ).bind(vehicleId, user.id).first();
  if (!veh || !veh.fuel_type) return null;
  const fp = await env.DB.prepare('SELECT petrol_95, diesel FROM fuel_prices WHERE id = 1').first();
  if (!fp) return null;
  const p = veh.fuel_type === 'diesel' ? fp.diesel : fp.petrol_95;
  return (p != null && Number.isFinite(p)) ? p : null;
}

async function handleListVehicles(user, env) {
  const result = await env.DB.prepare(
    `SELECT v.*, COUNT(r.id) AS report_count
     FROM vehicles v LEFT JOIN reports r ON r.vehicle_id = v.id
     WHERE v.user_id = ?
     GROUP BY v.id
     ORDER BY v.is_default DESC, v.archived ASC, v.id ASC`
  ).bind(user.id).all();
  return json(result.results || []);
}

// Validate a fuel type. Returns { ok, value } — value is '95' | 'diesel' | null.
function parseFuelType(v) {
  if (v == null || v === '') return { ok: true, value: null };
  const s = String(v);
  return (s === '95' || s === 'diesel') ? { ok: true, value: s } : { ok: false };
}
// Validate consumption (L/100km). Returns { ok, value } — value is number | null.
function parseConsumption(v) {
  if (v == null || v === '') return { ok: true, value: null };
  const n = parseFloat(v);
  return (Number.isFinite(n) && n > 0 && n < 100) ? { ok: true, value: n } : { ok: false };
}

async function handleCreateVehicle(req, user, env) {
  const body = await req.json().catch(() => ({}));
  const plate = (body.plate || '').trim();
  if (!plate) return json({ error: 'Reg. märk on nõutud' }, { status: 400 });
  const label = (body.label || '').trim() || null;

  const ft = parseFuelType(body.fuel_type);
  if (!ft.ok) return json({ error: 'Kütuse tüüp peab olema 95 või diesel' }, { status: 400 });
  const fc = parseConsumption(body.fuel_consumption);
  if (!fc.ok) return json({ error: 'Vigane kütusekulu (L/100km)' }, { status: 400 });

  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM vehicles WHERE user_id = ?').bind(user.id).first();
  // First vehicle, or explicit request, becomes the default.
  const makeDefault = count.n === 0 || body.is_default ? 1 : 0;
  if (makeDefault) await env.DB.prepare('UPDATE vehicles SET is_default = 0 WHERE user_id = ?').bind(user.id).run();

  const result = await env.DB.prepare(
    'INSERT INTO vehicles (user_id, plate, label, is_default, fuel_type, fuel_consumption) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(user.id, plate, label, makeDefault, ft.value, fc.value).run();
  return json({ id: result.meta.last_row_id, plate, label, is_default: makeDefault, archived: 0,
                fuel_type: ft.value, fuel_consumption: fc.value });
}

async function handleUpdateVehicle(id, req, user, env) {
  const owned = await env.DB.prepare('SELECT id FROM vehicles WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!owned) return json({ error: 'Sõidukit ei leitud' }, { status: 404 });
  const body = await req.json().catch(() => ({}));

  if (body.is_default) await env.DB.prepare('UPDATE vehicles SET is_default = 0 WHERE user_id = ?').bind(user.id).run();

  const plate = body.plate != null ? String(body.plate).trim() : null;
  if (plate === '') return json({ error: 'Reg. märk ei tohi olla tühi' }, { status: 400 });

  const ftPresent = body.fuel_type !== undefined;
  const ft = ftPresent ? parseFuelType(body.fuel_type) : { ok: true, value: null };
  if (!ft.ok) return json({ error: 'Kütuse tüüp peab olema 95 või diesel' }, { status: 400 });
  const fcPresent = body.fuel_consumption !== undefined;
  const fc = fcPresent ? parseConsumption(body.fuel_consumption) : { ok: true, value: null };
  if (!fc.ok) return json({ error: 'Vigane kütusekulu (L/100km)' }, { status: 400 });

  await env.DB.prepare(
    `UPDATE vehicles SET
       plate            = COALESCE(?, plate),
       label            = CASE WHEN ? THEN ? ELSE label END,
       is_default       = CASE WHEN ? THEN 1 ELSE is_default END,
       archived         = CASE WHEN ? THEN ? ELSE archived END,
       fuel_type        = CASE WHEN ? THEN ? ELSE fuel_type END,
       fuel_consumption = CASE WHEN ? THEN ? ELSE fuel_consumption END
     WHERE id = ?`
  ).bind(
    plate,
    body.label !== undefined ? 1 : 0, body.label != null ? String(body.label).trim() || null : null,
    body.is_default ? 1 : 0,
    body.archived !== undefined ? 1 : 0, body.archived ? 1 : 0,
    ftPresent ? 1 : 0, ft.value,
    fcPresent ? 1 : 0, fc.value,
    id
  ).run();
  return json({ ok: true });
}

async function handleDeleteVehicle(id, user, env) {
  const owned = await env.DB.prepare('SELECT id FROM vehicles WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!owned) return json({ error: 'Sõidukit ei leitud' }, { status: 404 });
  const used = await env.DB.prepare('SELECT COUNT(*) AS n FROM reports WHERE vehicle_id = ?').bind(id).first();
  if (used.n > 0)
    return json({ error: 'Sõidukil on aruandeid — arhiveeri see kustutamise asemel', report_count: used.n }, { status: 409 });
  await env.DB.prepare('DELETE FROM vehicles WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ============================================================
// Admin
// ============================================================
async function handleAdminListUsers(user, env) {
  if (user.is_admin !== 1) return json({ error: 'Pole õigust' }, { status: 403 });
  const result = await env.DB.prepare(
    `SELECT u.id, u.email, u.display_name, u.is_admin, u.created_at, u.last_login_at,
            COUNT(DISTINCT r.id) AS report_count,
            COUNT(DISTINCT t.id) AS trip_count,
            MAX(r.updated_at) AS last_activity_at
     FROM users u
     LEFT JOIN reports r ON r.user_id = u.id
     LEFT JOIN trips t ON t.report_id = r.id
     GROUP BY u.id ORDER BY u.created_at DESC`
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
// Fuel prices (Estonia national average — informational badge)
// ============================================================
// Public read: anyone (even logged-out) can see the current prices.
async function handleGetFuelPrices(env) {
  const row = await env.DB.prepare(
    'SELECT petrol_95, diesel, price_date, source, updated_at FROM fuel_prices WHERE id = 1'
  ).first();
  return json(row || { petrol_95: null, diesel: null, price_date: null, source: 'auto', updated_at: null });
}

// Admin write: set a manual override, or clear it back to automatic.
async function handlePutFuelPrices(req, user, env) {
  if (user.is_admin !== 1) return json({ error: 'Pole õigust' }, { status: 403 });
  const body = await req.json().catch(() => ({}));

  // Clear override → the daily cron takes over managing the prices again.
  if (body.clear === true || body.source === 'auto') {
    await env.DB.prepare(
      "UPDATE fuel_prices SET source = 'auto', updated_at = datetime('now') WHERE id = 1"
    ).run();
    return json({ ok: true, source: 'auto' });
  }

  const p95 = parseFloat(body.petrol_95);
  const die = parseFloat(body.diesel);
  if (![p95, die].every(v => Number.isFinite(v) && v > 0 && v < 10))
    return json({ error: 'Vigased hinnad' }, { status: 400 });

  const today = new Date().toISOString().slice(0, 10);
  await env.DB.prepare(
    `UPDATE fuel_prices
       SET petrol_95 = ?, diesel = ?, price_date = ?, source = 'manual', updated_at = datetime('now')
     WHERE id = 1`
  ).bind(p95, die, today).run();
  return json({ ok: true, source: 'manual' });
}

// Fetch Estonia's national-average price for one fuel type from the public
// globalpetrolprices.com page. The page contains a sentence like
//   "... in Estonia is  EUR 1.68 per liter ..."
// and a date range "... to 2026-07-06." whose end date we use as the "as of".
// Returns { price, date } or null if the page can't be fetched/parsed.
async function fetchGppPrice(fuelPath) {
  const res = await fetch(`https://www.globalpetrolprices.com/Estonia/${fuelPath}/`, {
    headers: { 'user-agent': 'Mozilla/5.0 (compatible; SoidupaevikBot/1.0; +https://soidud.org)' },
    cf: { cacheTtl: 3600, cacheEverything: true },
  });
  if (!res.ok) return null;
  const html = await res.text();
  const priceMatch = html.match(/Estonia is\s+EUR\s+([0-9]+\.[0-9]+)\s+per liter/i);
  if (!priceMatch) return null;
  const price = parseFloat(priceMatch[1]);
  if (!Number.isFinite(price) || price <= 0 || price > 10) return null;
  const dateMatch = html.match(/to\s+(\d{4}-\d{2}-\d{2})\./);
  return { price, date: dateMatch ? dateMatch[1] : new Date().toISOString().slice(0, 10) };
}

// Daily cron: refresh the automatic prices, unless an admin override is active.
// On any fetch/parse failure we keep the last known values (never blank them).
async function refreshFuelPrices(env) {
  const current = await env.DB.prepare('SELECT source FROM fuel_prices WHERE id = 1').first();
  if (current && current.source === 'manual') return; // respect admin override

  const [petrol, diesel] = await Promise.all([
    fetchGppPrice('gasoline_prices'),
    fetchGppPrice('diesel_prices'),
  ]);
  if (!petrol || !diesel) {
    console.error('refreshFuelPrices: could not parse prices', { petrol, diesel });
    return; // keep last known values
  }
  const date = petrol.date > diesel.date ? petrol.date : diesel.date;
  await env.DB.prepare(
    `UPDATE fuel_prices
       SET petrol_95 = ?, diesel = ?, price_date = ?, source = 'auto', updated_at = datetime('now')
     WHERE id = 1`
  ).bind(petrol.price, diesel.price, date).run();
}

// ============================================================
// Router
// ============================================================
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = env.ALLOWED_ORIGIN || '*';

    if (req.method === 'OPTIONS')
      return new Response(null, { status: 204, headers: corsHeaders(origin) });

    let response;
    try {
      response = await route(req, url, env);
    } catch (e) {
      console.error('Worker error:', e);
      response = json({ error: 'Serveri viga: ' + e.message }, { status: 500 });
    }
    return withCors(response, origin);
  },

  // Daily cron (see wrangler.toml [triggers]) — refresh Estonia fuel prices.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      refreshFuelPrices(env).catch(e => console.error('scheduled refreshFuelPrices:', e))
    );
  },
};

async function route(req, url, env) {
  const path = url.pathname;
  const method = req.method;

  if (path === '/' || path === '/api')
    return json({ ok: true, message: 'Sõidupäeviku API' });

  // Public auth endpoints
  if (path === '/api/auth/register' && method === 'POST') return handleRegister(req, env);
  if (path === '/api/auth/login'    && method === 'POST') return handleLogin(req, env);
  if (path === '/api/auth/logout'   && method === 'POST') return handleLogout();
  if (path === '/api/auth/me'       && method === 'GET')  return handleMe(req, env);

  // Public: current Estonia fuel prices (info badge, visible logged-out too)
  if (path === '/api/fuel-prices' && method === 'GET') return handleGetFuelPrices(env);

  // All other endpoints require JWT
  const user = await getUserFromRequest(req, env);
  if (!user) return json({ error: 'Pole sisse logitud' }, { status: 401 });

  if (path === '/api/auth/password' && method === 'POST') return handleChangePassword(req, user, env);
  if (path === '/api/auth/me'       && method === 'PUT')  return handleUpdateMe(req, user, env);

  if (path === '/api/settings' && method === 'GET') return handleGetSettings(user, env);
  if (path === '/api/settings' && method === 'PUT') return handlePutSettings(req, user, env);

  if (path === '/api/vehicles' && method === 'GET')  return handleListVehicles(user, env);
  if (path === '/api/vehicles' && method === 'POST') return handleCreateVehicle(req, user, env);
  const vehicleMatch = path.match(/^\/api\/vehicles\/(\d+)$/);
  if (vehicleMatch) {
    const vid = parseInt(vehicleMatch[1]);
    if (method === 'PUT')    return handleUpdateVehicle(vid, req, user, env);
    if (method === 'DELETE') return handleDeleteVehicle(vid, user, env);
  }

  if (path === '/api/reports' && method === 'GET')  return handleListReports(user, env);
  if (path === '/api/reports' && method === 'POST') return handleCreateReport(req, user, env);

  const reportMatch = path.match(/^\/api\/reports\/(\d+)$/);
  if (reportMatch) {
    const id = parseInt(reportMatch[1]);
    if (method === 'GET')    return handleGetReport(id, user, env);
    if (method === 'PUT')    return handleUpdateReport(id, req, user, env);
    if (method === 'DELETE') return handleDeleteReport(id, user, env);
  }

  // Admin: manual fuel-price override (set / clear)
  if (path === '/api/fuel-prices' && method === 'PUT') return handlePutFuelPrices(req, user, env);

  if (path === '/api/admin/users' && method === 'GET') return handleAdminListUsers(user, env);
  const adminUserMatch = path.match(/^\/api\/admin\/users\/(\d+)$/);
  if (adminUserMatch && method === 'DELETE')
    return handleAdminDeleteUser(parseInt(adminUserMatch[1]), user, env);

  return json({ error: 'Ei leitud' }, { status: 404 });
}
