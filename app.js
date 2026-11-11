const express = require('express');
const crypto = require('crypto');
const path = require('path');

// Running as a Netlify Function (serverless) needs an online database and a fixed secret
const ON_NETLIFY = !!process.env.NETLIFY || !!process.env.AWS_LAMBDA_FUNCTION_NAME;
if (ON_NETLIFY && !process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not set. Add your PostgreSQL connection string in Netlify > Site configuration > Environment variables.');
}
if (ON_NETLIFY && !process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is not set. Add any long random text in Netlify > Site configuration > Environment variables.');
}

const app = express();
app.set('trust proxy', 1);
// Netlify may pass the function path; make sure routes always see /api/...
app.use((req, res, next) => {
  if (req.url.startsWith('/.netlify/functions/api')) req.url = req.url.replace('/.netlify/functions/api', '/api');
  next();
});
app.use(express.json());
// On Netlify the body can arrive as raw text; turn it into an object
app.use((req, res, next) => {
  if (Buffer.isBuffer(req.body) || typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body.toString() || '{}'); } catch (e) { req.body = {}; }
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

/* ---------- Database: online Postgres if DATABASE_URL is set, else local SQLite file ---------- */
const USE_PG = !!process.env.DATABASE_URL;
let db;
if (USE_PG) {
  const { Pool } = require('pg');
  const url = process.env.DATABASE_URL;
  const pool = new Pool({
    connectionString: url,
    ssl: /localhost|127\.0\.0\.1/.test(url) ? false : { rejectUnauthorized: false },
    max: ON_NETLIFY ? 2 : 10
  });
  const toPg = (sql) => { let i = 0; return sql.replace(/\?/g, () => '$' + (++i)); };
  db = {
    async all(sql, p = []) { return (await pool.query(toPg(sql), p)).rows; },
    async get(sql, p = []) { return (await pool.query(toPg(sql), p)).rows[0]; },
    async run(sql, p = []) {
      const q = toPg(sql) + (/^\s*insert/i.test(sql) ? ' RETURNING id' : '');
      const r = await pool.query(q, p);
      return { id: r.rows[0] ? r.rows[0].id : null };
    },
    async exec(sql) { await pool.query(sql); }
  };
} else {
  const { DatabaseSync } = require('node:sqlite');
  const sqlite = new DatabaseSync(process.env.DB_FILE || 'noxin.db');
  db = {
    async all(sql, p = []) { return sqlite.prepare(sql).all(...p); },
    async get(sql, p = []) { return sqlite.prepare(sql).get(...p); },
    async run(sql, p = []) { const r = sqlite.prepare(sql).run(...p); return { id: Number(r.lastInsertRowid) }; },
    async exec(sql) { sqlite.exec(sql); }
  };
}

const ID = USE_PG ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT';
const REAL = USE_PG ? 'DOUBLE PRECISION' : 'REAL';
const NOW = USE_PG
  ? "TEXT DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')"
  : 'TEXT DEFAULT CURRENT_TIMESTAMP';

const STATUSES = [
  'Registered', 'Picked up', 'At sorting hub', 'In transit', 'Arrived at destination branch',
  'Out for delivery', 'Delivery attempted', 'Delivered', 'Returned to sender', 'Cancelled'
];

/* ---------- Passwords and sign-in tokens (no extra packages needed) ---------- */
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPassword(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(pw, salt, 64);
  const real = Buffer.from(hash, 'hex');
  return real.length === test.length && crypto.timingSafeEqual(real, test);
}
function sign(body) { return crypto.createHmac('sha256', SECRET).update(body).digest('base64url'); }
function makeToken(username) {
  const body = Buffer.from(JSON.stringify({ u: username, exp: Date.now() + 12 * 3600 * 1000 })).toString('base64url');
  return body + '.' + sign(body);
}
function readToken(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const good = sign(body);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}

/* ---------- Helpers ---------- */
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const auth = wrap(async (req, res, next) => {
  const p = readToken((req.get('authorization') || '').replace(/^Bearer /, ''));
  const user = p && (await db.get('SELECT username, full_name, role, active FROM users WHERE username = ?', [p.u]));
  if (!user || !Number(user.active)) return res.status(401).json({ error: 'Please sign in again' });
  req.user = user;
  next();
});
const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });

const log = (username, action, detail) =>
  db.run('INSERT INTO activity_log (username, action, detail) VALUES (?,?,?)', [username, action, detail || null]).catch(() => {});

function rateLimit(max, windowMs) {
  const hits = new Map();
  setInterval(() => hits.clear(), 10 * 60 * 1000).unref();
  return (req, res, next) => {
    const now = Date.now();
    const recent = (hits.get(req.ip) || []).filter((t) => now - t < windowMs);
    if (recent.length >= max) return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
    recent.push(now);
    hits.set(req.ip, recent);
    next();
  };
}

function makeCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'NX-';
  for (const b of crypto.randomBytes(8)) code += chars[b % chars.length];
  return code;
}
function maskName(name) {
  const parts = String(name).trim().split(/\s+/);
  return parts.length > 1 ? `${parts[0]} ${parts[1][0]}.` : parts[0];
}
const cleanUser = (s) => String(s || '').trim().toLowerCase();
const goodUser = (s) => /^[a-z0-9._-]{3,30}$/.test(s);

/* ---------- Public routes ---------- */
app.get('/api/statuses', (req, res) => res.json(STATUSES));

app.get('/api/track/:code', rateLimit(60, 60 * 1000), wrap(async (req, res) => {
  const parcel = await db.get(
    'SELECT id, tracking_number, receiver_name, origin, destination, description, weight_kg, status, created_at FROM parcels WHERE tracking_number = ?',
    [req.params.code.trim().toUpperCase()]
  );
  if (!parcel) return res.status(404).json({ error: 'Tracking number not found' });
  const events = await db.all(
    'SELECT status, location, transport, note, created_at FROM events WHERE parcel_id = ? ORDER BY id DESC', [parcel.id]
  );
  res.json({
    tracking_number: parcel.tracking_number,
    receiver: maskName(parcel.receiver_name),
    origin: parcel.origin,
    destination: parcel.destination,
    description: parcel.description,
    weight_kg: parcel.weight_kg,
    status: parcel.status,
    created_at: parcel.created_at,
    events
  });
}));

/* ---------- Sign in and account ---------- */
// Only WRONG passwords count towards the limit (10 per 15 minutes per visitor),
// so a team sharing one office internet connection is never locked out by normal sign-ins
const loginFails = new Map();
setInterval(() => loginFails.clear(), 15 * 60 * 1000).unref();
app.post('/api/login', wrap(async (req, res) => {
  const fails = loginFails.get(req.ip) || 0;
  if (fails >= 10) return res.status(429).json({ error: 'Too many wrong attempts. Please wait 15 minutes and try again.' });
  const username = cleanUser(req.body.username);
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  if (!user || !Number(user.active) || !checkPassword(String(req.body.password || ''), user.password_hash)) {
    loginFails.set(req.ip, fails + 1);
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  await log(user.username, 'Signed in');
  res.json({ token: makeToken(user.username), user: { username: user.username, full_name: user.full_name, role: user.role } });
}));

app.get('/api/me', auth, (req, res) =>
  res.json({ username: req.user.username, full_name: req.user.full_name, role: req.user.role }));

app.post('/api/me/password', auth, wrap(async (req, res) => {
  const { current, next } = req.body;
  const user = await db.get('SELECT password_hash FROM users WHERE username = ?', [req.user.username]);
  if (!checkPassword(String(current || ''), user.password_hash)) return res.status(400).json({ error: 'Current password is wrong' });
  if (!next || String(next).length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  await db.run('UPDATE users SET password_hash = ? WHERE username = ?', [hashPassword(String(next)), req.user.username]);
  await log(req.user.username, 'Changed own password');
  res.json({ ok: true });
}));

/* ---------- Admin: staff accounts and activity ---------- */
app.get('/api/users', auth, adminOnly, wrap(async (req, res) =>
  res.json(await db.all('SELECT username, full_name, role, active, created_at FROM users ORDER BY id'))));

app.post('/api/users', auth, adminOnly, wrap(async (req, res) => {
  const username = cleanUser(req.body.username);
  const { full_name, password, role } = req.body;
  if (!goodUser(username)) return res.status(400).json({ error: 'Username: 3-30 letters, numbers, dots, dashes or underscores' });
  if (!password || String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (await db.get('SELECT 1 FROM users WHERE username = ?', [username])) return res.status(409).json({ error: 'That username already exists' });
  await db.run('INSERT INTO users (username, full_name, password_hash, role) VALUES (?,?,?,?)',
    [username, full_name || username, hashPassword(String(password)), role === 'admin' ? 'admin' : 'staff']);
  await log(req.user.username, 'Created account', username);
  res.status(201).json({ ok: true });
}));

app.patch('/api/users/:username', auth, adminOnly, wrap(async (req, res) => {
  const target = cleanUser(req.params.username);
  const user = await db.get('SELECT username FROM users WHERE username = ?', [target]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (target === req.user.username && req.body.active === false) return res.status(400).json({ error: 'You cannot deactivate your own account' });
  if (typeof req.body.active === 'boolean') {
    await db.run('UPDATE users SET active = ? WHERE username = ?', [req.body.active ? 1 : 0, target]);
    await log(req.user.username, req.body.active ? 'Reactivated account' : 'Deactivated account', target);
  }
  if (req.body.password) {
    if (String(req.body.password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    await db.run('UPDATE users SET password_hash = ? WHERE username = ?', [hashPassword(String(req.body.password)), target]);
    await log(req.user.username, 'Reset password', target);
  }
  res.json({ ok: true });
}));

app.get('/api/activity', auth, adminOnly, wrap(async (req, res) =>
  res.json(await db.all('SELECT id, username, action, detail, created_at FROM activity_log ORDER BY id DESC LIMIT 100'))));

// Admin: delete ONE activity line
app.delete('/api/activity/:id', auth, adminOnly, wrap(async (req, res) => {
  await db.run('DELETE FROM activity_log WHERE id = ?', [Number(req.params.id) || 0]);
  res.json({ ok: true });
}));

// Admin: clear the WHOLE activity log (one line is kept to record who cleared it)
app.delete('/api/activity', auth, adminOnly, wrap(async (req, res) => {
  await db.run('DELETE FROM activity_log');
  await db.run('INSERT INTO activity_log (username, action, detail) VALUES (?,?,?)',
    [req.user.username, 'cleared the activity log', null]);
  res.json({ ok: true });
}));

// Short tracking link used in QR codes and barcodes: /t/NUMBER shows the customer page
// (on Netlify the same thing is done by a redirect in netlify.toml)
app.get('/t/:code', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

/* ---------- Staff: parcels ---------- */
// Staff cannot see or change parcels that an administrator registered. Admins see everything.
// Only an admin, or the staff member who registered the parcel, may change its status or print its label
const NOT_YOURS = 'Only an admin or the staff member who registered this parcel can change it';
function canEdit(user, parcel) {
  return user.role === 'admin' || parcel.created_by === user.username;
}
function hiddenFromStaff(user) {
  return user.role === 'admin' ? '' : " AND (owner_role IS NULL OR owner_role <> 'admin')";
}

app.post('/api/parcels', auth, wrap(async (req, res) => {
  const { tracking_number, sender_name, sender_phone, receiver_name, receiver_phone, origin, destination, description, weight_kg } = req.body;
  const transport = String(req.body.transport || '').trim().slice(0, 120) || null;
  if (!sender_name || !receiver_name || !origin || !destination) {
    return res.status(400).json({ error: 'Sender, receiver, origin and destination are required' });
  }
  let code;
  if (tracking_number && tracking_number.trim()) {
    code = tracking_number.trim().toUpperCase();
    if (!/^[A-Z0-9-]{4,30}$/.test(code)) return res.status(400).json({ error: 'Tracking number must be 4-30 letters, numbers or dashes' });
    if (await db.get('SELECT 1 FROM parcels WHERE tracking_number = ?', [code])) return res.status(409).json({ error: 'That tracking number already exists' });
  } else {
    code = makeCode();
  }
  const info = await db.run(
    `INSERT INTO parcels (tracking_number, sender_name, sender_phone, receiver_name, receiver_phone, origin, destination, description, weight_kg, created_by, owner_role)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [code, sender_name, sender_phone || null, receiver_name, receiver_phone || null, origin, destination,
      description || null, weight_kg ? Number(weight_kg) : null, req.user.username, req.user.role]
  );
  await db.run('INSERT INTO events (parcel_id, status, location, transport, created_by) VALUES (?,?,?,?,?)',
    [info.id, 'Registered', origin, transport, req.user.username]);
  await log(req.user.username, 'Registered parcel', code);
  res.status(201).json({ tracking_number: code });
}));

const limitText = (v, max) => String(v ?? '').trim().slice(0, max);

// One status update. Same rules for one parcel or many: returns { ok: true } or { status, error }.
async function applyEvent(user, rawCode, data) {
  const code = String(rawCode || '').trim().toUpperCase();
  const parcel = await db.get('SELECT id, created_by, status FROM parcels WHERE tracking_number = ?' + hiddenFromStaff(user), [code]);
  if (!parcel) return { status: 404, error: 'Tracking number not found' };
  if (!canEdit(user, parcel)) return { status: 403, error: NOT_YOURS };
  // A cancelled parcel can only be changed again by an admin
  if (parcel.status === 'Cancelled' && user.role !== 'admin') {
    return { status: 403, error: 'This parcel is cancelled. Only an admin can change it.' };
  }
  await db.run('INSERT INTO events (parcel_id, status, location, transport, note, created_by) VALUES (?,?,?,?,?,?)',
    [parcel.id, data.status, data.location || null, data.transport || null, data.note || null, user.username]);
  await db.run('UPDATE parcels SET status = ? WHERE id = ?', [data.status, parcel.id]);
  return { ok: true, code };
}

const eventData = (b) => ({
  status: b.status, location: limitText(b.location, 120), transport: limitText(b.transport, 120), note: limitText(b.note, 300)
});

app.post('/api/parcels/:code/events', auth, wrap(async (req, res) => {
  const b = req.body || {};
  if (!STATUSES.includes(b.status)) return res.status(400).json({ error: 'Invalid status' });
  const r = await applyEvent(req.user, req.params.code, eventData(b));
  if (!r.ok) return res.status(r.status).json({ error: r.error });
  await log(req.user.username, 'Updated parcel', `${r.code}: ${b.status}`);
  res.status(201).json({ ok: true });
}));

// Update MANY parcels at once (for example everything on one flight or truck)
app.post('/api/batch-events', auth, wrap(async (req, res) => {
  const b = req.body || {};
  if (!STATUSES.includes(b.status)) return res.status(400).json({ error: 'Choose a status' });
  const codes = [...new Set((Array.isArray(b.codes) ? b.codes : []).map(c => String(c || '').trim().toUpperCase()).filter(Boolean))];
  if (!codes.length) return res.status(400).json({ error: 'Enter at least one tracking number' });
  if (codes.length > 200) return res.status(400).json({ error: 'You can update up to 200 parcels at once' });
  const data = eventData(b);
  const updated = [], skipped = [];
  for (const code of codes) {
    const r = await applyEvent(req.user, code, data);
    if (r.ok) updated.push(code); else skipped.push({ code, error: r.error });
  }
  if (updated.length) {
    await log(req.user.username, 'Updated many parcels',
      `${updated.length} set to ${b.status}: ${updated.slice(0, 5).join(', ')}${updated.length > 5 ? ' ...' : ''}`);
  }
  res.json({ updated: updated.length, skipped });
}));

// Full details of one parcel, for the edit form
const PARCEL_COLUMNS = 'id, tracking_number, sender_name, sender_phone, receiver_name, receiver_phone, origin, destination, description, weight_kg, status, created_by';
app.get('/api/parcels/:code', auth, wrap(async (req, res) => {
  const p = await db.get(`SELECT ${PARCEL_COLUMNS} FROM parcels WHERE tracking_number = ?` + hiddenFromStaff(req.user),
    [req.params.code.trim().toUpperCase()]);
  if (!p) return res.status(404).json({ error: 'Tracking number not found' });
  if (!canEdit(req.user, p)) return res.status(403).json({ error: NOT_YOURS });
  delete p.id;
  res.json(p);
}));

// Correct a parcel's details (the tracking number and status are not changed here)
const FIELD_NAMES = { sender_name: 'Sender name', receiver_name: 'Receiver name', origin: 'From (town)', destination: 'To (town)' };
app.patch('/api/parcels/:code', auth, wrap(async (req, res) => {
  const p = await db.get(`SELECT ${PARCEL_COLUMNS} FROM parcels WHERE tracking_number = ?` + hiddenFromStaff(req.user),
    [req.params.code.trim().toUpperCase()]);
  if (!p) return res.status(404).json({ error: 'Tracking number not found' });
  if (!canEdit(req.user, p)) return res.status(403).json({ error: NOT_YOURS });
  if (p.status === 'Cancelled' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'This parcel is cancelled. Only an admin can change it.' });
  }
  const b = req.body || {};
  const next = { ...p };
  const changed = [];
  const set = (field, value) => {
    if (String(p[field] ?? '') !== String(value ?? '')) { next[field] = value; changed.push(field); }
  };
  for (const f of Object.keys(FIELD_NAMES)) {
    if (b[f] === undefined) continue;
    const v = limitText(b[f], 120);
    if (!v) return res.status(400).json({ error: `${FIELD_NAMES[f]} cannot be empty` });
    set(f, v);
  }
  for (const f of ['sender_phone', 'receiver_phone']) if (b[f] !== undefined) set(f, limitText(b[f], 40) || null);
  if (b.description !== undefined) set('description', limitText(b.description, 300) || null);
  if (b.weight_kg !== undefined) {
    const w = b.weight_kg === '' || b.weight_kg === null ? null : Number(b.weight_kg);
    if (w !== null && (!Number.isFinite(w) || w < 0)) return res.status(400).json({ error: 'Weight must be a positive number' });
    set('weight_kg', w);
  }
  if (!changed.length) return res.json({ ok: true, changed: [] });
  await db.run(
    'UPDATE parcels SET sender_name = ?, sender_phone = ?, receiver_name = ?, receiver_phone = ?, origin = ?, destination = ?, description = ?, weight_kg = ? WHERE id = ?',
    [next.sender_name, next.sender_phone, next.receiver_name, next.receiver_phone, next.origin, next.destination, next.description, next.weight_kg, p.id]);
  await log(req.user.username, 'Edited parcel', `${p.tracking_number}: ${changed.join(', ')}`);
  res.json({ ok: true, changed });
}));

/* ---------- Reports and Excel (CSV) export: admin only ---------- */
const TS = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
const stamp = (d) => d.toISOString().slice(0, 19).replace('T', ' ');
// The page sends the start and end of the period as UTC times (it works out "today" in your own time zone)
function periodFrom(req, allTimeByDefault) {
  const from = String(req.query.from || ''), to = String(req.query.to || '');
  if (TS.test(from) && TS.test(to) && from < to) return { from, to };
  if (allTimeByDefault) return { from: '0000-01-01 00:00:00', to: '9999-12-31 23:59:59' };
  const now = new Date();
  return { from: stamp(new Date(now.getTime() - 30 * 86400000)), to: stamp(new Date(now.getTime() + 60000)) };
}
const num = (v) => Number(v) || 0;

app.get('/api/reports', auth, adminOnly, wrap(async (req, res) => {
  const { from, to } = periodFrom(req, false);
  const registered = await db.get('SELECT COUNT(*) AS n FROM parcels WHERE created_at >= ? AND created_at < ?', [from, to]);
  const noReceipt = await db.get(
    `SELECT COUNT(*) AS n FROM parcels WHERE created_at >= ? AND created_at < ? AND status <> 'Cancelled'
       AND NOT EXISTS (SELECT 1 FROM payments pm WHERE pm.parcel_id = parcels.id AND pm.voided = 0)`, [from, to]);
  const updates = await db.all('SELECT status, COUNT(*) AS n FROM events WHERE created_at >= ? AND created_at < ? GROUP BY status ORDER BY n DESC', [from, to]);
  const now = await db.all('SELECT status, COUNT(*) AS n FROM parcels GROUP BY status ORDER BY n DESC');
  const money = await db.all(
    `SELECT currency, method, COUNT(*) AS n, SUM(subtotal_cents) AS subtotal, SUM(tax_cents) AS tax, SUM(total_cents) AS total
       FROM payments WHERE voided = 0 AND created_at >= ? AND created_at < ?
       GROUP BY currency, method ORDER BY currency, method`, [from, to]);
  const rows = money.map(m => ({ currency: m.currency, method: m.method, n: num(m.n), subtotal: num(m.subtotal), tax: num(m.tax), total: num(m.total) }));
  const totals = {};
  for (const m of rows) {
    const t = totals[m.currency] || (totals[m.currency] = { currency: m.currency, n: 0, subtotal: 0, tax: 0, total: 0 });
    t.n += m.n; t.subtotal += m.subtotal; t.tax += m.tax; t.total += m.total;
  }
  res.json({
    registered: num(registered && registered.n),
    without_receipt: num(noReceipt && noReceipt.n),
    updates: updates.map(u => ({ status: u.status, n: num(u.n) })),
    parcels_now: now.map(u => ({ status: u.status, n: num(u.n) })),
    money: rows,
    totals: Object.values(totals)
  });
}));

// CSV opens directly in Excel
class Raw { constructor(s) { this.s = s; } }
const asText = (v) => (v ? new Raw(`="${String(v).replace(/"/g, '""')}"`) : '');   // keeps phone numbers exactly as typed in Excel
function csvCell(v) {
  if (v === null || v === undefined) return '';
  let t = v instanceof Raw ? v.s : String(v);
  if (!(v instanceof Raw) && (/^[=@\t\r]/.test(t) || (/^[+-]/.test(t) && !/^[+-]?[\d\s()-]+$/.test(t)))) t = "'" + t;   // stops spreadsheet formulas
  return /[",\n\r]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t;
}
const toCsv = (head, rows) => [head, ...rows].map(r => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
const money2 = (c) => (num(c) / 100).toFixed(2);
function sendCsv(res, name, body) {
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${name}"` });
  res.send(body);
}

app.get('/api/export/parcels.csv', auth, adminOnly, wrap(async (req, res) => {
  const { from, to } = periodFrom(req, true);
  const rows = await db.all(
    `SELECT tracking_number, status, sender_name, sender_phone, receiver_name, receiver_phone, origin, destination, description, weight_kg, created_by, created_at,
            CASE WHEN EXISTS (SELECT 1 FROM payments pm WHERE pm.parcel_id = parcels.id AND pm.voided = 0) THEN 'Yes' ELSE 'No' END AS paid
       FROM parcels WHERE created_at >= ? AND created_at < ? ORDER BY id DESC LIMIT 50000`, [from, to]);
  sendCsv(res, 'parcels.csv', toCsv(
    ['Tracking number', 'Status', 'Sender', 'Sender phone', 'Receiver', 'Receiver phone', 'From', 'To', 'Contents', 'Weight (kg)', 'Registered by', 'Registered (UTC)', 'Has receipt'],
    rows.map(r => [r.tracking_number, r.status, r.sender_name, asText(r.sender_phone), r.receiver_name, asText(r.receiver_phone), r.origin, r.destination, r.description, r.weight_kg, r.created_by, r.created_at, r.paid])));
}));

app.get('/api/export/receipts.csv', auth, adminOnly, wrap(async (req, res) => {
  const { from, to } = periodFrom(req, true);
  const rows = await db.all(
    `SELECT pm.id, pm.created_at, p.tracking_number, pm.item, pm.qty, pm.unit_cents, pm.subtotal_cents, pm.tax_rate, pm.tax_cents, pm.total_cents,
            pm.currency, pm.method, pm.paid_by, pm.served_by, pm.created_by, pm.voided
       FROM payments pm JOIN parcels p ON p.id = pm.parcel_id
      WHERE pm.created_at >= ? AND pm.created_at < ? ORDER BY pm.id DESC LIMIT 50000`, [from, to]);
  sendCsv(res, 'receipts.csv', toCsv(
    ['Receipt no', 'Date (UTC)', 'Tracking number', 'Item', 'Qty', 'Unit price', 'Subtotal', 'Tax %', 'Tax', 'Total', 'Currency', 'Paid by', 'Received from', 'Served by', 'Issued by', 'Void'],
    rows.map(r => [receiptNo(r.id), r.created_at, r.tracking_number, r.item, r.qty, money2(r.unit_cents), money2(r.subtotal_cents), r.tax_rate, money2(r.tax_cents), money2(r.total_cents),
      r.currency, r.method, r.paid_by, r.served_by || r.created_by, r.created_by, Number(r.voided) === 1 ? 'VOID' : ''])));
}));

app.get('/api/export/activity.csv', auth, adminOnly, wrap(async (req, res) => {
  const rows = await db.all('SELECT created_at, username, action, detail FROM activity_log ORDER BY id DESC LIMIT 50000');
  sendCsv(res, 'activity-log.csv', toCsv(['Time (UTC)', 'User', 'Action', 'Details'], rows.map(r => [r.created_at, r.username, r.action, r.detail])));
}));



app.get('/api/parcels', auth, wrap(async (req, res) => {
  const q = `%${(req.query.q || '').trim()}%`;
  const rows = await db.all(
    `SELECT tracking_number, sender_name, receiver_name, receiver_phone, origin, destination, status, created_by, created_at,
            CASE WHEN EXISTS (SELECT 1 FROM payments pm WHERE pm.parcel_id = parcels.id AND pm.voided = 0) THEN 1 ELSE 0 END AS paid
     FROM parcels
     WHERE (LOWER(tracking_number) LIKE LOWER(?) OR LOWER(receiver_name) LIKE LOWER(?) OR LOWER(sender_name) LIKE LOWER(?))${hiddenFromStaff(req.user)}
     ORDER BY id DESC LIMIT 50`, [q, q, q]);
  res.json(rows.map(p => ({ ...p, paid: Number(p.paid) === 1, can_edit: canEdit(req.user, p) })));
}));

app.get('/api/parcels/:code/label', auth, wrap(async (req, res) => {
  const parcel = await db.get('SELECT tracking_number, created_by FROM parcels WHERE tracking_number = ?' + hiddenFromStaff(req.user),
    [req.params.code.trim().toUpperCase()]);
  if (!parcel) return res.status(404).json({ error: 'Tracking number not found' });
  if (!canEdit(req.user, parcel)) return res.status(403).json({ error: NOT_YOURS });
  res.json({ tracking_number: parcel.tracking_number });
}));

/* ---------- Payment receipts (delivery fee paid) ---------- */
// Staff can issue and view receipts only for parcels they registered; admins for every parcel.
const PAY_METHODS = [
  'Cash',
  'M-Pesa', 'Airtel Money', 'MTN Mobile Money', 'Vodacom M-Pesa', 'Tigo Pesa',
  'EVC Plus', 'Waafi', 'Sahal', 'ZAAD Service',
  'Dahabshiil', 'Western Union', 'Mukuru',
  'Card', 'Bank transfer', 'Other'
];
const receiptNo = (id) => 'RC-' + String(id).padStart(6, '0');

async function parcelForReceipt(req, res, code) {
  const parcel = await db.get(
    'SELECT id, tracking_number, created_by FROM parcels WHERE tracking_number = ?' + hiddenFromStaff(req.user), [code]);
  if (!parcel) { res.status(404).json({ error: 'Tracking number not found' }); return null; }
  if (!canEdit(req.user, parcel)) { res.status(403).json({ error: NOT_YOURS }); return null; }
  return parcel;
}

app.post('/api/parcels/:code/payments', auth, wrap(async (req, res) => {
  const parcel = await parcelForReceipt(req, res, req.params.code.trim().toUpperCase());
  if (!parcel) return;
  const b = req.body || {};
  const item = String(b.item || 'Delivery fee').trim().slice(0, 120) || 'Delivery fee';
  const qty = Number(b.qty || 1);
  const unit = Number(b.amount);
  const taxRate = b.tax_rate === '' || b.tax_rate == null ? 0 : Number(b.tax_rate);
  const currency = String(b.currency || '').trim().toUpperCase();
  const method = PAY_METHODS.includes(b.method) ? b.method : null;
  if (!Number.isInteger(qty) || qty < 1 || qty > 1000) return res.status(400).json({ error: 'Quantity must be a whole number from 1 to 1000' });
  if (!Number.isFinite(unit) || unit <= 0 || unit > 100000000) return res.status(400).json({ error: 'Enter the amount the customer paid' });
  if (!Number.isFinite(taxRate) || taxRate < 0 || taxRate > 100) return res.status(400).json({ error: 'Tax must be between 0 and 100' });
  if (!/^[A-Z]{2,5}$/.test(currency)) return res.status(400).json({ error: 'Enter a currency, for example KES' });
  if (!method) return res.status(400).json({ error: 'Choose how the customer paid' });

  // Money is stored in whole cents to avoid rounding errors
  const unitC = Math.round(unit * 100);
  const subC = unitC * qty;
  const taxC = Math.round(subC * taxRate / 100);
  const totC = subC + taxC;
  const { id } = await db.run(
    `INSERT INTO payments (parcel_id, item, qty, unit_cents, subtotal_cents, tax_rate, tax_cents, total_cents, currency, method, paid_by, created_by, served_by)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [parcel.id, item, qty, unitC, subC, taxRate, taxC, totC, currency, method,
      String(b.paid_by || '').trim().slice(0, 120) || null, req.user.username,
      String(b.served_by || '').trim().slice(0, 80) || req.user.full_name || req.user.username]);
  await log(req.user.username, 'Issued receipt', `${receiptNo(id)} for ${parcel.tracking_number}: ${currency} ${(totC / 100).toFixed(2)}`);
  res.status(201).json({ id, receipt_no: receiptNo(id) });
}));

app.get('/api/parcels/:code/payments', auth, wrap(async (req, res) => {
  const parcel = await parcelForReceipt(req, res, req.params.code.trim().toUpperCase());
  if (!parcel) return;
  const rows = await db.all('SELECT id, total_cents, currency, voided, created_at FROM payments WHERE parcel_id = ? ORDER BY id DESC', [parcel.id]);
  res.json(rows.map(r => ({ ...r, voided: Number(r.voided) === 1, receipt_no: receiptNo(r.id) })));
}));

app.get('/api/receipts/:id', auth, wrap(async (req, res) => {
  const pay = await db.get('SELECT * FROM payments WHERE id = ?', [Number(req.params.id) || 0]);
  if (!pay) return res.status(404).json({ error: 'Receipt not found' });
  const parcel = await db.get(
    'SELECT id, tracking_number, sender_name, receiver_name, origin, destination, created_by FROM parcels WHERE id = ?' + hiddenFromStaff(req.user),
    [pay.parcel_id]);
  if (!parcel) return res.status(404).json({ error: 'Receipt not found' });
  if (!canEdit(req.user, parcel)) return res.status(403).json({ error: NOT_YOURS });
  res.json({
    id: pay.id, receipt_no: receiptNo(pay.id), created_at: pay.created_at,
    tracking_number: parcel.tracking_number, sender_name: parcel.sender_name, receiver_name: parcel.receiver_name,
    origin: parcel.origin, destination: parcel.destination,
    item: pay.item, qty: pay.qty, unit_cents: pay.unit_cents, subtotal_cents: pay.subtotal_cents,
    tax_rate: pay.tax_rate, tax_cents: pay.tax_cents, total_cents: pay.total_cents,
    currency: pay.currency, method: pay.method, paid_by: pay.paid_by,
    voided: Number(pay.voided) === 1, served_by: pay.served_by || pay.created_by
  });
}));

// Change the "Served by" name on a receipt (admin, or the staff member who owns the parcel)
app.patch('/api/receipts/:id', auth, wrap(async (req, res) => {
  const pay = await db.get('SELECT id, parcel_id, voided FROM payments WHERE id = ?', [Number(req.params.id) || 0]);
  if (!pay) return res.status(404).json({ error: 'Receipt not found' });
  const parcel = await db.get('SELECT id, created_by FROM parcels WHERE id = ?' + hiddenFromStaff(req.user), [pay.parcel_id]);
  if (!parcel) return res.status(404).json({ error: 'Receipt not found' });
  if (!canEdit(req.user, parcel)) return res.status(403).json({ error: NOT_YOURS });
  if (Number(pay.voided) === 1) return res.status(400).json({ error: 'A voided receipt cannot be changed' });
  const name = String(req.body.served_by || '').trim().slice(0, 80);
  if (!name) return res.status(400).json({ error: 'Enter the name of the person who served the customer' });
  await db.run('UPDATE payments SET served_by = ? WHERE id = ?', [name, pay.id]);
  await log(req.user.username, 'Edited receipt', `${receiptNo(pay.id)}: served by ${name}`);
  res.json({ ok: true, served_by: name });
}));

// Admin only: a wrong receipt is voided (kept on record, marked VOID), never silently deleted
app.post('/api/receipts/:id/void', auth, adminOnly, wrap(async (req, res) => {
  const pay = await db.get('SELECT id FROM payments WHERE id = ?', [Number(req.params.id) || 0]);
  if (!pay) return res.status(404).json({ error: 'Receipt not found' });
  await db.run('UPDATE payments SET voided = 1, voided_by = ? WHERE id = ?', [req.user.username, pay.id]);
  await log(req.user.username, 'Voided receipt', receiptNo(pay.id));
  res.json({ ok: true });
}));

app.delete('/api/parcels/:code', auth, adminOnly, wrap(async (req, res) => {
  const code = req.params.code.trim().toUpperCase();
  const parcel = await db.get('SELECT id FROM parcels WHERE tracking_number = ?', [code]);
  if (!parcel) return res.status(404).json({ error: 'Tracking number not found' });
  await db.run('DELETE FROM events WHERE parcel_id = ?', [parcel.id]);
  await db.run('DELETE FROM payments WHERE parcel_id = ?', [parcel.id]);
  await db.run('DELETE FROM parcels WHERE id = ?', [parcel.id]);
  await log(req.user.username, 'Deleted parcel', code);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server' });
});

/* ---------- Start up ---------- */
async function init() {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id ${ID}, username TEXT UNIQUE NOT NULL, full_name TEXT, password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'staff', active INTEGER NOT NULL DEFAULT 1, created_at ${NOW}
    );
    CREATE TABLE IF NOT EXISTS parcels (
      id ${ID}, tracking_number TEXT UNIQUE NOT NULL, sender_name TEXT NOT NULL, sender_phone TEXT,
      receiver_name TEXT NOT NULL, receiver_phone TEXT, origin TEXT NOT NULL, destination TEXT NOT NULL,
      description TEXT, weight_kg ${REAL}, status TEXT NOT NULL DEFAULT 'Registered', created_by TEXT, owner_role TEXT, created_at ${NOW}
    );
    CREATE TABLE IF NOT EXISTS events (
      id ${ID}, parcel_id INTEGER NOT NULL REFERENCES parcels(id), status TEXT NOT NULL,
      location TEXT, transport TEXT, note TEXT, created_by TEXT, created_at ${NOW}
    );
    CREATE TABLE IF NOT EXISTS activity_log (
      id ${ID}, username TEXT, action TEXT NOT NULL, detail TEXT, created_at ${NOW}
    );
    CREATE TABLE IF NOT EXISTS payments (
      id ${ID}, parcel_id INTEGER NOT NULL REFERENCES parcels(id), item TEXT NOT NULL, qty INTEGER NOT NULL,
      unit_cents INTEGER NOT NULL, subtotal_cents INTEGER NOT NULL, tax_rate ${REAL} NOT NULL, tax_cents INTEGER NOT NULL,
      total_cents INTEGER NOT NULL, currency TEXT NOT NULL, method TEXT NOT NULL, paid_by TEXT, note TEXT,
      voided INTEGER NOT NULL DEFAULT 0, voided_by TEXT, created_by TEXT, served_by TEXT, created_at ${NOW}
    );
    CREATE INDEX IF NOT EXISTS idx_events_parcel ON events(parcel_id);
    CREATE INDEX IF NOT EXISTS idx_payments_parcel ON payments(parcel_id);
  `);
  // Older local databases: add the new "created_by" columns if missing
  for (const t of ['parcels', 'events']) {
    try { await db.exec(`ALTER TABLE ${t} ADD COLUMN created_by TEXT`); } catch (e) { /* already there */ }
  }

  // Databases created by an earlier version: add the new columns if they are missing
  for (const sql of ['ALTER TABLE events ADD COLUMN transport TEXT', 'ALTER TABLE parcels ADD COLUMN owner_role TEXT', 'ALTER TABLE payments ADD COLUMN served_by TEXT']) {
    try { await db.exec(sql); } catch (e) { /* already there */ }
  }

  // First start: create the first admin account
  const { n } = await db.get('SELECT COUNT(*) AS n FROM users');
  if (Number(n) === 0) {
    const pass = process.env.ADMIN_PASSWORD || process.env.API_KEY;
    const name = cleanUser(process.env.ADMIN_USERNAME) || 'admin';
    if (pass && pass.length >= 8) {
      await db.run('INSERT INTO users (username, full_name, password_hash, role) VALUES (?,?,?,?)',
        [name, 'Administrator', hashPassword(pass), 'admin']);
      console.log(`First admin created. Username: ${name}`);
    } else {
      console.log('No users yet. Start again with ADMIN_PASSWORD set (at least 8 characters) to create the first admin.');
    }
  }

}
const ready = init();
ready.catch((e) => console.error('Could not start:', e.message));

module.exports = { app, ready, USE_PG };
