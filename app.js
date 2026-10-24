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
  'Out for delivery', 'Delivery attempted', 'Delivered', 'Returned to sender'
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
    'SELECT status, location, note, created_at FROM events WHERE parcel_id = ? ORDER BY id DESC', [parcel.id]
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
  res.json(await db.all('SELECT username, action, detail, created_at FROM activity_log ORDER BY id DESC LIMIT 100'))));

/* ---------- Staff: parcels ---------- */
app.post('/api/parcels', auth, wrap(async (req, res) => {
  const { tracking_number, sender_name, sender_phone, receiver_name, receiver_phone, origin, destination, description, weight_kg } = req.body;
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
    `INSERT INTO parcels (tracking_number, sender_name, sender_phone, receiver_name, receiver_phone, origin, destination, description, weight_kg, created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
    [code, sender_name, sender_phone || null, receiver_name, receiver_phone || null, origin, destination,
      description || null, weight_kg ? Number(weight_kg) : null, req.user.username]
  );
  await db.run('INSERT INTO events (parcel_id, status, location, created_by) VALUES (?,?,?,?)',
    [info.id, 'Registered', origin, req.user.username]);
  await log(req.user.username, 'Registered parcel', code);
  res.status(201).json({ tracking_number: code });
}));

app.post('/api/parcels/:code/events', auth, wrap(async (req, res) => {
  const code = req.params.code.trim().toUpperCase();
  const parcel = await db.get('SELECT id FROM parcels WHERE tracking_number = ?', [code]);
  if (!parcel) return res.status(404).json({ error: 'Tracking number not found' });
  const { status, location, note } = req.body;
  if (!STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  await db.run('INSERT INTO events (parcel_id, status, location, note, created_by) VALUES (?,?,?,?,?)',
    [parcel.id, status, location || null, note || null, req.user.username]);
  await db.run('UPDATE parcels SET status = ? WHERE id = ?', [status, parcel.id]);
  await log(req.user.username, 'Updated parcel', `${code}: ${status}`);
  res.status(201).json({ ok: true });
}));

app.get('/api/parcels', auth, wrap(async (req, res) => {
  const q = `%${(req.query.q || '').trim()}%`;
  res.json(await db.all(
    `SELECT tracking_number, sender_name, receiver_name, receiver_phone, origin, destination, status, created_at
     FROM parcels
     WHERE LOWER(tracking_number) LIKE LOWER(?) OR LOWER(receiver_name) LIKE LOWER(?) OR LOWER(sender_name) LIKE LOWER(?)
     ORDER BY id DESC LIMIT 50`, [q, q, q]));
}));

app.delete('/api/parcels/:code', auth, adminOnly, wrap(async (req, res) => {
  const code = req.params.code.trim().toUpperCase();
  const parcel = await db.get('SELECT id FROM parcels WHERE tracking_number = ?', [code]);
  if (!parcel) return res.status(404).json({ error: 'Tracking number not found' });
  await db.run('DELETE FROM events WHERE parcel_id = ?', [parcel.id]);
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
      description TEXT, weight_kg ${REAL}, status TEXT NOT NULL DEFAULT 'Registered', created_by TEXT, created_at ${NOW}
    );
    CREATE TABLE IF NOT EXISTS events (
      id ${ID}, parcel_id INTEGER NOT NULL REFERENCES parcels(id), status TEXT NOT NULL,
      location TEXT, note TEXT, created_by TEXT, created_at ${NOW}
    );
    CREATE TABLE IF NOT EXISTS activity_log (
      id ${ID}, username TEXT, action TEXT NOT NULL, detail TEXT, created_at ${NOW}
    );
    CREATE INDEX IF NOT EXISTS idx_events_parcel ON events(parcel_id);
  `);
  // Older local databases: add the new "created_by" columns if missing
  for (const t of ['parcels', 'events']) {
    try { await db.exec(`ALTER TABLE ${t} ADD COLUMN created_by TEXT`); } catch (e) { /* already there */ }
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
