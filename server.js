const express = require('express'), Database = require('better-sqlite3'), crypto = require('crypto'), path = require('path'), fs = require('fs');
const PORT = process.env.PORT || 3000;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PROD = process.env.NODE_ENV === 'production';
const SIGNUP = process.env.ALLOW_SIGNUP === 'true';   // first account is always allowed
fs.mkdirSync(DIR, { recursive: true });
const db = new Database(path.join(DIR, 'office.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS data(user_id INTEGER PRIMARY KEY, json TEXT NOT NULL, ver INTEGER NOT NULL DEFAULT 0, updated INTEGER);`);

const hashPw = (p, salt) => crypto.scryptSync(p, salt, 64).toString('hex');
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const userCount = () => db.prepare('SELECT COUNT(*) c FROM users').get().c;
const sid = q => ((q.headers.cookie || '').split(';').map(x => x.trim().split('=')).find(x => x[0] === 'sid') || [])[1];
const uidOf = q => {
  const t = sid(q); if (!t) return null;
  const r = db.prepare('SELECT user_id, expires FROM sessions WHERE token=?').get(sha(t));
  return r && r.expires > Date.now() ? r.user_id : null;
};
const auth = (q, s, n) => { const u = uidOf(q); if (!u) return s.status(401).json({ error: 'Not signed in' }); q.uid = u; n(); };
const tries = new Map();
const limit = (q, s, n) => {
  const now = Date.now(), a = (tries.get(q.ip) || []).filter(t => now - t < 60000);
  if (a.length >= 8) return s.status(429).json({ error: 'Too many attempts. Please wait a minute.' });
  a.push(now); tries.set(q.ip, a); n();
};
function startSession(s, uid) {
  const token = crypto.randomBytes(32).toString('hex'), maxAge = 30 * 864e5;
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(sha(token), uid, Date.now() + maxAge);
  s.cookie('sid', token, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge });
}
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now()), 36e5).unref();

const app = express();
app.disable('x-powered-by'); app.set('trust proxy', 1);
app.use(express.json({ limit: '8mb' }));
app.use((q, s, n) => { s.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }); n(); });

app.get('/api/status', (q, s) => s.json({ setup: userCount() === 0, signup: SIGNUP }));
app.post('/api/register', limit, (q, s) => {
  const { username, password } = q.body || {};
  if (userCount() > 0 && !SIGNUP) return s.status(403).json({ error: 'Sign-ups are closed.' });
  if (!/^[\w.@-]{3,40}$/.test(username || '')) return s.status(400).json({ error: 'Username must be 3–40 letters, numbers or . _ - @' });
  if (typeof password !== 'string' || password.length < 8) return s.status(400).json({ error: 'Password must be at least 8 characters.' });
  const salt = crypto.randomBytes(16).toString('hex');
  try {
    const r = db.prepare('INSERT INTO users(username,salt,hash,created) VALUES(?,?,?,?)').run(username.toLowerCase(), salt, hashPw(password, salt), Date.now());
    startSession(s, r.lastInsertRowid); s.json({ ok: true });
  } catch (e) { s.status(409).json({ error: 'That username is already taken.' }); }
});
app.post('/api/login', limit, (q, s) => {
  const { username, password } = q.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || '').toLowerCase());
  const ok = u && crypto.timingSafeEqual(Buffer.from(hashPw(String(password || ''), u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
  if (!ok) return s.status(401).json({ error: 'Incorrect username or password.' });
  startSession(s, u.id); s.json({ ok: true });
});
app.post('/api/logout', (q, s) => { const t = sid(q); if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(sha(t)); s.clearCookie('sid'); s.json({ ok: true }); });
app.get('/api/me', auth, (q, s) => s.json({ username: db.prepare('SELECT username FROM users WHERE id=?').get(q.uid).username }));
app.post('/api/password', auth, (q, s) => {
  const { current, next } = q.body || {};
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(q.uid);
  if (hashPw(String(current || ''), u.salt) !== u.hash) return s.status(403).json({ error: 'Current password is incorrect.' });
  if (typeof next !== 'string' || next.length < 8) return s.status(400).json({ error: 'New password must be at least 8 characters.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET salt=?, hash=? WHERE id=?').run(salt, hashPw(next, salt), q.uid);
  s.json({ ok: true });
});
app.get('/api/data', auth, (q, s) => {
  const r = db.prepare('SELECT json, ver FROM data WHERE user_id=?').get(q.uid);
  s.json(r ? { data: JSON.parse(r.json), ver: r.ver } : { data: null, ver: 0 });
});
app.put('/api/data', auth, (q, s) => {
  const { data, ver } = q.body || {};
  if (!data || !Array.isArray(data.companies)) return s.status(400).json({ error: 'Invalid data' });
  const cur = db.prepare('SELECT ver FROM data WHERE user_id=?').get(q.uid), cv = cur ? cur.ver : 0;
  if ((ver | 0) !== cv) return s.status(409).json({ error: 'conflict', ver: cv });
  db.prepare(`INSERT INTO data(user_id,json,ver,updated) VALUES(?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, ver=excluded.ver, updated=excluded.updated`).run(q.uid, JSON.stringify(data), cv + 1, Date.now());
  s.json({ ver: cv + 1 });
});

const pub = path.join(__dirname, 'public');
app.get(['/', '/index.html'], (q, s) => uidOf(q) ? s.sendFile(path.join(pub, 'index.html')) : s.redirect('/login.html'));
app.use(express.static(pub, { index: false }));
app.use((e, q, s, n) => s.status(e.status || 500).json({ error: e.status === 413 ? 'Data too large (try a smaller logo or signature).' : 'Server error' }));
app.listen(PORT, () => console.log('My Cloud Office running on port ' + PORT));
