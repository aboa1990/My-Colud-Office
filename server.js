const express = require('express'), { Pool } = require('pg'), crypto = require('crypto'), path = require('path');
const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
const SIGNUP = process.env.ALLOW_SIGNUP === 'true';   // the first account is always allowed
const DB_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || '';
if (!DB_URL) console.error('DATABASE_URL is not set. Add a Postgres database and set DATABASE_URL.');
const local = /localhost|127\.0\.0\.1/.test(DB_URL);
const pool = new Pool({ connectionString: DB_URL, max: 3, ssl: local || /sslmode=/.test(DB_URL) ? undefined : { rejectUnauthorized: false } });
const db = (text, params) => pool.query(text, params);
let ready = null;
const init = () => ready || (ready = db(`
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, created BIGINT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS data(user_id INTEGER PRIMARY KEY, json TEXT NOT NULL, ver INTEGER NOT NULL DEFAULT 0, updated BIGINT);`).catch(e => { ready = null; console.error('Database setup failed:', e.message); throw e; }));

const hashPw = (p, salt) => crypto.scryptSync(p, salt, 64).toString('hex');
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const ah = f => (q, s, n) => f(q, s, n).catch(n);
const userCount = async () => Number((await db('SELECT COUNT(*) c FROM users')).rows[0].c);
const sid = q => ((q.headers.cookie || '').split(';').map(x => x.trim().split('=')).find(x => x[0] === 'sid') || [])[1];
const uidOf = async q => {
  const t = sid(q); if (!t) return null;
  const r = (await db('SELECT user_id, expires FROM sessions WHERE token=$1', [sha(t)])).rows[0];
  return r && Number(r.expires) > Date.now() ? r.user_id : null;
};
const auth = ah(async (q, s, n) => { const u = await uidOf(q); if (!u) return s.status(401).json({ error: 'Not signed in' }); q.uid = u; n(); });
const tries = new Map();   // best-effort limiter (per server instance)
const limit = (q, s, n) => {
  const now = Date.now(), a = (tries.get(q.ip) || []).filter(t => now - t < 60000);
  if (a.length >= 8) return s.status(429).json({ error: 'Too many attempts. Please wait a minute.' });
  a.push(now); tries.set(q.ip, a); n();
};
async function startSession(s, uid) {
  const token = crypto.randomBytes(32).toString('hex'), maxAge = 30 * 864e5;
  await db('INSERT INTO sessions VALUES($1,$2,$3)', [sha(token), uid, Date.now() + maxAge]);
  db('DELETE FROM sessions WHERE expires<$1', [Date.now()]).catch(() => {});
  s.cookie('sid', token, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge });
}

const app = express();
app.disable('x-powered-by'); app.set('trust proxy', 1);
app.use(express.json({ limit: '4mb' }));
app.use((q, s, n) => { s.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }); n(); });
app.get('/api/health', ah(async (q, s) => {
  if (!DB_URL) return s.status(503).json({ database: 'not configured', hint: 'DATABASE_URL is missing' });
  try { await init(); await db('SELECT 1'); s.json({ database: 'connected' }); }
  catch (e) { s.status(503).json({ database: 'error', hint: e.code || 'could not connect' }); }
}));
app.use('/api', (q, s, n) => {
  if (!DB_URL) return s.status(503).json({ error: 'The database is not connected yet. Add a Postgres database to this project (DATABASE_URL) and redeploy.' });
  init().then(() => n(), n);
});

app.get('/api/status', ah(async (q, s) => s.json({ setup: (await userCount()) === 0, signup: SIGNUP })));
app.post('/api/register', limit, ah(async (q, s) => {
  const { username, password } = q.body || {};
  if ((await userCount()) > 0 && !SIGNUP) return s.status(403).json({ error: 'Sign-ups are closed.' });
  if (!/^[\w.@-]{3,40}$/.test(username || '')) return s.status(400).json({ error: 'Username must be 3–40 letters, numbers or . _ - @' });
  if (typeof password !== 'string' || password.length < 8) return s.status(400).json({ error: 'Password must be at least 8 characters.' });
  const salt = crypto.randomBytes(16).toString('hex');
  try {
    const r = await db('INSERT INTO users(username,salt,hash,created) VALUES($1,$2,$3,$4) RETURNING id', [username.toLowerCase(), salt, hashPw(password, salt), Date.now()]);
    await startSession(s, r.rows[0].id); s.json({ ok: true });
  } catch (e) { if (e.code === '23505') return s.status(409).json({ error: 'That username is already taken.' }); throw e; }
}));
app.post('/api/login', limit, ah(async (q, s) => {
  const { username, password } = q.body || {};
  const u = (await db('SELECT * FROM users WHERE username=$1', [String(username || '').toLowerCase()])).rows[0];
  const ok = u && crypto.timingSafeEqual(Buffer.from(hashPw(String(password || ''), u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
  if (!ok) return s.status(401).json({ error: 'Incorrect username or password.' });
  await startSession(s, u.id); s.json({ ok: true });
}));
app.post('/api/logout', ah(async (q, s) => { const t = sid(q); if (t) await db('DELETE FROM sessions WHERE token=$1', [sha(t)]); s.clearCookie('sid'); s.json({ ok: true }); }));
app.get('/api/me', auth, ah(async (q, s) => s.json({ username: (await db('SELECT username FROM users WHERE id=$1', [q.uid])).rows[0].username })));
app.post('/api/password', auth, ah(async (q, s) => {
  const { current, next } = q.body || {};
  const u = (await db('SELECT * FROM users WHERE id=$1', [q.uid])).rows[0];
  if (hashPw(String(current || ''), u.salt) !== u.hash) return s.status(403).json({ error: 'Current password is incorrect.' });
  if (typeof next !== 'string' || next.length < 8) return s.status(400).json({ error: 'New password must be at least 8 characters.' });
  const salt = crypto.randomBytes(16).toString('hex');
  await db('UPDATE users SET salt=$1, hash=$2 WHERE id=$3', [salt, hashPw(next, salt), q.uid]);
  s.json({ ok: true });
}));
app.get('/api/data', auth, ah(async (q, s) => {
  const r = (await db('SELECT json, ver FROM data WHERE user_id=$1', [q.uid])).rows[0];
  s.json(r ? { data: JSON.parse(r.json), ver: r.ver } : { data: null, ver: 0 });
}));
app.put('/api/data', auth, ah(async (q, s) => {
  const { data, ver } = q.body || {};
  if (!data || !Array.isArray(data.companies)) return s.status(400).json({ error: 'Invalid data' });
  const v = ver | 0, json = JSON.stringify(data), now = Date.now();
  let r = v === 0 ? await db('INSERT INTO data(user_id,json,ver,updated) VALUES($1,$2,1,$3) ON CONFLICT DO NOTHING RETURNING ver', [q.uid, json, now]) : null;
  if (!r || !r.rowCount) r = await db('UPDATE data SET json=$1, ver=ver+1, updated=$2 WHERE user_id=$3 AND ver=$4 RETURNING ver', [json, now, q.uid, v]);
  if (!r.rowCount) { const c = (await db('SELECT ver FROM data WHERE user_id=$1', [q.uid])).rows[0]; return s.status(409).json({ error: 'conflict', ver: c ? c.ver : 0 }); }
  s.json({ ver: r.rows[0].ver });
}));

const pub = path.join(__dirname, 'public');
app.get(['/', '/index.html'], ah(async (q, s) => (await uidOf(q)) ? s.sendFile(path.join(pub, 'index.html')) : s.redirect('/login.html')));
app.use(express.static(pub, { index: false }));
app.use((e, q, s, n) => {
  if (e.status === 413) return s.status(413).json({ error: 'Data too large (try a smaller logo or signature).' });
  console.error(e);
  const dbErr = /ECONN|ENOTFOUND|ETIMEDOUT|28P01|3D000|SSL|self.signed|authentication/i.test((e.code || '') + ' ' + (e.message || ''));
  s.status(dbErr ? 503 : 500).json({ error: dbErr ? 'Cannot connect to the database. Check that DATABASE_URL is correct.' : 'Server error' });
});

if (require.main === module) app.listen(PORT, () => console.log('My Cloud Office running on port ' + PORT));
module.exports = app;
