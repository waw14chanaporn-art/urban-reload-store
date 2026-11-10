const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const fs = require('fs');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'store.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT_please_64_chars_minimum',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false, message: { error: 'ลองใหม่ภายหลังนะ' } });
const getUser = id => db.prepare('SELECT id, username, created_at FROM users WHERE id = ?').get(id);
const requireAuth = (req, res, next) => req.session.userId ? next() : res.status(401).json({ error: 'กรุณาเข้าสู่ระบบก่อน' });

app.post('/api/register', authLimiter, async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'ชื่อผู้ใช้ต้องยาว 3–20 ตัว ใช้ A-Z, 0-9 หรือ _ เท่านั้น' });
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'รหัสผ่านต้องมี 8–72 ตัวอักษร' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'สร้างเซสชันไม่สำเร็จ ลองอีกครั้ง' });
      req.session.userId = Number(result.lastInsertRowid);
      req.session.save(err2 => err2 ? res.status(500).json({ error: 'เข้าสู่ระบบไม่สำเร็จ' }) : res.json({ user: getUser(req.session.userId) }));
    });
  } catch (err) {
    if (String(err.code).includes('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'ชื่อผู้ใช้นี้ถูกใช้แล้ว' });
    console.error(err); res.status(500).json({ error: 'เกิดข้อผิดพลาด กรุณาลองใหม่' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE').get(username);
  const valid = user ? await bcrypt.compare(password, user.password_hash) : false;
  if (!valid) return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'เข้าสู่ระบบไม่สำเร็จ' });
    req.session.userId = user.id;
    req.session.save(err2 => err2 ? res.status(500).json({ error: 'เข้าสู่ระบบไม่สำเร็จ' }) : res.json({ user: getUser(user.id) }));
  });
});
app.get('/api/me', (req, res) => res.json({ user: req.session.userId ? getUser(req.session.userId) : null }));
app.post('/api/logout', requireAuth, (req, res) => req.session.destroy(() => { res.clearCookie('connect.sid'); res.json({ ok: true }); }));
app.get('/api/orders', requireAuth, (req, res) => res.json({ message: 'ส่งข้อความหาแอดมินเพื่อสั่งซื้อได้เลย', products: [{ name: '5M', price: 60 }, { name: '10M', price: 120 }, { name: '15M', price: 160 }] }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`URBAN RELOAD STORE listening on ${PORT}`));
