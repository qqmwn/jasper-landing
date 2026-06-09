require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('rate-limiter-flexible').RateLimiterMemory;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { verifyToken, requireAdmin } = require('./middleware/auth');
const { validateSignup, validateSignin } = require('./middleware/validate');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@jasper.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123456';
const SALT_ROUNDS = 12;

const USERS_FILE = path.join(__dirname, 'users.json');
const CONTENT_FILE = path.join(__dirname, 'content.json');

// In-memory password reset tokens (token → { email, expires })
const resetTokens = {};

// ── Security middleware ──
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ── Rate limiter ──
const authLimiter = new rateLimit({ points: 20, duration: 60 });

async function rateLimitMiddleware(req, res, next) {
  try {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    await authLimiter.consume(ip);
    next();
  } catch {
    res.status(429).json({ error: '请求过于频繁，请稍后再试' });
  }
}

// ── Static files & 404 fallback ──
app.use(express.static(__dirname));
app.use((req, res, next) => {
  // Only intercept HTML requests that aren't API calls
  if (req.path.startsWith('/api/')) return next();
  if (req.method !== 'GET') return next();
  // If it looks like a page request without extension, serve 404.html
  if (!path.extname(req.path) && req.path !== '/') {
    res.status(404).sendFile(path.join(__dirname, '404.html'));
  } else {
    next();
  }
});

// ── User helpers ──
function readUsers() {
  try { const raw = fs.readFileSync(USERS_FILE, 'utf-8'); return JSON.parse(raw); }
  catch { return []; }
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function ensureAdmin() {
  const users = readUsers();
  if (!users.find(u => u.role === 'admin')) {
    users.push({
      id: 'admin-' + Date.now(), name: '管理员',
      email: ADMIN_EMAIL.toLowerCase(),
      password: bcrypt.hashSync(ADMIN_PASSWORD, SALT_ROUNDS),
      role: 'admin', createdAt: new Date().toISOString()
    });
    writeUsers(users);
    console.log('[init] 管理员账号已创建: ' + ADMIN_EMAIL);
  }
}

// ── Content helpers ──
function readContent() {
  return JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf-8'));
}
function writeContent(content) {
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(content, null, 2));
}

// ── Auth routes ──

app.post('/api/signup', rateLimitMiddleware, validateSignup, (req, res) => {
  const { name, email, password } = req.body;
  const users = readUsers();
  if (users.find(u => u.email === email)) {
    return res.status(409).json({ error: '该邮箱已被注册' });
  }
  const user = {
    id: 'u-' + Date.now(), name, email,
    password: bcrypt.hashSync(password, SALT_ROUNDS),
    role: 'user', createdAt: new Date().toISOString()
  };
  users.push(user); writeUsers(users);
  const token = jwt.sign({ userId: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/signin', rateLimitMiddleware, validateSignin, (req, res) => {
  const { email, password } = req.body;
  const users = readUsers();
  const user = users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: '邮箱或密码错误' });
  }
  const token = jwt.sign({ userId: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.get('/api/me', verifyToken, (req, res) => {
  res.json({ user: { id: req.user.userId, name: req.user.name, email: req.user.email, role: req.user.role } });
});

// ── Password reset routes ──

app.post('/api/forgot-password', rateLimitMiddleware, (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ error: '请输入邮箱地址' });
  const users = readUsers();
  const user = users.find(u => u.email === email);
  // Always return success to not leak whether email exists
  if (!user) return res.json({ ok: true, msg: '如果该邮箱已注册，重置链接已发送' });
  
  const token = crypto.randomBytes(32).toString('hex');
  resetTokens[token] = { email, expires: Date.now() + 30 * 60 * 1000 }; // 30 min
  console.log('[reset] 重置令牌: ' + token + ' (邮箱: ' + email + ')');
  res.json({ ok: true, token }); // In production, email the token; here we return it directly
});

app.post('/api/reset-password', rateLimitMiddleware, (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: '缺少参数' });
  if (password.length < 8) return res.status(400).json({ error: '密码至少需要8个字符' });
  if (password.length > 128) return res.status(400).json({ error: '密码不能超过128个字符' });
  if (/^\d+$/.test(password) || /^[a-zA-Z]+$/.test(password)) {
    return res.status(400).json({ error: '密码不能为纯数字或纯字母' });
  }
  
  const entry = resetTokens[token];
  if (!entry || entry.expires < Date.now()) {
    delete resetTokens[token];
    return res.status(400).json({ error: '重置链接已过期或无效' });
  }
  
  const users = readUsers();
  const user = users.find(u => u.email === entry.email);
  if (!user) {
    delete resetTokens[token];
    return res.status(404).json({ error: '用户不存在' });
  }
  
  user.password = bcrypt.hashSync(password, SALT_ROUNDS);
  writeUsers(users);
  delete resetTokens[token];
  res.json({ ok: true, msg: '密码已重置，请登录' });
});

// ── Profile routes ──

app.put('/api/me', verifyToken, (req, res) => {
  const { name } = req.body || {};
  if (!name || typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 100) {
    return res.status(400).json({ error: '姓名不能为空且不超过100个字符' });
  }
  const users = readUsers();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  user.name = name.trim();
  writeUsers(users);
  const token = jwt.sign({ userId: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.put('/api/me/password', verifyToken, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: '请填写当前密码和新密码' });
  if (newPassword.length < 8) return res.status(400).json({ error: '新密码至少需要8个字符' });
  if (newPassword.length > 128) return res.status(400).json({ error: '密码不能超过128个字符' });
  if (/^\d+$/.test(newPassword) || /^[a-zA-Z]+$/.test(newPassword)) {
    return res.status(400).json({ error: '新密码不能为纯数字或纯字母' });
  }
  
  const users = readUsers();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  if (!bcrypt.compareSync(currentPassword, user.password)) {
    return res.status(400).json({ error: '当前密码错误' });
  }
  user.password = bcrypt.hashSync(newPassword, SALT_ROUNDS);
  writeUsers(users);
  res.json({ ok: true, msg: '密码已修改' });
});

app.delete('/api/me', verifyToken, (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.user.userId);
  if (idx === -1) return res.status(404).json({ error: '用户不存在' });
  if (users[idx].role === 'admin') return res.status(403).json({ error: '管理员账号不能通过此方式删除' });
  users.splice(idx, 1);
  writeUsers(users);
  res.json({ ok: true, msg: '账号已删除' });
});

// ── Content routes ──

app.get('/api/content', (req, res) => res.json(readContent()));

app.put('/api/content', verifyToken, requireAdmin, (req, res) => {
  const { hero, features, pricing } = req.body || {};
  const content = readContent();
  if (hero) content.hero = hero;
  if (features) content.features = features;
  if (pricing) content.pricing = pricing;
  writeContent(content);
  res.json({ ok: true, content });
});

// ── Admin routes ──

app.get('/api/admin/stats', verifyToken, requireAdmin, (req, res) => {
  const users = readUsers();
  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  const weekAgo = new Date(now.getTime() - 7 * 86400000).toISOString();
  const total = users.length;
  const todayNew = users.filter(u => u.createdAt >= todayStart).length;
  const weekNew = users.filter(u => u.createdAt >= weekAgo).length;
  const admins = users.filter(u => u.role === 'admin').length;
  const dailyData = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 86400000);
    const ds = new Date(d.getFullYear(), d.getMonth(), d.getDate()).toISOString();
    const de = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1).toISOString();
    dailyData.push({ date: d.toISOString().slice(0, 10), count: users.filter(u => u.createdAt >= ds && u.createdAt < de).length });
  }
  res.json({ total, todayNew, weekNew, admins, regularUsers: total - admins, dailyData });
});

app.get('/api/admin/users', verifyToken, requireAdmin, (req, res) => {
  const users = readUsers();
  const search = (req.query.search || '').toLowerCase();
  const filtered = search ? users.filter(u => u.name.toLowerCase().includes(search) || u.email.toLowerCase().includes(search)) : users;
  res.json({ users: filtered.map(({ password, ...rest }) => rest) });
});

app.delete('/api/admin/users/:id', verifyToken, requireAdmin, (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: '用户不存在' });
  if (users[idx].role === 'admin' && users[idx].email === ADMIN_EMAIL.toLowerCase()) {
    return res.status(403).json({ error: '不能删除主管理员账号' });
  }
  const removed = users.splice(idx, 1)[0];
  writeUsers(users);
  res.json({ ok: true, removed: { id: removed.id, name: removed.name, email: removed.email } });
});

// ── Start ──
ensureAdmin();
app.listen(PORT, () => console.log('Server running at http://localhost:' + PORT));
