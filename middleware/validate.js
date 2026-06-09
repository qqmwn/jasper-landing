function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateSignup(req, res, next) {
  const { name, email, password } = req.body || {};

  if (!name || typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 100) {
    return res.status(400).json({ error: '姓名不能为空且不超过100个字符' });
  }
  if (!email || typeof email !== 'string' || !EMAIL_RE.test(email.trim())) {
    return res.status(400).json({ error: '请输入有效的邮箱地址' });
  }
  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: '密码至少需要8个字符' });
  }
  if (password.length > 128) {
    return res.status(400).json({ error: '密码不能超过128个字符' });
  }
  if (/^\d+$/.test(password) || /^[a-zA-Z]+$/.test(password)) {
    return res.status(400).json({ error: '密码不能为纯数字或纯字母' });
  }

  req.body.name = sanitize(name.trim());
  req.body.email = email.trim().toLowerCase();
  next();
}

function validateSignin(req, res, next) {
  const { email, password } = req.body || {};

  if (!email || typeof email !== 'string' || !EMAIL_RE.test(email.trim())) {
    return res.status(400).json({ error: '请输入有效的邮箱地址' });
  }
  if (!password || typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ error: '请输入密码' });
  }

  req.body.email = email.trim().toLowerCase();
  next();
}

module.exports = { validateSignup, validateSignin, sanitize };
