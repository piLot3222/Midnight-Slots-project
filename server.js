'use strict';

/**
 * Secure Slots — сервер без внешних зависимостей (только встроенные модули Node.js).
 *
 * Главный принцип: клиенту не доверяем ничего. Личность, роль, баланс и результат
 * игры определяются только на сервере. Браузер лишь показывает то, что вернул сервер.
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);
const env = process.env;

// ───────────────────────── Конфигурация ─────────────────────────

const PROD = env.NODE_ENV === 'production';
const PORT = Number(env.PORT) || 3000;
// По умолчанию слушаем только localhost: наружу сервис выставляется через reverse proxy с HTTPS.
const HOST = env.HOST || '127.0.0.1';
// Сколько доверенных прокси стоит перед сервером (нужно для корректного IP в rate limit).
const TRUST_PROXY_HOPS = Math.max(0, Number(env.TRUST_PROXY_HOPS) || 0);
// Белый список Host-заголовков, например: "slots.example.com". Пусто = не проверять.
const ALLOWED_HOSTS = (env.ALLOWED_HOSTS || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const DATA_DIR = env.DATA_DIR ? path.resolve(env.DATA_DIR) : path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.log');
const PUBLIC_DIR = path.join(__dirname, 'public');

const CFG = {
  startBalance: 1000,
  spinCost: 10,
  jackpotPayout: 500,
  symbols: 7,
  reels: 3,
  spinCooldownMs: Number(env.SPIN_COOLDOWN_MS) || 1500,
  sessionIdleMs: 30 * 60_000,
  sessionMaxMs: 8 * 3_600_000,
  maxSessionsPerUser: 5,
  adminMaxDelta: 10_000,
  maxUsers: Number(env.MAX_USERS) || 10_000,
  maxBodyBytes: 2048,
  apiRatePerMin: Number(env.API_RATE_PER_MIN) || 120,
};

const SCRYPT_PARAMS = { N: 2 ** 15, r: 8, p: 3, keylen: 64 }; // рекомендации OWASP для scrypt
const COOKIE_NAME = PROD ? '__Host-sid' : 'sid';
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/; // только ASCII: защита от «двойников» имени (кириллическая «а» и т.п.)
const RESERVED_NAMES = new Set(['admin', 'administrator', 'root', 'system', 'moderator', 'support']);
const COMMON_PASSWORDS = new Set([
  'password12', 'password123', '1234567890', '12345678910', 'qwertyuiop', 'qwerty12345',
  'passw0rd123', 'iloveyou123', 'admin12345', 'letmein1234',
]);

// ───────────────────────── Утилиты ─────────────────────────

class HttpError extends Error {
  constructor(status, message, headers) {
    super(message);
    this.status = status;
    this.headers = headers || {};
  }
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

function makeLimiter(windowMs, max) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
  }, Math.min(windowMs, 60_000)).unref();
  // Возвращает 0, если запрос разрешён, иначе — через сколько секунд повторить.
  return (key) => {
    const now = Date.now();
    if (hits.size > 100_000) hits.clear(); // защита памяти от флуда уникальными ключами
    let h = hits.get(key);
    if (!h || h.resetAt <= now) {
      h = { count: 0, resetAt: now + windowMs };
      hits.set(key, h);
    }
    h.count += 1;
    return h.count <= max ? 0 : Math.max(1, Math.ceil((h.resetAt - now) / 1000));
  };
}

const apiLimiter = makeLimiter(60_000, CFG.apiRatePerMin);

function clientIp(req) {
  const direct = req.socket.remoteAddress || 'unknown';
  if (!TRUST_PROXY_HOPS) return direct;
  const parts = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const idx = parts.length - TRUST_PROXY_HOPS; // берём запись, добавленную ближайшим доверенным прокси
  return idx >= 0 ? parts[idx] : direct;
}

// ───────────────────────── Хранилище пользователей ─────────────────────────

/** key (имя в нижнем регистре) -> { username, role, pass, balance, createdAt, failed, lockedUntil, lastSpinAt } */
const users = new Map();
let saveTimer = null;

function loadUsers() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(USERS_FILE)) return;
  const list = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  for (const u of list) users.set(String(u.username).toLowerCase(), u);
}

function flushUsers() {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  const tmp = USERS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify([...users.values()]), { mode: 0o600 });
  fs.renameSync(tmp, USERS_FILE); // атомарная замена: файл не повредится при сбое
}

function scheduleSave() {
  if (!saveTimer) saveTimer = setTimeout(flushUsers, 300);
}

function audit(event, ip, details) {
  const line = JSON.stringify({ ts: new Date().toISOString(), event, ip, ...details }) + '\n';
  fs.appendFile(AUDIT_FILE, line, { mode: 0o600 }, () => {});
}

// ───────────────────────── Пароли ─────────────────────────

let hashingInFlight = 0;
let DUMMY_PASS = null;

async function derive(password, rec) {
  return scrypt(password, Buffer.from(rec.salt, 'base64'), rec.keylen, {
    N: rec.N,
    r: rec.r,
    p: rec.p,
    maxmem: 128 * rec.N * rec.r * 2,
  });
}

async function hashPassword(password) {
  if (hashingInFlight >= 16) throw new HttpError(503, 'Сервер занят, попробуйте чуть позже');
  hashingInFlight += 1;
  try {
    const rec = { ...SCRYPT_PARAMS, salt: crypto.randomBytes(16).toString('base64') };
    rec.hash = (await derive(password, rec)).toString('base64');
    return rec;
  } finally {
    hashingInFlight -= 1;
  }
}

async function verifyPassword(password, rec) {
  if (hashingInFlight >= 16) throw new HttpError(503, 'Сервер занят, попробуйте чуть позже');
  hashingInFlight += 1;
  try {
    const got = await derive(password, rec);
    const want = Buffer.from(rec.hash, 'base64');
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  } finally {
    hashingInFlight -= 1;
  }
}

function validateUsername(u) {
  if (typeof u !== 'string' || !USERNAME_RE.test(u)) {
    throw new HttpError(400, 'Имя: 3–20 символов, только латиница, цифры и _');
  }
  return u;
}

function validatePasswordShape(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > 128 || Buffer.byteLength(p) > 512) {
    throw new HttpError(400, 'Некорректный пароль');
  }
  return p;
}

function validateNewPassword(p, username) {
  validatePasswordShape(p);
  if (p.length < 10) throw new HttpError(400, 'Пароль должен быть не короче 10 символов');
  if (COMMON_PASSWORDS.has(p.toLowerCase()) || p.toLowerCase().includes(username.toLowerCase())) {
    throw new HttpError(400, 'Слишком простой пароль');
  }
  return p;
}

// ───────────────────────── Сессии ─────────────────────────

/** sha256(sessionId) -> { userKey, csrf, createdAt, lastSeen }. В памяти хранится только хэш идентификатора. */
const sessions = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) {
    if (now - s.lastSeen > CFG.sessionIdleMs || now - s.createdAt > CFG.sessionMaxMs) sessions.delete(k);
  }
}, 60_000).unref();

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function cookieHeader(value, maxAgeSec) {
  return [
    `${COOKIE_NAME}=${value}`,
    'HttpOnly', // недоступна из JavaScript → XSS не украдёт сессию
    'SameSite=Strict', // не отправляется с чужих сайтов → базовая защита от CSRF
    'Path=/',
    `Max-Age=${maxAgeSec}`,
    ...(PROD ? ['Secure'] : []),
  ].join('; ');
}

function startSession(req, res, userKey) {
  // Ротация: старая сессия (если была) уничтожается — защита от session fixation.
  const old = readCookie(req, COOKIE_NAME);
  if (old) sessions.delete(sha256(old));

  // Не больше N одновременных сессий на пользователя: вытесняем самые старые.
  const mine = [...sessions.entries()].filter(([, s]) => s.userKey === userKey);
  mine.sort((a, b) => a[1].createdAt - b[1].createdAt);
  while (mine.length >= CFG.maxSessionsPerUser) sessions.delete(mine.shift()[0]);

  const sid = randomToken(32);
  const now = Date.now();
  const session = { userKey, csrf: randomToken(32), createdAt: now, lastSeen: now };
  sessions.set(sha256(sid), session);
  res.setHeader('Set-Cookie', cookieHeader(sid, Math.floor(CFG.sessionMaxMs / 1000)));
  return session;
}

function loadSession(req) {
  const sid = readCookie(req, COOKIE_NAME);
  if (!sid || sid.length > 100) return;
  const key = sha256(sid);
  const s = sessions.get(key);
  if (!s) return;
  const now = Date.now();
  const user = users.get(s.userKey);
  if (!user || now - s.lastSeen > CFG.sessionIdleMs || now - s.createdAt > CFG.sessionMaxMs) {
    sessions.delete(key);
    return;
  }
  s.lastSeen = now;
  req.session = s;
  req.sessionKey = key;
  req.user = user;
}

// ───────────────────────── Ответы и проверки запросов ─────────────────────────

function setSecurityHeaders(res) {
  const csp = [
    "default-src 'none'",
    "script-src 'self'", // никакого inline-кода: XSS почти не имеет шансов выполниться
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    ...(PROD ? ['upgrade-insecure-requests'] : []),
  ].join('; ');
  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  if (PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

function send(res, status, body, headers) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': payload.length,
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(payload);
}

function checkSameOrigin(req) {
  const origin = req.headers.origin;
  if (origin) {
    let host;
    try {
      host = new URL(origin).host.toLowerCase();
    } catch {
      throw new HttpError(403, 'Запрещено');
    }
    if (host !== String(req.headers.host || '').toLowerCase()) throw new HttpError(403, 'Запрещено');
    return;
  }
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') throw new HttpError(403, 'Запрещено');
}

function requireCsrf(req) {
  const token = req.headers['x-csrf-token'];
  if (typeof token !== 'string' || !safeEqual(token, req.session.csrf)) {
    throw new HttpError(403, 'Неверный CSRF-токен');
  }
}

function requireAuth(req) {
  if (!req.user) throw new HttpError(401, 'Требуется вход');
}

function requireAdmin(req) {
  // Роль берётся ТОЛЬКО из серверной записи пользователя, а не из запроса.
  if (req.user.role !== 'admin') {
    audit('admin_denied', req.ip, { username: req.user.username, path: req.url });
    throw new HttpError(403, 'Недостаточно прав');
  }
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/json') return reject(new HttpError(415, 'Ожидается application/json'));
    let size = 0;
    let tooBig = false;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > CFG.maxBodyBytes) {
        tooBig = true;
        chunks.length = 0;
        return;
      }
      if (!tooBig) chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) return reject(new HttpError(413, 'Слишком большой запрос', { Connection: 'close' }));
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('shape');
        resolve(v);
      } catch {
        reject(new HttpError(400, 'Некорректный JSON'));
      }
    });
    req.on('error', reject);
  });
}

function publicState(user, session) {
  return {
    authenticated: true,
    username: user.username,
    role: user.role,
    balance: user.balance,
    csrfToken: session.csrf,
    spinCost: CFG.spinCost,
    jackpotPayout: CFG.jackpotPayout,
  };
}

// ───────────────────────── API ─────────────────────────

async function handleApi(req, res, pathname) {
  const wait = apiLimiter(req.ip);
  if (wait) throw new HttpError(429, 'Слишком много запросов', { 'Retry-After': String(wait) });

  loadSession(req);
  const route = `${req.method} ${pathname}`;

  if (req.method === 'GET') {
    if (route === 'GET /api/me') {
      if (!req.user) return send(res, 200, { authenticated: false });
      return send(res, 200, publicState(req.user, req.session));
    }
    if (route === 'GET /api/leaderboard') {
      const leaderboard = [...users.values()]
        .filter((user) => user.role !== 'admin')
        .sort((a, b) => b.balance - a.balance || a.username.localeCompare(b.username))
        .slice(0, 10)
        .map((user, index) => ({ rank: index + 1, username: user.username, balance: user.balance }));
      return send(res, 200, { leaderboard });
    }
    throw new HttpError(404, 'Не найдено');
  }

  if (req.method !== 'POST') throw new HttpError(405, 'Метод не поддерживается', { Allow: 'GET, POST' });

  // Для всех POST: тот же origin + JSON (кросс-сайтовая форма не сможет отправить application/json без preflight).
  checkSameOrigin(req);
  const body = await readJson(req);

  switch (route) {
    case 'POST /api/register': {
      const username = validateUsername(body.username);
      validateNewPassword(body.password, username);
      const key = username.toLowerCase();
      if (RESERVED_NAMES.has(key) || key === ADMIN_KEY) throw new HttpError(400, 'Это имя зарезервировано');
      if (users.size >= CFG.maxUsers) throw new HttpError(503, 'Регистрация временно закрыта');
      if (users.has(key)) throw new HttpError(409, 'Имя уже занято');

      const pass = await hashPassword(body.password);
      if (users.has(key)) throw new HttpError(409, 'Имя уже занято'); // повторная проверка после await (гонка)
      const user = {
        username,
        role: 'user', // роль всегда 'user'; поля из тела запроса игнорируются
        pass,
        balance: CFG.startBalance,
        createdAt: Date.now(),
        failed: 0,
        lockedUntil: 0,
        lastSpinAt: 0,
      };
      users.set(key, user);
      scheduleSave();
      audit('register', req.ip, { username });
      const session = startSession(req, res, key);
      return send(res, 201, publicState(user, session));
    }

    case 'POST /api/login': {
      const username = typeof body.username === 'string' ? body.username : '';
      const password = validatePasswordShape(body.password);
      const key = username.toLowerCase();
      const user = USERNAME_RE.test(username) ? users.get(key) : undefined;
      // Всегда считаем хэш, даже если пользователя нет, чтобы не раскрывать существование аккаунта.
      const ok = await verifyPassword(password, user ? user.pass : DUMMY_PASS);

      if (!user || !ok) {
        audit('login_failed', req.ip, { username: USERNAME_RE.test(username) ? username : '(invalid)' });
        throw new HttpError(401, 'Неверное имя или пароль');
      }
      scheduleSave();
      audit('login', req.ip, { username: user.username });
      const session = startSession(req, res, key);
      return send(res, 200, publicState(user, session));
    }

    case 'POST /api/logout': {
      requireAuth(req);
      requireCsrf(req);
      sessions.delete(req.sessionKey);
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
    }

    case 'POST /api/spin': {
      requireAuth(req);
      requireCsrf(req);
      const user = req.user;
      const now = Date.now();
      // Проверка и списание выполняются синхронно, без await между ними → гонки (двойное списание/трата) невозможны.
      const since = now - user.lastSpinAt;
      if (since < CFG.spinCooldownMs) {
        const retry = Math.ceil((CFG.spinCooldownMs - since) / 1000);
        throw new HttpError(429, 'Слишком быстро', { 'Retry-After': String(retry) });
      }
      if (user.balance < CFG.spinCost) throw new HttpError(402, 'Недостаточно токенов');
      user.lastSpinAt = now;
      user.balance -= CFG.spinCost;

      // Результат определяет сервер криптографическим ГСЧ (в оригинале — Math.random на клиенте).
      const guaranteed = forceNextJackpot;
      forceNextJackpot = false;
      const reels = guaranteed
        ? Array(CFG.reels).fill(CFG.symbols)
        : Array.from({ length: CFG.reels }, () => crypto.randomInt(1, CFG.symbols + 1));
      const win = guaranteed || reels.every((r) => r === reels[0]);
      if (win) user.balance += CFG.jackpotPayout;
      scheduleSave();
      return send(res, 200, { reels, win, payout: win ? CFG.jackpotPayout : 0, balance: user.balance });
    }

    case 'POST /api/admin/tokens': {
      requireAuth(req);
      requireCsrf(req);
      requireAdmin(req);
      const delta = body.delta;
      if (!Number.isInteger(delta) || delta === 0 || Math.abs(delta) > CFG.adminMaxDelta) {
        throw new HttpError(400, `delta: целое число, не равное 0, по модулю не больше ${CFG.adminMaxDelta}`);
      }
      let target = req.user;
      if (body.username !== undefined) {
        const name = validateUsername(body.username);
        target = users.get(name.toLowerCase());
        if (!target) throw new HttpError(404, 'Пользователь не найден');
      }
      if (target.balance + delta < 0) throw new HttpError(400, 'Баланс не может стать отрицательным');
      target.balance += delta;
      scheduleSave();
      audit('admin_tokens', req.ip, { admin: req.user.username, target: target.username, delta });
      return send(res, 200, { balance: req.user.balance, target: { username: target.username, balance: target.balance } });
    }

    case 'POST /api/admin/next-jackpot': {
      requireAuth(req);
      requireCsrf(req);
      requireAdmin(req);
      forceNextJackpot = true;
      return send(res, 200, { armed: true });
    }

    case 'POST /api/admin/jackpot': {
      requireAuth(req);
      requireCsrf(req);
      requireAdmin(req);
      req.user.balance += CFG.jackpotPayout;
      scheduleSave();
      audit('admin_jackpot', req.ip, { admin: req.user.username });
      return send(res, 200, {
        reels: Array(CFG.reels).fill(CFG.symbols),
        win: true,
        payout: CFG.jackpotPayout,
        balance: req.user.balance,
      });
    }

    default:
      throw new HttpError(404, 'Не найдено');
  }
}

// ───────────────────────── Статика (только белый список файлов из памяти) ─────────────────────────

const STATIC = new Map();
for (const [route, file, type] of [
  ['/', 'index.html', 'text/html; charset=utf-8'],
  ['/index.html', 'index.html', 'text/html; charset=utf-8'],
  ['/logo.png', 'logo.png', 'image/png'],
  ['/favicon.png', 'favicon.png', 'image/png'],
  ['/machine', 'index.html', 'text/html; charset=utf-8'],
  ['/leaderboard', 'index.html', 'text/html; charset=utf-8'],
  ['/profile', 'index.html', 'text/html; charset=utf-8'],
  ['/controller', 'index.html', 'text/html; charset=utf-8'],
  ['/style.css', 'style.css', 'text/css; charset=utf-8'],
  ['/app.js', 'app.js', 'text/javascript; charset=utf-8'],
]) {
  STATIC.set(route, { body: fs.readFileSync(path.join(PUBLIC_DIR, file)), type });
}

function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Метод не поддерживается', { Allow: 'GET, HEAD' });
  const file = STATIC.get(pathname); // только точное совпадение: обход каталогов (../) невозможен по построению
  if (!file) throw new HttpError(404, 'Не найдено');
  res.writeHead(200, {
    'Content-Type': file.type,
    'Content-Length': file.body.length,
    'Cache-Control': 'no-cache',
  });
  res.end(req.method === 'HEAD' ? undefined : file.body);
}

// ───────────────────────── Сервер ─────────────────────────

async function handle(req, res) {
  setSecurityHeaders(res);
  req.ip = clientIp(req);

  try {
    const host = String(req.headers.host || '').toLowerCase();
    if (ALLOWED_HOSTS.length && !ALLOWED_HOSTS.includes(host)) throw new HttpError(421, 'Неверный хост');

    let pathname;
    try {
      pathname = new URL(req.url, 'http://localhost').pathname;
    } catch {
      throw new HttpError(400, 'Некорректный URL');
    }

    if (pathname.startsWith('/api/')) await handleApi(req, res, pathname);
    else serveStatic(req, res, pathname);
  } catch (err) {
    if (err instanceof HttpError) {
      if (!res.headersSent) {
        if (req.url.startsWith('/api/')) return send(res, err.status, { error: err.message }, err.headers);
        res.writeHead(err.status, { 'Content-Type': 'text/plain; charset=utf-8', ...err.headers });
        return res.end(err.message);
      }
      return;
    }
    console.error('Необработанная ошибка:', err); // подробности — только в лог, клиенту — общий ответ
    if (!res.headersSent) send(res, 500, { error: 'Внутренняя ошибка сервера' });
  }
}

let ADMIN_KEY = null;
let forceNextJackpot = false;

async function bootstrapAdmin() {
  const name = env.ADMIN_USER || 'admin';
  validateUsername(name);
  ADMIN_KEY = name.toLowerCase();

  const existing = users.get(ADMIN_KEY);
  if (existing && existing.role !== 'admin') {
    throw new Error(`Пользователь "${name}" уже существует как обычный аккаунт — выберите другой ADMIN_USER`);
  }

  const password = randomToken(18);
  const pass = await hashPassword(password);
  if (existing) {
    existing.pass = pass;
  } else {
    users.set(ADMIN_KEY, {
      username: name, role: 'admin', pass, balance: CFG.startBalance,
      createdAt: Date.now(), failed: 0, lockedUntil: 0, lastSpinAt: 0,
    });
  }
  flushUsers();
  console.log(`Администратор "${name}" настроен. Новый пароль: ${password}`);
}

async function main() {
  loadUsers();
  DUMMY_PASS = await hashPassword(randomToken(16));
  await bootstrapAdmin();

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      console.error(e);
      if (!res.headersSent) res.writeHead(500).end();
    });
  });
  server.requestTimeout = 10_000; // защита от slowloris
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  server.on('clientError', (_err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  const shutdown = () => {
    try { flushUsers(); } catch (e) { console.error(e); }
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  server.listen(PORT, HOST, () => {
    console.log(`Слушаю http://${HOST}:${PORT} (${PROD ? 'production' : 'development'})`);
  });
}

main().catch((e) => {
  console.error('Не удалось запустить сервер:', e.message);
  process.exit(1);
});
