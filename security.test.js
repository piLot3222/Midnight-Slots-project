'use strict';

// Автотесты безопасности. Запуск: npm test
// Каждый тест — это реальная атака на запущенный сервер (подмена роли, IDOR, CSRF, перебор паролей и т.д.).

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PASS = 'correct horse battery';

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function startServer(extraEnv = {}) {
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'slots-'));
  const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dir, ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('сервер не запустился')), 20000);
    child.stdout.on('data', (d) => {
      if (String(d).includes('Слушаю')) {
        clearTimeout(t);
        resolve();
      }
    });
    child.on('exit', (code) => reject(new Error('сервер завершился: ' + code)));
  });
  return {
    port,
    dir,
    stop: () => new Promise((r) => { child.once('exit', r); child.kill('SIGTERM'); }),
  };
}

function rawRequest(port, method, urlPath, headers, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: urlPath, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* не JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

class Client {
  constructor(port) {
    this.port = port;
    this.cookie = null;
    this.csrf = null;
    this.lastSetCookie = null;
  }

  async req(method, url, body, headers = {}) {
    const h = { ...headers };
    if (this.cookie) h.Cookie = this.cookie;
    let payload;
    if (body !== undefined) {
      if (!h['Content-Type']) h['Content-Type'] = 'application/json';
      payload = typeof body === 'string' ? body : JSON.stringify(body);
      h['Content-Length'] = Buffer.byteLength(payload);
    }
    const r = await rawRequest(this.port, method, url, h, payload);
    for (const c of r.headers['set-cookie'] || []) {
      this.lastSetCookie = c;
      this.cookie = /Max-Age=0/i.test(c) ? null : c.split(';')[0];
    }
    return r;
  }

  post(url, body, extra = {}) {
    const h = { ...extra };
    if (this.csrf && !('X-CSRF-Token' in h)) h['X-CSRF-Token'] = this.csrf;
    return this.req('POST', url, body === undefined ? {} : body, h);
  }

  async register(u, p = PASS) {
    const r = await this.req('POST', '/api/register', { username: u, password: p });
    if (r.status === 201) this.csrf = r.json.csrfToken;
    return r;
  }

  async login(u, p = PASS) {
    const r = await this.req('POST', '/api/login', { username: u, password: p });
    if (r.status === 200) this.csrf = r.json.csrfToken;
    return r;
  }

  me() {
    return this.req('GET', '/api/me');
  }
}

describe('Безопасность', () => {
  let srv;
  const ADMIN_PASS = 'AdminPassw0rd!!';

  before(async () => {
    srv = await startServer({
      SPIN_COOLDOWN_MS: '300',
      AUTH_RATE_MAX: '1000',
      ADMIN_USER: 'chief',
      ADMIN_PASSWORD: ADMIN_PASS,
    });
  });
  after(async () => { await srv.stop(); });

  it('неавторизованный пользователь не может играть и не видит чужих данных', async () => {
    const c = new Client(srv.port);
    assert.equal((await c.post('/api/spin')).status, 401);
    assert.equal((await c.me()).json.authenticated, false);
    assert.equal((await c.post('/api/admin/jackpot')).status, 401);
  });

  it('регистрация и вход работают; cookie сессии HttpOnly + SameSite=Strict', async () => {
    const c = new Client(srv.port);
    const r = await c.register('alice');
    assert.equal(r.status, 201);
    assert.equal(r.json.role, 'user');
    assert.equal(r.json.balance, 1000);
    assert.match(c.lastSetCookie, /HttpOnly/);
    assert.match(c.lastSetCookie, /SameSite=Strict/);
    const me = await c.me();
    assert.equal(me.json.username, 'alice');
  });

  it('mass assignment: нельзя зарегистрироваться админом или с чужим балансом', async () => {
    const c = new Client(srv.port);
    const r = await c.req('POST', '/api/register', {
      username: 'mallory', password: PASS, role: 'admin', balance: 999999, isAdmin: true,
    });
    assert.equal(r.status, 201);
    assert.equal(r.json.role, 'user');
    assert.equal(r.json.balance, 1000);
  });

  it('подмена роли/баланса «из консоли» невозможна: эти данные есть только на сервере', async () => {
    const c = new Client(srv.port);
    await c.register('eve');
    c.csrf = (await c.me()).json.csrfToken;
    for (const url of ['/api/admin/tokens', '/api/admin/jackpot']) {
      const r = await c.post(url, { delta: 2000, role: 'admin' }, { 'X-Role': 'admin' });
      assert.equal(r.status, 403, url);
    }
    // Обычный пользователь не может править баланс другого (IDOR/BOLA)
    const idor = await c.post('/api/admin/tokens', { delta: 2000, username: 'alice' });
    assert.equal(idor.status, 403);
    // /api/me всегда возвращает ТОЛЬКО свои данные, параметры в URL игнорируются
    const me = await c.req('GET', '/api/me?username=alice&id=1');
    assert.equal(me.json.username, 'eve');
  });

  it('CSRF: запрос без токена или с чужим токеном отклоняется', async () => {
    const c = new Client(srv.port);
    await c.register('carol');
    assert.equal((await c.req('POST', '/api/spin', {})).status, 403);
    assert.equal((await c.post('/api/spin', {}, { 'X-CSRF-Token': 'x'.repeat(43) })).status, 403);
    assert.equal((await c.post('/api/logout', {}, { 'X-CSRF-Token': '' })).status, 403);
  });

  it('кросс-сайтовые запросы отклоняются (Origin / Sec-Fetch-Site)', async () => {
    const c = new Client(srv.port);
    const bad1 = await c.req('POST', '/api/login', { username: 'carol', password: PASS }, { Origin: 'https://evil.example' });
    assert.equal(bad1.status, 403);
    const bad2 = await c.req('POST', '/api/login', { username: 'carol', password: PASS }, { 'Sec-Fetch-Site': 'cross-site' });
    assert.equal(bad2.status, 403);
    const bad3 = await c.req('POST', '/api/login', { username: 'carol', password: PASS }, { Origin: 'null' });
    assert.equal(bad3.status, 403);
    const ok = await c.req('POST', '/api/login', { username: 'carol', password: PASS }, { Origin: `http://127.0.0.1:${srv.port}` });
    assert.equal(ok.status, 200);
  });

  it('Content-Type и размер тела проверяются', async () => {
    const c = new Client(srv.port);
    const form = await c.req('POST', '/api/login', 'username=a&password=b', { 'Content-Type': 'application/x-www-form-urlencoded' });
    assert.equal(form.status, 415);
    const plain = await c.req('POST', '/api/login', '{"username":"a"}', { 'Content-Type': 'text/plain' });
    assert.equal(plain.status, 415);
    const broken = await c.req('POST', '/api/login', '{oops');
    assert.equal(broken.status, 400);
    const arr = await c.req('POST', '/api/login', '[1,2,3]');
    assert.equal(arr.status, 400);
    const huge = await c.req('POST', '/api/login', JSON.stringify({ username: 'a', password: 'x'.repeat(5000) }));
    assert.equal(huge.status, 413);
  });

  it('результат игры и баланс определяет сервер, а не клиент', async () => {
    const c = new Client(srv.port);
    await c.register('dave');
    // Клиент «присылает» невозможный результат и баланс — сервер обязан всё это проигнорировать.
    const r = await c.post('/api/spin', { balance: 999999, reels: [99, 99, 99], win: true, payout: 1e9 });
    assert.equal(r.status, 200);
    assert.equal(r.json.reels.length, 3);
    for (const n of r.json.reels) assert.ok(Number.isInteger(n) && n >= 1 && n <= 7);
    const win = r.json.reels.every((x) => x === r.json.reels[0]);
    assert.equal(r.json.win, win);
    assert.equal(r.json.balance, 1000 - 10 + (win ? 500 : 0));
    assert.equal((await c.me()).json.balance, r.json.balance);
  });

  it('гонка: 20 параллельных спинов дают ровно одно списание', async () => {
    const c = new Client(srv.port);
    await c.register('racer');
    const results = await Promise.all(Array.from({ length: 20 }, () => c.post('/api/spin')));
    const okCount = results.filter((r) => r.status === 200).length;
    const limited = results.filter((r) => r.status === 429).length;
    assert.equal(okCount, 1);
    assert.equal(limited, 19);
    const win = results.find((r) => r.status === 200).json.win;
    assert.equal((await c.me()).json.balance, 1000 - 10 + (win ? 500 : 0));
  });

  it('при нулевом балансе играть нельзя', async () => {
    const c = new Client(srv.port);
    await c.register('broke');
    const adm = new Client(srv.port);
    await adm.login('chief', ADMIN_PASS);
    const drain = await adm.post('/api/admin/tokens', { delta: -1000, username: 'broke' });
    assert.equal(drain.json.target.balance, 0);
    const r = await c.post('/api/spin');
    assert.equal(r.status, 402);
    assert.equal((await c.me()).json.balance, 0); // баланс не ушёл в минус
  });

  it('админ: права проверяются на сервере, ввод валидируется', async () => {
    const adm = new Client(srv.port);
    const login = await adm.login('chief', ADMIN_PASS);
    assert.equal(login.status, 200);
    assert.equal(login.json.role, 'admin');

    const plus = await adm.post('/api/admin/tokens', { delta: 2000 });
    assert.equal(plus.status, 200);
    assert.equal(plus.json.balance, 3000);

    for (const bad of [0, 1.5, '2000', 1e9, -1e9, null, [], {}]) {
      const r = await adm.post('/api/admin/tokens', { delta: bad });
      assert.equal(r.status, 400, 'delta=' + JSON.stringify(bad));
    }
    const other = await adm.post('/api/admin/tokens', { delta: 100, username: 'alice' });
    assert.equal(other.status, 200);
    assert.equal(other.json.target.balance, 1100);
    assert.equal((await adm.post('/api/admin/tokens', { delta: 1, username: 'nobody123' })).status, 404);
    assert.equal((await adm.post('/api/admin/tokens', { delta: -10000, username: 'alice' })).status, 400); // ниже нуля нельзя
    assert.equal((await adm.post('/api/admin/tokens', { delta: 1, username: '<script>' })).status, 400);

    const jp = await adm.post('/api/admin/jackpot');
    assert.deepEqual(jp.json.reels, [7, 7, 7]);
    assert.equal(jp.json.balance, 3500);
  });

  it('имена: XSS-строки, «двойники» и зарезервированные имена отклоняются', async () => {
    const c = new Client(srv.port);
    for (const name of ['<script>alert(1)</script>', 'аdmin', 'Admin', 'ADMIN', 'chief', 'CHIEF', 'root', 'a', 'x'.repeat(21), 'bob smith', "bob'--", '']) {
      const r = await c.register(name);
      assert.ok(r.status === 400, `имя ${JSON.stringify(name)} → ${r.status}`);
    }
    assert.equal((await c.register('alice')).status, 409); // занято
    assert.equal((await c.register('ALICE')).status, 409); // регистр не важен
  });

  it('слабые пароли отклоняются', async () => {
    const c = new Client(srv.port);
    assert.equal((await c.register('weak1', 'short')).status, 400);
    assert.equal((await c.register('weak2', 'password123')).status, 400);
    assert.equal((await c.register('weak3', 'myweak3password')).status, 400); // содержит имя
    assert.equal((await c.register('weak4', 'x'.repeat(129))).status, 400);
    assert.equal((await c.req('POST', '/api/register', { username: 'weak5', password: 12345678901234 })).status, 400);
    assert.equal((await c.req('POST', '/api/register', { username: ['a'], password: PASS })).status, 400);
  });

  it('пароли хранятся только как scrypt-хэш, файл доступен лишь владельцу', async () => {
    const c = new Client(srv.port);
    const secret = 'Zx9!unique-secret-passphrase';
    await c.register('stored1', secret);
    await sleep(700); // запись на диск отложена на 300 мс
    const file = path.join(srv.dir, 'users.json');
    const raw = fs.readFileSync(file, 'utf8');
    assert.ok(!raw.includes(secret), 'пароль не должен храниться открытым текстом');
    const rec = JSON.parse(raw).find((u) => u.username === 'stored1');
    assert.ok(rec.pass.hash && rec.pass.salt && rec.pass.N >= 2 ** 14);
    if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  });

  it('вход: одинаковый ответ для неизвестного пользователя и неверного пароля', async () => {
    const c = new Client(srv.port);
    const a = await c.login('alice', 'wrong-password-123');
    const b = await c.login('no_such_user', 'wrong-password-123');
    assert.equal(a.status, 401);
    assert.equal(b.status, 401);
    assert.equal(a.json.error, b.json.error);
  });

  it('перебор пароля: после 5 ошибок аккаунт блокируется, даже верный пароль не пускает', async () => {
    const reg = new Client(srv.port);
    await reg.register('victim');
    const c = new Client(srv.port);
    for (let i = 0; i < 5; i++) assert.equal((await c.login('victim', 'bad-guess-' + i + '-xx')).status, 401);
    const locked = await c.login('victim', PASS);
    assert.equal(locked.status, 429);
    assert.ok(Number(locked.headers['retry-after']) > 0);
  });

  it('сессия: ротация при входе, logout уничтожает сессию на сервере', async () => {
    const c = new Client(srv.port);
    await c.login('alice');
    const first = c.cookie;
    const stolen = new Client(srv.port);
    stolen.cookie = first;
    assert.equal((await stolen.me()).json.authenticated, true);

    await c.login('alice'); // повторный вход → новый идентификатор, старый недействителен
    assert.notEqual(c.cookie, first);
    assert.equal((await stolen.me()).json.authenticated, false);

    const before = c.cookie;
    assert.equal((await c.post('/api/logout')).status, 200);
    const replay = new Client(srv.port);
    replay.cookie = before;
    assert.equal((await replay.me()).json.authenticated, false);
    assert.equal((await replay.post('/api/spin')).status, 401);
  });

  it('поддельные/мусорные cookie не дают доступа', async () => {
    for (const cookie of ['sid=abc', 'sid=' + 'A'.repeat(500), 'sid=; sid=', 'sid=../../etc/passwd']) {
      const r = await rawRequest(srv.port, 'GET', '/api/me', { Cookie: cookie });
      assert.equal(r.status, 200);
      assert.equal(r.json.authenticated, false);
    }
  });

  it('заголовки безопасности на месте, строгий CSP без inline', async () => {
    const r = await rawRequest(srv.port, 'GET', '/', {});
    assert.equal(r.status, 200);
    const csp = r.headers['content-security-policy'];
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /default-src 'none'/);
    assert.ok(!csp.includes('unsafe-inline') && !csp.includes('unsafe-eval'));
    assert.equal(r.headers['x-content-type-options'], 'nosniff');
    assert.equal(r.headers['x-frame-options'], 'DENY');
    assert.equal(r.headers['referrer-policy'], 'no-referrer');
    assert.equal(r.headers['x-powered-by'], undefined);
    const api = await rawRequest(srv.port, 'GET', '/api/me', {});
    assert.equal(api.headers['cache-control'], 'no-store');
    // На странице нет inline-скриптов и inline-стилей/обработчиков
    assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(r.text), 'inline <script>');
    assert.ok(!/\son\w+\s*=/i.test(r.text), 'inline-обработчики');
    assert.ok(!/\sstyle\s*=/i.test(r.text), 'inline style');
  });

  it('обход каталогов и утечка файлов исключены', async () => {
    for (const p of ['/../server.js', '/%2e%2e/server.js', '/..%2fserver.js', '/server.js', '/package.json', '/.env', '/data/users.json', '/data/audit.log', '/test/security.test.js', '/public/app.js', '//etc/passwd', '/%00', '/app.js/../server.js']) {
      const r = await rawRequest(srv.port, 'GET', p, {});
      assert.ok(r.status === 404 || r.status === 400, `${p} → ${r.status}`);
      assert.ok(!r.text.includes('crypto.timingSafeEqual') && !r.text.includes('"pass"'), `${p} утекло содержимое`);
    }
  });

  it('методы: лишние запрещены', async () => {
    assert.equal((await rawRequest(srv.port, 'PUT', '/api/spin', {})).status, 405);
    assert.equal((await rawRequest(srv.port, 'DELETE', '/api/me', {})).status, 405);
    assert.equal((await rawRequest(srv.port, 'GET', '/api/spin', {})).status, 404);
    assert.equal((await rawRequest(srv.port, 'POST', '/', {})).status, 405);
    assert.equal((await rawRequest(srv.port, 'TRACE', '/', {})).status, 405);
  });

  it('ошибки не раскрывают внутренности', async () => {
    const c = new Client(srv.port);
    const r = await c.req('POST', '/api/login', '{"username":{"$ne":""},"password":{"$ne":""}}');
    assert.ok([400, 401].includes(r.status));
    assert.ok(!/at .*\.js|node_modules|Error:/.test(r.text));
  });

  it('аудит-лог ведётся, пароли в него не попадают', async () => {
    await sleep(200);
    const log = fs.readFileSync(path.join(srv.dir, 'audit.log'), 'utf8');
    assert.match(log, /"event":"login_failed"/);
    assert.match(log, /"event":"lockout"/);
    assert.match(log, /"event":"admin_denied"/);
    assert.match(log, /"event":"admin_tokens"/);
    assert.ok(!log.includes(PASS) && !log.includes(ADMIN_PASS));
  });
});

describe('Ограничение частоты запросов (rate limit)', () => {
  let srv;
  before(async () => { srv = await startServer({ AUTH_RATE_MAX: '5' }); });
  after(async () => { await srv.stop(); });

  it('после 5 попыток входа с одного IP приходит 429', async () => {
    const c = new Client(srv.port);
    const codes = [];
    for (let i = 0; i < 7; i++) codes.push((await c.login('nobody', 'wrong-password-' + i)).status);
    assert.deepEqual(codes.slice(0, 5), [401, 401, 401, 401, 401]);
    assert.deepEqual(codes.slice(5), [429, 429]);
  });
});

describe('Проверка Host и режим без админа', () => {
  let srv;
  before(async () => { srv = await startServer({ ALLOWED_HOSTS: 'slots.example.test' }); });
  after(async () => { await srv.stop(); });

  it('запрос с чужим Host отклоняется (421), с разрешённым — проходит', async () => {
    assert.equal((await rawRequest(srv.port, 'GET', '/', { Host: 'evil.example' })).status, 421);
    assert.equal((await rawRequest(srv.port, 'GET', '/', { Host: 'slots.example.test' })).status, 200);
  });

  it('без ADMIN_PASSWORD админа не существует, имя admin занять нельзя', async () => {
    const c = new Client(srv.port);
    const h = { Host: 'slots.example.test' };
    const r = await c.req('POST', '/api/register', { username: 'admin', password: PASS }, h);
    assert.equal(r.status, 400);
    const l = await c.req('POST', '/api/login', { username: 'admin', password: PASS }, h);
    assert.equal(l.status, 401);
  });
});
