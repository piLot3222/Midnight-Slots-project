'use strict';

// Клиент ничего не решает сам: он только отправляет действия на сервер и показывает ответ.
// Весь вывод — через textContent (никакого innerHTML), поэтому XSS через имя пользователя невозможен.
(() => {
  const $ = (id) => document.getElementById(id);
  const page = location.pathname.slice(1) || 'machine';
  document.body.dataset.page = ['machine', 'leaderboard', 'profile', 'controller'].includes(page) ? page : 'machine';
  document.querySelectorAll('.category-card').forEach((link) => {
    const active = link.getAttribute('href') === `/${document.body.dataset.page}`;
    link.classList.toggle('category-active', active && link.classList.contains('category-card'));
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  const cherryField = document.querySelector('.cherry-field');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const cherryCount = 18;
  for (let i = 0; i < cherryCount; i += 1) {
    const cherry = document.createElement('span');
    const duration = 22 + Math.random() * 8;
    cherry.className = 'falling-cherry';
    cherry.style.setProperty('--left', `${(i + .15 + Math.random() * .7) * 100 / cherryCount}%`);
    cherry.style.setProperty('--size', `${26 + Math.random() * 14}px`);
    cherry.style.setProperty('--duration', `${duration}s`);
    cherry.style.setProperty('--delay', `${-duration * ((i * 7 % cherryCount + Math.random() * .4) / cherryCount)}s`);
    cherry.style.setProperty('--rotation', Math.random() < .5 ? '360deg' : '-360deg');
    cherryField.append(cherry);
  }
  const flames = document.querySelector('.win-flames');
  for (let i = 0; i < 180; i += 1) {
    const flame = document.createElement('i');
    flame.className = `win-ember ember-tone-${1 + Math.floor(Math.random() * 4)}`;
    flame.style.setProperty('--ember-left', `${Math.random() * 99}%`);
    flame.style.setProperty('--ember-start', `${Math.random() * 8}vh`);
    flame.style.setProperty('--ember-height', `${25 + Math.random() * 30}vh`);
    flame.style.setProperty('--ember-size', `${7 + Math.random() * 9}px`);
    flame.style.setProperty('--ember-drift', `${-34 + Math.random() * 68}px`);
    flame.style.setProperty('--ember-life', `${1.1 + Math.random() * 1.3}s`);
    flame.style.setProperty('--ember-delay', `${-Math.random() * 2}s`);
    flames.append(flame);
  }
  let winTimer;
  function celebrateWin() {
    if (reducedMotion.matches) return;
    clearTimeout(winTimer);
    document.body.classList.remove('celebrating');
    void document.body.offsetWidth;
    document.body.classList.add('celebrating');
    winTimer = setTimeout(() => document.body.classList.remove('celebrating'), 3000);
  }

  const pixelField = document.querySelector('.pixel-break');
  if (pixelField) {
    const cols = Math.max(20, Math.floor(window.innerWidth / 16));
    const rows = Math.max(10, Math.min(15, Math.floor(Math.min(270, Math.max(180, window.innerWidth * 0.22)) / 18)));
    pixelField.replaceChildren();
    for (let row = 0; row < rows; row += 1) {
      const depth = Math.min(1, row / Math.max(1, rows - 3));
      const fillChance = Math.min(1, 0.025 + depth ** 3 * 1.15);
      for (let col = 0; col < cols; col += 1) {
        const pixel = document.createElement('i');
        if (Math.random() > fillChance) {
          pixel.className = 'pixel-void';
        } else {
          pixel.className = `pixel-wine-${1 + Math.floor(Math.random() * 4)} pixel-blink-${1 + Math.floor(Math.random() * 8)}`;
        }
        pixelField.append(pixel);
      }
    }
    for (let index = 0; index < 48; index += 1) {
      const ember = document.createElement('i');
      const tone = 1 + Math.floor(Math.random() * 4);
      const randomBetween = (min, max) => min + Math.random() * (max - min);
      ember.className = `pixel-ember ember-tone-${tone}`;
      ember.style.setProperty('--ember-left', `${randomBetween(0, 99)}%`);
      ember.style.setProperty('--ember-start', `${randomBetween(0, 44)}px`);
      ember.style.setProperty('--ember-life', `${randomBetween(2.4, 6.8)}s`);
      ember.style.setProperty('--ember-delay', `${-randomBetween(0, 6.8)}s`);
      ember.style.setProperty('--ember-height', `${randomBetween(70, 190)}px`);
      ember.style.setProperty('--ember-size', `${randomBetween(6, 15)}px`);
      ember.style.setProperty('--ember-drift', `${randomBetween(-34, 34)}px`);
      ember.style.setProperty('--ember-brightness', randomBetween(0.65, 1.45));
      pixelField.append(ember);
    }
  }

  const el = {
    form: $('login-form'),
    user: $('user-input'),
    pass: $('pass-input'),
    loginBtn: $('login-btn'),
    registerBtn: $('register-btn'),
    logoutBtn: $('logout-btn'),
    sessionInfo: $('session-info'),
    sessionName: $('session-username'),
    sessionRole: $('session-role'),
    avatarLetter: $('avatar-letter'),
    balance: $('account-balance'),
    leaderboard: $('leaderboard'),
    spin: $('action-btn'),
    spinCost: $('spin-cost'),
    status: $('status-msg'),
    admin: $('debug-zone'),
    admPlus: $('adm-plus'),
    admMinus: $('adm-minus'),
    admJackpot: $('adm-jackpot'),
    admNextJackpot: $('adm-next-jackpot'),
    slots: [$('s1'), $('s2'), $('s3')],
    serialConnect: $('serial-connect-btn'),
    serialStatus: $('serial-status'),
  };

  const MIN_ANIMATION_MS = 1200;
  let state = { user: null, csrf: null };
  let busy = false;
  let pendingHardwareSpin = false;
  let serialWriter = null;

  function setStatus(text, isError) {
    el.status.textContent = text || '';
    el.status.classList.toggle('error', Boolean(isError));
  }

  async function api(method, url, body) {
    const headers = {};
    if (method !== 'GET') headers['Content-Type'] = 'application/json';
    if (state.csrf) headers['X-CSRF-Token'] = state.csrf;

    let res;
    try {
      res = await fetch(url, {
        method,
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        body: method === 'GET' ? undefined : JSON.stringify(body || {}),
      });
    } catch {
      throw new Error('Нет связи с сервером');
    }

    let data = null;
    try {
      data = await res.json();
    } catch {
      // Пустой или не-JSON ответ.
    }

    if (!res.ok) {
      const err = new Error((data && data.error) || `Ошибка ${res.status}`);
      err.status = res.status;
      throw err;
    }

    return data;
  }

  function applyState(data) {
    if (data && data.authenticated) {
      state = { user: data, csrf: data.csrfToken };
    } else {
      state = { user: null, csrf: null };
    }

    render();
    if (!state.user && page !== 'profile') {
      location.replace(`/profile?next=${encodeURIComponent(document.body.dataset.page)}`);
    } else if (state.user && page === 'profile') {
      const nextPage = new URLSearchParams(location.search).get('next');
      if (['machine', 'leaderboard', 'controller'].includes(nextPage)) {
        location.replace('/' + nextPage);
      }
    }
  }

  function render() {
    const u = state.user;
    document.body.dataset.auth = u ? 'yes' : 'no';

    el.form.hidden = Boolean(u);
    el.sessionInfo.hidden = !u;
    el.admin.hidden = !(u && u.role === 'admin' && document.body.dataset.page === 'machine');
    el.balance.textContent = u ? String(u.balance) : '—';
    el.spinCost.textContent = u ? `−${u.spinCost}` : '−10';
    el.spin.disabled = !u || busy;
    el.spin.textContent = u
      ? `Запустить цикл (-${u.spinCost})`
      : 'Войдите в аккаунт';

    if (u) {
      el.sessionName.textContent = u.username;
      el.avatarLetter.textContent = u.username.charAt(0).toUpperCase();
      const admin = u.role === 'admin';
      el.sessionRole.textContent = admin ? 'ADMIN' : 'USER';
      el.sessionRole.className =
        'role-indicator ' + (admin ? 'role-admin' : 'role-user');
    }
  }

  function showReels(reels, jackpot) {
    el.slots.forEach((slot, index) => {
      slot.textContent = String(reels[index]);
      slot.classList.toggle('jackpot-active', Boolean(jackpot));
    });
  }

  function handleError(err) {
    if (err.status === 401 && state.user) {
      applyState(null);
      setStatus('Сессия истекла. Войдите снова.', true);
      return;
    }

    setStatus(err.message, true);
  }

  async function authenticate(path) {
    const username = el.user.value.trim();
    const password = el.pass.value;

    if (!username || !password) {
      return setStatus('Введите имя и пароль', true);
    }

    el.loginBtn.disabled = true;
    el.registerBtn.disabled = true;

    try {
      applyState(await api('POST', path, { username, password }));
      el.pass.value = '';
      setStatus('');
    } catch (err) {
      setStatus(err.message, true);
    } finally {
      el.loginBtn.disabled = false;
      el.registerBtn.disabled = false;
    }
  }

  async function spin() {
    if (busy || !state.user) return;

    busy = true;
    el.spin.disabled = true;
    setStatus('');
    el.slots.forEach((slot) => slot.classList.remove('jackpot-active'));

    // Анимация для показа; настоящий результат приходит с сервера.
    const startedAt = Date.now();
    const timer = setInterval(() => {
      el.slots.forEach((slot) => {
        slot.textContent = String(1 + Math.floor(Math.random() * 7));
      });
    }, 80);

    let result = null;
    let error = null;

    try {
      result = await api('POST', '/api/spin');
    } catch (err) {
      error = err;
    }

    const rest = MIN_ANIMATION_MS - (Date.now() - startedAt);
    if (rest > 0) {
      await new Promise((resolve) => setTimeout(resolve, rest));
    }

    clearInterval(timer);
    busy = false;

    if (error) {
      handleError(error);
      render();
      return;
    }

    showReels(result.reels, result.win);
    if (result.win) celebrateWin();
    if (serialWriter) {
      const command = result.win ? 'WIN\n' : 'LOSE\n';
      serialWriter.write(new TextEncoder().encode(command)).catch(() => {});
    }
    state.user.balance = result.balance;
    setStatus(
      result.win
        ? `Успешное совпадение! (+${result.payout})`
        : 'Попробуйте еще раз!'
    );
    render();
    loadLeaderboard();

    if (pendingHardwareSpin) {
      pendingHardwareSpin = false;
      setTimeout(spin, 350);
    }
  }

  async function loadLeaderboard() {
    try {
      const result = await api('GET', '/api/leaderboard');
      if (!result.leaderboard.length) {
        el.leaderboard.textContent = 'Пока здесь тихо. Станьте первым игроком.';
        return;
      }
      el.leaderboard.textContent = '';
      result.leaderboard.forEach((player) => {
        const row = document.createElement('div');
        row.className = 'leader-row';
        const rank = document.createElement('span');
        rank.className = 'leader-rank';
        rank.textContent = String(player.rank).padStart(2, '0');
        const name = document.createElement('span');
        name.textContent = player.username;
        const coins = document.createElement('span');
        coins.className = 'leader-coins';
        coins.textContent = `${player.balance} ◈`;
        row.append(rank, name, coins);
        el.leaderboard.append(row);
      });
    } catch {
      el.leaderboard.textContent = 'Рейтинг временно недоступен';
    }
  }

  async function adminTokens(delta) {
    try {
      const result = await api('POST', '/api/admin/tokens', { delta });
      state.user.balance = result.balance;
      setStatus(`Баланс изменён на ${delta > 0 ? '+' : ''}${delta}`);
      render();
    } catch (err) {
      handleError(err);
    }
  }

  async function adminJackpot() {
    try {
      const result = await api('POST', '/api/admin/jackpot');
      showReels(result.reels, true);
      state.user.balance = result.balance;
      setStatus('Trigger Event: Принудительный джекпот');
      render();
    } catch (err) {
      handleError(err);
    }
  }

  async function armNextJackpot() {
    try {
      await api('POST', '/api/admin/next-jackpot');
      setStatus('Следующая прокрутка гарантированно выигрышная');
    } catch (err) {
      handleError(err);
    }
  }

  el.form.addEventListener('submit', (event) => {
    event.preventDefault();
    authenticate('/api/login');
  });

  el.registerBtn.addEventListener('click', () => {
    authenticate('/api/register');
  });

  el.logoutBtn.addEventListener('click', async () => {
    try {
      await api('POST', '/api/logout');
    } catch {
      // Сессия уже недействительна.
    }

    applyState(null);
    setStatus('');
  });

  el.spin.addEventListener('click', spin);

  el.serialConnect.addEventListener('click', async () => {
    if (!('serial' in navigator)) {
      el.serialStatus.textContent =
        'Web Serial недоступен. Откройте localhost в Chrome или Edge.';
      return;
    }

    el.serialConnect.disabled = true;

    try {
      const port = await navigator.serial.requestPort();
      await port.open({ baudRate: 115200 });
      serialWriter = port.writable.getWriter();

      el.serialStatus.textContent =
        'ESP32 подключена — нажмите кнопку на плате';

      const decoder = new TextDecoderStream();
      const pipeClosed = port.readable.pipeTo(decoder.writable);
      const reader = decoder.readable.getReader();
      let pending = '';

      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;

          pending += value;
          const lines = pending.split(/\r?\n/);
          pending = lines.pop();

          for (const line of lines) {
            if (line.trim() === 'SPIN') {
              if (!state.user) {
                setStatus('Сначала войдите в аккаунт.', true);
              } else if (busy) {
                // Не теряем нажатие платы, если предыдущая анимация ещё идёт.
                pendingHardwareSpin = true;
              } else {
                spin();
              }
            }
          }
        }
      } finally {
        reader.releaseLock();
        if (serialWriter) {
          serialWriter.releaseLock();
          serialWriter = null;
        }
        await pipeClosed.catch(() => {});
        await port.close().catch(() => {});
      }
    } catch (err) {
      el.serialStatus.textContent =
        'Не удалось подключить ESP32: ' + err.message;
    } finally {
      el.serialConnect.disabled = false;
    }
  });

  el.admPlus.addEventListener('click', () => adminTokens(2000));
  el.admMinus.addEventListener('click', () => adminTokens(-2000));
  el.admJackpot.addEventListener('click', adminJackpot);
  el.admNextJackpot.addEventListener('click', armNextJackpot);

  api('GET', '/api/me')
    .then(applyState)
    .catch(() => render());
  loadLeaderboard();
})();
