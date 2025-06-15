(() => {
  const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?'.split('');
  const INACTIVITY_LIMIT = 5 * 60 * 1000;
  let currentUser = null;
  let masterKey = null;
  let db = null;
  let inactivityTimeout;

  function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
  }

  async function sha512(str) {
    const buf = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest('SHA-512', buf);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function deriveMasterKey(pass, user) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(pass),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    const salt = enc.encode(user);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-512', salt: salt, iterations: 200000 },
      keyMaterial,
      512
    );
    return Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function derivePasswordBytes(seedBytes, info, length) {
    const key = await crypto.subtle.importKey('raw', seedBytes, 'HKDF', false, ['deriveBits']);
    const saltBuf = new TextEncoder().encode(currentUser);
    const infoBuf = new TextEncoder().encode(info);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: saltBuf, info: infoBuf },
      key,
      length * 8
    );
    return new Uint8Array(bits);
  }

  async function generatePassword(seedBytes, info, length) {
    const rawBytes = await derivePasswordBytes(seedBytes, info, length * 4);
    const threshold = Math.floor(256 / CHARSET.length) * CHARSET.length;
    const pwdChars = [];
    for (const b of rawBytes) {
      if (b < threshold) {
        pwdChars.push(CHARSET[b % CHARSET.length]);
        if (pwdChars.length === length) break;
      }
    }
    if (pwdChars.length < length) throw new Error('Not enough entropy to generate the password');
    return pwdChars.join('');
  }

  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('pwdManagerDB', 1);
      req.onupgradeneeded = e => {
        const database = e.target.result;
        const store = database.createObjectStore('sites', { keyPath: 'id', autoIncrement: true });
        store.createIndex('by_domain', 'domain', { unique: false });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function deleteSite(id) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sites', 'readwrite');
      tx.objectStore('sites').delete(id);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async function loadSites() {
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sites', 'readonly');
      const req = tx.objectStore('sites').getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(tx.error);
    });
  }

  function promptSite(existing) {
    return new Promise(res => {
      const modal = document.createElement('div');
      modal.className = 'modal';
      const box = document.createElement('div');
      box.className = 'modal-content';
      const title = document.createElement('h3');
      title.textContent = existing ? 'Edit Site' : 'Add Site';
      const form = document.createElement('form');
      const inputDomain = document.createElement('input');
      inputDomain.id = 'd';
      inputDomain.placeholder = 'Domain (e.g. example.com)';
      inputDomain.required = true;
      inputDomain.value = existing ? existing.domain : '';
      const inputLogin = document.createElement('input');
      inputLogin.id = 'l';
      inputLogin.placeholder = 'Login (optional)';
      inputLogin.value = existing && existing.login ? existing.login : '';
      const inputVersion = document.createElement('input');
      inputVersion.id = 'v';
      inputVersion.type = 'number';
      inputVersion.min = '1';
      inputVersion.placeholder = 'Version (optional)';
      inputVersion.value = existing && existing.version ? existing.version : '';
      const actions = document.createElement('div');
      actions.className = 'modal-actions';
      const btnCancel = document.createElement('button');
      btnCancel.type = 'button';
      btnCancel.textContent = 'Cancel';
      const btnOk = document.createElement('button');
      btnOk.type = 'submit';
      btnOk.textContent = 'OK';
      actions.append(btnCancel, btnOk);
      form.append(inputDomain, inputLogin, inputVersion, actions);
      box.append(title, form);
      modal.appendChild(box);
      document.body.appendChild(modal);
      btnCancel.addEventListener('click', () => {
        document.body.removeChild(modal);
        res(null);
      });
      form.addEventListener('submit', e => {
        e.preventDefault();
        const domain = inputDomain.value.trim();
        const login = inputLogin.value.trim() || null;
        const v = inputVersion.value.trim();
        const version = v ? parseInt(v, 10) : null;
        document.body.removeChild(modal);
        const result = { domain, login, version };
        if (existing && existing.id != null) result.id = existing.id;
        res(result);
      });
    });
  }

  async function renderList(records) {
    const ul = document.getElementById('site-list');
    ul.textContent = '';
    for (const r of records) {
      try {
        const seedHex = await sha512(masterKey + currentUser + r.domain + (r.login || '') + (r.version || ''));
        const seedBytes = hexToBytes(seedHex);
        const info = r.domain + (r.login || '') + (r.version || '');
        const pwd = await generatePassword(seedBytes, info, 20);
        const li = document.createElement('li');
        const spanDomain = document.createElement('span');
        spanDomain.className = 'domain';
        spanDomain.textContent = r.domain;
        li.appendChild(spanDomain);
        if (r.login) {
          const spanLogin = document.createElement('span');
          spanLogin.className = 'login';
          spanLogin.textContent = 'Login: ' + r.login;
          li.appendChild(spanLogin);
        }
        const spanPwd = document.createElement('span');
        spanPwd.className = 'pwd';
        spanPwd.textContent = pwd;
        li.appendChild(spanPwd);
        const actions = document.createElement('div');
        actions.className = 'actions';
        const btnCopy = document.createElement('button');
        btnCopy.className = 'copy';
        btnCopy.textContent = 'Copy';
        btnCopy.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(pwd);
            if ('Notification' in window) {
              if (Notification.permission === 'granted') {
                new Notification('Password copied', { body: 'It will be cleared from the clipboard in 20 seconds.' });
              } else if (Notification.permission !== 'denied') {
                try {
                  const permission = await Notification.requestPermission();
                  if (permission === 'granted') {
                    new Notification('Password copied', { body: 'It will be cleared from the clipboard in 20 seconds.' });
                  }
                } catch (e) {}
              }
            } else {
              alert('🔒 Password copied! It will be cleared from the clipboard in 20 seconds.');
            }
            setTimeout(async () => {
              try { await navigator.clipboard.writeText(''); } catch (e) {}
            }, 20000);
          } catch (e) {
            alert('Could not copy password: ' + e.message);
          }
        });
        const btnEdit = document.createElement('button');
        btnEdit.className = 'edit';
        btnEdit.textContent = 'Edit';
        btnEdit.addEventListener('click', async () => {
          try {
            const updated = await promptSite(r);
            if (updated) { await saveSite(updated); renderList(await loadSites()); }
          } catch (e) {}
        });
        const btnDelete = document.createElement('button');
        btnDelete.className = 'delete';
        btnDelete.textContent = 'Delete';
        btnDelete.addEventListener('click', async () => {
          try { await deleteSite(r.id); renderList(await loadSites()); } catch (e) {}
        });
        actions.append(btnCopy, btnEdit, btnDelete);
        li.appendChild(actions);
        ul.appendChild(li);
      } catch (e) {
        console.error('Error rendering site', r.id, e);
      }
    }
  }

  async function saveSite(site) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sites', 'readwrite');
      const store = tx.objectStore('sites');
      const record = { domain: site.domain, login: site.login, version: site.version };
      if (typeof site.id === 'number') {
        store.put({ id: site.id, ...record });
      } else {
        store.add(record);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  function lock() {
    if (db) { db.close(); db = null; }
    masterKey = null; currentUser = null;
    clearTimeout(inactivityTimeout);
    document.getElementById('app').hidden = true;
    document.getElementById('login-screen').hidden = false;
    const ul = document.getElementById('site-list');
    if (ul) { ul.textContent = ''; }
    alert('Session expired, please log in again.');
  }

  function resetInactivityTimer() {
    clearTimeout(inactivityTimeout);
    inactivityTimeout = setTimeout(lock, INACTIVITY_LIMIT);
  }

  document.addEventListener('click', resetInactivityTimer);
  document.addEventListener('keydown', resetInactivityTimer);

  document.getElementById('btn-login').addEventListener('click', async () => {
    const passElem = document.getElementById('passphrase');
    const userElem = document.getElementById('username');
    const pass = passElem.value;
    const user = userElem.value.trim();
    if (!pass || !user) return;
    try {
      masterKey = await deriveMasterKey(pass, user);
      currentUser = user;
      passElem.value = '';
      userElem.value = '';
      document.getElementById('login-screen').hidden = true;
      document.getElementById('app').hidden = false;
      db = await openDB();
      await renderList(await loadSites());
      document.getElementById('add-button').addEventListener('click', async () => {
        try {
          const site = await promptSite();
          if (site) { await saveSite(site); await renderList(await loadSites()); }
        } catch (e) { alert('Error adding site: ' + e.message); }
      });
      resetInactivityTimer();
    } catch (e) {
      alert('Login failed: ' + e.message);
    }
  });

  document.getElementById('reset-db-link').addEventListener('click', async e => {
    e.preventDefault();
    if (!confirm('Are you sure you want to reset all your data?')) return;
    try {
      if (db) { db.close(); db = null; }
      await new Promise((resolve, reject) => {
        const req = indexedDB.deleteDatabase('pwdManagerDB');
        req.onblocked = () => console.warn('Please close other tabs using the database.');
        req.onerror = () => reject(req.error);
        req.onsuccess = () => resolve();
      });
      localStorage.clear();
      if ('serviceWorker' in navigator) {
        const regs = await navigator.serviceWorker.getRegistrations();
        await Promise.all(regs.map(r => r.unregister()));
      }
      window.location.reload();
    } catch (e) {
      console.error('Database reset error', e);
      alert('Reset failed: ' + e.message);
    }
  });

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
})();
