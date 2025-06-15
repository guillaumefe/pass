(() => {
  const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?'.split('');
  const INACTIVITY_LIMIT = 1.5 * 60 * 1000;
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

  function createWorker() {
    const workerCode = `
importScripts('https://cdn.jsdelivr.net/npm/argon2-browser/dist/argon2-browser.min.js');
const CHARSET = ${JSON.stringify(CHARSET)};
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
self.onmessage = async function(e) {
  const { type, masterPass, user, pin, info, length } = e.data;
  if (!self.isSecureContext) return;
  if (type === 'derive') {
    const saltHex = pin ? await sha512(masterPass + pin) : await sha512(masterPass + user);
    const saltBytes = hexToBytes(saltHex);
    const { hash: derived } = await argon2.hash({
      pass: masterPass,
      salt: saltBytes,
      type: argon2.ArgonType.Argon2id,
      hashLen: 64,
      time: 3,
      mem: 65536
    });
    self.postMessage({ type: 'derived', derived });
  } else if (type === 'generate') {
    const saltHex = pin ? await sha512(masterPass + pin) : await sha512(masterPass + user);
    const saltBytes = hexToBytes(saltHex);
    const infoBytes = new TextEncoder().encode(info);
    const combinedSalt = new Uint8Array(saltBytes.length + infoBytes.length);
    combinedSalt.set(saltBytes, 0);
    combinedSalt.set(infoBytes, saltBytes.length);
    const { hash: derived } = await argon2.hash({
      pass: masterPass,
      salt: combinedSalt,
      type: argon2.ArgonType.Argon2id,
      hashLen: 64,
      time: 3,
      mem: 65536
    });
    const seedBytes = hexToBytes(derived);
    const key = await crypto.subtle.importKey('raw', seedBytes, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: combinedSalt, info: new TextEncoder().encode(info) },
      key,
      length * 8
    );
    const rawBytes = new Uint8Array(bits);
    const threshold = Math.floor(256 / CHARSET.length) * CHARSET.length;
    const pwdChars = [];
    for (const b of rawBytes) {
      if (b < threshold) {
        pwdChars.push(CHARSET[b % CHARSET.length]);
        if (pwdChars.length === length) break;
      }
    }
    const pwd = pwdChars.join('');
    try {
      await navigator.clipboard.writeText(pwd);
      setTimeout(() => navigator.clipboard.writeText(''), 20000);
    } catch {}
  }
};`;
    return new Worker(URL.createObjectURL(new Blob([workerCode], { type: 'application/javascript' })));
  }

  const pwdWorker = createWorker();

  async function deriveMasterKey(pass, user) {
    return new Promise((resolve, reject) => {
      const pin = document.getElementById('pin').value.trim();
      pwdWorker.onmessage = function(e) {
        if (e.data.type === 'derived') {
          resolve(e.data.derived);
        }
      };
      pwdWorker.postMessage({ type: 'derive', masterPass: pass, user, pin });
    });
  }

  async function openDB() {
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
      const info = r.domain + (r.login || '') + (r.version || '');
      const li = document.createElement('li');
      const spanDomain = document.createElement('span');
      spanDomain.className = 'domain';
      spanDomain.textContent = r.domain;
      li.appendChild(spanDomain);
      if (r.login) {
        const spanLogin = document.createElement('span');
        spanLogin.className = 'login';
        spanLogin.textContent = r.login;
        li.appendChild(spanLogin);
      }
      const actions = document.createElement('div');
      actions.className = 'actions';
      const btnCopy = document.createElement('button');
      btnCopy.className = 'copy';
      btnCopy.textContent = 'Copy';
      btnCopy.addEventListener('click', () => {
        if (!location.protocol.startsWith('https:') || !document.hasFocus() || document.visibilityState !== 'visible') return;
        const pin = document.getElementById('pin').value.trim();
        pwdWorker.postMessage({ type: 'generate', masterPass: masterKey, user: currentUser, pin, info, length: 20 });
      });
      const btnEdit = document.createElement('button');
      btnEdit.className = 'edit';
      btnEdit.textContent = 'Edit';
      btnEdit.addEventListener('click', async () => {
        const updated = await promptSite(r);
        if (updated) { await saveSite(updated); renderList(await loadSites()); }
      });
      const btnDelete = document.createElement('button');
      btnDelete.className = 'delete';
      btnDelete.textContent = 'Delete';
      btnDelete.addEventListener('click', async () => { await deleteSite(r.id); renderList(await loadSites()); });
      actions.append(btnCopy, btnEdit, btnDelete);
      li.appendChild(actions);
      ul.appendChild(li);
    }
  }

  async function saveSite(site) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sites', 'readwrite');
      const store = tx.objectStore('sites');
      const record = { domain: site.domain, login: site.login, version: site.version };
      if (typeof site.id === 'number') store.put({ id: site.id, ...record }); else store.add(record);
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
    if (ul) ul.textContent = '';
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
    masterKey = await deriveMasterKey(pass, user);
    currentUser = user;
    passElem.value = '';
    userElem.value = '';
    document.getElementById('login-screen').hidden = true;
    document.getElementById('app').hidden = false;
    db = await openDB();
    await renderList(await loadSites());
    document.getElementById('add-button').addEventListener('click', async () => {
      const site = await promptSite();
      if (site) { await saveSite(site); await renderList(await loadSites()); }
    });
    resetInactivityTimer();
  });

  document.getElementById('reset-db-link').addEventListener('click', async e => {
    e.preventDefault();
    if (!confirm('Are you sure you want to reset all your data?')) return;
    if (db) { db.close(); db = null; }
    await new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase('pwdManagerDB');
      req.onblocked = () => {};
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve();
    });
    localStorage.clear();
    if ('serviceWorker' in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map(r => r.unregister()));
    }
    window.location.reload();
  });

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
})();
