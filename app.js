const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?'.split('');

function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

async function sha512(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-512', buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function deriveKey(hashHex, saltHex) {
  const hashBuf = hexToBytes(hashHex);
  const saltBuf = hexToBytes(saltHex);
  const material = await crypto.subtle.importKey('raw', hashBuf, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBuf, iterations: 250000, hash: 'SHA-512' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
}

async function derivePasswordBytes(seedBytes, info, length) {
  const key = await crypto.subtle.importKey('raw', seedBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: new TextEncoder().encode(info) },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

function mapBytesToPassword(bytes) {
  return Array.from(bytes).map(b => CHARSET[b % CHARSET.length]).join('');
}

function openDB() {
  return new Promise((res, rej) => {
    const req = indexedDB.open('pwdManagerDB', 1);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      const store = db.createObjectStore('sites', { keyPath: 'id', autoIncrement: true });
      store.createIndex('by_domain', 'domain', { unique: false });
    };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

async function deleteSite(id) {
  return new Promise((res, rej) => {
    const tx = db.transaction('sites', 'readwrite');
    tx.objectStore('sites').delete(id);
    tx.oncomplete = res;
    tx.onerror = () => rej(tx.error);
  });
}

async function loadSites() {
  return new Promise((res, rej) => {
    const tx = db.transaction('sites', 'readonly');
    const req = tx.objectStore('sites').getAll();
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
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

let passHash, salt, db, cryptoKey;

document.getElementById('btn-login').addEventListener('click', async () => {
  const pass = document.getElementById('passphrase').value;
  const user = document.getElementById('username').value.trim();
  if (!pass || !user) return;
  passHash = await sha512(pass);
  const saltKey = 'pwdManager_salt_' + user;
  let stored = localStorage.getItem(saltKey);
  if (!stored) {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    stored = Array.from(buf).map(b => b.toString(16).padStart(2,'0')).join('');
    localStorage.setItem(saltKey, stored);
  }
  salt = stored;
  document.getElementById('passphrase').value = '';
  document.getElementById('login-screen').hidden = true;
  document.getElementById('app').hidden = false;
  cryptoKey = await deriveKey(passHash, salt);
  db = await openDB();
  renderList(await loadSites());
});

document.getElementById('add-button').addEventListener('click', async () => {
  const site = await promptSite();
  if (site) {
    await saveSite(site);
    renderList(await loadSites());
  }
});

async function saveSite(site) {
  return new Promise((res, rej) => {
    const tx = db.transaction('sites', 'readwrite');
    const store = tx.objectStore('sites');
    const record = { domain: site.domain, login: site.login, version: site.version };
    if (typeof site.id === 'number') store.put({ id: site.id, ...record });
    else store.add(record);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

async function renderList(records) {
  const ul = document.getElementById('site-list');
  ul.textContent = '';
  for (const r of records) {
    const seedHex = await sha512(passHash + salt + r.domain + (r.login||'') + (r.version||''));
    const seedBytes = hexToBytes(seedHex);
    const info = r.domain + (r.login||'') + (r.version||'');
    const pwdBytes = await derivePasswordBytes(seedBytes, info, 20);
    const pwd = mapBytesToPassword(pwdBytes);
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
    btnCopy.addEventListener('click', () => {
      navigator.clipboard.writeText(pwd).then(() => {
        setTimeout(() => {
          navigator.clipboard.writeText('');
        }, 30000);
      });
    });
    const btnEdit = document.createElement('button');
    btnEdit.className = 'edit';
    btnEdit.textContent = 'Edit';
    btnEdit.addEventListener('click', async () => {
      const updated = await promptSite(r);
      if (updated) {
        updated.id = r.id;
        await saveSite(updated);
        renderList(await loadSites());
      }
    });
    const btnDelete = document.createElement('button');
    btnDelete.className = 'delete';
    btnDelete.textContent = 'Delete';
    btnDelete.addEventListener('click', async () => {
      await deleteSite(r.id);
      renderList(await loadSites());
    });
    actions.append(btnCopy, btnEdit, btnDelete);
    li.appendChild(actions);
    ul.appendChild(li);
  }
}

document.getElementById('reset-db-link').addEventListener('click', async e => {
  e.preventDefault();
  if (!confirm('Are you sure you want to reset all your data ?')) return;
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase('pwdManagerDB');
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
    req.onblocked = () => {/* bloqué */};
  });
  localStorage.clear();
  location.reload();
});

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js');
}
