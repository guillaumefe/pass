(() => {
  const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?'.split('');
  const INACTIVITY_LIMIT = 5 * 60 * 1000; // 5 minutes

  let session = {
    user: null,
    passHash: null,
    db: null
  };
  let inactivityTimeout;

  // --- CRYPTO UTILITIES ---
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

  // HKDF with salt = username (session.user)
  async function derivePasswordBytes(seedBytes, info, length) {
    const key = await crypto.subtle.importKey(
      'raw', seedBytes, 'HKDF', false, ['deriveBits']
    );
    const saltBuf = new TextEncoder().encode(session.user);
    const infoBuf = new TextEncoder().encode(info);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: saltBuf, info: infoBuf },
      key,
      length * 8
    );
    return new Uint8Array(bits);
  }

  // Generates a 'length'-character password with rejection sampling
  async function generatePassword(seedBytes, info, length) {
    // Generate 4× more bytes to compensate for rejections
    const rawBytes = await derivePasswordBytes(seedBytes, info, length * 4);
    const threshold = Math.floor(256 / CHARSET.length) * CHARSET.length;
    const pwdChars = [];
    for (let b of rawBytes) {
      if (b < threshold) {
        pwdChars.push(CHARSET[b % CHARSET.length]);
        if (pwdChars.length === length) break;
      }
    }
    if (pwdChars.length < length) {
      throw new Error('Not enough entropy to generate the password');
    }
    return pwdChars.join('');
  }

  // --- INDEXEDDB DATABASE ---
  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('pwdManagerDB', 1);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        const store = db.createObjectStore('sites', { keyPath: 'id', autoIncrement: true });
        store.createIndex('by_domain', 'domain', { unique: false });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function deleteSite(id) {
    return new Promise((resolve, reject) => {
      const tx = session.db.transaction('sites', 'readwrite');
      tx.objectStore('sites').delete(id);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async function loadSites() {
    return new Promise((resolve, reject) => {
      const tx = session.db.transaction('sites', 'readonly');
      const req = tx.objectStore('sites').getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(tx.error);
    });
  }

  // --- MODAL INTERFACE FOR ADD/EDIT ---
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

  // --- LIST RENDERING ---
  async function renderList(records) {
    const ul = document.getElementById('site-list');
    ul.textContent = '';
    for (const r of records) {
      // derive seedHex with passHash + username + domain/login/version
      const seedHex = await sha512(
        session.passHash + session.user + r.domain + (r.login || '') + (r.version || '')
      );
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
      btnCopy.addEventListener('click', () => {
        navigator.clipboard.writeText(pwd).then(() => {
          // request permission if needed
          if ('Notification' in window) {
            if (Notification.permission === 'granted') {
              new Notification('Password copied', {
                body: 'It will be cleared from the clipboard in 20 seconds.'
              });
            } else if (Notification.permission !== 'denied') {
              Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                  new Notification('Password copied', {
                    body: 'It will be cleared from the clipboard in 20 seconds.'
                  });
                }
              });
            }
          } else {
            // fallback if Notification API is not available
            alert('🔒 Password copied! It will be cleared from the clipboard in 20 seconds.');
          }
          setTimeout(() => navigator.clipboard.writeText(''), 20000);
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

  // --- SAVE FUNCTION ---
  async function saveSite(site) {
    return new Promise((resolve, reject) => {
      const tx = session.db.transaction('sites', 'readwrite');
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

  // --- LOCK ON INACTIVITY ---
  function lock() {
    session.passHash = null;
    session.user = null;
    clearTimeout(inactivityTimeout);
    document.getElementById('app').hidden = true;
    document.getElementById('login-screen').hidden = false;
    alert('Session expired, please log in again.');
  }

  function resetInactivityTimer() {
    clearTimeout(inactivityTimeout);
    inactivityTimeout = setTimeout(lock, INACTIVITY_LIMIT);
  }

  document.addEventListener('click', resetInactivityTimer);
  document.addEventListener('keydown', resetInactivityTimer);

  // --- LOGIN HANDLING ---
  document.getElementById('btn-login').addEventListener('click', async () => {
    const pass = document.getElementById('passphrase').value;
    const user = document.getElementById('username').value.trim();
    if (!pass || !user) return;

    session.user = user;
    session.passHash = await sha512(pass);

    document.getElementById('passphrase').value = '';
    document.getElementById('login-screen').hidden = true;
    document.getElementById('app').hidden = false;

    session.db = await openDB();
    await renderList(await loadSites());
    document.getElementById('add-button').addEventListener('click', async () => {
      // open the modal to create a new site
      const site = await promptSite();
      if (!site) return;             // if the user cancels
      await saveSite(site);           
      const all = await loadSites(); 
      await renderList(all);          // re-render the list with all sites
    });

    resetInactivityTimer();
  });

  // --- DATABASE RESET ---
  document.getElementById('reset-db-link').addEventListener('click', e => {
    e.preventDefault();
    if (!confirm('Are you sure you want to reset all your data?')) return;
    if (session.db) session.db.close();
    const req = indexedDB.deleteDatabase('pwdManagerDB');
    req.onblocked = () => console.warn('Please close other tabs using the database.');
    req.onerror = e => console.error('Database deletion error:', e);
    req.onsuccess = async () => {
      localStorage.clear();
      if ('serviceWorker' in navigator) {
        const regs = await navigator.serviceWorker.getRegistrations();
        await Promise.all(regs.map(r => r.unregister()));
      }
      window.location.reload();
    };
  });

  // --- SERVICE WORKER REGISTRATION ---
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js');
  }
})();
