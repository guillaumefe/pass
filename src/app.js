(() => {

const pwdCache = new Map();  // info → mot de passe
let initialLoad = true;

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

let dbPromise = null;
function getDB() {
  if (!dbPromise) {
    dbPromise = openDB().then(database => {
      database.onversionchange = () => {
        database.close();
        alert('Base de données mise à jour, rechargez la page.');
      };
      return database;
    });
  }
  return dbPromise;
}

const pwdWorker = new Worker(
  new URL('./worker.bundle.js', import.meta.url),
  { type: 'module' }
);

function deriveSitePassword(info, length = 20, pin) {
  return new Promise((resolve, reject) => {
    function handler(e) {
      if (e.data.type === 'generated' && e.data.info === info) {
        pwdWorker.removeEventListener('message', handler);
        resolve(e.data.password);
      }
    }
    pwdWorker.addEventListener('message', handler);
    pwdWorker.postMessage({
      type: 'generate',
      masterPass: masterKey,
      user:        currentUser,
      pin,
      info,
      length
    });
  });
}

// after: const pwdWorker = new Worker(…)
pwdWorker.addEventListener('error', e => {
  console.error('⚠️ Worker load/runtime error:', e.message, e.filename, e.lineno, e.colno);
});
pwdWorker.addEventListener('messageerror', e => {
  console.error('⚠️ Worker message parsing error:', e);
});
pwdWorker.onmessage = e => {
  if (e.data.type === 'generated') {
    const { info, password } = e.data;

    const spans = document.querySelectorAll('li span.password');
    for (const span of spans) {
      // ici on suppose que tu as stocké `info` en data-attribute sur le <li> :
      if (span.parentElement.dataset.info === info) {
        span.textContent = password;
      }
    }
  }
};


async function deriveMasterKey(pass, user, pin) {
  return new Promise((resolve, reject) => {
    function handler(e) {
      if (e.data.type === 'derived') {
        pwdWorker.removeEventListener('message', handler);
        resolve(e.data.derived);
      }
    }
    pwdWorker.addEventListener('message', handler);
    pwdWorker.postMessage({ type: 'derive', masterPass: pass, user, pin });
  }).then(derivedBytes =>
    Array.from(derivedBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  );
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

/**
 * @param {Object} r        — enregistrement {id, domain, login?, version?}
 * @param {Object} handlers — callbacks { onCopy(info, spanPwd), onEdit(r), onDelete(id, li) }
 * @returns {HTMLLIElement}
 */
function createSiteElement(r, { onCopy, onEdit, onDelete }) {
  const info = buildInfoKey(r.domain, r.login, r.version);
  const li   = document.createElement('li');
  li.dataset.info = info;

  // — Domain
  const spanDomain = document.createElement('span');
  spanDomain.className   = 'domain';
  spanDomain.textContent = r.domain;
  li.appendChild(spanDomain);

  // — Login (si présent)
  if (r.login) {
    const spanLogin = document.createElement('span');
    spanLogin.className   = 'login';
    spanLogin.textContent = `Login: ${r.login}`;
    li.appendChild(spanLogin);
  }

  // — Password placeholder
  const spanPwd = document.createElement('span');
  spanPwd.className   = 'password';
  spanPwd.textContent = pwdCache.has(info)
    ? `Password: ${pwdCache.get(info)}`
    : 'Password: … génération …';
  li.appendChild(spanPwd);

  // — Actions
  const actions = document.createElement('div');
  actions.className = 'actions';

  const btnCopy = document.createElement('button');
  btnCopy.textContent = 'Copy';
  btnCopy.addEventListener('click', () => onCopy(info, spanPwd));

  const btnEdit = document.createElement('button');
  btnEdit.textContent = 'Edit';
  btnEdit.addEventListener('click', () => onEdit(r));

  const btnDelete = document.createElement('button');
  btnDelete.textContent = 'Delete';
  btnDelete.addEventListener('click', () => onDelete(r.id, li));

  actions.append(btnCopy, btnEdit, btnDelete);
  li.appendChild(actions);

  return li;
}

async function renderList(records, pin) {
  const addBtn     = document.getElementById('add-button');
  const addText    = document.getElementById('add-text');
  const addSpinner = document.getElementById('add-spinner');

  const useLoader = initialLoad && records.length > 0;
  if (useLoader) {
    addBtn.disabled    = true;
    addSpinner.hidden   = false;
    addText.textContent = 'Chargement…';
  } else {
    addBtn.disabled    = false;
    addSpinner.hidden   = true;
  }

  // on vide la liste
  const ul = document.getElementById('site-list');
  ul.textContent = '';

  // tri du plus récent au plus ancien
  records.sort((a, b) => b.id - a.id);

  // pour chaque enregistrement, on appelle appendSite
  for (const site of records) {
    const li = appendSite(site, pin);
    ul.appendChild(li);
  }

  // génération initiale séquentielle
  if (initialLoad && records.length) {
    for (const r of records) {
      const info   = buildInfoKey(r.domain, r.login, r.version);
      const li     = ul.querySelector(`li[data-info="${info}"]`);
      const spanPwd= li.querySelector('.password');
      try {
        const pwd = await deriveSitePassword(info, 20, pin);
        pwdCache.set(info, pwd);
        spanPwd.textContent = `Password: ${pwd}`;
      } catch {
        spanPwd.textContent = '— erreur —';
      }
    }
  }

  if (useLoader) {
    addBtn.disabled    = false;
    addSpinner.hidden   = true;
    addText.textContent = 'Add Password';
  }

  initialLoad = false;
  resetInactivityTimer();
}


function appendSite(site, pin) {
  const li = document.createElement('li');
  li.dataset.info = buildInfoKey(site.domain, site.login, site.version);

  // — Domain
  const spanDomain = document.createElement('span');
  spanDomain.className   = 'domain';
  spanDomain.textContent = `Domain: ${site.domain}`;
  li.appendChild(spanDomain);

  // — Login (optionnel)
  if (site.login) {
    const spanLogin = document.createElement('span');
    spanLogin.className   = 'login';
    spanLogin.textContent = `Login: ${site.login}`;
    li.appendChild(spanLogin);
  }

  // — Password placeholder (on réutilise le cache si dispo)
  const info   = buildInfoKey(site.domain, site.login, site.version);
  const spanPwd = document.createElement('span');
  spanPwd.className = 'password';
  if (pwdCache.has(info)) {
    // on affiche directement le mot de passe déjà calculé
    spanPwd.textContent = `Password: ${pwdCache.get(info)}`;
  } else {
    spanPwd.textContent = 'Password: … génération …';
  }
  li.appendChild(spanPwd);

  // — Actions wrapper
  const actions = document.createElement('div');
  actions.className = 'actions';

  const btnCopy = document.createElement('button');
  btnCopy.className = 'copy';
  btnCopy.textContent = '📋';
btnCopy.addEventListener('click', async () => {
  const info = buildInfoKey(site.domain, site.login, site.version);
  const pwd  = await deriveSitePassword(info, 20, pin);
  spanPwd.textContent = `Password: ${pwd}`;
  pwdCache.set(info, pwd);

  try {
    await navigator.clipboard.writeText(pwd);
    showToast('Mot de passe copié ! Pensez à le vider après usage.', 4000);
    clearClipboardContainer.hidden = false;   // on révèle le lien
  } catch {
    showToast('Échec de la copie', 2000);
  }

  resetInactivityTimer();
});

  const btnEdit = document.createElement('button');
  btnEdit.className = 'edit';
  btnEdit.textContent = '✎';
  btnEdit.addEventListener('click', async () => {
    const newInfo = await promptSite(site);
    if (!newInfo) return;
    newInfo.id = site.id;

    spanPwd.textContent = 'Password: … génération …';

    try {
      await saveSite(newInfo);
      // mettre à jour le label Domain/Login si besoin
      spanDomain.textContent = `Domain: ${newInfo.domain}`;
      if (newInfo.login) {
        if (!li.querySelector('.login')) {
          const s = document.createElement('span');
          s.className = 'login';
          li.insertBefore(s, spanPwd);
        }
        li.querySelector('.login').textContent = `Login: ${newInfo.login}`;
      } else {
        const old = li.querySelector('.login');
        if (old) old.remove();
      }

      const info = buildInfoKey(newInfo.domain, newInfo.login, newInfo.version);
      const pwd  = await deriveSitePassword(info, 20, pin);
      spanPwd.textContent = `Password: ${pwd}`;
    } catch (err) {
      console.error(err);
      spanPwd.textContent = 'Password: erreur';
    }

    resetInactivityTimer();
  });

  const btnDelete = document.createElement('button');
  btnDelete.className = 'delete';
  btnDelete.textContent = '🗑';
btnDelete.addEventListener('click', async () => {
  // 1) on supprime de la base
  await deleteSite(site.id);

  // 2) on enlève le <li> du DOM
  li.remove();

  // 3) on purge le cache pour cet item
  const info = buildInfoKey(site.domain, site.login, site.version);
  pwdCache.delete(info);

  // 4) on réinitialise juste le timer d’inactivité
  resetInactivityTimer();
});

  actions.append(btnCopy, btnEdit, btnDelete);
  li.appendChild(actions);

  return li;
}


async function onEdit(event, oldInfo) {
  event.preventDefault();
  // currentTarget = le <button> sur lequel on a branché le listener
  const btn = event.currentTarget;
  const row = btn.closest('tr');           // ne sera plus null
  const spanPwd = row.querySelector('.site-password');
  spanPwd.textContent = 'Génération…';

  // 1) afficher le popup d’édition
  const newInfo = await promptSite(oldInfo);
  if (!newInfo) {
    spanPwd.textContent = '••••••';
    return;
  }

  // 2) sauvegarder
  newInfo.id = oldInfo.id;
  try {
    await saveSite(newInfo);
  } catch (err) {
    spanPwd.textContent = 'Erreur de sauvegarde';
    console.error(err);
    return;
  }

  // 3) dériver + afficher le mot de passe
  try {
    const pwd = await deriveSitePassword(newInfo, 20, pin);
    spanPwd.textContent = pwd;
  } catch (err) {
    spanPwd.textContent = 'Erreur';
    console.error(err);
  }
}


async function saveSite(site) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('sites', 'readwrite');
    const store = tx.objectStore('sites');
    const record = { domain: site.domain, login: site.login, version: site.version };
    let req;
    if (typeof site.id === 'number') {
      req = store.put({ id: site.id, ...record });
    } else {
      req = store.add(record);
    }
    tx.oncomplete = () => resolve(req.result);
    tx.onerror    = () => reject(tx.error);
  });
}

function showToast(message, duration = 3000) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  // trigger CSS transition
  requestAnimationFrame(() => toast.classList.add('show'));
  // auto-dismiss
  setTimeout(() => {
    toast.classList.remove('show');
    toast.addEventListener('transitionend', () => toast.remove());
  }, duration);
}

function lock() {
  if (db) { db.close(); db = null; }
  masterKey = null;
  currentUser = null;
  clearTimeout(inactivityTimeout);
  document.getElementById('app').hidden = true;
  document.getElementById('login-screen').hidden = false;
  const ul = document.getElementById('site-list');
  if (ul) ul.textContent = '';

  showToast('Session expirée, vous allez être redirigé…', 2000);

  // après le toast, reload pour réinitialiser complètement IndexedDB
  setTimeout(() => {
    window.location.reload();
  }, 0);
}

  function resetInactivityTimer() {
    clearTimeout(inactivityTimeout);
    inactivityTimeout = setTimeout(lock, INACTIVITY_LIMIT);
  }

  document.addEventListener('click', resetInactivityTimer);
  document.addEventListener('keydown', resetInactivityTimer);

window.addEventListener('DOMContentLoaded', () => {
  e.preventDefault();

  const form = document.getElementById('login-form');
  if (!form) {
    console.error('❌ #login-form non trouvé');
    return;
  }

  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }

  form.addEventListener('submit', e => {

  const passElem = document.getElementById('passphrase');
  const userElem = document.getElementById('username');
  const pinElem = document.getElementById('pin');

  const pass = form.passphrase.value;
  const user = form.username.value.trim();
  const pin = form.pin.value.trim();

  if (!pass || !user) return;

  masterKey = deriveMasterKey(pass, user, pin);
  currentUser = user;

  passElem.value = '';
  userElem.value = '';

  document.getElementById('login-screen').hidden = true;
  document.getElementById('app').hidden = false;

  db = await getDB();
  await renderList(await loadSites(), pin);

  const addBtn = document.getElementById('add-button');

addBtn.onclick = async () => {
  const site = await promptSite();
  if (!site) return;
  const id = await saveSite(site);
  site.id = id;

  const li = appendSite(site, pin);
  document.getElementById('site-list').prepend(li);

  const info   = buildInfoKey(site.domain, site.login, site.version);
  const spanPwd = li.querySelector('.password');
  try {
    const pwd = await deriveSitePassword(info, 20, pin);
    pwdCache.set(info, pwd);
    spanPwd.textContent = `Password: ${pwd}`;
  } catch {
    spanPwd.textContent = 'Password: erreur';
  }

  resetInactivityTimer();
};

});

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

const clearClipboardContainer = document.getElementById('reset-clip');
const clearClipboardLink = document.getElementById('reset-clip-link');

clearClipboardLink.addEventListener('click', async e => {
  e.preventDefault();
  try {
    await navigator.clipboard.writeText('');
    showToast('Presse-papier vidé ✅', 2000);
    clearClipboardContainer.hidden = true;
  } catch {
    showToast('Échec du vidage', 2000);
  }
});

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }

function buildInfoKey(domain, login, version) {
  return `${domain}|${login || ''}|${version == null ? '' : String(version)}`;
}

})();
