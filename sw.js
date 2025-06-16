const CACHE_NAME = 'pwd-manager-v1';
const ASSETS = [
  './',
  './index.html',
  './styles.css',
  './dist/app.bundle.js',
  './dist/worker.bundle.js',
  './manifest.json',
  './sw.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  // **1) ne gérer que les GET**
  if (event.request.method !== 'GET') {
    return;
  }
  // **2) tenter de servir depuis le cache**, sinon aller au réseau et mettre à jour
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) {
        return cached;
      }
      return fetch(event.request).then(response => {
        // uniquement si réponse OK, on la met en cache
        if (!response.ok) return response;
        return caches.open(CACHE_NAME).then(cache => {
          cache.put(event.request, response.clone());
          return response;
        });
      });
    })
  );
});

