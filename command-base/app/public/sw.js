// Service Worker — Network-first with content-aware caching
// No manual version bumps needed. Cache key uses response ETag/Last-Modified.

const CACHE_NAME = 'command-base-cache';

// Network-first for everything — always try fresh, fall back to cache
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // API calls — always network, never cache
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // Static assets (JS, CSS, HTML) — network first, cache fallback
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, clone);
          });
        }
        return response;
      })
      .catch(() => {
        return caches.match(event.request);
      })
  );
});

// On activation, clear old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) => {
      return Promise.all(
        names.filter((name) => name !== CACHE_NAME).map((name) => caches.delete(name))
      );
    })
  );
  // Take control of all clients immediately
  self.clients.claim();
});

// On install, skip waiting — take over immediately
self.addEventListener('install', () => {
  self.skipWaiting();
});
