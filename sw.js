/* Shree IT Asset Intelligence - Progressive Web App Service Worker */
const CACHE_NAME = 'shree-pwa-v6';
const STATIC_ASSETS = [
  '/',
  '/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
  '/static/icons/icon-maskable-192.png',
  '/static/icons/icon-maskable-512.png',
  '/static/icons/apple-touch-icon-180.png',
  '/static/icons/apple-touch-icon-167.png',
  '/static/icons/apple-touch-icon-152.png',
  '/static/icons/icon.svg',
  '/apple-touch-icon.png',
  '/favicon.ico'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[PWA SW] Pre-cache partial failure:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // 1. NEVER cache live streams, login media, or API requests - always network only
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/cctv/') || url.pathname.startsWith('/login-media/')) {
    return;
  }

  // 2. Navigation requests: Network-first with cache fallback
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(() => {
        return caches.match(req).then((cached) => {
          return cached || caches.match('/');
        });
      })
    );
    return;
  }

  // 3. Static assets: Stale-While-Revalidate
  if (
    url.pathname.startsWith('/static/') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.svg') ||
    url.pathname.endsWith('.ico') ||
    url.pathname === '/manifest.json' ||
    url.pathname.endsWith('.js') ||
    url.pathname.endsWith('.css')
  ) {
    event.respondWith(
      caches.match(req).then((cached) => {
        const fetchPromise = fetch(req).then((networkRes) => {
          if (networkRes && networkRes.status === 200) {
            const clone = networkRes.clone();
            caches.open(CACHE_NAME).then((c) => c.put(req, clone));
          }
          return networkRes;
        }).catch(() => cached || Response.error());
        return cached || fetchPromise;
      })
    );
  }
});

/* Mobile Notifications & Action Handling */
self.addEventListener('message', (event) => {
  if (!event.data) return;

  if (event.data.type === 'SHOW_NOTIFICATION') {
    const { title, options } = event.data;
    const notifOptions = Object.assign({
      body: '',
      icon: '/static/icons/icon-192.png',
      badge: '/static/icons/icon-192.png',
      tag: 'shree-alert',
      renotify: true,
      vibrate: [200, 100, 200],
      requireInteraction: false,
      data: {}
    }, options);

    event.waitUntil(
      self.registration.showNotification(title || 'Shree Alert', notifOptions)
    );
  } else if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const view = data.targetView || data.view || 'notifications';
  const thId = data.targetThreadId || (view === 'messages' ? (data.targetId || data.id || '') : '');
  const tkId = data.targetTicketId || '';
  const secId = data.complaintDesk || data.targetTab || '';
  let targetUrl = data.url || `/?view=${encodeURIComponent(view)}`;
  if (!data.url) {
    if (thId) targetUrl += `&thread=${encodeURIComponent(thId)}`;
    if (tkId) targetUrl += `&ticket=${encodeURIComponent(tkId)}`;
    if (secId) targetUrl += `&desk=${encodeURIComponent(secId)}`;
  }

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      for (const client of windowClients) {
        if ('focus' in client) {
          client.focus();
          client.postMessage({
            type: 'PWA_NAVIGATE',
            view: view,
            id: data.targetId || data.id || '',
            meta: data
          });
          return;
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});

self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (_) {
    payload = { title: 'Shree Notification', body: event.data ? event.data.text() : '' };
  }

  const title = payload.title || 'Shree Alert';
  const options = {
    body: payload.body || 'New IT update received.',
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    vibrate: [200, 100, 200],
    data: payload.data || {}
  };

  event.waitUntil(self.registration.showNotification(title, options));
});
