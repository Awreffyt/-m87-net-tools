/* © 2026 M87 · 离线缓存与秒开
 * 策略：同源静态资源走「网络优先 + 4 秒降级缓存」。
 * 网络通畅时拿最新版本，链路卡住时立刻回落到上次缓存，避免白屏与长时间无响应。
 */
const CACHE = 'm87-shell-v34';
const CORE = [
  './index.html',
  './styles.css',
  './site.config.js',
  './js/m87.bundle.obf.js',
  './js/assist.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(CORE).catch(() => null)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(req, { signal: controller.signal });
      clearTimeout(timer);
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    } catch (err) {
      const hit = await cache.match(req, { ignoreSearch: true });
      if (hit) return hit;
      throw err;
    }
  })());
});
