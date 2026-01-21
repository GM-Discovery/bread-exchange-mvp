const CACHE_NAME = "breadgov-shell-v1";
const SHELL = ["/", "/index.html", "/bread-poll-app.js", "/bread-poll-app.css", "/manifest.json",
               "/icons/icon-192.png", "/icons/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // Network-first for API
  if (url.pathname.startsWith("/api/")) {
    event.respondWith(fetch(event.request).catch(() => new Response(JSON.stringify({error:"offline"}), {
      status: 503, headers: {"Content-Type":"application/json"}
    })));
    return;
  }
  // Cache-first for shell
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});
