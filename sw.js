/* Tiny Thief VPK Builder: the service worker that keeps the page usable offline after the first visit (registered by
 * index.html only when served over https:// or localhost).
 *   - the page, builder.js and payload/version.json: network first, the saved copy when offline;
 *   - payload/payload.json?v=<sha256>: from the cache when it is there (its URL names its content), else fetched and
 *     saved; older payloads are removed once a new one is saved.
 * Nothing else is cached, and nothing the user drops into the page ever passes through here (it is read in the page). */
'use strict';
// GitHub Pages projects share an origin. Scope the cache and cleanup to this installation.
const PREFIX = 'tt-vpk-builder:' + encodeURIComponent(self.registration.scope) + ':';
const CACHE = PREFIX + 'v3';
const SHELL = ['./', 'index.html', 'builder.js', 'payload/version.json'];

self.addEventListener('install', event => {
    event.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
    event.waitUntil(caches.keys()
        .then(keys => Promise.all(keys.filter(k => k.startsWith(PREFIX) && k !== CACHE).map(k => caches.delete(k))))
        .then(() => self.clients.claim()));
});

async function networkFirst(request) {
    const cache = await caches.open(CACHE);
    try {
        /* by URL with cache 'no-cache': the browser's HTTP cache must ask the server (304 or the new file), or an updated
         * page or builder could be served stale from it for as long as the host's caching allows (seen 2026-11-17). A new
         * request by URL, because a navigation Request with fetch options would throw. */
        const res = await fetch(request.url, {cache: 'no-cache', credentials: 'same-origin'});
        if (res.ok) await cache.put(request, res.clone());
        return res;
    } catch (err) {
        const hit = await cache.match(request, {ignoreSearch: true});
        if (hit) return hit;
        throw err;
    }
}

async function payloadByHash(request) {
    const cache = await caches.open(CACHE);
    const hit = await cache.match(request);
    if (hit) return hit;
    const res = await fetch(request);
    if (res.ok) {
        const expected = new URL(request.url).searchParams.get('v');
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', await res.clone().arrayBuffer()));
        const actual = Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
        if (!/^[0-9a-f]{64}$/.test(expected) || actual !== expected)
            return new Response('Payload integrity check failed', {status: 502});
        for (const old of await cache.keys())
            if (new URL(old.url).pathname === new URL('payload/payload.json', self.registration.scope).pathname)
                await cache.delete(old);
        await cache.put(request, res.clone());
    }
    return res;
}

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
    const relative = url.href.slice(self.registration.scope.length);
    if (!url.href.startsWith(self.registration.scope)) return;
    if (url.pathname === new URL('payload/payload.json', self.registration.scope).pathname && url.searchParams.has('v')) {
        event.respondWith(payloadByHash(event.request)); return;
    }
    if (['', 'index.html', 'builder.js', 'payload/version.json'].includes(relative.split('?')[0]))
        event.respondWith(networkFirst(event.request));
});
