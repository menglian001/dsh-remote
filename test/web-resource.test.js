import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { randomBytes, createHmac } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { gunzipSync } from "node:zlib";

// No test reads an operator's home, account store, or signing key.
const root = mkdtempSync(join(tmpdir(), "dsh-remote-resource-test-"));
process.env.DSH_HOME = root;
const plugin = await import("../lib/index.js");
after(() => {
  const target = realpathSync(root);
  assert.equal(dirname(target), realpathSync(tmpdir()));
  assert.ok(target.startsWith(realpathSync(tmpdir()) + sep + "dsh-remote-resource-test-"));
  rmSync(target, { recursive: true, force: true });
});

async function fixture(t, options = {}) {
  const dir = mkdtempSync(join(root, "fixture-"));
  const authDir = join(dir, "auth");
  mkdirSync(authDir, { mode: 0o700 });
  const storePath = join(authDir, "store.json");
  if (options.brokenStore) writeFileSync(storePath, "not valid JSON", { mode: 0o600 });
  const secret = randomBytes(32);
  const password = randomBytes(24).toString("hex");
  const cleanups = [];
  const errors = [];
  const web = {
    port: 3080, exact: new Map(), prefixes: new Map(), upgrades: new Map(),
    register(route) {
      const map = route.kind === "exact" ? this.exact : this.prefixes;
      assert.ok(!map.has(route.path), "duplicate fixture route");
      map.set(route.path, route);
      return () => map.delete(route.path);
    },
    registerUpgrade(route) { this.upgrades.set(route.path, route); return () => this.upgrades.delete(route.path); },
    registerFallback(value) { assert.equal(this.fallback, undefined); this.fallback = value; return () => { this.fallback = undefined; }; }
  };
  const ctx = {
    webServer: web,
    logger: { info() {}, warn() {}, error(message) { errors.push(String(message)); } },
    credentials: {
      async readRecord(key) {
        assert.equal(key, plugin.BROWSER_SESSION_RECORD_KEY);
        if (options.beforeSecretRead) await options.beforeSecretRead();
        return { kind: "grant", payload: { version: 1, secret: secret.toString("base64url") } };
      }
    },
    inject(_names, fn) { fn(ctx); },
    emit() {},
    effect(fn) { const cleanup = fn(); if (typeof cleanup === "function") cleanups.push(cleanup); return () => {}; }
  };
  function validCore(request) {
    const authority = plugin.canonicalAuthority(request.headers.get("host"));
    const value = plugin.cookieValueOf(request.headers.get("cookie"), plugin.dshAuthCookieName(authority));
    return plugin.decodeDshAuthCookie(value, secret, authority) !== null;
  }
  const calls = [];
  function responder(name) {
    return async (request, peer) => {
      calls.push({ name, request, peer });
      if (options.response) return options.response(request, peer);
      return Response.json({ name, host: request.headers.get("host"), cookie: request.headers.get("cookie") });
    };
  }
  const exactBefore = responder("exact-before");
  const prefixBefore = responder("prefix-before");
  const exactAfter = responder("exact-after");
  const prefixAfter = responder("prefix-after");
  const fallbackOriginal = async (request, peer) => {
    calls.push({ name: "fallback", request, peer });
    if (peer === undefined && !validCore(request)) return new Response("CORE_AUTH_REQUIRED", { status: 401 });
    return new Response("<html><body>ISOLATED_APP</body></html>", {
      headers: { "content-type": "text/html", "cache-control": "no-store" }
    });
  };
  const fallbackValue = options.legacyFallback ? ((req, res) => {
    res.writeHead(200, { "content-type": "text/html" }); res.end("ISOLATED_APP");
  }) : { resource: fallbackOriginal, marker: "preserve-owner-metadata" };
  web.register({ kind: "exact", path: "/resource-before", resource: exactBefore });
  web.register({ kind: "prefix", path: "/prefix-before", resource: prefixBefore });
  web.register({ kind: "exact", path: "/api/probe", handler(req, res) {
    res.writeHead(200, { "content-type": "application/json" }); res.end('{"ok":true}');
  } });
  if (!options.lateFallback) web.registerFallback(fallbackValue);
  const cfg = plugin.Config({ accounts: [{ username: "fixture-admin", password, role: "admin" }],
    trustProxy: true, browserAuth: { enabled: options.browserAuth !== false },
    gzip: { enabled: options.gzip === true, minBytes: 1, remoteOnly: true }, files: { roots: [dir] } });
  cfg.storePath = storePath;
  cfg.filesRootsPath = join(dir, "file-roots.json");
  plugin.apply(ctx, cfg);
  web.register({ kind: "exact", path: "/resource-after", resource: exactAfter });
  web.register({ kind: "prefix", path: "/prefix-after", resource: prefixAfter });
  if (options.lateFallback) web.registerFallback(fallbackValue);
  function select(pathname) {
    return web.exact.get(pathname) ?? [...web.prefixes.values()]
      .filter(row => pathname === row.path || pathname.startsWith(row.path + "/"))
      .sort((a, b) => b.path.length - a.path.length)[0] ?? web.fallback;
  }
  const server = createServer((req, res) => {
    (async () => {
      const target = new URL(req.url, "http://fixture.invalid");
      const route = select(target.pathname);
      if (!route) { res.writeHead(404); res.end(); return; }
      if (typeof route === "function") { await route(req, res); return; }
      if (!("resource" in route)) { await route.handler(req, res); return; }
      if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405); res.end(); return; }
      const request = new Request(target, { method: req.method, headers: req.headers });
      const response = await route.resource(request);
      const headers = Object.fromEntries(response.headers);
      const cookies = response.headers.getSetCookie();
      if (cookies.length) headers["set-cookie"] = cookies;
      const bytes = response.body === null ? null : Buffer.from(await response.arrayBuffer());
      res.writeHead(response.status, headers);
      res.end(req.method === "HEAD" ? undefined : bytes);
    })().catch(error => { errors.push(String(error)); if (!res.headersSent) res.writeHead(500); res.end(); });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  web.port = server.address().port;
  const base = "http://127.0.0.1:" + web.port;
  const authority = options.publicHost ?? "127.0.0.1:" + web.port;
  async function request(path, { body, jar = new Map(), method, headers = {} } = {}) {
    const outgoing = { host: authority, cookie: [...jar].map(([k, v]) => k + "=" + v).join("; "), ...headers };
    if (body !== undefined) outgoing["content-type"] = "application/json";
    // Node's fetch suppresses a custom Host header; use the HTTP transport
    // to faithfully exercise public-Host normalization and remote-only gzip.
    const result = await new Promise((resolve, reject) => {
      const req = httpRequest(base + path, { method: method ?? (body === undefined ? "GET" : "POST"), headers: outgoing }, res => {
        const chunks = [];
        res.on("data", chunk => chunks.push(chunk));
        res.on("error", reject);
        res.on("end", () => {
          try {
            const responseHeaders = new Headers();
            for (let i = 0; i < res.rawHeaders.length; i += 2) responseHeaders.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
            const bytes = Buffer.concat(chunks);
            const text = responseHeaders.get("content-encoding") === "gzip" && bytes.length > 0
              ? gunzipSync(bytes).toString("utf8") : bytes.toString("utf8");
            let data; try { data = JSON.parse(text); } catch {}
            resolve({ status: res.statusCode, headers: responseHeaders, cookies: responseHeaders.getSetCookie(), text, data });
          } catch (error) { reject(error); }
        });
      });
      req.on("error", reject);
      req.setTimeout(5000, () => req.destroy(new Error("fixture request timeout")));
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
    for (const line of result.cookies) {
      const pair = line.split(";")[0]; const at = pair.indexOf("=");
      jar.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return result;
  }
  async function login(jar = new Map()) {
    const response = await request("/auth/login", { body: { username: "fixture-admin", password }, jar });
    assert.equal(response.status, 200); assert.equal(response.data.ok, true);
    return jar;
  }
  function dispose() { for (const cleanup of cleanups.splice(0).reverse()) cleanup(); }
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    dispose();
    if (!options.brokenStore) assert.deepEqual(errors, []);
  });
  return { web, cfg, calls, secret, authority, base, request, login, dispose, errors, storePath, dir,
    originals: { exactBefore, prefixBefore, exactAfter, prefixAfter, fallbackOriginal } };
}

for (const path of ["/resource-before", "/prefix-before/item", "/resource-after", "/prefix-after/item"]) {
  test("anonymous resource is blocked: " + path, async t => {
    const f = await fixture(t);
    const r = await f.request(path);
    assert.equal(r.status, 403); assert.equal(r.data.error, "unauthorized"); assert.deepEqual(f.calls, []);
    assert.equal(r.headers.get("cache-control"), "no-store");
  });
}
for (const lateFallback of [false, true]) {
  test("login page gates a " + (lateFallback ? "late" : "pre-existing") + " resource fallback", async t => {
    const f = await fixture(t, { lateFallback });
    const r = await f.request("/?next=example");
    assert.equal(r.status, 200); assert.ok(r.text.includes('id="password"')); assert.ok(!r.text.includes("ISOLATED_APP"));
    assert.equal(r.headers.get("x-frame-options"), "DENY"); assert.equal(r.headers.get("referrer-policy"), "no-referrer");
    assert.ok(r.headers.get("content-security-policy").includes("frame-ancestors 'none'"));
    assert.equal(f.web.fallback.marker, "preserve-owner-metadata"); assert.deepEqual(f.calls, []);
  });
}
test("HEAD login response has no body and keeps security headers", async t => {
  const f = await fixture(t); const r = await f.request("/", { method: "HEAD" });
  assert.equal(r.status, 200); assert.equal(r.text, ""); assert.equal(r.headers.get("cache-control"), "no-store");
});
test("legacy fallback keeps the same login gate", async t => {
  const f = await fixture(t, { legacyFallback: true }); const r = await f.request("/");
  assert.equal(r.status, 200); assert.ok(r.text.includes('id="password"')); assert.ok(!r.text.includes("ISOLATED_APP"));
});
test("ordinary API and unauthenticated WebSocket gate are retained", async t => {
  const f = await fixture(t); assert.equal((await f.request("/api/probe")).status, 403);
  let called = false, destroyed = false;
  f.web.registerUpgrade({ path: "/socket", handler() { called = true; } });
  f.web.upgrades.get("/socket").handler({ headers: {}, url: "/socket" }, { destroy() { destroyed = true; } });
  assert.equal(called, false); assert.equal(destroyed, true);
});
test("logged-in resources work and normalize only named-route authority", async t => {
  const f = await fixture(t, { publicHost: "remote.example:8443" }); const jar = await f.login();
  const r = await f.request("/resource-before", { jar });
  assert.equal(r.status, 200); assert.equal(r.data.host, "127.0.0.1:" + f.web.port);
  const index = await f.request("/", { jar }); assert.equal(index.status, 200); assert.ok(index.text.includes("ISOLATED_APP"));
  assert.equal(f.calls.find(row => row.name === "fallback").request.headers.get("host"), "remote.example:8443");
});
test("first resource request repairs a missing core cookie without a 401 round-trip", async t => {
  const f = await fixture(t); const all = await f.login(); const jar = new Map([[f.cfg.session.cookieName, all.get(f.cfg.session.cookieName)]]);
  const r = await f.request("/", { jar }); assert.equal(r.status, 200); assert.ok(r.text.includes("ISOLATED_APP"));
  assert.equal(r.cookies.length, 1); assert.equal(r.headers.get("cache-control"), "private, no-store");
  assert.equal(r.headers.get("cdn-cache-control"), "no-store");
});
test("an invalid core cookie is replaced, not forwarded beside a valid duplicate", async t => {
  const f = await fixture(t); const jar = await f.login(); const name = plugin.dshAuthCookieName(f.authority);
  jar.set(name, "v1.invalid.invalid"); const r = await f.request("/", { jar });
  assert.equal(r.status, 200); assert.ok(r.text.includes("ISOLATED_APP")); assert.equal(r.cookies.length, 1);
});
test("valid v2 core cookies retain their Peer identity", async t => {
  const f = await fixture(t); const jar = await f.login(); const name = plugin.dshAuthCookieName(f.authority);
  const now = Date.now(); const payload = { version: 2, authority: f.authority, id: "fixture-browser-peer", issuedAt: now, expiresAt: now + 3600000 };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const value = "v2." + body + "." + createHmac("sha256", f.secret).update(body).digest("base64url");
  jar.set(name, value); const r = await f.request("/", { jar }); assert.equal(r.status, 200); assert.equal(r.cookies.length, 0);
  assert.equal(plugin.cookieValueOf(f.calls.at(-1).request.headers.get("cookie"), name), value);
});
test("core cookies and forged proxy/Peer headers cannot substitute for plugin login", async t => {
  const f = await fixture(t); const all = await f.login(); const jar = new Map([...all].filter(([name]) => name !== f.cfg.session.cookieName));
  const r = await f.request("/resource-before", { jar, headers: { "x-dsh-peer": "owner", "x-forwarded-for": "127.0.0.1" } });
  assert.equal(r.status, 403); assert.deepEqual(f.calls, []);
  assert.ok((await f.request("/", { jar })).text.includes('id="password"'));
});
test("invalid plugin cookies never reach the underlying resource", async t => {
  const f = await fixture(t); const jar = await f.login(); jar.set(f.cfg.session.cookieName, "v1.invalid.invalid");
  assert.equal((await f.request("/resource-after", { jar })).status, 403); assert.deepEqual(f.calls, []);
});
test("revoked device loses both the application index and named resource access", async t => {
  const f = await fixture(t); const admin = await f.login(); const other = await f.login();
  const list = await f.request("/auth/sessions", { body: { action: "list" }, jar: admin });
  const sid = list.data.sessions.find(row => row.sid !== list.data.current).sid;
  const revoke = await f.request("/auth/sessions", { body: { action: "revoke", sid }, jar: admin });
  assert.equal(revoke.data.revoked, true); assert.equal(revoke.data.persisted, true);
  assert.equal((await f.request("/resource-before", { jar: other })).status, 403);
  const index = await f.request("/", { jar: other }); assert.equal(index.status, 200); assert.ok(index.text.includes('id="password"'));
  assert.ok(!index.text.includes("ISOLATED_APP")); assert.equal((await f.request("/api/probe", { jar: other })).status, 403);
  assert.equal((await f.request("/resource-before", { jar: admin })).status, 200);
});
test("authenticated internal Peer reads retain resource identity and need no browser cookie", async t => {
  const f = await fixture(t); const peer = { id: "admitted-peer" }; const request = new Request("http://internal/resource-before");
  const response = await f.web.exact.get("/resource-before").resource(request, peer); assert.equal(response.status, 200);
  assert.strictEqual(f.calls[0].request, request); assert.strictEqual(f.calls[0].peer, peer);
  const index = await f.web.fallback.resource(new Request("http://internal/"), peer); assert.ok((await index.text()).includes("ISOLATED_APP"));
});
test("resource /api/file inherits the authentication-store path fence", async t => {
  const f = await fixture(t); const jar = await f.login(); let called = false;
  f.web.register({ kind: "exact", path: "/api/file", resource: async () => { called = true; return new Response("secret"); } });
  const r = await f.request("/api/file?path=" + encodeURIComponent(f.storePath), { jar });
  assert.equal(r.status, 403); assert.equal(called, false);
});
test("disposing the plugin restores exact/prefix resources and fallback metadata", async t => {
  const f = await fixture(t); f.dispose();
  assert.strictEqual(f.web.exact.get("/resource-before").resource, f.originals.exactBefore);
  assert.strictEqual(f.web.exact.get("/resource-after").resource, f.originals.exactAfter);
  assert.strictEqual(f.web.prefixes.get("/prefix-before").resource, f.originals.prefixBefore);
  assert.strictEqual(f.web.prefixes.get("/prefix-after").resource, f.originals.prefixAfter);
  assert.strictEqual(f.web.fallback.resource, f.originals.fallbackOriginal);
  assert.equal(f.web.fallback.marker, "preserve-owner-metadata");
});
for (const lateFallback of [false, true]) {
  test("activation failure denies existing/future resources and " + (lateFallback ? "late" : "existing") + " fallback", async t => {
    const f = await fixture(t, { brokenStore: true, lateFallback }); assert.ok(f.errors.length > 0);
    for (const path of ["/resource-before", "/resource-after", "/prefix-before/item", "/prefix-after/item", "/"]) {
      assert.equal((await f.request(path)).status, 503, path);
    }
    assert.deepEqual(f.calls, []);
  });
}
test("resource gzip stays streaming and weakens the original representation ETag", async t => {
  const text = "stream-body-".repeat(100);
  const f = await fixture(t, { publicHost: "remote.example:8443", gzip: true,
    response: () => new Response(text, { headers: { "content-type": "text/plain", "content-length": String(text.length), "etag": '"fixture"' } }) });
  const jar = await f.login(); const r = await f.request("/resource-before", { jar, headers: { "accept-encoding": "gzip" } });
  assert.equal(r.status, 200); assert.equal(r.text, text); assert.equal(r.headers.get("content-encoding"), "gzip");
  assert.equal(r.headers.get("content-length"), null); assert.equal(r.headers.get("etag"), 'W/"fixture"');
  assert.ok(r.headers.get("vary").includes("Accept-Encoding"));
});
test("HEAD resources do not claim a compressed body", async t => {
  const f = await fixture(t, { publicHost: "remote.example:8443", gzip: true,
    response: () => new Response(null, { headers: { "content-type": "text/plain", "content-length": "1200" } }) });
  const jar = await f.login(); const r = await f.request("/resource-before", { jar, method: "HEAD", headers: { "accept-encoding": "gzip" } });
  assert.equal(r.status, 200); assert.equal(r.text, ""); assert.equal(r.headers.get("content-encoding"), null);
  assert.equal(r.headers.get("content-length"), "1200");
});
test("range/SSE/already-encoded resources keep their response semantics", async t => {
  for (const [status, headers] of [[206, { "content-type": "text/plain" }], [200, { "content-type": "text/event-stream" }], [200, { "content-type": "text/plain", "content-encoding": "identity" }]]) {
    const f = await fixture(t, { publicHost: "remote.example:8443", gzip: true, response: () => new Response("fixture", { status, headers }) });
    const jar = await f.login(); const r = await f.request("/resource-before", { jar, headers: { "accept-encoding": "gzip" } });
    assert.equal(r.status, status); assert.equal(r.text, "fixture"); assert.notEqual(r.headers.get("content-encoding"), "gzip");
  }
});
test("a revoke while the credential provider awaits wins before resource dispatch", { timeout: 8000 }, async t => {
  let release, started;
  const began = new Promise(resolve => { started = resolve; });
  const f = await fixture(t, { browserAuth: false, beforeSecretRead: () => {
    started(); return new Promise(resolve => { release = resolve; });
  } });
  const admin = await f.login(); const other = await f.login();
  const list = await f.request("/auth/sessions", { body: { action: "list" }, jar: admin });
  const sid = list.data.sessions.find(row => row.sid !== list.data.current).sid;
  f.cfg.browserAuth.enabled = true;
  const pending = f.request("/resource-before", { jar: other });
  await began;
  try {
    const revoke = await f.request("/auth/sessions", { body: { action: "revoke", sid }, jar: admin });
    assert.equal(revoke.data.revoked, true);
  } finally { release(); }
  const result = await pending;
  assert.equal(result.status, 403); assert.equal(result.cookies.length, 0); assert.deepEqual(f.calls, []);
});

test("aborted Fetch requests are not sent to the underlying resource", async t => {
  const f = await fixture(t); const jar = await f.login(); const controller = new AbortController(); controller.abort("fixture-abort");
  const req = new Request(f.base + "/resource-before", { headers: { host: f.authority, cookie: [...jar].map(([k,v]) => k + "=" + v).join("; ") }, signal: controller.signal });
  await assert.rejects(f.web.exact.get("/resource-before").resource(req), error => error === "fixture-abort"); assert.deepEqual(f.calls, []);
});
