import test, { after } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { createServer, request as httpRequest } from "node:http";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { tmpdir } from "node:os";
const root = mkdtempSync(join(tmpdir(), "dsh-remote-lifetime-test-"));
process.env.DSH_HOME = root;
const plugin = await import("../lib/index.js");
const { AccountStore, hmac } = await import("../lib/store.js");
const { SessionRegistry } = await import("../lib/audit-sessions.js");
const { generateTotpSecret, matchTotpCounter, totp } = await import(
  "../lib/totp.js"
);
after(() => {
  const target = realpathSync(root);
  assert.equal(dirname(target), realpathSync(tmpdir()));
  assert.ok(
    target.startsWith(
      realpathSync(tmpdir()) + sep + "dsh-remote-lifetime-test-",
    ),
  );
  rmSync(target, { recursive: true, force: true });
});
class ProbeSocket extends EventEmitter {
  destroyed = false;
  remoteAddress = "127.0.0.1";
  destroy() {
    if (!this.destroyed) {
      this.destroyed = true;
      this.emit("close");
    }
    return this;
  }
}
async function fixture(t, options = {}) {
  const dir = options.dir ?? mkdtempSync(join(root, "fixture-"));
  const authDir = join(dir, "auth");
  mkdirSync(authDir, { recursive: true, mode: 0o700 });
  const storePath = join(authDir, "store.json"),
    password = options.password ?? randomBytes(24).toString("hex");
  const cleanups = [],
    events = new EventEmitter(),
    errors = [];
  const web = {
    port: 3080,
    exact: new Map(),
    prefixes: new Map(),
    upgrades: new Map(),
    register(route) {
      const rows = route.kind === "exact" ? this.exact : this.prefixes;
      rows.set(route.path, route);
      return () => rows.delete(route.path);
    },
    registerUpgrade(route) {
      this.upgrades.set(route.path, route);
      return () => this.upgrades.delete(route.path);
    },
    registerFallback(value) {
      this.fallback = value;
      return () => {
        this.fallback = undefined;
      };
    },
  };
  const secret = randomBytes(32);
  const ctx = {
    webServer: web,
    logger: {
      info() {},
      warn() {},
      error(e) {
        errors.push(String(e));
      },
    },
    credentials: {
      async readRecord() {
        if (options.beforeSecretRead) await options.beforeSecretRead();
        return {
          kind: "grant",
          payload: { version: 1, secret: secret.toString("base64url") },
        };
      },
    },
    inject(_names, fn) {
      fn(ctx);
    },
    emit() {},
    effect(fn) {
      const d = fn();
      if (typeof d === "function") cleanups.push(d);
      return () => {};
    },
  };
  web.register({
    kind: "exact",
    path: "/api/probe",
    handler(_req, res) {
      res.writeHead(200);
      res.end("allowed");
    },
  });
  const cfg = plugin.Config({
    accounts: [{ username: "fixture-admin", password, role: "admin" }],
    browserAuth: { enabled: options.browserAuth === true },
    gzip: { enabled: false },
    mfa: { window: 3 },
    rateLimit: { maxAttempts: options.maxAttempts ?? 5, windowMs: 60000 },
  });
  cfg.storePath = storePath;
  cfg.filesRootsPath = join(dir, "roots.json");
  plugin.apply(ctx, cfg);
  let admitted = 0;
  web.registerUpgrade({
    path: "/probe-ws",
    handler() {
      admitted++;
    },
  });
  const server = createServer((req, res) => {
    (async () => {
      const path = new URL(req.url, "http://fixture.invalid").pathname;
      const route = web.exact.get(path);
      if (!route) {
        res.writeHead(404);
        res.end();
        return;
      }
      await route.handler(req, res);
    })()
      .catch((e) => {
        errors.push(String(e));
        if (!res.headersSent) res.writeHead(500);
        res.end();
      })
      .finally(() => events.emit("settled:" + req.url));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  web.port = server.address().port;
  const base = "http://127.0.0.1:" + web.port;
  async function request(path, { body, jar = new Map(), signal } = {}) {
    const headers = {
      host: "remote.example:8443",
      cookie: [...jar].map(([k, v]) => k + "=" + v).join("; "),
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    const response = await new Promise((resolve, reject) => {
      const req = httpRequest(
        base + path,
        { method: body === undefined ? "GET" : "POST", headers, signal },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("error", reject);
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString();
            let data;
            try {
              data = JSON.parse(text);
            } catch {}
            resolve({
              status: res.statusCode,
              data,
              cookies: res.headers["set-cookie"] ?? [],
            });
          });
        },
      );
      req.on("error", reject);
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
    for (const line of response.cookies) {
      const pair = line.split(";")[0],
        at = pair.indexOf("=");
      jar.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return response;
  }
  async function login(jar = new Map()) {
    const r = await request("/auth/login", {
      body: { username: "fixture-admin", password },
      jar,
    });
    assert.equal(r.status, 200);
    assert.equal(r.data.ok, true);
    return jar;
  }
  function upgrade(jar) {
    const socket = new ProbeSocket();
    const req = {
      method: "GET",
      url: "/probe-ws",
      headers: {
        host: "remote.example:8443",
        cookie: [...jar].map(([k, v]) => k + "=" + v).join("; "),
      },
      socket,
    };
    web.upgrades.get("/probe-ws").handler(req, socket, Buffer.alloc(0));
    return socket;
  }
  let stopped = false;
  async function stop() {
    if (stopped) return;
    stopped = true;
    for (const d of cleanups) d();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
  t.after(stop);
  return {
    request,
    login,
    upgrade,
    stop,
    events,
    dir,
    storePath,
    password,
    cfg,
    errors,
    get admitted() {
      return admitted;
    },
  };
}
test("revoking a device closes only its admitted transports", async (t) => {
  const f = await fixture(t),
    a = await f.login(),
    b = await f.login();
  const first = f.upgrade(a),
    second = f.upgrade(b);
  assert.equal(f.admitted, 2);
  const rows = await f.request("/auth/sessions", {
    body: { action: "list" },
    jar: a,
  });
  const sid = rows.data.sessions.find((s) => s.sid !== rows.data.current).sid;
  const r = await f.request("/auth/sessions", {
    body: { action: "revoke", sid },
    jar: a,
  });
  assert.equal(r.data.revoked, true);
  assert.equal(r.data.persisted, true);
  assert.equal(second.destroyed, true);
  assert.equal(first.destroyed, false);
  assert.equal((await f.request("/api/probe", { jar: b })).status, 403);
  assert.equal(f.upgrade(b).destroyed, true);
});
test("revoke-all preserves the current transport only when keepSelf is requested", async (t) => {
  const f = await fixture(t),
    a = await f.login(),
    b = await f.login();
  const first = f.upgrade(a),
    second = f.upgrade(b);
  const r = await f.request("/auth/sessions", {
    body: {
      action: "revoke-all",
      username: "fixture-admin",
      keepCurrent: true,
    },
    jar: a,
  });
  assert.equal(r.status, 200);
  assert.equal(second.destroyed, true);
  assert.equal(first.destroyed, false);
});
test("logout and plugin disposal close owned transports", async (t) => {
  const f = await fixture(t),
    a = await f.login();
  const one = f.upgrade(a);
  assert.equal(
    (await f.request("/auth/logout", { body: {}, jar: a })).status,
    200,
  );
  assert.equal(one.destroyed, true);
  const b = await f.login(),
    two = f.upgrade(b);
  await f.stop();
  assert.equal(two.destroyed, true);
});
test("enabling MFA invalidates previously admitted transports", async (t) => {
  const f = await fixture(t),
    a = await f.login();
  const socket = f.upgrade(a);
  const setup = await f.request("/auth/mfa/setup", { body: {}, jar: a });
  const step = Math.floor(Date.now() / 30000);
  assert.equal(
    (
      await f.request("/auth/mfa/verify", {
        body: { code: totp(setup.data.secret, step - 1) },
        jar: a,
      })
    ).status,
    200,
  );
  assert.equal(socket.destroyed, true);
});
test("a transport closes at its signed session expiry without an idle timeout", async (t) => {
  const f = await fixture(t),
    a = await f.login();
  const store = new AccountStore(f.storePath);
  store.load();
  const token = a.get(f.cfg.session.cookieName),
    parts = token.split(".");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  payload.exp = Date.now() + 100;
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  a.set(
    f.cfg.session.cookieName,
    "v1." + body + "." + hmac(store.secret, "v1." + body).toString("base64url"),
  );
  const socket = f.upgrade(a);
  assert.equal(socket.destroyed, false);
  await Promise.race([
    once(socket, "close"),
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error("expiry did not close transport")),
        1500,
      ),
    ),
  ]);
  assert.equal(socket.destroyed, true);
});
test("parallel password failures cannot overrun reserved attempt limits", async (t) => {
  const f = await fixture(t, { maxAttempts: 3 });
  const results = await Promise.all(
    Array.from({ length: 8 }, () =>
      f.request("/auth/login", {
        body: { username: "fixture-admin", password: "wrong" },
      }),
    ),
  );
  assert.equal(results.filter((r) => r.status === 401).length, 3);
  assert.equal(results.filter((r) => r.status === 429).length, 5);
  assert.equal(
    (
      await f.request("/auth/login", {
        body: { username: "fixture-admin", password: "wrong" },
      })
    ).status,
    429,
  );
});
test("successful parallel verification releases all attempt reservations", async (t) => {
  const f = await fixture(t, { maxAttempts: 3 });
  const results = await Promise.all(
    Array.from({ length: 3 }, () =>
      f.request("/auth/login", {
        body: { username: "fixture-admin", password: f.password },
      }),
    ),
  );
  assert.ok(results.every((r) => r.status === 200));
  assert.equal(
    (
      await f.request("/auth/login", {
        body: { username: "fixture-admin", password: f.password },
      })
    ).status,
    200,
  );
});
test("client abort does not release verification slots before the handler settles", async (t) => {
  let release, entered;
  const held = new Promise((resolve) => (release = resolve)),
    ready = new Promise((resolve) => (entered = resolve));
  const f = await fixture(t, {
    maxAttempts: 1,
    browserAuth: true,
    beforeSecretRead: async () => {
      entered();
      await held;
    },
  });
  const abort = new AbortController();
  const first = f
    .request("/auth/login?held=1", {
      body: { username: "fixture-admin", password: f.password },
      signal: abort.signal,
    })
    .catch(() => null);
  await ready;
  abort.abort();
  await first;
  assert.equal(
    (
      await f.request("/auth/login", {
        body: { username: "fixture-admin", password: f.password },
      })
    ).status,
    429,
  );
  const settled = once(f.events, "settled:/auth/login?held=1");
  release();
  await settled;
  assert.equal(
    (
      await f.request("/auth/login", {
        body: { username: "fixture-admin", password: f.password },
      })
    ).status,
    200,
  );
});
test("TOTP counters survive reload and are not exposed by public account views", () => {
  const dir = mkdtempSync(join(root, "store-"));
  const path = join(dir, "store.json");
  const s = new AccountStore(path);
  s.load();
  s.upsert({
    username: "fixture-admin",
    passwordHash: "synthetic-fixture-hash",
    role: "admin",
  });
  s.beginTotpSetup("fixture-admin", generateTotpSecret(), []);
  assert.equal(s.consumeTotpCounter("fixture-admin", 100), true);
  assert.equal(s.consumeTotpCounter("fixture-admin", 100), false);
  assert.equal(s.consumeTotpCounter("fixture-admin", 99), false);
  s.save();
  const reload = new AccountStore(path);
  reload.load();
  assert.equal(reload.consumeTotpCounter("fixture-admin", 100), false);
  assert.equal(reload.consumeTotpCounter("fixture-admin", 101), true);
  assert.equal(
    JSON.stringify(reload.list()).includes("lastUsedCounter"),
    false,
  );
  assert.equal(
    JSON.stringify(reload.mfaInfo("fixture-admin")).includes("lastUsedCounter"),
    false,
  );
});
test("fresh MFA challenges cannot reuse a successfully consumed TOTP", async (t) => {
  const f = await fixture(t),
    a = await f.login();
  const setup = await f.request("/auth/mfa/setup", { body: {}, jar: a });
  const step = Math.floor(Date.now() / 30000),
    secret = setup.data.secret;
  assert.equal(
    (
      await f.request("/auth/mfa/verify", {
        body: { code: totp(secret, step - 1) },
        jar: a,
      })
    ).status,
    200,
  );
  const challenge = () =>
    f.request("/auth/login", {
      body: { username: "fixture-admin", password: f.password },
    });
  const c1 = await challenge();
  assert.equal(
    (
      await f.request("/auth/mfa/login", {
        body: { mfaToken: c1.data.mfaToken, code: totp(secret, step) },
      })
    ).status,
    200,
  );
  const c2 = await challenge();
  assert.equal(
    (
      await f.request("/auth/mfa/login", {
        body: { mfaToken: c2.data.mfaToken, code: totp(secret, step) },
      })
    ).status,
    401,
  );
  const c3 = await challenge();
  assert.equal(
    (
      await f.request("/auth/mfa/login", {
        body: { mfaToken: c3.data.mfaToken, code: totp(secret, step + 1) },
      })
    ).status,
    200,
  );
  await f.stop();
  const reloaded = await fixture(t, { dir: f.dir, password: f.password });
  const c4 = await reloaded.request("/auth/login", {
    body: { username: "fixture-admin", password: f.password },
  });
  assert.equal(
    (
      await reloaded.request("/auth/mfa/login", {
        body: { mfaToken: c4.data.mfaToken, code: totp(secret, step + 1) },
      })
    ).status,
    401,
  );
});
test("session removal notifications cover eviction, expiration and explicit revocation", () => {
  const dir = mkdtempSync(join(root, "registry-")),
    removed = [];
  const r = new SessionRegistry(join(dir, "sessions.json"), {
    maxPerUser: 2,
    onRevoke: (sid) => removed.push(sid),
  }).load();
  const args = {
    username: "fixture-admin",
    ip: "192.0.2.1",
    ua: "fixture",
    ttlMs: 60000,
  };
  const a = r.create(args),
    b = r.create(args),
    c = r.create(args);
  assert.ok(removed.includes(a));
  r.revoke(b);
  assert.ok(removed.includes(b));
  r.data.find((s) => s.sid === c).expiresAt = Date.now() - 1;
  r.prune();
  assert.ok(removed.includes(c));
});
test("matching TOTP counters preserve existing clock-drift verification", () => {
  const secret = generateTotpSecret(),
    step = Math.floor(Date.now() / 30000);
  assert.equal(matchTotpCounter(secret, totp(secret, step), 1), step);
  assert.equal(matchTotpCounter(secret, totp(secret, step + 1), 1), step + 1);
  assert.equal(matchTotpCounter(secret, "not-a-code", 1), null);
});

test("password changes close even the retained current-session transport", async (t) => {
  const f = await fixture(t),
    a = await f.login(),
    socket = f.upgrade(a);
  const response = await f.request("/auth/accounts", {
    body: {
      action: "upsert",
      username: "fixture-admin",
      password: "New-fixture-password-9876!",
    },
    jar: a,
  });
  assert.equal(response.status, 200);
  assert.equal(socket.destroyed, true);
  assert.equal((await f.request("/api/probe", { jar: a })).status, 200);
});

test("credential and identity mutations notify live-connection invalidation", () => {
  const dir = mkdtempSync(join(root, "notify-")),
    notices = [];
  const s = new AccountStore(join(dir, "store.json"), {
    onInvalidate: (name) => notices.push(name),
  });
  s.load();
  s.upsert({
    username: "fixture-admin",
    role: "admin",
    passwordHash: "synthetic-a",
  });
  s.upsert({ username: "fixture-admin", passwordHash: "synthetic-b" });
  s.beginTotpSetup("fixture-admin", generateTotpSecret(), []);
  s.confirmTotp("fixture-admin");
  s.disableTotp("fixture-admin");
  s.rename("fixture-admin", "fixture-renamed");
  s.remove("fixture-renamed");
  s.rotateSecret();
  assert.deepEqual(notices, [
    "fixture-admin",
    "fixture-admin",
    "fixture-admin",
    "fixture-admin",
    "fixture-renamed",
    null,
  ]);
});

test("verification exceptions release their reserved attempt budget", async (t) => {
  const f = await fixture(t, { maxAttempts: 1 }),
    find = AccountStore.prototype.find;
  let onceOnly = true;
  AccountStore.prototype.find = function (name) {
    if (this.path === f.storePath && onceOnly) {
      onceOnly = false;
      throw new Error("fixture lookup failure");
    }
    return find.call(this, name);
  };
  try {
    assert.equal(
      (
        await f.request("/auth/login", {
          body: { username: "fixture-admin", password: f.password },
        })
      ).status,
      500,
    );
  } finally {
    AccountStore.prototype.find = find;
  }
  assert.equal(
    (
      await f.request("/auth/login", {
        body: { username: "fixture-admin", password: f.password },
      })
    ).status,
    200,
  );
});

test("TOTP persistence failure cannot issue an authenticated session", async (t) => {
  const f = await fixture(t),
    a = await f.login();
  const setup = await f.request("/auth/mfa/setup", { body: {}, jar: a }),
    step = Math.floor(Date.now() / 30000);
  assert.equal(
    (
      await f.request("/auth/mfa/verify", {
        body: { code: totp(setup.data.secret, step - 1) },
        jar: a,
      })
    ).status,
    200,
  );
  const challenge = await f.request("/auth/login", {
      body: { username: "fixture-admin", password: f.password },
    }),
    save = AccountStore.prototype.save;
  AccountStore.prototype.save = function () {
    if (this.path === f.storePath) throw new Error("fixture disk failure");
    return save.call(this);
  };
  try {
    const r = await f.request("/auth/mfa/login", {
      body: {
        mfaToken: challenge.data.mfaToken,
        code: totp(setup.data.secret, step),
      },
    });
    assert.equal(r.status, 500);
    assert.equal(
      r.cookies.some((c) => c.startsWith(f.cfg.session.cookieName + "=")),
      false,
    );
  } finally {
    AccountStore.prototype.save = save;
  }
});
