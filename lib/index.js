/**
 * dsh-remote — account/password authentication for the DeepSeek Harness
 * web surface.
 *
 * Host half: registers the /auth/* HTTP plane (login, logout, me, bootstrap,
 * accounts) and installs a session-cookie gate over the web server's route
 * table (HTTP + WebSocket upgrades + the SPA fallback). The browser half
 * (`./client.js`) renders the in-app login overlay on session expiry and a
 * Settings > 登录与账号 page for account management.
 *
 * Security posture:
 *  - Passwords are stored as scrypt hashes (N=16384,r=8,p=1) in
 *    $DSH_HOME/auth/store.json (0600). The Settings page never receives or
 *    returns a hash.
 *  - Sessions are HMAC-SHA256-signed cookies (v1.<payload>.<sig>) with an
 *    expiry; the signing secret is a persisted random value unless the
 *    composition pins one.
 *  - The gate covers every registered HTTP route, every WebSocket upgrade,
 *    and the SPA fallback, except the /auth/* plane itself. Unauthenticated
 *    browsers get a self-contained login page (or 403 for non-page
 *    requests); unauthenticated upgrades are rejected.
 *  - Login attempts are rate limited per IP+username.
 *  - First-run bootstrap (creating the first admin) is loopback-only.
 *  - When `enforceRoles` is on, non-admin sessions are method-gated on /api:
 *    `user` is denied the configuration/credentials/agent-preset plane,
 *    `guest` is additionally read-only.
 */
import z from "@deepseek-ai/schemastery";
import { Readable } from "node:stream";
import { createGzip, inflateRawSync } from "node:zlib";
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { chmodSync, createReadStream, existsSync, readdirSync, readFileSync, realpathSync, rmSync, statSync } from "node:fs";
import { basename, dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { dshHomePath } from "@deepseek-ai/dsh-home-paths";
import QRCode from "qrcode";
import { AccountStore, defaultStorePath, generateSecret, hashPasswordSync, hmac, verifyPassword } from "./store.js";
import { FilesRootsStore, filesRootsPath } from "./files-store.js";
import { renderLoginPage } from "./login-page.js";
import { AuditLog, SessionRegistry } from "./audit-sessions.js";
import { generateBackupCodes, generateTotpSecret, hashBackupCode, otpauthUri, verifyTotp } from "./totp.js";

/**
 * Read the app-level locale preference (`locale.preference` in
 * $DSH_HOME/settings.yaml -- probed as settings.yaml.imported on dsh >= 0.1.7)
 * so the login page follows the same language the
 * DSH shell uses. Returns "zh" | "en" | null (absent/unreadable — the caller
 * then falls back to the request's Accept-Language).
 */
const readLocalePreference = () => {
	// dsh >= 0.1.7 renames settings.yaml to settings.yaml.imported after the
	// one-time settings import (dsh-settings), so probe both names.
	for (const fileName of ["settings.yaml.imported", "settings.yaml"]) {
		try {
			const raw = readFileSync(join(dshHomePath(), fileName), "utf8");
			const match = /(?:^|\n)locale:\n(?:[ \t]+[^\n]*\n)*?[ \t]+preference:\s*(\S+)/.exec(raw);
			const value = match?.[1]?.replace(/^["']|["']$/g, "");
			if (value === "zh" || value === "en") return value;
		} catch {
			// absent/unreadable -- probe the next name, else Accept-Language
		}
	}
	return null;
};

/** Stable Cordis plugin name. */
const name = "remote";

/** Services required before this plugin activates. */
const inject = ["webServer"];

/** Marker placed on gated handlers so re-application never double-wraps. */
const GATED = Symbol("dsh-remote.gated");

/**
 * Where the ORIGINAL (pre-`normalizeForFence`) Host is stashed before the /api
 * trust fence rewrites it to loopback. `shouldGzip` reads this to decide
 * whether the request came from a remote (non-loopback) browser — gzip is only
 * useful / desired for those, not for local direct access.
 * Internal implementation detail; not a stable API.
 */
const ORIGINAL_HOST = Symbol("dsh-remote.originalHost");

/** wrapped -> original, module-level so hot re-application can unwrap. */
const wrappedOriginals = new WeakMap();

/** 常见弱口令（只收最高频的一小撮，避免体积失控）。 */
const WEAK_PASSWORDS = new Set([
	"123456", "1234567", "12345678", "123456789", "1234567890", "12345678910",
	"password", "password1", "password123", "passw0rd", "p@ssw0rd", "pa$$word",
	"qwerty", "qwerty123", "qwertyuiop", "abc123", "abcd1234", "a123456",
	"111111", "000000", "666666", "888888", "123123", "112233", "121212",
	"iloveyou", "admin", "admin123", "administrator", "root", "toor", "letmein",
	"welcome", "welcome1", "monkey", "dragon", "sunshine", "princess", "football",
	"1qaz2wsx", "qazwsx", "zaq12wsx", "asdfgh", "asdfghjkl", "zxcvbnm",
	"woaini", "woaini1314", "5201314", "1314520", "a123456789", "aa123456",
	"changeme", "secret", "test123", "guest", "master", "shadow"
]);

/** 口令不合格的原因码 -> 中英双语文案（登录页可能是英文的）。 */
const PASSWORD_PROBLEMS = {
	"too-short": { zh: "口令至少 10 位", en: "Password must be at least 10 characters" },
	"all-digits": { zh: "口令不能是纯数字", en: "Password cannot be all digits" },
	"too-simple": { zh: "口令字符太单一（不要重复同一个或两个字符）", en: "Password is too repetitive" },
	"common": { zh: "这是常见弱口令，换一个", en: "That is a commonly used password" },
	"contains-username": { zh: "口令不能包含用户名", en: "Password must not contain the username" }
};

/**
 * 检查口令强度。
 * 规则：≥10 位；不是纯数字；不是同一个字符重复；不在常见弱口令表里；不包含用户名。
 * @param {string} username - 账号名（用于"口令不能含用户名"判断）。
 * @param {string} password - 待检查的口令。
 * @returns {string|null} 不合格时返回原因码（见 PASSWORD_PROBLEMS），合格返回 null。
 */
/** 用户名合法字符集（新建与改名共用同一口径）。 */
const USERNAME_PATTERN = /^[A-Za-z0-9._+@-]{1,64}$/;

function passwordProblem(username, password) {
	const value = String(password ?? "");
	// 先查常见弱口令：这些多半短于 10 位，若先做长度检查就永远命中不到。
	if (WEAK_PASSWORDS.has(value.toLowerCase())) return "common";
	if (value.length < 10) return "too-short";
	if (/^\d+$/.test(value)) return "all-digits";
	if (new Set(value).size <= 2) return "too-simple";
	const name = String(username ?? "").trim().toLowerCase();
	if (name.length >= 3 && value.toLowerCase().includes(name)) return "contains-username";
	return null;
}

/**
 * 把原因码翻成当前请求语言的文案。
 * @param {string} code - passwordProblem 的返回值。
 * @param {"zh"|"en"} lang - 目标语言。
 * @returns {string} 人类可读的报错文案。
 */
function passwordProblemMessage(code, lang) {
	const entry = PASSWORD_PROBLEMS[code];
	if (entry === undefined) return String(code);
	return lang === "zh" ? entry.zh : entry.en;
}

/**
 * 请求语言：优先跟随 DSH 面板的语言设置，否则看 Accept-Language。
 * @param {object} req - HTTP 请求。
 * @returns {"zh"|"en"} 语言。
 */
function requestLanguage(req) {
	const preference = readLocalePreference();
	if (preference !== null) return preference;
	return /^zh/i.test(String(req?.headers?.["accept-language"] ?? "")) ? "zh" : "en";
}

/** Paths owned by this plugin — never gated. */
function isPublicPath(pathname) {
	return pathname === "/auth" || pathname.startsWith("/auth/");
}

/** Wire methods any non-admin session may not call. Names exist per dsh
 *  generation: the rc-era dotted entries and their dsh ≥ 0.1.2-alpha
 *  renames (evaluateRoleGate normalizes `namespace/method` → dotted before
 *  matching, so one list covers both). The native-open methods are denied so
 *  a non-admin session can never pop a host desktop surface — the remote
 *  browser file panel never reaches the wire for these anyway (the client
 *  half intercepts the fetch first); this is defense in depth. */
const NON_ADMIN_DENY = new Set([
	"settings.describe",
	"settings.openDocument",
	"settings.openSettingsDocument",
	"settings.update",
	"settings.replace",
	"settings.mutate",
	"credentials.describe",
	"credentials.set",
	"credentials.unset",
	"agentPreset.read",
	"agentPreset.copy",
	"agentPreset.openDocument",
	"settings.openAgentPresetDirectory",
	"agentPreset.remove",
	"host.pickDirectory",
	"host.openPath",
	"session.openWorkspacePath",
	"llm.discoverModels"
]);

/** Wire methods a guest (read-only) session may not call either. */
const GUEST_DENY = new Set([
	"session.prompt",
	"session.create",
	"session.delete",
	"session.fork",
	"session.rename",
	"session.selectModel",
	"session.updateQueue",
	"session.cancel",
	"workspace.create",
	"workspace.delete",
	"workspace.insertBefore",
	"workspace.archiveSession",
	"command.execute"
]);

const Config = z.object({
	enabled: z.boolean().default(true),
	accounts: z.array(z.object({
		username: z.string().min(1),
		password: z.string().min(1),
		role: z.union([z.const("admin"), z.const("user"), z.const("guest")]).default("user")
	})).default([]),
	secret: z.string().default(""),
	session: z.object({
		cookieName: z.string().default("dsh_session"),
		ttlSeconds: z.natural().min(60).max(60 * 60 * 24 * 30).default(7 * 24 * 60 * 60),
		secure: z.boolean().default(false),
		sameSite: z.union([z.const("lax"), z.const("strict"), z.const("none")]).default("lax")
	}).default({}),
	enforceRoles: z.boolean().default(true),
	// Admin-only mode: accounts are created only at bootstrap or through the
	// composition seed; runtime account creation is refused and every account
	// (seed included) is forced to the admin role. The Settings page hides the
	// add-account form while this is on.
	// Headless/Linux bootstrap: the browser bootstrap endpoint is loopback-only,
	// which a server without a local browser can never reach. Declaring
	// credentials here provisions the first admin at startup (once); ignored as
	// soon as any account exists.
	bootstrap: z.object({
		username: z.string().min(1),
		password: z.string().min(1)
	}),
	adminOnly: z.boolean().default(true),
	// Authenticated sessions may present any external Host/Origin: the request
	// is normalized to the loopback authority before the connection plugin's
	// browser-trust fence runs, so remote (reverse-proxied) browsers can use
	// the privileged /api plane (host.pickDirectory, settings.*, ...) that the
	// fence pins to loopback "until a real authentication layer exists" — this
	// plugin IS that layer. Unauthenticated requests never reach /api (our
	// gate), so the DNS-rebinding defense is redundant behind the cookie.
	trustProxy: z.boolean().default(true),
	mfa: z.object({
		enabled: z.boolean().default(true),
		issuer: z.string().default("DeepSeek Harness"),
		window: z.natural().min(0).max(3).default(1),
		backupCodes: z.natural().min(0).max(20).default(10)
	}).default({}),
	rateLimit: z.object({
		maxAttempts: z.natural().min(1).default(5),
		windowMs: z.natural().min(1000).default(15 * 60 * 1000)
	}).default({}),
	gzip: z.object({
		enabled: z.boolean().default(true),
		// Only compress responses served to remote (non-loopback original Host)
		// browsers. Local loopback access already has near-zero latency and
		// plenty of bandwidth, so compression there only costs CPU.
		remoteOnly: z.boolean().default(true),
		// Below this many response bytes skip compression (gzip overhead beats
		// any savings on tiny bodies).
		minBytes: z.natural().default(1024)
	}).default({}),
	// Remote file display: in remote mode the browser redirects host.openPath
	// clicks to /auth/file (served by this plugin) so the file is DISPLAYED in
	// the remote browser instead of being opened by a desktop app on the host,
	// where the remote user would never see it.
	files: z.object({
		enabled: z.boolean().default(true),
		// Extra allowed read roots (absolute paths). The default roots are the
		// DSH home directory and the process working directory (where sessions
		// and agent-produced files usually live); list more here to expose
		// files stored elsewhere.
		roots: z.array(z.string()).default([]),
		// Cap entries rendered per directory listing page.
		maxListing: z.natural().min(10).max(5000).default(500)
	}).default({}),
	// dsh ≥ 0.1.2-alpha browser-session cookie minting (issue #10). New dsh
	// builds gate /api and index.html behind a persistent, Host-bound signed
	// cookie (`dsh-auth-<sha256(host)>`, verified by client-connection's
	// browserAuth). Remote browsers can never hold the cookie bound to the
	// loopback authority this plugin normalizes requests to, so after login
	// every /api call 401s. This plugin therefore MINTS that cookie itself —
	// signing it with the same persisted secret client-connection uses (read
	// through the credentials service) and binding it to the authority the
	// core will see (loopback under trustProxy, the original Host otherwise).
	// A self-heal re-mint on gated requests also upgrades sessions created
	// before this fix. No-op on dsh builds without the credential record.
	browserAuth: z.object({
		enabled: z.boolean().default(true),
		// Minted-cookie lifetime in seconds; 0 follows `session.ttlSeconds`
		// (the default 7d sits well inside client-connection's default
		// cookieMaxAgeDays of 30, which bounds the accepted window). Raise
		// this above the deployment's cookieMaxAgeDays and the core would
		// reject every minted cookie.
		cookieTtlSeconds: z.natural().default(0)
	}).default({})
});

// ── small HTTP helpers ────────────────────────────────────────────────────────

function pathnameOf(req) {
	return new URL(req.url ?? "/", "http://dsh.internal").pathname;
}

function json(res, status, body) {
	const text = JSON.stringify(body);
	res.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Cache-Control": "no-store",
		"X-Content-Type-Options": "nosniff",
		"Content-Length": Buffer.byteLength(text)
	});
	res.end(text);
}

function denyJson(res, status, message, extra) {
	json(res, status, { ok: false, error: message, ...extra });
}

/**
 * Pure role-gate decision, exported for tests. Only client-request envelopes
 * carry a `method` and are subject to role gating. Everything else is a
 * wire-protocol message — most importantly /api/respond, whose
 * client-response envelope answers a host server-request (approvals,
 * questions, tool results, subagent submissions…). Denying those broke the
 * respond channel for EVERY session (method === null fell into the deny
 * branch), which aborted pending host streams, forced a WebSocket reconnect,
 * and left the workspace/session baselines appearing wiped. Such envelopes
 * pass through (authenticated) with their body replayed untouched.
 * @param pathname - request pathname.
 * @param httpMethod - request method ("GET"/"POST"/…).
 * @param body - POST body buffer (null when not read / over the cap).
 * @param role - session role ("admin"/"user"/"guest").
 * @returns {allowed, body, replayed}.
 */
function evaluateRoleGate(pathname, httpMethod, body, role) {
	if (!pathname.startsWith("/api/")) return { allowed: true, body: null, replayed: false };
	if (pathname === "/api/file") return { allowed: role !== "guest", body: null, replayed: false };
	if (pathname === "/api/session.export") return { allowed: role !== "guest", body: null, replayed: false };
	if (httpMethod !== "POST") return { allowed: true, body: null, replayed: false };
	if (body === null) return { allowed: role !== "guest", body: null, replayed: false };
	let envelope;
	try {
		envelope = JSON.parse(body.toString("utf8"));
	} catch {
		return { allowed: false, body, replayed: true };
	}
	if (envelope?.type !== "client-request" || typeof envelope.method !== "string") {
		return { allowed: true, body, replayed: true };
	}
	// dsh ≥ 0.1.2-alpha names RPC endpoints `namespace/method` (slash) on the
	// wire while the deny lists above are dotted rc-era names — normalize the
	// separators before matching so role gating binds on both generations.
	const method = envelope.method.replaceAll("/", ".");
	if (NON_ADMIN_DENY.has(method)) return { allowed: false, body, replayed: true };
	if (role === "guest" && GUEST_DENY.has(method)) return { allowed: false, body, replayed: true };
	return { allowed: true, body, replayed: true };
}

/**
 * Answer a denied client-request with a WIRE-COMPLIANT server-response
 * envelope (HTTP 200) so the browser's connection layer parses a clean
 * business error instead of a transport/schema failure: the client validates
 * every /api body against serverResponseSchema
 * ({type,rpcId,result:{ok:false,error:{code,message,details}}}); a plain
 * denyJson body made every denied RPC (e.g. credentials.describe for a
 * `user` session) throw inside the client and broke flows downstream.
 * `error.code` must be one of the client schema's discriminated codes.
 */
function denyRpcEnvelope(res, requestBody, message) {
	let rpcId = null;
	try {
		const envelope = JSON.parse(requestBody.toString("utf8"));
		if (typeof envelope?.rpcId === "string") rpcId = envelope.rpcId;
	} catch {
		// unreadable request — emit with a null id rather than fail
	}
	json(res, 200, {
		type: "server-response",
		rpcId,
		result: { ok: false, error: { code: "internal", message, details: {} } }
	});
}

/** Buffer a request body up to `limit` bytes; null when it exceeds the cap. */
async function readBodyBounded(req, limit) {
	const chunks = [];
	let received = 0;
	for await (const chunk of req) {
		received += chunk.length;
		if (received > limit) return null;
		chunks.push(chunk);
	}
	return Buffer.concat(chunks);
}

/** Replay a fully-read request body through the same node:http request shape. */
function replayable(req, body) {
	const stream = Readable.from([body]);
	return new Proxy(req, {
		get(target, prop, receiver) {
			if (prop === Symbol.asyncIterator) return stream[Symbol.asyncIterator].bind(stream);
			const value = Reflect.get(target, prop, receiver);
			return typeof value === "function" ? value.bind(target) : value;
		}
	});
}

function readCookie(req, cookieName) {
	const header = req.headers.cookie;
	if (!header) return null;
	for (const part of header.split(";")) {
		const idx = part.indexOf("=");
		if (idx === -1) continue;
		if (part.slice(0, idx).trim() === cookieName) return part.slice(idx + 1).trim();
	}
	return null;
}

/** Loopback classification for the bootstrap endpoint (mirrors the /api fence). */
function isLoopbackRequest(req) {
	// Security: a Host header is attacker-controlled, so it can never be the only
	// signal. Require the TCP peer itself to be loopback AND the request to carry
	// no proxy forwarding headers — a real local browser sends none, while a
	// reverse proxy or tunnel always adds at least one.
	const peer = req.socket?.remoteAddress;
	const peerIsLoopback = peer === "127.0.0.1" || peer === "::1" || peer === "::ffff:127.0.0.1";
	if (!peerIsLoopback) return false;
	const headers = req.headers ?? {};
	// 任何反向代理/隧道都会留下痕迹。不能只列已知的几个名字 —— 攻击者只要发一个
	// 没被列出的头（Via / CF-Visitor / X-Forwarded-Proto / True-Client-IP ...）
	// 就能让"看起来是本机"成立。按前缀族枚举，宁可误拒。
	const proxyHeaderPrefixes = [
		"x-forwarded-", "cf-", "x-real-ip", "x-client-ip", "x-cluster-client-ip",
		"x-proxyuser-ip", "true-client-ip", "forwarded", "via", "proxy-",
		"x-bluecoat-", "x-wap-", "x-coming-from"
	];
	for (const name of Object.keys(headers)) {
		const lower = name.toLowerCase();
		if (proxyHeaderPrefixes.some((p) => lower === p || lower.startsWith(p))) return false;
	}
	// Host 必须是纯粹的 host[:port]。含 @ / ? # 空白一律视为非本机，
	// 否则 "127.0.0.1:3080@evil.example" 会被 split(":")[0] 误判成本机，
	// 而 canonicalAuthority() 得到的是 evil.example。
	const rawHost = String(headers.host ?? "");
	if (rawHost === "" || /[@/?#\s]/.test(rawHost)) return false;
	const hostMatch = /^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::\d{1,5})?$/.exec(rawHost);
	if (hostMatch === null) return false;
	const hostname = hostMatch[1].replace(/^\[|\]$/g, "").toLowerCase();
	if (hostname === "localhost" || hostname === "::1") return true;
	const parts = hostname.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

// ── response gzip / static cache helpers ───────────────────────────────────────
// These run AFTER authentication (the gate wraps `res` only for authed requests),
// and only for remote (non-loopback) original Host when `gzip.remoteOnly`.

/** Content-Types worth gzip-ing (lower-cased). Intentional narrow allow-list so
 *  binary and streaming responses are never wrongly compressed. */
const GZIP_TEXT_TYPES = new Set([
	"text/html",
	"text/css",
	"text/plain",
	"text/javascript",
	"application/javascript",
	"application/x-javascript",
	"application/json",
	"text/json",
	"image/svg+xml",
	"application/manifest+json",
]);

/** Request paths / URL features that resolve to rev-hashed static assets — safe
 *  to cache immutable + CDN-cache (mirrors dsh-web-remote's isCacheable). */
/** Request paths that resolve to rev-hashed static assets — safe to cache. */
function shouldCache(req) {
	const u = String(req.url ?? "");
	// Security: /api 与 /auth 永远不能下发"公开缓存"。
	// 原来只要 URL 里出现 rev= 就返回 true，于是
	//   GET /api/file?path=<私密文件>&rev=1
	// 会拿到 cache-control: public, max-age=31536000, immutable
	// 加 cdn-cache-control: public, max-age=86400，覆盖源站的 private,no-store
	// —— CDN 可能把它缓存下来回给未登录的人。
	if (u.startsWith("/api/") || u.startsWith("/auth/")) return false;
	if (u.startsWith("/assets/") || u.startsWith("/plugins/")) return true;
	if (u === "/favicon.svg" || u === "/manifest.webmanifest") return true;
	// rev= 只能作为附加指纹，且必须是像样的十六进制，不能单独决定可缓存。
	return /[?&]rev=[0-9a-f]{6,}/i.test(u);
}

/** Is a raw Host header value a loopback authority (localhost, [::1], 127.x)? */
function isLoopbackHostHeader(host) {
	const s = String(host ?? "").toLowerCase();
	// IPv6 loopback uses brackets, e.g. `[::1]` or `[::1]:3080`.
	if (s.startsWith("[")) return s.startsWith("[::1]");
	const hostname = s.split(":")[0];
	if (hostname === "localhost") return true;
	const parts = hostname.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/** Is the request's ORIGINAL Host (pre-fence rewrite) a remote, non-loopback host? */
function isRemoteOrigin(req) {
	return !isLoopbackHostHeader(req[ORIGINAL_HOST]);
}

/** Stash the raw Host before `normalizeForFence` rewrites it. Must be called
 *  BEFORE the fence normalization on the gated HTTP/fallback path. */
function captureOriginalHost(req) {
	req[ORIGINAL_HOST] = req.headers.host;
}

// ── dsh browser-session cookie minting (dsh ≥ 0.1.2-alpha, issue #10) ─────────
// dsh's client-connection plugin authenticates browsers with a persistent,
// Host-bound signed cookie (`dsh-auth-<sha256(authority)>`): the request Host
// selects the cookie name AND the payload `authority` must equal it. The
// functions below mirror packages/client/connection/src/browser-auth.ts
// (COOKIE_PAYLOAD_VERSION 1) so this plugin can mint cookies the core accepts.
// Pure helpers, exported for tests.

/** Credential record holding client-connection's persistent signing secret. */
const BROWSER_SESSION_RECORD_KEY = "client-connection/browser-session";

/** Cookie payload version minted/accepted by dsh core browser-auth v1. */
const BROWSER_COOKIE_VERSION = 1;
/** client-connection.cookieMaxAgeDays default — bounds any minted window. */
const BROWSER_COOKIE_MAX_AGE_DAYS_DEFAULT = 30;

/**
 * Canonical request authority exactly as dsh core derives it from a Host
 * header (WHATWG normalization: lowercased host, explicit port kept).
 * @returns {string|null} canonical `host[:port]`, or null when unparsable.
 */
function canonicalAuthority(host) {
	if (typeof host !== "string" || host === "") return null;
	try {
		return new URL(`http://${host}`).host;
	} catch {
		return null;
	}
}

/** Cookie name for an authority: `dsh-auth-` + base64url(sha256(authority)). */
function dshAuthCookieName(authority) {
	return "dsh-auth-" + createHash("sha256").update(authority).digest("base64url");
}

/**
 * Serialize one v1 browser-session cookie the way dsh core mints them.
 * @param {string} authority - bound authority (must match the request Host the core sees).
 * @param {Buffer} secret - client-connection's persisted signing secret (32 bytes).
 * @param {number} ttlMs - cookie window; the core rejects windows beyond cookieMaxAgeDays.
 * @param {number} [nowMs] - issuedAt override (tests).
 * @returns {{name: string, value: string, cookie: string}} name/value pair plus a full Set-Cookie line.
 */
function encodeDshAuthCookie(authority, secret, ttlMs, nowMs = Date.now()) {
	const issuedAt = nowMs;
	const expiresAt = issuedAt + ttlMs;
	const body = Buffer.from(JSON.stringify({
		version: BROWSER_COOKIE_VERSION,
		authority,
		issuedAt,
		expiresAt
	}), "utf8").toString("base64url");
	const sig = createHmac("sha256", secret).update(body).digest("base64url");
	const name = dshAuthCookieName(authority);
	const value = `v1.${body}.${sig}`;
	// Attribute set mirrors dsh core's sessionCookie() exactly.
	return { name, value, cookie: `${name}=${value}; Max-Age=${Math.floor(ttlMs / 1000)}; Path=/; Expires=${new Date(expiresAt).toUTCString()}; HttpOnly; SameSite=Strict` };
}

/**
 * Parse and verify one minted-or-core-minted cookie value (mirror of the
 * core's decodeCookie + isAuthenticated checks that matter to us).
 * @returns {object|null} payload when the signature, version, authority and window are live.
 */
function decodeDshAuthCookie(value, secret, authority, nowMs = Date.now()) {
	const parts = String(value ?? "").split(".");
	if (parts.length !== 3 || parts[0] !== "v1") return null;
	const [, body, sigB64] = parts;
	let sig, expected;
	try {
		sig = Buffer.from(sigB64, "base64url");
		expected = createHmac("sha256", secret).update(body).digest();
	} catch {
		return null;
	}
	if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null;
	let payload;
	try {
		payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
	} catch {
		return null;
	}
	if (payload?.version !== BROWSER_COOKIE_VERSION
		|| typeof payload.authority !== "string"
		|| !Number.isSafeInteger(payload.issuedAt)
		|| !Number.isSafeInteger(payload.expiresAt)) return null;
	if (payload.authority !== authority) return null;
	const maxAgeMs = BROWSER_COOKIE_MAX_AGE_DAYS_DEFAULT * 24 * 60 * 60 * 1000;
	return payload.issuedAt <= nowMs && payload.expiresAt > nowMs
		&& payload.expiresAt > payload.issuedAt
		&& payload.expiresAt - payload.issuedAt <= maxAgeMs ? payload : null;
}

/** Pull one cookie value out of a raw Cookie header (exact name match). */
function cookieValueOf(cookieHeader, name) {
	const header = String(cookieHeader ?? "");
	for (const segment of header.split(";")) {
		const at = segment.indexOf("=");
		if (at === -1 || segment.slice(0, at).trim() !== name) continue;
		return segment.slice(at + 1).trim();
	}
	return null;
}

/**
 * Validate the stored browser-session credential record and extract the
 * signing secret (mirror of the core's storedSecret/canonicalSecret).
 * @returns {Buffer|null} 32-byte HMAC key, or null when absent/malformed.
 */
function readBrowserAuthSecret(record) {
	if (record === null || typeof record !== "object") return null;
	if (record.kind !== "grant" || record.payload?.version !== 1) return null;
	const raw = record.payload.secret;
	if (typeof raw !== "string") return null;
	const secret = Buffer.from(raw, "base64url");
	return secret.byteLength === 32 ? secret : null;
}

/**
 * Does the request already carry a LIVE dsh-auth cookie for this authority?
 * Core-minted cookies (direct loopback `?token=` access) validate too — the
 * name, secret and authority are the same, so there is nothing to re-mint.
 */
function hasLiveDshAuthCookie(cookieHeader, authority, secret) {
	if (!authority || !secret) return false;
	const value = cookieValueOf(cookieHeader, dshAuthCookieName(authority));
	if (value === null) return false;
	return decodeDshAuthCookie(value, secret, authority) !== null;
}

/** Look up the effective content-type of a response from its resolved headers. */
function contentTypeOf(headers) {
	if (headers && typeof headers["content-type"] === "string") return headers["content-type"].split(";")[0].trim().toLowerCase();
	return "";
}

/** Decide whether a gated response should be gzip-compressed.
 *  @param remoteOnly - when true, only remote (non-loopback original Host) requests compress.
 *  @param minBytes - responses with a known Content-Length below this are skipped. */
function shouldGzip(req, status, headers, remoteOnly = true, minBytes = 1024) {
	if (status === 204 || status === 206 || status === 304) return false;
	if (remoteOnly && !isRemoteOrigin(req)) return false; // local direct access: no gzip
	if (String(req.headers["accept-encoding"] ?? "").indexOf("gzip") === -1) return false;
	if (headers && headers["content-encoding"]) return false; // already compressed
	const ctype = contentTypeOf(headers);
	if (ctype === "text/event-stream") return false; // SSE: streaming, never gzip
	let eligible = false;
	if (ctype === "") {
		// Content-Type absent: fall back to URL extension (.js/.css/.json/.map/...)
		const u = String(req.url ?? "").toLowerCase();
		eligible = /\.(?:js|mjs|cjs|css|json|map|svg|html)$/.test(u);
	} else {
		eligible = GZIP_TEXT_TYPES.has(ctype);
	}
	if (!eligible) return false;
	const len = headers && typeof headers["content-length"] === "string" ? Number(headers["content-length"]) : NaN;
	if (Number.isFinite(len) && len >= 0 && len < minBytes) return false; // too small
	return true;
}

/**
 * Wrap a node:http ServerResponse so that (a) gzip compression is applied to the
 * body when eligible, and (b) rev-hashed static assets get long-lived cache
 * headers. The real `writeHead` is deferred to the first `write`/`end` so the
 * decision can inspect the response headers before they are emitted. Only the
 * minimal surface (`writeHead`/`write`/`end`/`flushHeaders`/`destroy`) is
 * intercepted; everything else is forwarded to the real `res` via a Proxy so
 * `headersSent`, event listeners, `setTimeout`, `socket`, etc. behave normally.
 */
function makeGzipRes(res, req, cfg) {
	const minBytes = (cfg && cfg.minBytes) || 1024;
	const remoteOnly = !cfg || cfg.remoteOnly !== false;

	let statusCode = 200;
	let resolvedHeaders = null;   // merged headers seen in writeHead
	let gzip = null;              // null = undecided; then true/false
	let rawHeaders = null;        // headers to emit when NOT gzipped

	let gzStream = null;

	const emit = (finalHeaders) => {
		if (res.headersSent) return;
		res.writeHead(statusCode, finalHeaders);
	};

	const maybeStart = () => {
		// Decide once, at the first write/end, when the real headers are about to
		// go on the wire.
		if (gzip !== null) return;
		const eligible = shouldGzip(req, statusCode, resolvedHeaders, remoteOnly, minBytes);
		if (eligible) {
			gzip = true;
			gzStream = createGzip();
			gzStream.on("error", () => { try { res.destroy(); } catch { /* ignore */ } });
			// headers to emit: our own + the originals minus content-length
			const out = {};
			for (const [k, v] of Object.entries(resolvedHeaders || {})) {
				const lk = k.toLowerCase();
				if (lk === "content-length" || lk === "transfer-encoding" || lk === "connection" || lk === "keep-alive") continue;
				out[k] = v;
			}
			out["content-encoding"] = "gzip";
			if (out["vary"]) out["vary"] = String(out["vary"]).replace(/accept-encoding/gi, "").replace(/,{2,}/g, ",") + ", Accept-Encoding";
			else out["vary"] = "Accept-Encoding";
			// rev-hashed assets: long-lived caches (phone re-open is fast; CDN edge hits)
			if (shouldCache(req)) {
				out["cache-control"] = "public, max-age=31536000, immutable";
				out["cdn-cache-control"] = "public, max-age=86400";
			}
			emit(out);
			// Compressed bytes flow from the gzip stream into the client socket.
			// pipe() with default end:true calls res.end() when the gzip stream
			// finishes flushing its final block — this is what guarantees the
			// complete gzip trailer reaches the client.
			gzStream.pipe(res);
			// 客户端提前断开（关页面/切网）时 gzip 流不会自己停，会继续吃进内存。
			res.on("close", () => {
				if (gzStream !== null && !gzStream.destroyed) {
					try {
						gzStream.destroy();
					} catch {
						// ignore
					}
				}
			});
		} else {
			gzip = false;
			emit(rawHeaders ?? resolvedHeaders ?? {});
		}
	};

		const writeChunk = (chunk, encoding, cb) => {
		if (gzip) {
			// 背压必须真实反映 gzip 流的缓冲状态：DSH 的 /api 桥接层靠
			// res.write() 的返回值决定是否等 drain。原来无条件 return true，
			// 等于告诉桥接层可以无限写，整个响应体会堆在内存里
			// （实测产出 32MB 全部驻留、RSS 67MB 涨到 115MB）。
			// 这里返回 gzStream.write 的真实结果，并把 gzStream 的 drain 转发给
			// res，避免桥接层等一个永远不会来的事件。
			const accepted = gzStream.write(chunk, encoding, cb);
			if (!accepted && !gzStream.destroyed) {
				gzStream.once("drain", () => {
					try {
						res.emit("drain");
					} catch {
						// ignore
					}
				});
			}
			return accepted;
		}
		return res.write(chunk, encoding, cb);
	};

	const wrapper = {
		writeHead(status, headers, ...rest) {
			// Node allows writeHead(headers) with status 200 implicit; normalize.
			if (typeof status === "object" && status !== null) {
				headers = status;
				status = 200;
			}
			statusCode = status;
			const h = Object.assign({}, headers ?? {});
			resolvedHeaders = Object.assign({}, resolvedHeaders ?? {}, h);
			// Keep original headers (pre-rewrite) so non-gzipped responses match DSH.
			rawHeaders = Object.assign({}, rawHeaders ?? {}, h);
			// Don't emit yet — decide at first write/end.
			return res;
		},
		flushHeaders() {
			maybeStart();
			if (!gzip) res.flushHeaders();
		},
		write(chunk, encoding, cb) {
			maybeStart();
			return writeChunk(chunk, encoding, cb);
		},
		end(chunk, encoding, cb) {
			maybeStart();
			if (gzip) {
				// Ending the gzip stream flushes its final block; the pipe (default
				// end:true) then calls res.end() once the full trailer is delivered.
				if (chunk !== undefined && chunk !== null) gzStream.end(chunk, encoding, cb);
				else gzStream.end();
				return res;
			}
			if (chunk !== undefined && chunk !== null) return res.end(chunk, encoding, cb);
			return res.end();
		},
		destroy(...args) {
			if (gzStream) { try { gzStream.destroy(); } catch { /* ignore */ } }
			return res.destroy(...args);
		},
	};

	return new Proxy(res, {
		get(target, prop, receiver) {
			if (prop in wrapper) return wrapper[prop];
			const value = Reflect.get(target, prop, receiver);
			return typeof value === "function" ? value.bind(target) : value;
		},
		set(target, prop, value, receiver) {
			return Reflect.set(target, prop, value, receiver);
		},
	});
}

/** Resolve the effective allowed roots (realpaths; unreadable roots drop out). */
function fileRootsFor(extraRoots = []) {
	const candidates = [dshHomePath(), process.cwd(), ...extraRoots];
	const roots = [];
	for (const candidate of candidates) {
		if (typeof candidate !== "string" || candidate === "") continue;
		try {
			const real = realpathSync(resolve(candidate));
			if (!roots.includes(real)) roots.push(real);
		} catch {
			// root does not exist / unreadable — skip it
		}
	}
	return roots;
}

// ── .docx text extraction (in-app viewer panel) ───────────────────────────────
// A .docx is a ZIP of XML; the panel only needs the words. This is a
// dependency-free best effort: parse the central directory, inflate
// word/document.xml (Node's own zlib), turn paragraph ends into newlines and
// strip the remaining tags. Formatting is lost, content survives. Old `.doc`
// (OLE binary) is NOT supported — those stay download-only.

/** Maximum .docx source accepted for extraction (larger → download only). */
const DOCX_EXTRACT_MAX_BYTES = 64 * 1024 * 1024;
/** Cap on the extracted text served to the browser. */
const DOCX_EXTRACT_MAX_CHARS = 2 * 1024 * 1024;

const ZIP_EOCD_SIG = 0x06054b50;
const ZIP_CD_SIG = 0x02014b50;
const ZIP_LFH_SIG = 0x04034b50;

/**
 * Parse one ZIP central directory (no ZIP64 / encryption / data descriptors).
 * @param {Buffer} buf - the ZIP file bytes.
 * @returns {Map<string, {method: number, dataStart: number, compSize: number}> | null}
 *   entry name → compression method (0 stored / 8 deflate), payload start and
 *   payload size; null on any structural surprise.
 */
export function zipEntries(buf) {
	try {
		// Locate the End Of Central Directory record (comment ≤ 64 KiB).
		let eocd = -1;
		const minEocd = Math.max(0, buf.length - 22 - 65535);
		for (let i = buf.length - 22; i >= minEocd; i--) {
			if (buf.readUInt32LE(i) === ZIP_EOCD_SIG) {
				eocd = i;
				break;
			}
		}
		if (eocd < 0) return null;
		const count = buf.readUInt16LE(eocd + 10);
		let ptr = buf.readUInt32LE(eocd + 16);
		const entries = new Map();
		for (let n = 0; n < count; n++) {
			if (ptr + 46 > buf.length || buf.readUInt32LE(ptr) !== ZIP_CD_SIG) return null;
			const method = buf.readUInt16LE(ptr + 10);
			const compSize = buf.readUInt32LE(ptr + 20);
			const nameLen = buf.readUInt16LE(ptr + 28);
			const extraLen = buf.readUInt16LE(ptr + 30);
			const commentLen = buf.readUInt16LE(ptr + 32);
			const lfhOffset = buf.readUInt32LE(ptr + 42);
			const name = buf.slice(ptr + 46, ptr + 46 + nameLen).toString("utf8");
			// The local header repeats its own name/extra lengths.
			if (lfhOffset + 30 > buf.length || buf.readUInt32LE(lfhOffset) !== ZIP_LFH_SIG) return null;
			const lfhNameLen = buf.readUInt16LE(lfhOffset + 26);
			const lfhExtraLen = buf.readUInt16LE(lfhOffset + 28);
			entries.set(name, {
				method,
				compSize,
				dataStart: lfhOffset + 30 + lfhNameLen + lfhExtraLen
			});
			ptr += 46 + nameLen + extraLen + commentLen;
		}
		return entries;
	} catch {
		return null;
	}
}

/**
 * Extract human-readable plain text from a .docx buffer.
 * @param {Buffer} buf - the whole .docx file.
 * @returns {string | null} the extracted text (capped), null when the
 *   document is too large, not a readable ZIP, or carries no main part.
 */
export function extractDocxText(buf) {
	try {
		if (!(buf instanceof Buffer) || buf.length === 0 || buf.length > DOCX_EXTRACT_MAX_BYTES) return null;
		const entries = zipEntries(buf);
		const entry = entries && entries.get("word/document.xml");
		if (!entry) return null;
		const payload = buf.slice(entry.dataStart, entry.dataStart + entry.compSize);
		let xml;
		if (entry.method === 0) xml = payload;
		else if (entry.method === 8) xml = inflateRawSync(payload);
		else return null;
		const text = xml.toString("utf8")
			.replace(/<w:tab\b[^>]*\/?>/g, "\t")
			.replace(/<w:br\b[^>]*\/?>/g, "\n")
			.replace(/<\/w:p>/g, "\n")
			.replace(/<[^>]+>/g, "")
			.replace(/&lt;/g, "<")
			.replace(/&gt;/g, ">")
			.replace(/&quot;/g, "\"")
			.replace(/&apos;/g, "'")
			.replace(/&amp;/g, "&");
		return text.length > DOCX_EXTRACT_MAX_CHARS
			? text.slice(0, DOCX_EXTRACT_MAX_CHARS) + "\n…"
			: text;
	} catch {
		return null;
	}
}

/**
 * Is a requested absolute path inside one of the allowed roots (DSH home,
 * process cwd, plus `extraRoots`)? Symlink escapes are neutralized by
 * comparing realpaths. Exported for tests.
 *
 * Windows note: the filesystem is case-insensitive but realpath returns one
 * canonical spelling, so a root configured as `E:\CODE` may realpath to
 * `E:\code`. Comparisons are therefore case-folded on win32 (override via
 * options.caseInsensitive for tests on case-sensitive hosts).
 * @returns {ok, real, reason} — reason is a stable short code for tests.
 */
function checkFilePathAgainst(rawPath, extraRoots = [], options = {}) {
	if (typeof rawPath !== "string" || rawPath.trim() === "") return { ok: false, reason: "no-path" };
	const resolved = resolve(rawPath);
	let real;
	try {
		real = realpathSync(resolved);
	} catch {
		return { ok: false, reason: "not-found" };
	}
	let st;
	try {
		st = statSync(real);
	} catch {
		return { ok: false, reason: "not-found" };
	}
	if (!st.isFile() && !st.isDirectory()) return { ok: false, reason: "not-a-file" };
	const roots = fileRootsFor(extraRoots);
	const caseInsensitive = options.caseInsensitive ?? process.platform === "win32";
	const norm = caseInsensitive ? (p) => p.toLowerCase() : (p) => p;
	const inside = roots.some((root) => norm(real) === norm(root) || norm(real).startsWith(norm(root) + sep));
	if (!inside) return { ok: false, reason: "outside-roots" };
	return { ok: true, real, isDirectory: st.isDirectory(), size: st.isFile() ? st.size : undefined };
}

// ── plugin ────────────────────────────────────────────────────────────────────

function applyInner(ctx, config) {
	const cfg = config;
	// 本加固版只支持单管理员模式。
	// adminOnly=false 会打开 guest / user 角色，而这两条路尚未加固：
	//   - core 的 POST /open-in-app/open 不在 /api/* 角色门的覆盖范围内
	//   - wrapUpgrade 只校验登录、不校验角色
	// 与其留一个"改个配置就多出攻击面"的开关，不如直接锁死。
	if (cfg.adminOnly !== true) {
		ctx.logger.warn("[dsh-remote] adminOnly=false is unsupported in this hardened build; forcing admin-only mode");
		cfg.adminOnly = true;
	}
	const store = new AccountStore(config.storePath ?? defaultStorePath());
	store.load();
	// Security: 有账号但一个 admin 都没有 = 谁都管不了的死局
	// （protected 账号被禁止改角色，自救路也堵死）。直接抛错，交给 apply 的 fail-closed 兜底。
	if (store.list().length > 0 && store.countAdmins() === 0) {
		throw new Error("dsh-remote: account store has no admin; refusing to activate (repair store.json or delete it to re-bootstrap)");
	}
	// One-time session-secret rotation request. An operator drops
	// <store dir>/.rotate-session-secret and restarts; the secret is replaced here,
	// at boot, before any session can be served — the only moment where rotating
	// cannot race a live process (each successful login persists the in-memory
	// secret, so an out-of-band file edit would simply be overwritten).
	const rotateRequest = join(dirname(store.path), ".rotate-session-secret");
	if (existsSync(rotateRequest)) {
		store.rotateSecret();
		safeSave();
		try {
			rmSync(rotateRequest, { force: true });
		} catch {
			// best effort: a leftover marker would rotate again on the next boot
		}
		ctx.logger.warn("[dsh-remote] session signing secret rotated — every existing session is now invalid");
	}
	// Runtime-editable allowed-file roots (the settings UI's "允许的目录"):
	// layered on top of config `files.roots`. Loosely coupled to the account
	// store — same file-store conventions, separate file.
	const filesRoots = new FilesRootsStore(config.filesRootsPath ?? filesRootsPath());
	filesRoots.load();
	// 审计日志 + 会话注册表：与账号库同目录，均 0600。
	const authDir = dirname(store.path);
	const audit = new AuditLog(join(authDir, "audit.jsonl"));
	const sessions = new SessionRegistry(join(authDir, "sessions.json")).load();
	// 账号库目录在建库时就存在了，mkdir 的 mode 只在创建时生效，这里补一次收紧。
	try {
		chmodSync(authDir, 0o700);
	} catch {
		// 非本人所有或只读挂载：保持原样
	}
	/** 请求上下文：真实客户端 IP（经反代时取转发头）+ UA。 */
	const requestContext = (req) => ({
		ip: clientIp(req),
		ua: String(req.headers?.["user-agent"] ?? "").slice(0, 200)
	});
	// 限流事件按 key 节流：否则攻击者可以用无限次 429 把审计日志刷爆轮转。
	const limitedAuditAt = new Map();
	const auditLimited = (key, entry) => {
		const now = Date.now();
		const last = limitedAuditAt.get(key);
		if (last !== undefined && now - last < 60_000) return;
		if (limitedAuditAt.size > 512) limitedAuditAt.clear();
		limitedAuditAt.set(key, now);
		audit.append(entry);
	};
	/**
	 * 落盘失败绝不能抛：这些 handler 是同步的，抛出去会让请求挂起并触发
	 * unhandledRejection。失败时内存态仍有效，只是重启后会丢（审计里仍有记录）。
	 * 用函数声明以便在 applyInner 内任意位置调用。
	 *
	 * 必须写成 store["save"]()：构建脚本会全局替换 safeSave(); → safeSave();，
	 * 若这里写成普通调用形式，函数体会被替换成自递归、账号库将永不落盘。
	 */
	function safeSave() {
		try {
			store["save"]();
			return true;
		} catch {
			return false;
		}
	}

	// Seed accounts from the composition (plaintext passwords are hashed once
	// and persisted; existing store entries are never overwritten). In
	// admin-only mode every seeded account is forced to the admin role.
	for (const seed of cfg.accounts) {
		if (store.find(seed.username)) continue;
		const passwordHash = seed.password.startsWith("scrypt$") ? seed.password : hashPasswordSync(seed.password);
		// Security: 第一个账号必须是 admin。否则会造出 "protected 但非 admin" 的根账号，
		// 之后既没有管理员可用、protected 又被禁止改角色，只能手改 store.json 才能救。
		const firstAccount = store.list().length === 0;
		store.upsert({
			username: seed.username,
			role: firstAccount ? "admin" : (cfg.adminOnly ? "admin" : seed.role),
			passwordHash
		});
	}

	// Config bootstrap (headless servers): the browser bootstrap endpoint is
	// loopback-only, so a Linux box without a local browser cannot create the
	// first admin through the UI. Declaring credentials in the composition
	// provisions the root admin here instead — idempotent, and the first
	// account of an empty store is protected exactly like a UI bootstrap.
	const boot = cfg.bootstrap;
	if (boot?.username && boot?.password) {
		if (store.hasAccounts) {
			ctx.logger.warn("[dsh-remote] bootstrap config ignored: accounts already exist — remove the credentials from cordis.patch.yml");
		} else {
			const username = String(boot.username).trim();
			if (!username) throw new Error("dsh-remote: bootstrap.username must not be empty");
						const bootProblem = passwordProblem(username, String(boot.password));
			if (bootProblem !== null) {
				throw new Error("dsh-remote: bootstrap.password rejected: " + passwordProblemMessage(bootProblem, "en"));
			}
			store.upsert({ username, role: "admin", passwordHash: hashPasswordSync(String(boot.password)) });
			ctx.logger.info("[dsh-remote] bootstrapped first admin account %q from config — remove the credentials from cordis.patch.yml after first login", username);
		}
	}
	safeSave();

	// 生效密钥必须同时受 cfg.secret 与 store.secret 影响：
	// 否则配置了 cfg.secret 时 .rotate-session-secret 完全空转（标记被消费、
	// store 里的 secret 被换、日志声称全部会话已失效，但签名仍用 cfg.secret，
	// 一个会话都没失效）—— 事故止血会变成假动作。
	const secret = cfg.secret && cfg.secret.length >= 32
		? hmac(cfg.secret, store.secret).toString("base64url")
		: store.secret;
	const webServer = ctx.webServer;

	// ── dsh browser-session cookie minting (issue #10) ──────────────────────────
	// On dsh ≥ 0.1.2-alpha, /api and index.html are gated behind a persistent
	// Host-bound cookie minted by client-connection's browserAuth. Remote
	// browsers can never hold the cookie bound to the loopback authority the
	// gate normalizes requests to (and never hold the launch token to mint
	// it), so this plugin mints the cookies itself, signed with the SAME
	// persisted secret client-connection uses. The `credentials` service does
	// not exist on every dsh build/runtime this plugin supports, so it is
	// resolved opportunistically — when absent, minting stays off and
	// behavior is exactly the pre-fix one.
	let credentialsProvider = null;
	try {
		ctx.inject(["credentials"], (credCtx) => {
			credentialsProvider = credCtx.credentials ?? null;
		});
	} catch {
		// Older runtimes without context.inject semantics: stay mint-free.
	}

	/** Authority the CORE sees on gated HTTP/upgrade requests (post-normalization). */
	const gatedAuthority = () => (cfg.trustProxy
		? `127.0.0.1:${webServer.port ?? "3080"}`
		: null);
	/** Authority the CORE sees on fallback/index requests (never normalized). */
	const originalAuthority = (req) => canonicalAuthority(req[ORIGINAL_HOST] ?? req.headers.host);

	// Secret cache: the record lives in credentials-local's memory map, but the
	// provider may back onto disk/IPC, so keep a short positive TTL; a negative
	// probe (old dsh without the record) backs off much longer.
	let secretCache = null;
	let lastMissAt = 0;
	const SECRET_POSITIVE_TTL_MS = 30 * 1000;
	const SECRET_MISS_TTL_MS = 5 * 60 * 1000;
	const browserAuthSecret = async () => {
		if (!cfg.browserAuth.enabled || credentialsProvider === null) return null;
		const now = Date.now();
		if (secretCache !== null && now - secretCache.at < SECRET_POSITIVE_TTL_MS) return secretCache.value;
		if (now - lastMissAt < SECRET_MISS_TTL_MS) return null;
		try {
			const record = await credentialsProvider.readRecord(BROWSER_SESSION_RECORD_KEY);
			const value = readBrowserAuthSecret(record);
			if (value !== null) {
				secretCache = { value, at: now };
				return value;
			}
		} catch {
			// Provider differences must never break the request path.
		}
		lastMissAt = now;
		return null;
	};

	/** Minted-cookie window: config override, else follow the session TTL. */
	const cookieTtlMs = () => {
		const seconds = cfg.browserAuth.cookieTtlSeconds > 0
			? cfg.browserAuth.cookieTtlSeconds
			: cfg.session.ttlSeconds;
		// The core hard-rejects windows beyond its cookieMaxAgeDays (30 by
		// default) — stay inside that bound no matter how session TTL is set.
		return Math.min(seconds, BROWSER_COOKIE_MAX_AGE_DAYS_DEFAULT * 24 * 60 * 60) * 1000;
	};

	/**
	 * Append one Set-Cookie header unless the request already carries a live
	 * dsh-auth cookie for `authority` (core-minted or our own). Safe to call
	 * with the raw res or the gzip wrapper — both forward setHeader-time
	 * headers into writeHead — and a no-op while headers are already sent.
	 */
	const ensureDshAuthCookie = async (res, req, authority) => {
		if (authority === null || res.headersSent) return;
		const mintedSecret = await browserAuthSecret();
		if (mintedSecret === null) return;
		if (hasLiveDshAuthCookie(req.headers.cookie, authority, mintedSecret)) return;
		const { cookie } = encodeDshAuthCookie(authority, mintedSecret, cookieTtlMs());
		res.appendHeader?.("Set-Cookie", cookie);
	};

	/**
	 * Login/bootstrap/MFA success: hand the browser every dsh-auth cookie the
	 * core may demand from it — one bound to the original (public) Host for
	 * the fallback/index path, and (when the gate normalizes) one bound to the
	 * loopback authority for /api and the WebSocket upgrade.
	 */
	const setLoginDshAuthCookies = async (req, res) => {
		if (!cfg.browserAuth.enabled) return;
		const mintedSecret = await browserAuthSecret();
		if (mintedSecret === null) return;
		const original = originalAuthority(req);
		const loopback = gatedAuthority();
		const authorities = original === null ? [] : [original];
		if (loopback !== null && loopback !== original) authorities.push(loopback);
		for (const authority of authorities) {
			const { cookie } = encodeDshAuthCookie(authority, mintedSecret, cookieTtlMs());
			res.appendHeader?.("Set-Cookie", cookie);
		}
	};

	// ── session signing ─────────────────────────────────────────────────────────
	const issueSession = (account, ctx = {}) => {
		// 会话入库：只有登记过的 sid 才会被 requireAuth 接受，因此可以单独吊销。
		const sid = sessions.create({
			username: account.username,
			ip: ctx.ip,
			ua: ctx.ua,
			ttlMs: cfg.session.ttlSeconds * 1000
		});
		const payload = {
			sub: account.username,
			role: account.role ?? "user",
			// Security: binds the session to the account's credential generation, so a
			// password reset / role change / MFA removal retires it (see requireAuth).
			epoch: account.sessionEpoch ?? 0,
			sid,
			iat: Date.now(),
			exp: Date.now() + cfg.session.ttlSeconds * 1000
		};
		const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
		const sig = hmac(secret, `v1.${encoded}`).toString("base64url");
		return `v1.${encoded}.${sig}`;
	};

	const verifySession = (token) => {
		const parts = String(token).split(".");
		if (parts.length !== 3 || parts[0] !== "v1") return null;
		const [, encoded, sigB64] = parts;
		const expected = hmac(secret, `v1.${encoded}`);
		let sig;
		try {
			sig = Buffer.from(sigB64, "base64url");
		} catch {
			return null;
		}
		if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null;
		let payload;
		try {
			payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
		} catch {
			return null;
		}
		if (typeof payload?.sub !== "string" || typeof payload?.exp !== "number" || payload.exp <= Date.now()) return null;
		const role = payload.role === "admin" || payload.role === "guest" ? payload.role : "user";
		return { username: payload.sub, role, epoch: typeof payload.epoch === "number" ? payload.epoch : 0, sid: typeof payload.sid === "string" ? payload.sid : "" };
	};

	const requireAuth = (req) => {
		const token = readCookie(req, cfg.session.cookieName);
		if (!token) return { ok: false };
		const session = verifySession(token);
		if (!session) return { ok: false };
		// A removed account must not keep working through a stale cookie.
		const account = store.find(session.username);
		if (!account) return { ok: false };
		// Security: a credential or authority change bumps the account's session
		// epoch, which retires every session issued before it.
		if ((account.sessionEpoch ?? 0) !== (session.epoch ?? 0)) return { ok: false };
		// 会话必须在注册表里，且必须属于 token 里的这个账号（被单独吊销的 sid 立即失效）。
		if (!sessions.has(session.sid, session.username)) return { ok: false };
		sessions.touch(session.sid);
		return { ok: true, user: { username: account.username, role: account.role ?? "user" }, sid: session.sid };
	};

	// ── MFA challenge tokens (second login step) ────────────────────────────────
	// A signed, short-lived, single-use token proving the password step already
	// passed; replay is prevented with an in-memory consumed-nonce set. The
	// token is consumed ONLY on a successful code — a wrong code must be able
	// to retry with the same challenge.
	const consumedMfaNonces = new Set();
	const MFA_TOKEN_TTL_MS = 5 * 60 * 1000;

	const issueMfaToken = (username, epoch = 0) => {
		const nonce = randomUUID();
		const payload = { purpose: "mfa", sub: username, nonce, epoch, exp: Date.now() + MFA_TOKEN_TTL_MS };
		const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
		const sig = hmac(secret, `mfa.${encoded}`).toString("base64url");
		return `mfa.${encoded}.${sig}`;
	};

	/** Verify a challenge without consuming it (returns the nonce too). */
	const verifyMfaToken = (token) => {
		const parts = String(token).split(".");
		if (parts.length !== 3 || parts[0] !== "mfa") return null;
		const [, encoded, sigB64] = parts;
		const expected = hmac(secret, `mfa.${encoded}`);
		let sig;
		try {
			sig = Buffer.from(sigB64, "base64url");
		} catch {
			return null;
		}
		if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null;
		let payload;
		try {
			payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
		} catch {
			return null;
		}
		if (payload?.purpose !== "mfa" || typeof payload?.sub !== "string" || typeof payload?.nonce !== "string") return null;
		if (typeof payload?.exp !== "number" || payload.exp <= Date.now()) return null;
		if (consumedMfaNonces.has(payload.nonce)) return null;
		return { username: payload.sub, nonce: payload.nonce, epoch: typeof payload.epoch === "number" ? payload.epoch : 0 };
	};

	/** Mark a challenge consumed (single use) after a successful code. */
	const consumeMfaToken = (nonce) => {
		consumedMfaNonces.add(nonce);
		for (const used of consumedMfaNonces) {
			if (consumedMfaNonces.size <= 256) break;
			consumedMfaNonces.delete(used);
		}
	};

	const setSessionCookie = (res, token) => {
		const c = cfg.session;
		const parts = [`${c.cookieName}=${token}`, "Path=/", "HttpOnly", `Max-Age=${c.ttlSeconds}`, `SameSite=${c.sameSite}`];
		if (c.secure) parts.push("Secure");
		res.setHeader("Set-Cookie", parts.join("; "));
	};

	const clearSessionCookie = (res) => {
		const c = cfg.session;
		const parts = [`${c.cookieName}=`, "Path=/", "HttpOnly", "Max-Age=0", `SameSite=${c.sameSite}`];
		if (c.secure) parts.push("Secure");
		res.setHeader("Set-Cookie", parts.join("; "));
	};

	// ── rate limiting ───────────────────────────────────────────────────────────
	// Two buckets are tracked per attempt:
	//   u|<clientIp>|<username>  — the per-attacker credential limit
	//   s|<clientIp>             — a per-source aggregate, so one source cannot
	//                              spray a different username on every request
	//
	// The client IP comes from the forwarding headers ONLY when the TCP peer is
	// loopback (a local reverse proxy or tunnel); a direct connection is always
	// identified by its socket address. Without that distinction every request
	// arriving through a local tunnel collapses into one 127.0.0.1 bucket, and any
	// remote visitor could lock an account out by burning its attempts.
	const attempts = new Map();
	/** Hard cap on tracked keys: the map must never grow without bound. */
	const MAX_ATTEMPT_KEYS = 4096;
	/** Longest username component we will ever key on. */
	const MAX_ATTEMPT_USERNAME = 64;
	/** Per-source aggregate allowance per window, across all usernames. */
	const sourceAttemptLimit = () => Math.max(cfg.rateLimit.maxAttempts * 4, 20);
	/** A throwaway scrypt hash used to equalize login timing (see handleLogin). */
	const DUMMY_PASSWORD_HASH = hashPasswordSync(randomUUID());

	const peerIsLoopback = (req) => {
		const address = req.socket?.remoteAddress;
		return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
	};
	/** Effective client identity for rate limiting. */
	const clientIp = (req) => {
		// 转发头由客户端控制，长度必须设上限：否则 16KB 的 X-Forwarded-For 会撑大
		// 限流表的 key 与审计字段（真实 IP 远短于 64 字符）。
		if (peerIsLoopback(req)) {
			const headers = req.headers ?? {};
			for (const header of ["cf-connecting-ip", "x-forwarded-for", "x-real-ip"]) {
				const raw = String(headers[header] ?? "").split(",")[0].trim().slice(0, 64);
				if (raw !== "") return raw;
			}
		}
		return String(req.socket?.remoteAddress ?? "unknown").slice(0, 64);
	};
	/** Both buckets an attempt counts against, in [credential, source] order. */
	const rateKeys = (req, username) => {
		const ip = clientIp(req);
		const name = String(username ?? "").trim().slice(0, MAX_ATTEMPT_USERNAME);
		// Security: 凭据桶必须与 IP 无关。
		// IP 来自 cf-connecting-ip / x-forwarded-for，是客户端可写的；把它放进 key
		// 就等于"换个头换一个桶"，限流形同虚设（实测每请求换 cf-connecting-ip：
		// 30 次跨用户名喷射 0 次 429；固定 IP 时第 21 次就 429）。
		// 代价：知道用户名的人可以故意输错 5 次把该账号锁 15 分钟。
		// 对公网管理面板这个取舍值得（被爆破的后果远大于短暂锁不上）。
		// 源桶保留 IP 维度，作为"整条出口"的辅助兜底。
		return ["u|" + name, "s|" + ip];
	};
	/** Drop expired entries, then oldest first, until the map is back under the cap. */
	const pruneAttempts = (now) => {
		for (const [key, entry] of attempts) if (entry.resetAt <= now) attempts.delete(key);
		while (attempts.size > MAX_ATTEMPT_KEYS) {
			const oldest = attempts.keys().next();
			if (oldest.done) break;
			attempts.delete(oldest.value);
		}
	};
	const checkRate = (key, limit) => {
		const now = Date.now();
		const entry = attempts.get(key);
		if (entry === undefined || entry.resetAt <= now) return { ok: true };
		if (entry.count >= limit) return { ok: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
		return { ok: true };
	};
	const recordFailure = (key) => {
		const now = Date.now();
		if (attempts.size >= MAX_ATTEMPT_KEYS) pruneAttempts(now);
		const entry = attempts.get(key);
		if (entry === undefined || entry.resetAt <= now) attempts.set(key, { count: 1, resetAt: now + cfg.rateLimit.windowMs });
		else entry.count += 1;
	};
	const clearRate = (key) => attempts.delete(key);
	/**
	 * Check both buckets without consuming them.
	 * @returns {{ok: boolean, retryAfter?: number, credentialKey: string, sourceKey: string}}
	 */
	const takeRate = (req, username) => {
		const [credentialKey, sourceKey] = rateKeys(req, username);
		const credential = checkRate(credentialKey, cfg.rateLimit.maxAttempts);
		const source = checkRate(sourceKey, sourceAttemptLimit());
		const blocked = credential.ok ? (source.ok ? null : source) : credential;
		return {
			ok: blocked === null,
			retryAfter: blocked === null ? 0 : blocked.retryAfter,
			credentialKey,
			sourceKey
		};
	};

	// ── role gating on /api ─────────────────────────────────────────────────────
	// Returns { allowed, body, replayed }: when `replayed` is true the request
	// body was consumed for method inspection and must be replayed.
	const roleGate = async (req, role) => {
		const pathname = pathnameOf(req);
		const body = req.method === "POST"
			? await readBodyBounded(req, 16 * 1024 * 1024)
			: null;
		return evaluateRoleGate(pathname, req.method, body, role);
	};

	// ── the gate ────────────────────────────────────────────────────────────────
	/**
	* Normalize an authenticated request's Host/Origin to the loopback
	* authority so the connection plugin's browser-trust fence accepts it.
	* Mutates the IncomingMessage headers in place; the bridge copies them into
	* the fetch Request, and the upgrade handlers read them directly.
	*/
	const normalizeForFence = (req) => {
		if (!cfg.trustProxy) return;
		const authority = `127.0.0.1:${webServer.port ?? "3080"}`;
		if (typeof req.headers.host === "string") req.headers.host = authority;
		if (typeof req.headers.origin === "string" && req.headers.origin !== "") {
			let scheme = "http";
			try {
				scheme = new URL(req.headers.origin).protocol.replace(/:$/, "");
			} catch {
				// keep http
			}
			req.headers.origin = `${scheme}://${authority}`;
		}
	};

	const wrapHttp = (handler) => {
		if (typeof handler !== "function" || handler[GATED]) return handler;
		const gated = async (req, res) => {
			if (isPublicPath(pathnameOf(req))) return handler(req, res);
			captureOriginalHost(req);
			const verdict = requireAuth(req);
			if (!verdict.ok) {
				denyJson(res, 403, "unauthorized");
				return;
			}
			let outRes = res;
			if (cfg.gzip.enabled) {
				outRes = makeGzipRes(res, req, cfg.gzip);
			}
			normalizeForFence(req);
			// Self-heal the dsh browser-session cookie (issue #10): sessions
			// created before this fix — or browsers whose minted cookie was
			// evicted — carry only dsh_session, so the core's browserAuth
			// 401s every /api call. Appending the minted cookie onto THIS
			// response repairs the jar; the browser's next call succeeds.
			await ensureDshAuthCookie(outRes, req, gatedAuthority() ?? originalAuthority(req));
			// Security: 核心的 /api/file 只校验"是绝对路径"、不限根，而且
			// evaluateRoleGate 对所有非 POST 的 /api 请求放行 —— guest 也能读。
			// 这里把它接到插件自己的 checkFilePath（含账号库目录否决），并留审计。
			if (pathnameOf(req) === "/api/file") {
				let requested = null;
				try {
					requested = new URL(req.url ?? "/", "http://dsh.internal").searchParams.get("path");
				} catch {
					requested = null;
				}
				const fileVerdict = requested === null ? { ok: false, reason: "no-path" } : checkFilePath(requested, effectiveExtraRoots());
				if (!fileVerdict.ok) {
					audit.append({
						event: "file-read-denied",
						username: verdict.user.username,
						...requestContext(req),
						detail: "core /api/file " + String(fileVerdict.reason ?? "")
					});
					denyJson(res, 403, `cannot read file (${fileVerdict.reason})`);
					return;
				}
				audit.append({ event: "file-read", username: verdict.user.username, ...requestContext(req), detail: "core /api/file" });
			}			if (cfg.enforceRoles && verdict.user.role !== "admin") {
				const gate = await roleGate(req, verdict.user.role);
				if (!gate.allowed) {
					denyRpcEnvelope(outRes, gate.body, "forbidden for role " + verdict.user.role);
					return;
				}
				if (gate.replayed) return handler(replayable(req, gate.body), outRes);
			}
			return handler(req, outRes);
		};
		Object.defineProperty(gated, GATED, { value: true });
		wrappedOriginals.set(gated, handler);
		return gated;
	};

	const wrapUpgrade = (handler) => {
		if (typeof handler !== "function" || handler[GATED]) return handler;
		const gated = (req, socket, head) => {
			if (!requireAuth(req).ok) {
				socket.destroy();
				return;
			}
			normalizeForFence(req);
			return handler(req, socket, head);
		};
		Object.defineProperty(gated, GATED, { value: true });
		wrappedOriginals.set(gated, handler);
		return gated;
	};

	const wrapFallback = (handler) => {
		if (typeof handler !== "function" || handler[GATED]) return handler;
		const gated = async (req, res) => {
			if (!requireAuth(req).ok) {
				if (req.method === "GET" || req.method === "HEAD") {
					const pathname = pathnameOf(req);
					// i18n: prefer the app-level language preference (the same
					// value the DSH shell follows); otherwise fall back to the
					// browser's Accept-Language (zh for any zh-* tag, else en).
					const lang = readLocalePreference()
						?? (/^zh/i.test(req.headers?.["accept-language"] ?? "") ? "zh" : "en");
					// Security headers for the unauthenticated login surface:
					//   frame-ancestors/X-Frame-Options — the credential form must not be
					//     embeddable (UI-redress / overlay phishing);
					//   CSP — the page is fully self-contained (inline style + script,
					//     one data: QR image, same-origin fetch), so nothing else is needed;
					//   nosniff / no-referrer — cheap hardening for a page that renders
					//     attacker-influenced input (the requested path) back into HTML.
					res.writeHead(200, {
						"Content-Type": "text/html; charset=utf-8",
						"Cache-Control": "no-store",
						"X-Frame-Options": "DENY",
						"X-Content-Type-Options": "nosniff",
						"Referrer-Policy": "no-referrer",
						"Content-Security-Policy": [
							"default-src 'none'",
							"style-src 'unsafe-inline'",
							"script-src 'unsafe-inline'",
							"img-src data:",
							"connect-src 'self'",
							"form-action 'self'",
							"base-uri 'none'",
							"frame-ancestors 'none'"
						].join("; ")
					});
					res.end(renderLoginPage({
						bootstrap: !store.hasAccounts,
						next: (() => {
							// 保留 query，但只接受站内绝对路径，挡掉 //host 这种协议相对跳转。
							const raw = String(req.url ?? "/");
							if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return pathname;
							return raw;
						})(),
						lang
					}));
					return;
				}
				denyJson(res, 403, "unauthorized");
				return;
			}
			// Authenticated: static / SPA resources. Capture the original Host for
			// the remote-only gzip decision and wrap `res` so bundles, index.html
			// and JSON get compressed + long-lived cache headers for remote clients.
			captureOriginalHost(req);
			let outRes = res;
			if (cfg.gzip.enabled) {
				outRes = makeGzipRes(res, req, cfg.gzip);
			}
			// Self-heal the ORIGINAL-Host-bound dsh-auth cookie (issue #10): the
			// core's index/SPA path (frontend-static → authorizeIndex) validates
			// against the un-normalized Host, so document-like requests carry the
			// re-mint on their response when the jar lost it. Asset URLs and the
			// core's own `?token=` minting are left untouched.
			if ((req.method === "GET" || req.method === "HEAD") && !/\.[a-z0-9]{1,8}$/i.test(pathnameOf(req))) {
				try {
					if (new URL(req.url ?? "/", "http://dsh.internal").searchParams.get("token") === null) {
						await ensureDshAuthCookie(outRes, req, originalAuthority(req));
					}
				} catch {
					// unparsable URL — nothing to heal
				}
			}
			return handler(req, outRes);
		};
		Object.defineProperty(gated, GATED, { value: true });
		wrappedOriginals.set(gated, handler);
		return gated;
	};

	const unwrap = (handler) => wrappedOriginals.get(handler) ?? handler;

	// ── routes ──────────────────────────────────────────────────────────────────
	const handleLogin = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const body = await readBodyBounded(req, 64 * 1024);
		let input = null;
		if (body !== null) {
			try {
				input = JSON.parse(body.toString("utf8"));
			} catch {
				input = null;
			}
		}
		const username = typeof input?.username === "string" ? input.username.trim() : "";
		const password = typeof input?.password === "string" ? input.password : "";
		if (!username || !password) {
			denyJson(res, 400, "username and password are required");
			return;
		}
		const gate = takeRate(req, username);
		if (!gate.ok) {
			auditLimited("login:" + requestContext(req).ip, { event: "login-rate-limited", username, ...requestContext(req), detail: "retryAfter=" + gate.retryAfter });
			denyJson(res, 429, `too many attempts; retry in ${gate.retryAfter}s`, { retryAfter: gate.retryAfter });
			return;
		}
		const account = store.find(username);
		// Security: derive a scrypt hash even for an unknown username, so response
		// timing cannot be used to enumerate valid accounts.
		const storedHash = account !== null && account.passwordHash ? account.passwordHash : DUMMY_PASSWORD_HASH;
		const matches = await verifyPassword(password, storedHash);
		const ok = matches && account !== null && Boolean(account.passwordHash);
		if (!ok) {
			recordFailure(gate.credentialKey);
			recordFailure(gate.sourceKey);
			denyJson(res, 401, "invalid credentials");
			audit.append({ event: "login-fail", username, ...requestContext(req), detail: "bad-credentials" });
			return;
		}
		// Security: verifyPassword 期间账号可能被改密/删号，签发前复核一次。
		const stillThere = store.find(username);
		if (stillThere === null || stillThere.passwordHash !== storedHash) {
			denyJson(res, 401, "invalid credentials");
			return;
		}
		clearRate(gate.credentialKey);
		// Second factor: a verified TOTP setup requires the one-time code before
		// any session is issued. No cookie is set at this step.
		if (cfg.mfa.enabled && account.totp?.verified === true) {
			audit.append({ event: "login-password-ok", username, ...requestContext(req), detail: "mfa-required" });
			json(res, 200, {
				ok: false,
				mfaRequired: true,
				mfa: true,
				mfaToken: issueMfaToken(account.username, account.sessionEpoch ?? 0),
				user: { username: account.username, role: account.role ?? "user" }
			});
			return;
		}
		store.markLogin(username);
		audit.append({ event: "login-ok", username, ...requestContext(req), detail: "password" });
		safeSave();
		setSessionCookie(res, issueSession(account, requestContext(req)));
		await setLoginDshAuthCookies(req, res);
		json(res, 200, {
			ok: true,
			mfa: false,
			user: { username: account.username, role: account.role ?? "user" }
		});
	};

	/** Second login step: TOTP code or one-time backup code. */
	const handleMfaLogin = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const body = await readBodyBounded(req, 64 * 1024);
		let input = null;
		if (body !== null) {
			try {
				input = JSON.parse(body.toString("utf8"));
			} catch {
				input = null;
			}
		}
		const mfaToken = typeof input?.mfaToken === "string" ? input.mfaToken : "";
		const code = typeof input?.code === "string" ? input.code.trim() : "";
		if (!mfaToken || !code) {
			denyJson(res, 400, "mfaToken and code are required");
			return;
		}
		const challenge = verifyMfaToken(mfaToken);
		if (challenge === null) {
			denyJson(res, 401, "mfa challenge invalid or expired");
			return;
		}
		const account = store.find(challenge.username);
		// Security: 挑战令牌必须绑定签发时的 epoch，否则改密前拿到的挑战仍可换会话。
		if (account !== null && (account.sessionEpoch ?? 0) !== (challenge.epoch ?? 0)) {
			denyJson(res, 401, "mfa challenge invalid or expired");
			return;
		}
		if (account === null || account.totp?.verified !== true) {
			denyJson(res, 401, "mfa challenge invalid");
			return;
		}
		const gate = takeRate(req, "mfa:" + account.username);
		if (!gate.ok) {
			auditLimited("mfa:" + requestContext(req).ip, { event: "mfa-rate-limited", username: account.username, ...requestContext(req), detail: "retryAfter=" + gate.retryAfter });
			denyJson(res, 429, `too many attempts; retry in ${gate.retryAfter}s`, { retryAfter: gate.retryAfter });
			return;
		}
		const codeOk = verifyTotp(account.totp.secret, code, cfg.mfa.window) ||
			store.consumeBackupCode(account.username, code);
		if (!codeOk) {
			recordFailure(gate.credentialKey);
			recordFailure(gate.sourceKey);
			denyJson(res, 401, "invalid code");
			audit.append({ event: "mfa-fail", username: account.username, ...requestContext(req), detail: "invalid-code" });
			return;
		}
		clearRate(gate.credentialKey);
		// Success: only now consume the challenge (single use) so a wrong code
		// can retry with the same mfaToken.
		consumeMfaToken(challenge.nonce);
		store.markLogin(account.username);
		audit.append({ event: "mfa-ok", username: account.username, ...requestContext(req), detail: "totp-or-backup-code" });
		// 备份码是一次性凭据：消费后必须确认真的落盘，否则重启后同一个码还能再用。
		let mfaLoginPersisted = true;
		try {
			store["save"]();
		} catch {
			mfaLoginPersisted = false;
		}
		if (!mfaLoginPersisted) {
			audit.append({ event: "persist-failed", username: account.username, ...requestContext(req), detail: "mfa login" });
			denyJson(res, 500, "changes could not be persisted; nothing was written to disk");
			return;
		}
		safeSave();
		setSessionCookie(res, issueSession(account, requestContext(req)));
		await setLoginDshAuthCookies(req, res);
		json(res, 200, { ok: true, user: { username: account.username, role: account.role ?? "user" } });
	};

	/** Begin TOTP setup for the CURRENT session's account (self-service). */
	const handleMfaSetup = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const verdict = requireAuth(req);
		if (!verdict.ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		if (!cfg.mfa.enabled) {
			denyJson(res, 403, "mfa is disabled");
			return;
		}
		const account = store.find(verdict.user.username);
		if (account === null) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		// Security: 已绑定或正在绑定的账号换绑 MFA 必须重新认证（口令 + 当前验证码）。
		// 否则任何拿到会话的人都能把受害者的验证器换掉，并把账号永久锁死；
		// pending 状态下若不校验口令，只拿到口令的人也能抢先绑上自己的验证器。
		if (account.totp !== undefined) {
			const reauthGate = takeRate(req, "reauth:" + account.username);
			if (!reauthGate.ok) {
				denyJson(res, 429, `too many attempts; retry in ${reauthGate.retryAfter}s`, { retryAfter: reauthGate.retryAfter });
				return;
			}
			let reauth = null;
			const reauthBody = await readBodyBounded(req, 8 * 1024);
			if (reauthBody !== null) {
				try {
					reauth = JSON.parse(reauthBody.toString("utf8"));
				} catch {
					reauth = null;
				}
			}
			const passwordOk = typeof reauth?.password === "string"
				&& await verifyPassword(reauth.password, account.passwordHash);
			// 口令错就短路，不要消耗备份码（consumeBackupCode 有副作用）。
			const codeOk = passwordOk
				&& typeof reauth?.code === "string"
				&& (verifyTotp(account.totp.secret, reauth.code, cfg.mfa.window)
					|| store.consumeBackupCode(account.username, reauth.code));
			if (!passwordOk || !codeOk) {
				recordFailure(reauthGate.credentialKey);
				recordFailure(reauthGate.sourceKey);
				audit.append({ event: "mfa-rebind-denied", username: account.username, ...requestContext(req), detail: "reauth-required" });
				denyJson(res, 401, "rebinding mfa requires the current password and a valid code");
				return;
			}
			clearRate(reauthGate.credentialKey);
			audit.append({ event: "mfa-rebind", username: account.username, ...requestContext(req) });
		}
		const secret = generateTotpSecret();
		const backupCodes = generateBackupCodes(cfg.mfa.backupCodes);
		store.beginTotpSetup(account.username, secret, backupCodes.map((code) => hashBackupCode(code)));
		safeSave();
		const otpauth = otpauthUri({ secret, account: account.username, issuer: cfg.mfa.issuer });
		// Scan-ready QR (SVG data URL) for authenticator apps; null on failure.
		let qr = null;
		try {
			const svg = await QRCode.toString(otpauth, { type: "svg", errorCorrectionLevel: "M", margin: 1 });
			qr = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
		} catch (error) {
			ctx.logger.warn(`dsh-remote: qr generation failed: ${String(error)}`);
		}
		json(res, 200, {
			ok: true,
			secret,
			otpauth,
			qr,
			issuer: cfg.mfa.issuer,
			backupCodes
		});
	};

	/** Confirm a pending TOTP setup with one valid code. */
	const handleMfaVerify = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const verdict = requireAuth(req);
		if (!verdict.ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		const body = await readBodyBounded(req, 64 * 1024);
		let input = null;
		if (body !== null) {
			try {
				input = JSON.parse(body.toString("utf8"));
			} catch {
				input = null;
			}
		}
		const code = typeof input?.code === "string" ? input.code.trim() : "";
		if (!code) {
			denyJson(res, 400, "code is required");
			return;
		}
		const account = store.find(verdict.user.username);
		if (account === null || account.totp === undefined || account.totp.verified) {
			denyJson(res, 400, "no pending mfa setup");
			return;
		}
		if (!verifyTotp(account.totp.secret, code, cfg.mfa.window)) {
			denyJson(res, 400, "invalid code");
			return;
		}
		store.confirmTotp(account.username);
		let persisted = true;
		try {
			store["save"]();
		} catch {
			persisted = false;
		}
		if (!persisted) {
			audit.append({ event: "persist-failed", username: account.username, ...requestContext(req), detail: "confirm mfa" });
			denyJson(res, 500, "changes could not be persisted; nothing was written to disk");
			return;
		}
		audit.append({ event: "mfa-enabled", username: account.username, ...requestContext(req) });
		// 开启第二因素同样属于凭据变更：作废其它会话，并给当前这台续期。
		const selfAfterMfa = store.find(verdict.user.username);
		if (selfAfterMfa !== null) {
			setSessionCookie(res, issueSession(selfAfterMfa, requestContext(req)));
			await setLoginDshAuthCookies(req, res);
		}
		json(res, 200, { ok: true, mfa: true });
	};

	/** Disable MFA for the CURRENT account: password + (when active) a code. */
	const handleMfaDisable = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const verdict = requireAuth(req);
		if (!verdict.ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		const body = await readBodyBounded(req, 64 * 1024);
		let input = null;
		if (body !== null) {
			try {
				input = JSON.parse(body.toString("utf8"));
			} catch {
				input = null;
			}
		}
		const password = typeof input?.password === "string" ? input.password : "";
		const code = typeof input?.code === "string" ? input.code.trim() : "";
		if (!password) {
			denyJson(res, 400, "password is required to disable mfa");
			return;
		}
		const account = store.find(verdict.user.username);
		if (account === null) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		// Security: 关闭第二因素属于高危操作，必须限流（原来零限流，可高速撞码）。
		const disableGate = takeRate(req, "reauth:" + account.username);
		if (!disableGate.ok) {
			denyJson(res, 429, `too many attempts; retry in ${disableGate.retryAfter}s`, { retryAfter: disableGate.retryAfter });
			return;
		}
		const passwordOk = await verifyPassword(password, account.passwordHash);
		if (!passwordOk) {
			denyJson(res, 401, "invalid password");
			return;
		}
		// An ACTIVE setup additionally needs a live code (a session alone must
		// never be enough to strip the second factor).
		if (account.totp?.verified === true) {
			const codeOk = verifyTotp(account.totp.secret, code, cfg.mfa.window) ||
				store.consumeBackupCode(account.username, code);
			if (!codeOk) {
				denyJson(res, 401, "a valid mfa code is required to disable mfa");
				return;
			}
		}
		const had = store.disableTotp(account.username);
		let persisted = true;
		try {
			store["save"]();
		} catch {
			persisted = false;
		}
		if (!persisted) {
			audit.append({ event: "persist-failed", username: account.username, ...requestContext(req), detail: "disable mfa" });
			denyJson(res, 500, "changes could not be persisted; nothing was written to disk");
			return;
		}
		if (had) {
			audit.append({ event: "mfa-disabled", username: account.username, ...requestContext(req) });
			// 关 MFA 会自增 epoch，给当前设备续期，避免"关完把自己踢下线"。
			const selfAfterDisable = store.find(verdict.user.username);
			if (selfAfterDisable !== null) {
				setSessionCookie(res, issueSession(selfAfterDisable, requestContext(req)));
				await setLoginDshAuthCookies(req, res);
			}
		}
		json(res, 200, { ok: true, disabled: had });
	};

	const handleLogout = (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		// 登出同时把这个 sid 从注册表里摘掉，避免"已登出但仍出现在设备列表"。
		const token = readCookie(req, cfg.session.cookieName);
		const session = token === null ? null : verifySession(token);
		if (session !== null && session.sid !== "") {
			const revoked = sessions.revoke(session.sid);
			// 只有真正吊销成功才记审计：否则重放一个已失效的 cookie 就能无限写日志。
			if (revoked.revoked) {
				audit.append({ event: "logout", username: session.username, ...requestContext(req) });
			}
		}
		clearSessionCookie(res);
		json(res, 200, { ok: true });
	};

	const handleMe = (req, res) => {
		if (req.method !== "GET") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const verdict = requireAuth(req);
		json(res, 200, {
			authEnabled: cfg.enabled,
			bootstrap: cfg.enabled && !store.hasAccounts,
			authenticated: verdict.ok,
			username: verdict.ok ? verdict.user.username : null,
			role: verdict.ok ? verdict.user.role : null,
			mfa: verdict.ok ? store.mfaInfo(verdict.user.username).enabled : null,
			mfaAvailable: cfg.mfa.enabled,
			adminOnly: cfg.adminOnly
		});
	};

	const handleBootstrap = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		if (!cfg.enabled) {
			denyJson(res, 403, "authentication is disabled");
			return;
		}
		if (store.hasAccounts) {
			denyJson(res, 409, "accounts already exist");
			return;
		}
		if (!isLoopbackRequest(req)) {
			denyJson(res, 403, "first-account bootstrap is loopback-only");
			return;
		}
		const body = await readBodyBounded(req, 64 * 1024);
		let input = null;
		if (body !== null) {
			try {
				input = JSON.parse(body.toString("utf8"));
			} catch {
				input = null;
			}
		}
		const username = typeof input?.username === "string" ? input.username.trim() : "";
		const password = typeof input?.password === "string" ? input.password : "";
		if (!username || !password) {
			denyJson(res, 400, "username and password are required");
			return;
		}
		const bootstrapProblem = passwordProblem(username, password);
		if (bootstrapProblem !== null) {
			denyJson(res, 400, passwordProblemMessage(bootstrapProblem, requestLanguage(req)));
			return;
		}
		store.upsert({ username, role: "admin", passwordHash: hashPasswordSync(password) });
		audit.append({ event: "bootstrap-ok", username, ...requestContext(req), detail: "first-admin" });
		safeSave();
		const account = store.find(username);
		setSessionCookie(res, issueSession(account, requestContext(req)));
		await setLoginDshAuthCookies(req, res);
		json(res, 200, { ok: true, mfa: false, user: { username, role: "admin" } });
	};

	// Remote settings refresh (browser-half counterpart: unpinRemoteSettingsScopes
	// in lib/client.js). The client patches its settings scope queue so
	// memory-mode scopes perform their RPCs, but the scopes bound at boot already
	// swallowed their initial load — this endpoint makes the host re-broadcast
	// settings/document-updated (the invalidation every scope subscribes to) with
	// no namespace, reloading every scope through the now-working queue. Requires
	// a valid session so unauthenticated visitors cannot flood the broadcast.
	const handleSettingsRefresh = (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		if (!cfg.enabled) {
			denyJson(res, 403, "authentication is disabled");
			return;
		}
		if (!requireAuth(req).ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		// No namespace argument → the client refresh handler reloads every scope.
		ctx.emit("settings/document-updated");
		json(res, 200, { ok: true });
	};

	const handleAccounts = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const verdict = requireAuth(req);
		if (!verdict.ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		if (verdict.user.role !== "admin") {
			denyJson(res, 403, "admin required");
			return;
		}
		const body = await readBodyBounded(req, 128 * 1024);
		let input = null;
		if (body !== null) {
			try {
				input = JSON.parse(body.toString("utf8"));
			} catch {
				input = null;
			}
		}
		const action = typeof input?.action === "string" ? input.action : "";
		if (action === "list") {
			json(res, 200, { ok: true, accounts: store.list() });
			return;
		}
		if (action === "upsert") {
			const username = typeof input?.username === "string" ? input.username.trim() : "";
			// Absent role (a password-only reset) keeps the account's current role.
			const requestedRole = input?.role === "admin" || input?.role === "user" || input?.role === "guest" ? input.role : null;
			const password = typeof input?.password === "string" ? input.password : "";
			if (!username) {
				denyJson(res, 400, "username is required");
				return;
			}
			const existing = store.find(username);
			// 用户名必须与改名同一口径：否则会造出审计无法关联的脏名
			// （控制符在 store 里原样保存、在审计里被 clean 掉）。
			if (existing === null && !USERNAME_PATTERN.test(username)) {
				denyJson(res, 400, "username must match " + USERNAME_PATTERN.source);
				return;
			}
			// Admin-only mode: accounts are created only at bootstrap or via the
			// composition seed — runtime creation is refused, and every account
			// is forced to the admin role.
			if (cfg.adminOnly && existing === null) {
				denyJson(res, 400, "account creation is disabled (admin-only mode)");
				return;
			}
			const role = cfg.adminOnly ? "admin" : (requestedRole ?? existing?.role ?? "user");
			// The first (protected) account is the root: only its password may be
			// reset — explicit role changes are refused.
			if (existing !== null && existing.protected === true && requestedRole !== null && requestedRole !== (existing.role ?? "user")) {
				denyJson(res, 400, "cannot change the role of the first (protected) account");
				return;
			}
			if (existing === null && password === "") {
				denyJson(res, 400, "new accounts need a password");
				return;
			}
			const accountPasswordProblem = password ? passwordProblem(username, password) : null;
			if (accountPasswordProblem !== null) {
				denyJson(res, 400, passwordProblemMessage(accountPasswordProblem, requestLanguage(req)));
				return;
			}
			if (existing !== null && (existing.role ?? "user") === "admin" && role !== "admin" && store.countAdmins() <= 1) {
				denyJson(res, 400, "cannot demote the last admin");
				return;
			}
			const passwordHash = password ? hashPasswordSync(password) : undefined;
			// Security: 重置他人（尤其 admin/root）的口令必须重新输入操作者自己的口令，
			// 否则一个被盗的 admin cookie 就能直接夺取根账号。
			if (existing !== null && username !== verdict.user.username && password
				&& ((existing.role ?? "user") === "admin" || existing.protected === true)) {
				const resetGate = takeRate(req, "reauth:" + verdict.user.username);
				if (!resetGate.ok) {
					denyJson(res, 429, `too many attempts; retry in ${resetGate.retryAfter}s`, { retryAfter: resetGate.retryAfter });
					return;
				}
				const operator = store.find(verdict.user.username);
				const resetOwnOk = operator !== null
					&& typeof input?.adminPassword === "string"
					&& await verifyPassword(input.adminPassword, operator.passwordHash);
				if (!resetOwnOk) {
					recordFailure(resetGate.credentialKey);
					recordFailure(resetGate.sourceKey);
					audit.append({ event: "password-reset-denied", username, ...requestContext(req), detail: "reauth-required" });
					denyJson(res, 401, "resetting this account's password requires your own password");
					return;
				}
				clearRate(resetGate.credentialKey);
			}
			store.upsert({ username, role, passwordHash });
			let persisted = true;
			try {
				store["save"]();
			} catch {
				persisted = false;
			}
			if (!persisted) {
				audit.append({ event: "persist-failed", username: username, ...requestContext(req), detail: "account upsert" });
				denyJson(res, 500, "changes could not be persisted; nothing was written to disk");
				return;
			}
			// 凭据/权限变更后，该账号此前的其它会话已因 epoch 失效，从表里摘掉避免幽灵设备。
			if (passwordHash !== undefined || requestedRole !== null) {
				sessions.revokeAll(username, username === verdict.user.username ? (verdict.sid ?? "") : "");
			}
			audit.append({
				event: passwordHash === undefined ? "account-role-change" : "account-password-set",
				username,
				...requestContext(req),
				detail: "by=" + verdict.user.username + (requestedRole === null ? "" : " role=" + role)
			});
			// Security: a password/role change bumps the account's session epoch, which
			// retires every session issued before it. Re-issue our own cookie so an
			// admin changing their own credentials stays signed in.
			if (username === verdict.user.username) {
				const self = store.find(username);
				if (self !== null) {
					setSessionCookie(res, issueSession(self, requestContext(req)));
					await setLoginDshAuthCookies(req, res);
				}
			}
			json(res, 200, { ok: true, account: store.list().find((a) => a.username === username) });
			return;
		}
		if (action === "remove") {
			const username = typeof input?.username === "string" ? input.username : "";
			const target = store.find(username);
			if (target === null) {
				json(res, 200, { ok: true, removed: false });
				return;
			}
			if (target.protected === true) {
				denyJson(res, 400, "cannot remove the first (protected) account; reset its password instead");
				return;
			}
			if ((target.role ?? "user") === "admin" && store.countAdmins() <= 1) {
				denyJson(res, 400, "cannot remove the last admin");
				return;
			}
			const removed = store.remove(username);
			let persisted = true;
			try {
				store["save"]();
			} catch {
				persisted = false;
			}
			if (!persisted) {
				audit.append({ event: "persist-failed", username: username, ...requestContext(req), detail: "account remove" });
				denyJson(res, 500, "changes could not be persisted; nothing was written to disk");
				return;
			}
			if (removed) {
				// 删号必须连带清会话：否则同名重建后旧 token 会复活。
				sessions.revokeAll(username);
				audit.append({ event: "account-remove", username, ...requestContext(req), detail: "by=" + verdict.user.username });
			}
			json(res, 200, { ok: true, removed });
			return;
		}
		if (action === "disable-mfa") {
			// Admin recovery path: strip MFA from an account. Re-auths the admin
			// with their own password so a hijacked admin session alone cannot
			// silently remove another user's second factor.
			const username = typeof input?.username === "string" ? input.username : "";
			const password = typeof input?.password === "string" ? input.password : "";
			const target = store.find(username);
			if (target === null) {
				denyJson(res, 404, "account not found");
				return;
			}
			const adminAccount = store.find(verdict.user.username);
			const adminOk = adminAccount !== null && await verifyPassword(password, adminAccount.passwordHash);
			if (!adminOk) {
				denyJson(res, 401, "invalid admin password");
				return;
			}
			clearRate(adminMfaGate.credentialKey);
			const had = store.disableTotp(username);
			let persisted = true;
			try {
				store["save"]();
			} catch {
				persisted = false;
			}
			if (!persisted) {
				audit.append({ event: "persist-failed", username: username, ...requestContext(req), detail: "admin disable mfa" });
				denyJson(res, 500, "changes could not be persisted; nothing was written to disk");
				return;
			}
			if (had) {
				audit.append({ event: "mfa-disabled-by-admin", username, ...requestContext(req), detail: "by=" + verdict.user.username });
				// 关 MFA 会自增 epoch：如果操作的是自己，给当前设备续期，避免当场被踢下线。
				if (username === verdict.user.username) {
					const selfAfterAdminDisable = store.find(username);
					if (selfAfterAdminDisable !== null) {
						setSessionCookie(res, issueSession(selfAfterAdminDisable, requestContext(req)));
						await setLoginDshAuthCookies(req, res);
					}
				}
			}
			json(res, 200, { ok: true, disabled: had });
			return;
		}
		if (action === "rename") {
			// Rename in place: role, protection flag, MFA secret, backup codes and
			// timestamps all travel with the account object. Sessions carry the OLD
			// name as their subject, so they stop resolving (see requireAuth);
			// renaming your own account re-issues the cookie below so you stay in.
			const from = typeof input?.username === "string" ? input.username.trim() : "";
			const to = typeof input?.renameTo === "string" ? input.renameTo.trim() : "";
			if (!from || !to) {
				denyJson(res, 400, "username and renameTo are required");
				return;
			}
			if (to.length > 64 || !/^[A-Za-z0-9._+@-]+$/.test(to)) {
				denyJson(res, 400, "invalid new username (1-64 characters of A-Z a-z 0-9 . _ + - @)");
				return;
			}
			if (from === to) {
				json(res, 200, { ok: true, from, to, unchanged: true });
				return;
			}
			const target = store.find(from);
			if (target === null) {
				denyJson(res, 404, "account not found");
				return;
			}
			if (store.find(to) !== null) {
				denyJson(res, 409, "that username is already taken");
				return;
			}
			// Security: 改名 protected 账号等价于"删号 + 重建"，一次误点或一个被盗的
			// cookie 就能把唯一的根账号永久锁在门外。要求操作者重新输入自己的口令。
			if (target.protected === true) {
				const renameGate = takeRate(req, "reauth:" + verdict.user.username);
				if (!renameGate.ok) {
					denyJson(res, 429, `too many attempts; retry in ${renameGate.retryAfter}s`, { retryAfter: renameGate.retryAfter });
					return;
				}
				const operator = store.find(verdict.user.username);
				const renameOwnOk = operator !== null
					&& typeof input?.password === "string"
					&& await verifyPassword(input.password, operator.passwordHash);
				if (!renameOwnOk) {
					recordFailure(renameGate.credentialKey);
					recordFailure(renameGate.sourceKey);
					audit.append({ event: "rename-denied", username: from, ...requestContext(req), detail: "reauth-required" });
					denyJson(res, 401, "renaming the protected account requires your own password");
					return;
				}
				clearRate(renameGate.credentialKey);
			}
			const renamed = store.rename(from, to);
			if (!renamed.ok) {
				denyJson(res, 400, `rename failed (${renamed.reason})`);
				return;
			}
			safeSave();
			let persisted = true;
			try {
				store["save"]();
			} catch {
				persisted = false;
			}
			if (!persisted) {
				audit.append({ event: "persist-failed", username: to, ...requestContext(req), detail: "account rename" });
				denyJson(res, 500, "changes could not be persisted; nothing was written to disk");
				return;
			}
			// 会话里的主体是旧用户名，改名后它们本来就会失效；这里顺手清表，避免留下脏记录。
			sessions.revokeAll(from);
			audit.append({ event: "account-rename", username: to, ...requestContext(req), detail: "from=" + from + " by=" + verdict.user.username });
			if (from === verdict.user.username) {
				setSessionCookie(res, issueSession(renamed.account, requestContext(req)));
				await setLoginDshAuthCookies(req, res);
			}
			json(res, 200, { ok: true, from, to });
			return;
		}
		denyJson(res, 400, `unknown action ${JSON.stringify(action)}`);
	};

	// ── remote file display (/auth/file) ───────────────────────────────────────
	// The web UI opens agent-produced files through the host.openPath RPC, which
	// hands the path to the HOST desktop's default application — invisible to a
	// remote browser. The browser half of this plugin intercepts those RPCs for
	// non-loopback clients and redirects them here, so the file is displayed in
	// the remote browser (inline) or downloaded, and directories get an HTML
	// listing instead of a host file-manager window.

	/** Content-Types for inline display by extension (lower-cased, no dot).
	 *  The text/code family serves as text/plain so the panel's "open in new
	 *  tab" shows source instead of downloading (and the client renders those
	 *  paths through its code/text view driven by the extension). */
	const TEXT_PLAIN = "text/plain; charset=utf-8";
	const FILE_MIME = {
		html: "text/html; charset=utf-8",
		htm: "text/html; charset=utf-8",
		css: "text/css; charset=utf-8",
		scss: TEXT_PLAIN,
		less: TEXT_PLAIN,
		vue: TEXT_PLAIN,
		svelte: TEXT_PLAIN,
		js: "text/javascript; charset=utf-8",
		mjs: "text/javascript; charset=utf-8",
		cjs: "text/javascript; charset=utf-8",
		jsx: TEXT_PLAIN,
		ts: TEXT_PLAIN,
		tsx: TEXT_PLAIN,
		mts: TEXT_PLAIN,
		cts: TEXT_PLAIN,
		json: "application/json; charset=utf-8",
		jsonc: TEXT_PLAIN,
		txt: "text/plain; charset=utf-8",
		md: "text/plain; charset=utf-8",
		mdx: TEXT_PLAIN,
		csv: "text/plain; charset=utf-8",
		tsv: TEXT_PLAIN,
		log: "text/plain; charset=utf-8",
		py: TEXT_PLAIN,
		rb: TEXT_PLAIN,
		go: TEXT_PLAIN,
		rs: TEXT_PLAIN,
		java: TEXT_PLAIN,
		c: TEXT_PLAIN,
		h: TEXT_PLAIN,
		cc: TEXT_PLAIN,
		cpp: TEXT_PLAIN,
		hpp: TEXT_PLAIN,
		cxx: TEXT_PLAIN,
		cs: TEXT_PLAIN,
		kt: TEXT_PLAIN,
		kts: TEXT_PLAIN,
		swift: TEXT_PLAIN,
		dart: TEXT_PLAIN,
		lua: TEXT_PLAIN,
		pl: TEXT_PLAIN,
		pm: TEXT_PLAIN,
		php: TEXT_PLAIN,
		r: TEXT_PLAIN,
		sql: TEXT_PLAIN,
		sh: TEXT_PLAIN,
		bash: TEXT_PLAIN,
		zsh: TEXT_PLAIN,
		fish: TEXT_PLAIN,
		ps1: TEXT_PLAIN,
		bat: TEXT_PLAIN,
		cmd: TEXT_PLAIN,
		yml: TEXT_PLAIN,
		yaml: TEXT_PLAIN,
		toml: TEXT_PLAIN,
		ini: TEXT_PLAIN,
		cfg: TEXT_PLAIN,
		conf: TEXT_PLAIN,
		env: TEXT_PLAIN,
		properties: TEXT_PLAIN,
		xml: TEXT_PLAIN,
		xhtml: TEXT_PLAIN,
		gitignore: TEXT_PLAIN,
		gitattributes: TEXT_PLAIN,
		dockerignore: TEXT_PLAIN,
		editorconfig: TEXT_PLAIN,
		npmrc: TEXT_PLAIN,
		diff: TEXT_PLAIN,
		patch: TEXT_PLAIN,
		graphql: TEXT_PLAIN,
		svg: "image/svg+xml",
		png: "image/png",
		jpg: "image/jpeg",
		jpeg: "image/jpeg",
		gif: "image/gif",
		webp: "image/webp",
		avif: "image/avif",
		ico: "image/x-icon",
		bmp: "image/bmp",
		pdf: "application/pdf",
		mp4: "video/mp4",
		webm: "video/webm",
		mp3: "audio/mpeg",
		wav: "audio/wav"
	};

	const escapeHtml = (s) => String(s)
		.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;").replaceAll("'", "&#39;");

	/**
	 * Is a requested absolute path inside one of the allowed roots (DSH home,
	 * process cwd, plus `extraRoots`)? Symlink escapes are neutralized by
	 * comparing realpaths. Exported for tests.
	 * @returns {ok, real, reason} — reason is a stable short code for tests.
	 */
	const checkFilePath = (rawPath, extraRoots = []) => {
		const verdict = checkFilePathAgainst(rawPath, extraRoots);
		// Security: 账号库目录（store.json 含签名密钥、audit.jsonl、sessions.json）
		// 永远不通过 /auth/file 对外提供，即使它落在允许根目录内。
		if (verdict.ok) {
			const real = String(verdict.real ?? "");
			if (real === authDir || real.startsWith(authDir + sep)) {
				return { ok: false, reason: "forbidden" };
			}
		}
		return verdict;
	};

	// Effective allowed roots for a request: the cordis `files.roots` config
	// PLUS the runtime store the settings UI manages (live add/remove). Read
	// fresh per request so a settings change applies without a restart.
	const effectiveExtraRoots = () => [...cfg.files.roots, ...filesRoots.list()];

	/** Simple HTML directory listing with clickable entries (files open inline). */
	const renderListing = (dirPath, entries, extraRoots = []) => {
		const rows = entries.map((entry) => {
			const href = `/auth/file?path=${encodeURIComponent(join(dirPath, entry.name))}`;
			const icon = entry.isDirectory ? "&#128193;" : "&#128196;";
			const size = entry.isDirectory ? "—" : `${Math.max(1, Math.round(entry.size / 1024))} KB`;
			return `<tr><td><a href="${href}">${icon} ${escapeHtml(entry.name)}${entry.isDirectory ? "/" : ""}</a></td><td>${size}</td></tr>`;
		}).join("\n");
		const parent = dirname(dirPath);
		const parentRow = parent !== dirPath && checkFilePath(parent, extraRoots).ok
			? `<tr><td><a href="/auth/file?path=${encodeURIComponent(parent)}">&#11014; ..</a></td><td>—</td></tr>` : "";
		return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(dirPath)}</title>` +
			`<style>body{font:13px/1.6 -apple-system,Segoe UI,sans-serif;background:#0d1117;color:#e6edf3;padding:24px;}` +
			`code{color:#8b949e}table{border-collapse:collapse}td{padding:3px 18px 3px 0}` +
			`a{color:#4c8bf5;text-decoration:none}a:hover{text-decoration:underline}</style></head><body>` +
			`<h3 style="margin:0 0 4px">Index of</h3><code>${escapeHtml(dirPath)}</code>` +
			`<table style="margin-top:14px">${parentRow}${rows}</table></body></html>`;
	};

	/** 审计日志查询（管理员）：{ action: "list", limit?, event? } */
	const handleAudit = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const verdict = requireAuth(req);
		if (!verdict.ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		if (verdict.user.role !== "admin") {
			denyJson(res, 403, "admin required");
			return;
		}
		const body = await readBodyBounded(req, 8 * 1024);
		let input = null;
		if (body !== null) {
			try {
				input = JSON.parse(body.toString("utf8"));
			} catch {
				input = null;
			}
		}
		const limit = Math.min(Math.max(Number(input?.limit) || 200, 1), 2000);
		const event = typeof input?.event === "string" ? input.event : "";
		let rows = audit.list({ limit: limit * 4 });
		if (event !== "") rows = rows.filter((row) => String(row.event ?? "").startsWith(event));
		json(res, 200, { ok: true, entries: rows.slice(0, limit), total: rows.length });
	};

	/** 在线设备（管理员）：{ action: "list" } / { action: "revoke", sid } / { action: "revoke-all", username } */
	const handleSessions = async (req, res) => {
		if (req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		const verdict = requireAuth(req);
		if (!verdict.ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		if (verdict.user.role !== "admin") {
			denyJson(res, 403, "admin required");
			return;
		}
		const body = await readBodyBounded(req, 8 * 1024);
		let input = null;
		if (body !== null) {
			try {
				input = JSON.parse(body.toString("utf8"));
			} catch {
				input = null;
			}
		}
		const action = typeof input?.action === "string" ? input.action : "list";
		if (action === "list") {
			json(res, 200, { ok: true, sessions: sessions.list(), current: verdict.sid ?? "" });
			return;
		}
		if (action === "revoke") {
			const sid = typeof input?.sid === "string" ? input.sid : "";
			if (sid === "") {
				denyJson(res, 400, "sid is required");
				return;
			}
			const row = sessions.list().find((item) => item.sid === sid);
			const result = sessions.revoke(sid);
			if (result.revoked) {
				audit.append({
					event: "session-revoke",
					username: row?.username ?? "",
					...requestContext(req),
					detail: "sid=" + sid.slice(0, 8) + " by=" + verdict.user.username
				});
			}
			// persisted=false 表示内存已生效但落盘失败，重启后该会话会复活 —— 必须让调用方知道。
			json(res, 200, { ok: true, revoked: result.revoked, persisted: result.persisted });
			return;
		}
		if (action === "revoke-all") {
			const username = typeof input?.username === "string" ? input.username.trim() : "";
			if (username === "") {
				denyJson(res, 400, "username is required");
				return;
			}
			const keepSelf = input?.keepCurrent === true ? (verdict.sid ?? "") : "";
			const result = sessions.revokeAll(username, keepSelf);
			if (result.removed > 0) {
				audit.append({
					event: "session-revoke-all",
					username,
					...requestContext(req),
					detail: "count=" + result.removed + " by=" + verdict.user.username
				});
			}
			json(res, 200, { ok: true, removed: result.removed, persisted: result.persisted });
			return;
		}
		denyJson(res, 400, `unknown action ${JSON.stringify(action)}`);
	};
	const handleFile = (req, res) => {
		if (req.method !== "GET" && req.method !== "HEAD") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		if (!requireAuth(req).ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		let rawPath = null;
		let format = null;
		try {
			const query = new URL(req.url ?? "/", "http://dsh.internal").searchParams;
			rawPath = query.get("path");
			format = query.get("format");
		} catch {
			rawPath = null;
		}
		const extraRoots = effectiveExtraRoots();
		const verdict = checkFilePath(rawPath, extraRoots);
		if (!verdict.ok) {
			const status = verdict.reason === "outside-roots" ? 403 : 404;
			// Self-diagnosing rejection: name the allowed roots so a remote user
			// immediately knows what to add (and where) — pointing at the
			// Settings > 允许的目录 page instead of a config file edit.
			const extra = verdict.reason === "outside-roots"
				? { allowedRoots: fileRootsFor(extraRoots), hint: "add the file's directory under the plugin's Settings > Allowed directories" }
				: undefined;
			denyJson(res, status, `cannot display file (${verdict.reason})`, extra);
			return;
		}
		if (verdict.isDirectory) {
			let list;
			try {
				list = readdirSync(verdict.real, { withFileTypes: true });
			} catch {
				denyJson(res, 403, "cannot read directory");
				return;
			}
			const rows = [];
			for (const ent of list) {
				if (rows.length >= cfg.files.maxListing) break;
				try {
					const st = statSync(join(verdict.real, ent.name));
					rows.push({ name: ent.name, isDirectory: st.isDirectory(), size: st.size });
				} catch {
					// dangling symlink etc. — skip
				}
			}
			rows.sort((a, b) => (a.isDirectory === b.isDirectory ? a.name.localeCompare(b.name) : (a.isDirectory ? -1 : 1)));
			// format=json powers the in-app viewer modal's directory navigation;
			// the default HTML listing serves direct browser opens.
			if (format === "json") {
				const parent = dirname(verdict.real);
				json(res, 200, {
					ok: true,
					path: verdict.real,
					parent: parent !== verdict.real && checkFilePath(parent, extraRoots).ok ? parent : null,
					entries: rows.map((row) => ({ ...row, path: join(verdict.real, row.name) }))
				});
				return;
			}
			const html = renderListing(verdict.real, rows, extraRoots);
			res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(html) });
			res.end(req.method === "HEAD" ? undefined : html);
			return;
		}
		const ext = extname(verdict.real).slice(1).toLowerCase();
		// format=text on a .docx serves extracted plain text for the in-app
		// viewer panel (the browser half classifies docx and asks here). Any
		// structural surprise answers 415 so the panel falls back to the
		// download card.
		if (format === "text" && ext === "docx") {
			if (verdict.size > DOCX_EXTRACT_MAX_BYTES) {
				denyJson(res, 415, "document too large for text extraction");
				return;
			}
			let text = null;
			try {
				text = extractDocxText(readFileSync(verdict.real));
			} catch {
				text = null;
			}
			if (typeof text !== "string") {
				denyJson(res, 415, "cannot extract text from this document");
				return;
			}
			res.writeHead(200, {
				"Content-Type": "text/plain; charset=utf-8",
				"Content-Length": Buffer.byteLength(text),
				"Cache-Control": "no-store",
				"X-Content-Type-Options": "nosniff"
			});
			res.end(req.method === "HEAD" ? undefined : text);
			return;
		}
		const mime = FILE_MIME[ext] ?? "application/octet-stream";
		const inline = mime !== "application/octet-stream" || ext === "";
		const disposition = inline
			? `inline; filename="${encodeURIComponent(basename(verdict.real))}"`
			: `attachment; filename="${encodeURIComponent(basename(verdict.real))}"`;
		res.writeHead(200, {
			"Content-Type": mime,
			"Content-Length": verdict.size,
			"Content-Disposition": disposition,
			"Cache-Control": "no-store",
			"X-Content-Type-Options": "nosniff"
		});
		if (req.method === "HEAD") {
			res.end();
			return;
		}
		const stream = createReadStream(verdict.real);
		stream.on("error", () => { try { res.destroy(); } catch { /* ignore */ } });
		stream.pipe(res);
	};

	// Snapshot returned by /auth/files so the settings UI can show the three
	// buckets: what config grants, what the runtime store adds, and the union
	// that actually gates /auth/file (realpath-resolved).
	const filesState = () => ({
		ok: true,
		enabled: cfg.files.enabled,
		configRoots: fileRootsFor(cfg.files.roots),
		userRoots: filesRoots.list(),
		effectiveRoots: fileRootsFor(effectiveExtraRoots())
	});

	/**
	 * GET  /auth/files  -> filesState()
	 * POST /auth/files  -> { action: "add"|"remove", path } persists the runtime
	 *                      store (admin only) and returns the fresh filesState().
	 */
	const handleFiles = async (req, res) => {
		if (req.method !== "GET" && req.method !== "POST") {
			denyJson(res, 405, "method not allowed");
			return;
		}
		if (!requireAuth(req).ok) {
			denyJson(res, 401, "unauthorized");
			return;
		}
		// Adding roots exposes the host filesystem — admin only.
		if (requireAuth(req).user.role !== "admin") {
			denyJson(res, 403, "admin required");
			return;
		}
		if (req.method === "GET") {
			// Always answer GET (even when disabled) so the settings page can
			// show the "viewer is off" note instead of silently hiding the block.
			json(res, 200, filesState());
			return;
		}
		if (!cfg.files.enabled) {
			denyJson(res, 403, "file viewer disabled");
			return;
		}
		const body = await readBodyBounded(req, 64 * 1024);
		let payload = null;
		if (body !== null) {
			try {
				payload = JSON.parse(body.toString("utf8"));
			} catch {
				payload = null;
			}
		}
		if (payload === null || typeof payload !== "object") {
			denyJson(res, 400, "bad request body");
			return;
		}
		const action = payload?.action;
		const path = typeof payload?.path === "string" ? payload.path : "";
		if (action === "add") {
			if (path.trim() === "" || !isAbsolute(path)) { denyJson(res, 400, "invalid path"); return; }
			if (filesRoots.add(path)) filesRoots.save();
			json(res, 200, filesState());
			return;
		}
		if (action === "remove") {
			if (filesRoots.remove(path)) filesRoots.save();
			json(res, 200, filesState());
			return;
		}
		denyJson(res, 400, "invalid action");
	};

	// Register the /auth/* plane with the ORIGINAL register (before the gate is
	// patched in) so these routes are never wrapped.
	const originalRegister = webServer.register.bind(webServer);
	const originalRegisterUpgrade = webServer.registerUpgrade.bind(webServer);
	const originalRegisterFallback = webServer.registerFallback.bind(webServer);

	const disposers = [];
	disposers.push(originalRegister({ kind: "exact", path: "/auth/login", handler: handleLogin }));
	disposers.push(originalRegister({ kind: "exact", path: "/auth/logout", handler: handleLogout }));
	disposers.push(originalRegister({ kind: "exact", path: "/auth/me", handler: handleMe }));
	if (cfg.enabled) {
		disposers.push(originalRegister({ kind: "exact", path: "/auth/bootstrap", handler: handleBootstrap }));
		disposers.push(originalRegister({ kind: "exact", path: "/auth/settings-refresh", handler: handleSettingsRefresh }));
		disposers.push(originalRegister({ kind: "exact", path: "/auth/accounts", handler: handleAccounts }));
		disposers.push(originalRegister({ kind: "exact", path: "/auth/mfa/login", handler: handleMfaLogin }));
		disposers.push(originalRegister({ kind: "exact", path: "/auth/mfa/setup", handler: handleMfaSetup }));
		disposers.push(originalRegister({ kind: "exact", path: "/auth/mfa/verify", handler: handleMfaVerify }));
		disposers.push(originalRegister({ kind: "exact", path: "/auth/mfa/disable", handler: handleMfaDisable }));
		disposers.push(originalRegister({ kind: "exact", path: "/auth/audit", handler: handleAudit }));
		disposers.push(originalRegister({ kind: "exact", path: "/auth/sessions", handler: handleSessions }));
		if (cfg.files.enabled) {
			disposers.push(originalRegister({ kind: "exact", path: "/auth/file", handler: handleFile }));
			disposers.push(originalRegister({ kind: "exact", path: "/auth/files", handler: handleFiles }));
		}
	}

	if (cfg.enabled) {
		// Wrap routes registered before this plugin activated.
		for (const route of webServer.exact.values()) route.handler = wrapHttp(route.handler);
		for (const route of webServer.prefixes.values()) route.handler = wrapHttp(route.handler);
		for (const route of webServer.upgrades.values()) route.handler = wrapUpgrade(route.handler);
		if (webServer.fallback !== undefined) webServer.fallback = wrapFallback(webServer.fallback);

		// Gate every route registered later.
		webServer.register = (route) => originalRegister({ ...route, handler: wrapHttp(route.handler) });
		webServer.registerUpgrade = (route) => originalRegisterUpgrade({ ...route, handler: wrapUpgrade(route.handler) });
		webServer.registerFallback = (handler) => originalRegisterFallback(wrapFallback(handler));
	}

	ctx.effect(() => () => {
		for (const dispose of disposers) dispose();
		if (cfg.enabled) {
			webServer.register = originalRegister;
			webServer.registerUpgrade = originalRegisterUpgrade;
			webServer.registerFallback = originalRegisterFallback;
			for (const route of webServer.exact.values()) route.handler = unwrap(route.handler);
			for (const route of webServer.prefixes.values()) route.handler = unwrap(route.handler);
			for (const route of webServer.upgrades.values()) route.handler = unwrap(route.handler);
			if (webServer.fallback !== undefined) webServer.fallback = unwrap(webServer.fallback);
		}
	}, "dsh-remote: gate");

	ctx.logger.info(
		`dsh-remote: authentication ${cfg.enabled ? "enabled" : "disabled"} ` +
		`(${store.list().length} account(s), store at ${defaultStorePath()}) [build dsh1-hardened]`
	);
}

/**
 * 激活入口：内部任何异常都必须 fail-closed。
 * 否则插件 fiber 标记失败但门禁从未安装，整个面板会变成无鉴权可访问。
 * @param {object} ctx - Cordis 上下文。
 * @param {object} config - 插件配置。
 */
function apply(ctx, config) {
	try {
		return applyInner(ctx, config);
	} catch (error) {
		ctx.logger.error(
			"[dsh-remote] activation failed, denying all traffic (fail-closed): " + String(error?.message ?? error)
		);
		const webServer = ctx?.webServer;
		if (webServer === undefined || webServer === null) throw error;
		const deny = (req, res) => {
			if (typeof res?.writeHead === "function") {
				res.writeHead(503, { "Content-Type": "application/json", "Cache-Control": "no-store" });
				res.end(JSON.stringify({ ok: false, error: "authentication unavailable" }));
			}
		};
		const denyUpgrade = (req, socket) => {
			try {
				socket.destroy();
			} catch {
				// ignore
			}
		};
		for (const route of webServer.exact?.values?.() ?? []) route.handler = deny;
		for (const route of webServer.prefixes?.values?.() ?? []) route.handler = deny;
		for (const route of webServer.upgrades?.values?.() ?? []) route.handler = denyUpgrade;
		if (webServer.fallback !== undefined) webServer.fallback = deny;
		// 之后注册的路由同样要拒绝；三个注册入口签名不同，不能混用同一个 register。
		const lateRegister = typeof webServer.register === "function" ? webServer.register.bind(webServer) : null;
		const lateRegisterUpgrade = typeof webServer.registerUpgrade === "function"
			? webServer.registerUpgrade.bind(webServer)
			: null;
		const lateRegisterFallback = typeof webServer.registerFallback === "function"
			? webServer.registerFallback.bind(webServer)
			: null;
		if (lateRegister !== null) webServer.register = (route) => lateRegister({ ...route, handler: deny });
		if (lateRegisterUpgrade !== null) {
			webServer.registerUpgrade = (route) => lateRegisterUpgrade({ ...route, handler: denyUpgrade });
		}
		if (lateRegisterFallback !== null) webServer.registerFallback = () => lateRegisterFallback(deny);
		return undefined;
	}
}

export { Config, apply, inject, name };
export {
	ORIGINAL_HOST,
	captureOriginalHost,
	isRemoteOrigin,
	BROWSER_SESSION_RECORD_KEY,
	BROWSER_COOKIE_MAX_AGE_DAYS_DEFAULT,
	canonicalAuthority,
	dshAuthCookieName,
	encodeDshAuthCookie,
	decodeDshAuthCookie,
	cookieValueOf,
	readBrowserAuthSecret,
	hasLiveDshAuthCookie,
	shouldGzip,
	shouldCache,
	makeGzipRes,
	checkFilePathAgainst,
	evaluateRoleGate,
	denyRpcEnvelope
};
export { FilesRootsStore, filesRootsPath };
export default { Config, apply, inject, name };
