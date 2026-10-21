import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, SessionRegistry } from "../lib/audit-sessions.js";

const dir = () => mkdtempSync(join(tmpdir(), "dsh-remote-audit-"));

// ── AuditLog ────────────────────────────────────────────────────────────────

test("AuditLog: append writes one JSON line and list returns it newest-first", () => {
	const log = new AuditLog(join(dir(), "audit.jsonl"));
	log.append({ event: "login-ok", username: "alice", ip: "127.0.0.1", ua: "UA/1.0", detail: "x" });
	log.append({ event: "login-fail", username: "bob", ip: "127.0.0.2", ua: "UA/2.0" });

	const rows = log.list({ limit: 10 });
	assert.equal(rows.length, 2);
	assert.equal(rows[0].event, "login-fail", "newest first");
	assert.equal(rows[1].event, "login-ok");
	assert.equal(typeof rows[0].ts, "number");
	assert.ok(rows[0].ts > 0);
});

test("AuditLog: list on a missing file returns an empty array", () => {
	const log = new AuditLog(join(dir(), "nope.jsonl"));
	assert.deepEqual(log.list(), []);
});

test("AuditLog: control characters and zero-width marks are stripped", () => {
	const log = new AuditLog(join(dir(), "audit.jsonl"));
	// C0, DEL, C1 (OSC 52 introducer), zero-width space, bidi override, BOM
	log.append({
		event: "login-fail",
		username: "a\u0000b\u001bc\u007fd\u009d52;c;UFdORUQ=\u009ce\u200bf\u202eg\ufeffh",
		ip: "1.1.1.1",
		ua: "u"
	});
	const raw = readFileSync(join(log.path), "utf8").replace(/\n$/, "");
	assert.equal(raw.trim().split("\n").length, 1, "still exactly one line");
	assert.ok(!/[\u0000-\u001f\u007f]/.test(raw), "no C0/DEL left");
	assert.ok(!/[\u0080-\u009f]/.test(raw), "no C1 left");
	assert.ok(!/[\u200b-\u200f\u202a-\u202e\ufeff]/.test(raw), "no zero-width/bidi left");
});

test("AuditLog: fields are truncated to their limits", () => {
	const log = new AuditLog(join(dir(), "audit.jsonl"));
	log.append({ event: "e".repeat(200), username: "u".repeat(200), ip: "i".repeat(200), ua: "a".repeat(500), detail: "d".repeat(500) });
	const row = log.list({ limit: 1 })[0];
	assert.equal(row.event.length, 48);
	assert.equal(row.username.length, 64);
	assert.equal(row.ip.length, 64);
	assert.equal(row.ua.length, 200);
	assert.equal(row.detail.length, 200);
});

test("AuditLog: a corrupt line is skipped instead of throwing", () => {
	const path = join(dir(), "audit.jsonl");
	writeFileSync(path, '{"ts":1,"event":"ok"}\nnot json\nnull\n[1,2]\n');
	const log = new AuditLog(path);
	const rows = log.list({ limit: 10 });
	assert.equal(rows.length, 1, "only the well-formed object survives");
	assert.equal(rows[0].event, "ok");
});

test("AuditLog: rotation keeps three generations and list reads across them", () => {
	const path = join(dir(), "audit.jsonl");
	const log = new AuditLog(path);
	// Pre-seed an "old" generation, then force rotation by writing past the cap.
	writeFileSync(path + ".1", JSON.stringify({ ts: 1, event: "gen1", username: "", ip: "", ua: "", detail: "" }) + "\n");
	writeFileSync(path, JSON.stringify({ ts: 2, event: "current", username: "", ip: "", ua: "", detail: "" }) + "\n");
	const events = log.list({ limit: 10 }).map((r) => r.event);
	assert.deepEqual(events, ["current", "gen1"], "newest first, both generations visible");
	assert.ok(statSync(path + ".1").size > 0);
});

test("AuditLog: limit is clamped", () => {
	const log = new AuditLog(join(dir(), "audit.jsonl"));
	for (let i = 0; i < 5; i += 1) log.append({ event: "e" + i });
	// A falsy limit (0, NaN) falls back to the default window, so it never
	// means "return nothing".
	assert.equal(log.list({ limit: 0 }).length, 5, "limit 0 falls back to the default");
	assert.equal(log.list({ limit: -5 }).length, 1, "negative clamps to the floor of 1");
	assert.equal(log.list({ limit: 999999 }).length, 5, "cannot exceed what exists");
	assert.equal(log.list({ limit: 2 }).length, 2);
});

// ── SessionRegistry ────────────────────────────────────────────────────────

test("SessionRegistry: create/has/revoke lifecycle", () => {
	const reg = new SessionRegistry(join(dir(), "sessions.json")).load();
	const sid = reg.create({ username: "alice", ip: "127.0.0.1", ua: "UA", ttlMs: 60_000 });
	assert.equal(typeof sid, "string");
	assert.ok(sid.length > 0);
	assert.equal(reg.has(sid), true);
	assert.equal(reg.has(sid, "alice"), true);
	assert.equal(reg.has(sid, "bob"), false, "sid is bound to its username");

	const res = reg.revoke(sid);
	assert.deepEqual(res, { revoked: true, persisted: true });
	assert.equal(reg.has(sid), false);
	assert.deepEqual(reg.revoke(sid), { revoked: false, persisted: true }, "revoking twice is idempotent");
});

test("SessionRegistry: empty or malformed sid never matches", () => {
	const reg = new SessionRegistry(join(dir(), "sessions.json")).load();
	reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	for (const bad of ["", null, undefined, 0, "nope", {}]) {
		assert.equal(reg.has(bad), false, "rejects " + String(bad));
	}
});

test("SessionRegistry: revokeAll drops every session of one account", () => {
	const reg = new SessionRegistry(join(dir(), "sessions.json")).load();
	const a1 = reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	const a2 = reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	const b1 = reg.create({ username: "bob", ip: "", ua: "", ttlMs: 60_000 });

	const res = reg.revokeAll("alice");
	assert.deepEqual(res, { removed: 2, persisted: true });
	assert.equal(reg.has(a1), false);
	assert.equal(reg.has(a2), false);
	assert.equal(reg.has(b1), true, "other accounts untouched");
});

test("SessionRegistry: revokeAll can keep one sid", () => {
	const reg = new SessionRegistry(join(dir(), "sessions.json")).load();
	const keep = reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	const res = reg.revokeAll("alice", keep);
	assert.equal(res.removed, 1);
	assert.equal(reg.has(keep), true);
});

test("SessionRegistry: per-account cap evicts the least recently seen", () => {
	const reg = new SessionRegistry(join(dir(), "sessions.json"), { maxPerUser: 3 }).load();
	const first = reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	assert.equal(reg.list("alice").length, 3);
	reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	assert.equal(reg.list("alice").length, 3, "stays at the cap");
	assert.equal(reg.has(first), false, "oldest evicted");
});

test("SessionRegistry: expired sessions are pruned and never match", () => {
	const reg = new SessionRegistry(join(dir(), "sessions.json")).load();
	const sid = reg.create({ username: "alice", ip: "", ua: "", ttlMs: 60_000 });
	// Rewind the expiry in place, then re-prune.
	reg.data[0].expiresAt = Date.now() - 1000;
	reg.prune();
	assert.equal(reg.has(sid), false);
	assert.equal(reg.list().length, 0);
});

test("SessionRegistry: create stores cleaned ip/ua/username", () => {
	const reg = new SessionRegistry(join(dir(), "sessions.json")).load();
	const sid = reg.create({ username: "ali\u200bce", ip: "1.1.1.1\u0000", ua: "UA\u001b", ttlMs: 60_000 });
	const row = reg.list().find((s) => s.sid === sid);
	assert.equal(row.username, "alice");
	assert.equal(row.ip, "1.1.1.1");
	assert.equal(row.ua, "UA");
});

test("SessionRegistry: persisted state survives a reload", () => {
	const path = join(dir(), "sessions.json");
	const reg = new SessionRegistry(path).load();
	const sid = reg.create({ username: "alice", ip: "1.1.1.1", ua: "UA", ttlMs: 60_000 });

	const reloaded = new SessionRegistry(path).load();
	assert.equal(reloaded.has(sid, "alice"), true);
});

test("SessionRegistry: a corrupt file loads as an empty table", () => {
	const path = join(dir(), "sessions.json");
	writeFileSync(path, "{ not json");
	const reg = new SessionRegistry(path).load();
	assert.equal(reg.list().length, 0);
});
