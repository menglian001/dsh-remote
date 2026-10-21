import { test } from "node:test";
import assert from "node:assert/strict";
import {
	TOTP_DIGITS,
	TOTP_PERIOD,
	base32Decode,
	base32Encode,
	findBackupCode,
	generateBackupCodes,
	generateTotpSecret,
	hashBackupCode,
	otpauthUri,
	totp,
	verifyTotp
} from "../lib/totp.js";

// RFC 6238 Appendix B test vectors (SHA-1, 8 digits), truncated to 6.
// secret "12345678901234567890" in base32:
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_VECTORS = [
	[59, "287082"],
	[1111111109, "081804"],
	[1111111111, "050471"],
	[1234567890, "005924"],
	[2000000000, "279037"],
	[20000000000, "353130"]
];

test("totp: matches the RFC 6238 SHA-1 test vectors", () => {
	for (const [seconds, expected] of RFC_VECTORS) {
		assert.equal(totp(RFC_SECRET, Math.floor(seconds / TOTP_PERIOD)), expected, "counter for t=" + seconds);
	}
});

test("totp: digits and period are the documented values", () => {
	assert.equal(TOTP_DIGITS, 6);
	assert.equal(TOTP_PERIOD, 30);
	assert.match(totp(RFC_SECRET), /^\d{6}$/);
});

test("verifyTotp: accepts the current step and rejects a stale one", () => {
	const secret = generateTotpSecret();
	const now = Math.floor(Date.now() / 1000);
	const current = totp(secret, Math.floor(now / TOTP_PERIOD));
	assert.equal(verifyTotp(secret, current, 1), true);
	// Ten windows back is outside any sane window.
	const stale = totp(secret, Math.floor(now / TOTP_PERIOD) - 10);
	assert.equal(verifyTotp(secret, stale, 1), false);
});

test("verifyTotp: window widens acceptance by that many steps each side", () => {
	const secret = generateTotpSecret();
	const base = Math.floor(Date.now() / 1000 / TOTP_PERIOD);
	const nextStep = totp(secret, base + 1);
	assert.equal(verifyTotp(secret, nextStep, 0), false, "window 0 accepts only the current step");
	assert.equal(verifyTotp(secret, nextStep, 1), true, "window 1 accepts ±1");
});

test("verifyTotp: malformed input never throws and never passes", () => {
	const secret = generateTotpSecret();
	for (const bad of ["", "12345", "1234567", "abcdef", "12 34 56", null, undefined, 123456]) {
		assert.equal(verifyTotp(secret, bad, 1), false, "rejects " + String(bad));
	}
});

test("base32: round-trips arbitrary bytes", () => {
	for (let i = 0; i < 50; i += 1) {
		const buf = Buffer.from(Array.from({ length: i }, (_, n) => (n * 37 + i) % 256));
		assert.deepEqual(base32Decode(base32Encode(buf)), buf, "length " + i);
	}
});

test("base32Decode: tolerates lowercase and spaces, rejects junk", () => {
	assert.deepEqual(base32Decode(base32Encode(Buffer.from("hi")).toLowerCase()), Buffer.from("hi"));
	assert.throws(() => base32Decode("!!!!"));
});

test("generateTotpSecret: 160-bit base32 secret, unique each call", () => {
	const a = generateTotpSecret();
	const b = generateTotpSecret();
	assert.equal(a.length, 32, "160 bits -> 32 base32 chars");
	assert.match(a, /^[A-Z2-7]+$/);
	assert.notEqual(a, b);
});

test("otpauthUri: encodes issuer and account", () => {
	const uri = otpauthUri({ secret: RFC_SECRET, account: "alice", issuer: "DSH" });
	assert.ok(uri.startsWith("otpauth://totp/"));
	assert.ok(uri.includes("secret=" + RFC_SECRET));
	assert.ok(uri.includes("issuer=DSH"));
});

test("backup codes: ten unique codes of the documented shape", () => {
	const codes = generateBackupCodes();
	assert.equal(codes.length, 10);
	assert.equal(new Set(codes).size, 10, "all unique");
	for (const code of codes) {
		assert.equal(typeof code, "string");
		assert.ok(code.length >= 6, "long enough to be usable");
	}
});

test("backup codes: hashing is stable and the code is not stored in clear", () => {
	const [code] = generateBackupCodes();
	const hash = hashBackupCode(code);
	assert.equal(hash, hashBackupCode(code), "same input, same hash");
	assert.notEqual(hash, hashBackupCode(code + "x"));
	assert.ok(!hash.includes(code), "hash must not contain the plaintext");
});

test("backup codes: lookup matches the stored hash and ignores used codes", () => {
	const codes = generateBackupCodes();
	// Store shape mirrors store.js: { hash } with usedAt absent while unused.
	const entries = codes.map((c) => ({ hash: hashBackupCode(c) }));
	const hit = findBackupCode(codes[3], entries);
	assert.notEqual(hit, null, "unused code is found");
	assert.equal(findBackupCode("ZZZZZZZZZZ", entries), null, "unknown code misses");
	// Once marked used the same code must stop matching (single use).
	hit.usedAt = Date.now();
	assert.equal(findBackupCode(codes[3], entries), null, "used code no longer matches");
});
