import { test } from "node:test";
import assert from "node:assert/strict";
import { passwordProblem, passwordProblemMessage } from "../lib/index.js";

test("passwordProblem: accepts a strong password", () => {
	assert.equal(passwordProblem("alice", "Kx7-mango-River-92"), null);
	assert.equal(passwordProblem("alice", "correct-horse-battery"), null);
});

test("passwordProblem: rejects anything shorter than 10 characters", () => {
	assert.equal(passwordProblem("alice", "Short-1"), "too-short");
	assert.equal(passwordProblem("alice", "Nine-char"), "too-short");
	assert.equal(passwordProblem("alice", "0123456789"), "all-digits", "10 digits hits the digit rule first");
	assert.equal(passwordProblem("alice", ""), "too-short");
});

test("passwordProblem: rejects all-digit passwords", () => {
	// 1234567890 is on the weak-password blacklist, so it reports "common"
	assert.equal(passwordProblem("alice", "1234567890"), "common");
	assert.equal(passwordProblem("alice", "9876543210"), "all-digits");
	assert.equal(passwordProblem("alice", "00000000000000"), "all-digits");
});

test("passwordProblem: rejects highly repetitive passwords", () => {
	assert.equal(passwordProblem("alice", "aaaaaaaaaaaa"), "too-simple");
	assert.equal(passwordProblem("alice", "abababababab"), "too-simple");
});

test("passwordProblem: rejects common passwords even when long enough", () => {
	// The blacklist is checked before the length rule, so short common
	// passwords report "common" rather than "too-short".
	assert.equal(passwordProblem("alice", "password"), "common");
	assert.equal(passwordProblem("alice", "password123"), "common");
	assert.equal(passwordProblem("alice", "PASSWORD"), "common", "case-insensitive");
	assert.equal(passwordProblem("alice", "123456"), "common");
});

test("passwordProblem: rejects a password containing the username", () => {
	assert.equal(passwordProblem("alice", "alice-2026-secret"), "contains-username");
	assert.equal(passwordProblem("alice", "ALICE-2026-secret"), "contains-username", "case-insensitive");
});

test("passwordProblem: skips the username rule for very short usernames", () => {
	// A 2-character username would match almost anything; the rule is skipped.
	assert.equal(passwordProblem("ab", "Kx7-mango-River-92"), null);
});

test("passwordProblemMessage: returns localised text for every reason code", () => {
	const codes = ["too-short", "all-digits", "too-simple", "common", "contains-username"];
	for (const code of codes) {
		const zh = passwordProblemMessage(code, "zh");
		const en = passwordProblemMessage(code, "en");
		assert.equal(typeof zh, "string");
		assert.ok(zh.length > 0, "zh text for " + code);
		assert.match(zh, /[\u4e00-\u9fa5]/, "zh is Chinese for " + code);
		assert.ok(en.length > 0, "en text for " + code);
		assert.match(en, /^[\x20-\x7e]+$/, "en is ASCII for " + code);
		assert.notEqual(zh, en);
	}
});

test("passwordProblemMessage: unknown code falls back to the code itself", () => {
	assert.equal(passwordProblemMessage("mystery", "en"), "mystery");
});
