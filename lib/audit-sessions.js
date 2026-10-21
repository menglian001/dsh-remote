/**
 * dsh-remote — 审计日志 + 会话注册表。
 *
 * 设计取舍：
 *   - 审计写失败绝不能影响登录，所有 IO 都 try/catch 吞掉。
 *   - 写入字段先脱敏截断（控制字符/零宽字符剥除 + 长度上限），防止未认证者用超长
 *     username 撑爆单行、把审计历史挤掉。
 *   - 轮转保留 .1/.2/.3 三份，且每份都收紧到 0600。
 *   - 会话表按需落盘（touch 节流 60s）；save()/revoke()/revokeAll() 都回传落盘结果，
 *     避免"内存已生效但磁盘没写成功"被静默当成成功。
 *   - 全局上限与每账号上限统一按 lastSeenAt 淘汰（LRU），不会把最活跃的会话挤掉。
 */
import { randomUUID } from "node:crypto";
import {
	appendFileSync, chmodSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync
} from "node:fs";
import { dirname } from "node:path";

/** 审计日志单文件上限，超过就轮转。 */
const MAX_AUDIT_BYTES = 2 * 1024 * 1024;
/** 单条审计记录的最大序列化长度（兜底，防止意外超大字段）。 */
const MAX_ENTRY_CHARS = 2048;
/** 单次查询最多返回多少条。 */
const MAX_AUDIT_LIMIT = 2000;
/** 轮转保留几份历史。 */
const ROTATE_KEEP = 3;
/** 目录权限：只有本用户可进。 */
const DIR_MODE = 0o700;
/** 文件权限。 */
const FILE_MODE = 0o600;

/**
 * 去掉控制字符并截断（审计字段一律过一遍）。
 * 必须覆盖整个 Unicode 控制/格式面：C0(0x00-0x1F)、DEL、C1(0x80-0x9F)、
 * 零宽与双向控制符(Cf)、行段分隔符(Zl/Zp)、代理与私用区。
 * 只剥 C0 会漏掉 C1 —— 攻击者可用 U+009D 起头的 8-bit OSC 52 序列
 * 在审计日志里植入终端转义，改写读日志者的剪贴板/标题/屏幕。
 */
function clean(value, limit) {
	return String(value ?? "")
		.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/gu, "")
		.slice(0, limit);
}

/** 追加式审计日志。 */
export class AuditLog {
	constructor(path) {
		this.path = path;
		this.permissionsChecked = false;
	}

	/** 首次写入后把权限收紧到 0600（appendFileSync 的 mode 只在创建时生效）。 */
	ensurePermissions() {
		if (this.permissionsChecked) return;
		try {
			chmodSync(this.path, FILE_MODE);
			this.permissionsChecked = true;
		} catch {
			// 文件还不存在：下次写入再收
		}
	}

	/** 轮转：path -> .1 -> .2 -> .3，最旧丢弃；每份都收紧权限。 */
	rotate() {
		try {
			rmSync(this.path + "." + ROTATE_KEEP, { force: true });
		} catch {
			// ignore
		}
		for (let index = ROTATE_KEEP - 1; index >= 1; index -= 1) {
			try {
				renameSync(this.path + "." + index, this.path + "." + (index + 1));
			} catch {
				// 该份历史不存在
			}
		}
		try {
			renameSync(this.path, this.path + ".1");
		} catch {
			// 当前文件不存在
		}
		for (let index = 1; index <= ROTATE_KEEP; index += 1) {
			try {
				chmodSync(this.path + "." + index, FILE_MODE);
			} catch {
				// 该份不存在
			}
		}
	}

	/**
	 * 追加一条事件。永不抛错（审计失败不应影响业务）。
	 * @param {object} entry - 事件字段（event/username/ip/ua/detail...）。
	 */
	append(entry) {
		try {
			mkdirSync(dirname(this.path), { recursive: true, mode: DIR_MODE });
			try {
				if (statSync(this.path).size > MAX_AUDIT_BYTES) this.rotate();
			} catch {
				// 文件还不存在
			}
			const row = {
				ts: Date.now(),
				event: clean(entry?.event, 48),
				username: clean(entry?.username, 64),
				ip: clean(entry?.ip, 64),
				ua: clean(entry?.ua, 200),
				detail: clean(entry?.detail, 200)
			};
			appendFileSync(this.path, JSON.stringify(row) + "\n", { mode: FILE_MODE });
			this.ensurePermissions();
		} catch {
			// 审计失败静默
		}
	}

	/**
	 * 读取最近的记录（新的在前）。
	 * @param {{limit?: number}} options - 返回条数上限。
	 * @returns {object[]}
	 */
	list(options = {}) {
		const limit = Math.min(Math.max(Number(options.limit) || 200, 1), MAX_AUDIT_LIMIT);
		// 跨轮转段读取：.3 最旧 → .1 → 当前。只读当前段会让历史在轮转后不可达。
		const segments = [];
		for (let index = ROTATE_KEEP; index >= 1; index -= 1) segments.push(this.path + "." + index);
		segments.push(this.path);
		const lines = [];
		for (const segment of segments) {
			let raw;
			try {
				raw = readFileSync(segment, "utf8");
			} catch {
				continue;
			}
			for (const line of raw.split("\n")) if (line.trim() !== "") lines.push(line);
		}
		const out = [];
		for (const line of lines.slice(-limit)) {
			try {
				const row = JSON.parse(line);
				// 只收普通对象：一行 null/数组会让上层过滤与前端渲染直接抛错。
				if (row !== null && typeof row === "object" && !Array.isArray(row)) out.push(row);
			} catch {
				// 半行/损坏行跳过
			}
		}
		return out.reverse();
	}
}

/** 会话注册表：sid -> 元数据，用于列出在线设备并单独吊销。 */
export class SessionRegistry {
	constructor(path, options = {}) {
		this.path = path;
		this.max = Math.max(Number(options.max) || 200, 10);
		this.maxPerUser = Math.max(Number(options.maxPerUser) || 10, 2);
		this.data = [];
		this.dirty = false;
		this.lastSaveOk = true;
	}

	/** 载入并清理过期项。文件不存在/损坏都按空表处理。 */
	load() {
		try {
			const parsed = JSON.parse(readFileSync(this.path, "utf8"));
			this.data = Array.isArray(parsed?.sessions) ? parsed.sessions : [];
		} catch {
			this.data = [];
		}
		const before = this.data.length;
		this.prune();
		// 清理掉的过期项要落盘，否则它们的 ip/ua 会一直留在磁盘上。
		if (this.data.length !== before) this.save();
		return this;
	}

	/**
	 * 原子落盘（tmp + rename + chmod 0600）。
	 * @returns {boolean} 是否真的写成功（失败时内存表仍有效，但重启后会丢）。
	 */
	save() {
		try {
			mkdirSync(dirname(this.path), { recursive: true, mode: DIR_MODE });
			const tmp = this.path + "." + process.pid + ".tmp";
			writeFileSync(tmp, JSON.stringify({ version: 1, sessions: this.data }, null, 2), { mode: FILE_MODE });
			renameSync(tmp, this.path);
			try {
				chmodSync(this.path, FILE_MODE);
			} catch {
				// best effort
			}
			this.dirty = false;
			return true;
		} catch {
			this.dirty = true;
			return false;
		}
	}

	/** 丢弃过期项，并按 lastSeenAt（LRU）压到全局上限以内。 */
	prune() {
		const now = Date.now();
		this.data = this.data.filter((s) => s && typeof s.sid === "string" && Number(s.expiresAt) > now);
		if (this.data.length > this.max) {
			this.data = this.data
				.slice()
				.sort(
					(a, b) =>
						Number(a.lastSeenAt ?? 0) - Number(b.lastSeenAt ?? 0) ||
						Number(a.createdAt ?? 0) - Number(b.createdAt ?? 0)
				)
				.slice(-this.max);
		}
	}

	/**
	 * 新建一个会话并立即落盘。超出每账号上限时淘汰该账号最旧的会话。
	 * @returns {string} 新的 sid。
	 */
	create({ username, ip, ua, ttlMs }) {
		this.prune();
		const mine = this.data.filter((s) => s.username === username);
		if (mine.length >= this.maxPerUser) {
			const drop = new Set(
				mine
					.sort((a, b) => Number(a.lastSeenAt ?? 0) - Number(b.lastSeenAt ?? 0))
					.slice(0, mine.length - this.maxPerUser + 1)
					.map((s) => s.sid)
			);
			this.data = this.data.filter((s) => !drop.has(s.sid));
		}
		const now = Date.now();
		const sid = randomUUID();
		this.data.push({
			sid,
			username: clean(username, 64),
			ip: clean(ip, 64),
			ua: clean(ua, 200),
			createdAt: now,
			lastSeenAt: now,
			expiresAt: now + Math.max(Number(ttlMs) || 0, 60_000)
		});
		if (this.data.length > this.max) this.prune();
		this.lastSaveOk = this.save();
		return sid;
	}

	/**
	 * 该 sid 是否仍然有效，且确实属于这个账号。
	 * @param {string} sid - 会话 id。
	 * @param {string} [username] - 传入时要求会话归属一致。
	 */
	has(sid, username) {
		if (typeof sid !== "string" || sid === "") return false;
		return this.data.some(
			(s) =>
				s.sid === sid &&
				Number(s.expiresAt) > Date.now() &&
				(username === undefined || s.username === username)
		);
	}

	/** 刷新最近活跃时间；最多每 60 秒落盘一次。 */
	touch(sid) {
		const entry = this.data.find((s) => s.sid === sid);
		if (entry === undefined) return false;
		const now = Date.now();
		if (now - Number(entry.lastSeenAt ?? 0) > 60_000) {
			entry.lastSeenAt = now;
			this.save();
		}
		return true;
	}

	/** 列出会话（新的在前）。 */
	list(username) {
		this.prune();
		const rows = username === undefined ? this.data : this.data.filter((s) => s.username === username);
		return rows
			.slice()
			.sort((a, b) => Number(b.lastSeenAt ?? 0) - Number(a.lastSeenAt ?? 0))
			.map((s) => ({ ...s }));
	}

	/**
	 * 吊销单个会话。
	 * @returns {{revoked: boolean, persisted: boolean}}
	 */
	revoke(sid) {
		const before = this.data.length;
		this.data = this.data.filter((s) => s.sid !== sid);
		if (this.data.length === before) return { revoked: false, persisted: true };
		return { revoked: true, persisted: this.save() };
	}

	/**
	 * 吊销某个账号的全部会话（可保留当前这一个）。
	 * @returns {{removed: number, persisted: boolean}}
	 */
	revokeAll(username, exceptSid) {
		const before = this.data.length;
		this.data = this.data.filter((s) => s.username !== username || s.sid === exceptSid);
		const removed = before - this.data.length;
		if (removed === 0) return { removed: 0, persisted: true };
		return { removed, persisted: this.save() };
	}
}
