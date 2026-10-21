/**
 * dsh-remote — self-contained login page (zh / en).
 *
 * Served by the gated fallback for unauthenticated browsers, so it must not
 * reference any bundled asset (everything is inline). The page is a complete
 * auth surface on its own:
 *   - bootstrap: no account exists yet -> create the first admin (loopback only)
 *   - login:     username + password
 *   - mfa code:  accounts with two-factor enabled -> 6-digit code / backup code
 *   - mfa offer: accounts without two-factor -> optional in-place binding
 *                (secret, otpauth link, backup codes, verify) using the session
 *                cookie the password step just issued
 * On completion it redirects to `next` (the originally requested path) or `/`.
 *
 * i18n: the host passes `lang` ("zh" | "en", derived from the request's
 * Accept-Language). All user-visible copy is selected from STRINGS at render
 * time, so the page never renegotiates language client-side.
 */

/** HTML-escape user-controlled values (the `next` path). */
function escapeHtml(value) {
	return String(value)
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

/** UI copy. Keys are shared between zh and en; missing keys fall back to en. */
const STRINGS = {
	zh: {
		pageTitle: "登录",
		headingBootstrap: "创建首个管理员账号",
		headingLogin: "登录 DeepSeek Harness",
		buttonBootstrap: "创建管理员账号",
		buttonLogin: "登录",
		hintBootstrap: "尚未配置任何账号。出于安全考虑，首个管理员账号只能在本地（loopback）创建。",
		hintLogin: "请输入用户名和密码。",
		username: "用户名",
		password: "密码",
		code: "两步验证码（或备用码）",
		offerOk: "双重验证尚未开启。现在用认证器 App 绑定，为账号加一层保护。",
		offerBind: "绑定双重验证",
		offerSkip: "跳过，直接进入",
		setupIntro: "用认证器 App（Google Authenticator、1Password、Authy 等）添加账号：",
		qrAlt: "扫码绑定二维码",
		setupSecret: "或手动录入密钥",
		setupOtpauth: "otpauth 链接",
		setupBackup: "一次性备用码（每个仅可使用一次，请妥善保存）",
		setupVerify: "在认证器中输入当前 6 位验证码以启用：",
		countdown: "有效剩余 {n} 秒",
		offerHeading: "绑定双重验证",
		offerSub: "为账号 {user} 开启两步验证。",
		generating: "正在生成密钥…",
		setupStep1: "第 1 步：在认证器 App 中添加以下账号（扫描或手动录入）。",
		verifyEnable: "验证并启用",
		verifying: "正在验证…",
		enabled: "双重验证已启用。请保存好备用码。",
		success: "登录成功，正在跳转…",
		codeHeading: "两步验证",
		codeSub: "请输入认证器中的动态验证码（或一次性备用码）。",
		verify: "验证",
		failed: "登录失败 ({status})"
	},
	en: {
		pageTitle: "Sign in",
		headingBootstrap: "Create the first admin account",
		headingLogin: "Sign in to DeepSeek Harness",
		buttonBootstrap: "Create admin account",
		buttonLogin: "Sign in",
		hintBootstrap: "No account is configured yet. For safety, the first admin account can only be created locally (loopback).",
		hintLogin: "Enter your username and password.",
		username: "Username",
		password: "Password",
		code: "Two-factor code (or backup code)",
		offerOk: "Two-factor authentication is not enabled yet. Bind it now with an authenticator app to protect this account.",
		offerBind: "Bind two-factor",
		offerSkip: "Skip for now",
		setupIntro: "Add the account in an authenticator app (Google Authenticator, 1Password, Authy, …):",
		qrAlt: "QR code for two-factor binding",
		setupSecret: "Or enter the key manually",
		setupOtpauth: "otpauth link",
		setupBackup: "One-time backup codes (each usable once — save them somewhere safe)",
		setupVerify: "Enter the current 6-digit code from the authenticator to enable:",
		countdown: "Valid for {n}s",
		offerHeading: "Bind two-factor",
		offerSub: "Enable two-factor for account {user}.",
		generating: "Generating key…",
		setupStep1: "Step 1: add the account in your authenticator app (scan or enter it manually).",
		verifyEnable: "Verify & enable",
		verifying: "Verifying…",
		enabled: "Two-factor enabled. Keep your backup codes safe.",
		success: "Signed in — redirecting…",
		codeHeading: "Two-factor",
		codeSub: "Enter the code from your authenticator (or a one-time backup code).",
		verify: "Verify",
		failed: "Sign-in failed ({status})"
	}
};

/**
 * @param {object} options
 * @param {boolean} options.bootstrap - whether to show the first-admin form.
 * @param {string} options.next - path to redirect to after login.
 * @param {string} [options.error] - pre-rendered error message.
 * @param {string} [options.title] - page title text.
 * @param {string} [options.lang] - "zh" or "en" (default "en").
 * @returns {string} the full HTML document.
 */
export function renderLoginPage({ bootstrap, next = "/", error = "", title = "DeepSeek Harness", lang = "en" }) {
	const s = STRINGS[lang === "zh" ? "zh" : "en"] ?? STRINGS.en;
	const htmlLang = lang === "zh" ? "zh-CN" : "en";
	const heading = bootstrap ? s.headingBootstrap : s.headingLogin;
	const button = bootstrap ? s.buttonBootstrap : s.buttonLogin;
	const endpoint = bootstrap ? "/auth/bootstrap" : "/auth/login";
	const hint = bootstrap ? s.hintBootstrap : s.hintLogin;
	const errorHtml = error ? `<div class="error" role="alert">${escapeHtml(error)}</div>` : "";
	return `<!doctype html>
<html lang="${htmlLang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} · ${s.pageTitle}</title>
  <meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#151517" media="(prefers-color-scheme: dark)">
  <script>
  (function () {
    var dark = false;
    try {
      var forced = location.search.match(/[?&]theme=(dark|light)/);
      dark = forced
        ? forced[1] === "dark"
        : !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
    } catch (e) {  }
    var root = document.documentElement;
    root.setAttribute("data-ds-theme", dark ? "dark" : "light");
    if (dark) root.setAttribute("data-ds-dark-theme", "");
    root.style.colorScheme = dark ? "dark" : "light";
  })();
  </script>
<style>
/* ============================================================================
 * ========================================================================== */

:root {
  
  --dsh-font-family-text-default: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC',
    'Hiragino Sans GB', 'Microsoft YaHei', 'Helvetica Neue', Helvetica, Arial, sans-serif;
  --dsh-font-family-code-default: 'SF Mono', 'JetBrains Mono', 'Fira Code', Consolas,
    'Liberation Mono', Menlo, Courier, 'PingFang SC', 'Microsoft YaHei';
  --dsw-font-family: var(--dsh-font-family-text-default);
  --ds-font-family-code: var(--dsh-font-family-code-default);

  
  --dsw-radius-xs: 4px;
  --dsw-radius-sm: 8px;
  --dsw-radius-md: 12px;
  --dsw-radius-lg: 16px;
  --dsw-radius-xl: 20px;
  --dsw-radius-panel: 28px;
  --ds-ease-in-out: cubic-bezier(0.4, 0, 0.2, 1);
  --ds-transition-duration: 0.2s;
  --ds-transition-duration-fast: 0.1s;
  --ds-transition-duration-slow: 0.3s;
  --dsw-focus-ring-width: 2px;

  
  --dsw-static-neutral-bluish-00: #fff;
  --dsw-static-neutral-bluish-50: #f9fafb;
  --dsw-static-neutral-bluish-60: #f5f6f7;
  --dsw-static-neutral-bluish-75: #f1f3f5;
  --dsw-static-neutral-bluish-100: #ebeef2;
  --dsw-static-neutral-bluish-150: #e9ecf2;
  --dsw-static-neutral-bluish-200: #e1e5ee;
  --dsw-static-neutral-bluish-300: #cfd3d6;
  --dsw-static-neutral-bluish-400: #adb2b8;
  --dsw-static-neutral-bluish-600: #81858c;
  --dsw-static-neutral-bluish-700: #61666b;
  --dsw-static-neutral-bluish-750: #43454a;
  --dsw-static-neutral-bluish-800: #353638;
  --dsw-static-neutral-bluish-850: #2c2c2e;
  --dsw-static-neutral-bluish-875: #232324;
  --dsw-static-neutral-bluish-900: #1b1b1c;
  --dsw-static-neutral-bluish-950: #151517;
  --dsw-static-neutral-bluish-1000: #0f1115;
  --dsw-static-deepseek-400: #7aaaff;
  --dsw-static-deepseek-450: #5686fe;
  --dsw-static-deepseek-500: #4176e6;
  --dsw-static-red-400: #f25a5a;
  --dsw-static-red-600: #ec1313;
  --dsw-static-green-400: #4ed17e;
  --dsw-static-green-500: #22c55e;
  --dsw-static-amber-500: #f59e0b;

  
  --dsw-alias-bg-base: var(--dsw-static-neutral-bluish-00);
  --dsw-alias-bg-layer-1: var(--dsw-static-neutral-bluish-00);
  --dsw-alias-bg-layer-2: var(--dsw-static-neutral-bluish-00);
  --dsw-alias-bg-layer-3: var(--dsw-static-neutral-bluish-00);

  --dsw-alias-border-l1: #0000000a;
  --dsw-alias-border-l2: #0000001a;
  --dsw-alias-border-l3: #0000001f;
  --dsw-alias-border-l4: #00000029;

  --dsw-alias-label-primary: var(--dsw-static-neutral-bluish-1000);
  --dsw-alias-label-secondary: var(--dsw-static-neutral-bluish-700);
  --dsw-alias-label-tertiary: var(--dsw-static-neutral-bluish-600);
  --dsw-alias-label-caption: var(--dsw-static-neutral-bluish-400);
  --dsw-alias-label-dimmed: var(--dsw-static-neutral-bluish-200);
  --dsw-alias-label-primary-foreground: var(--dsw-static-neutral-bluish-00);
  --dsw-alias-label-primary-inverted: var(--dsw-static-neutral-bluish-00);

  --dsw-alias-brand-primary: var(--dsw-static-neutral-bluish-1000);
  --dsw-alias-button-primary-fill: var(--dsw-alias-brand-primary);
  --dsw-alias-button-primary-hover: var(--dsw-static-neutral-bluish-750);

  --dsw-alias-interactive-bg-hover: #2631480f;
  --dsw-alias-interactive-bg-active: #2631481a;

  --dsw-alias-state-business-primary: var(--dsw-static-deepseek-500);
  --dsw-alias-state-error-primary: var(--dsw-static-red-600);
  --dsw-alias-state-success-primary: var(--dsw-static-green-500);
  --dsw-alias-state-warn-primary: var(--dsw-static-amber-500);
  --dsw-alias-state-warn-label: #dd8629;

  --dsw-specific-login-input: var(--dsw-static-neutral-bluish-50);
  --dsw-alias-link: var(--dsw-static-deepseek-500);

  
  --dsw-elevation-stroke-color: var(--dsw-alias-border-l4);
  --dsw-elevation-stroke: 0 0 0 0.5px var(--dsw-elevation-stroke-color);
  --dsw-elevation-panel: var(--dsw-elevation-stroke), 0 3px 8px 0 rgb(0 0 0 / 3%), 0 0 16px 0 rgb(0 0 0 / 2%);
  --dsw-elevation-prominent: var(--dsw-elevation-stroke), 0 3px 8px 0 rgb(0 0 0 / 4%), 0 0 20px 0 rgb(0 0 0 / 5%);

  color-scheme: light;
}


html[data-ds-theme='dark'] {
  --dsw-alias-bg-base: var(--dsw-static-neutral-bluish-950);
  --dsw-alias-bg-layer-1: var(--dsw-static-neutral-bluish-875);
  --dsw-alias-bg-layer-2: var(--dsw-static-neutral-bluish-850);
  --dsw-alias-bg-layer-3: var(--dsw-static-neutral-bluish-800);

  --dsw-alias-border-l1: #ffffff0f;
  --dsw-alias-border-l2: #ffffff1f;
  --dsw-alias-border-l3: #ffffff29;
  --dsw-alias-border-l4: #fff3;

  --dsw-alias-label-primary: var(--dsw-static-neutral-bluish-50);
  --dsw-alias-label-secondary: var(--dsw-static-neutral-bluish-300);
  --dsw-alias-label-tertiary: var(--dsw-static-neutral-bluish-400);
  --dsw-alias-label-caption: var(--dsw-static-neutral-bluish-600);
  --dsw-alias-label-dimmed: var(--dsw-static-neutral-bluish-750);
  --dsw-alias-label-primary-foreground: var(--dsw-static-neutral-bluish-1000);
  --dsw-alias-label-primary-inverted: var(--dsw-static-neutral-bluish-800);

  --dsw-alias-brand-primary: var(--dsw-static-neutral-bluish-50);
  --dsw-alias-button-primary-hover: var(--dsw-static-neutral-bluish-100);

  --dsw-alias-interactive-bg-hover: #ffffff14;
  --dsw-alias-interactive-bg-active: #ffffff24;

  --dsw-alias-state-business-primary: var(--dsw-static-deepseek-450);
  --dsw-alias-state-error-primary: var(--dsw-static-red-400);
  --dsw-alias-state-warn-label: #dd8629;

  --dsw-specific-login-input: var(--dsw-static-neutral-bluish-900);
  --dsw-alias-link: var(--dsw-static-deepseek-400);

  --dsw-elevation-stroke-color: var(--dsw-alias-border-l3);

  color-scheme: dark;
}

/* ============================================================================
 * ========================================================================== */

*,
*::before,
*::after { box-sizing: border-box; }

[hidden] { display: none !important; }

html { height: 100%; }

body {
  margin: 0;
  min-height: 100%;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  overflow: auto;
  padding: max(24px, min(7vh, 56px)) 24px;
  background: var(--dsw-alias-bg-base);
  color: var(--dsw-alias-label-primary);
  font-family: var(--dsw-font-family);
  font-size: 14px;
  line-height: 22px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}


.panel {
  display: flex;
  flex-direction: column;
  width: min(380px, 100%);
  
  margin: auto;
  border-radius: var(--dsw-radius-panel);
  background: var(--dsw-alias-bg-layer-2);
  box-shadow: var(--dsw-elevation-prominent);
  animation: panel-enter var(--ds-transition-duration) var(--ds-ease-in-out);
}

@keyframes panel-enter {
  from { opacity: 0; }
  to { opacity: 1; }
}

.panel-head {
  display: flex;
  flex-direction: column;
  gap: 18px;
  padding: 26px 24px 18px;
}

.brand { color: var(--dsw-alias-label-primary); }

.brand svg {
  display: block;
  height: 20px;
  width: auto;
}

.head {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

h1 {
  margin: 0;
  font-size: 16px;
  line-height: 24px;
  font-weight: 500;
  color: var(--dsw-alias-label-primary);
}

.sub {
  margin: 0;
  font-size: 13px;
  line-height: 20px;
  color: var(--dsw-alias-label-secondary);
}

.sub.tight { font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary); }

.panel-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 0 24px 24px;
}


.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.field + .field { margin-top: 14px; }

.field-label {
  font-size: 13px;
  font-weight: 500;
  line-height: 20px;
  color: var(--dsw-alias-label-primary);
}

.input {
  width: 100%;
  height: 36px;
  padding: 0 12px;
  border: 0.5px solid var(--dsw-alias-border-l4);
  border-radius: var(--dsw-radius-md);
  background: var(--dsw-specific-login-input);
  color: var(--dsw-alias-label-primary);
  font-family: inherit;
  font-size: 14px;
  line-height: 22px;
  transition: border-color var(--ds-transition-duration-fast) var(--ds-ease-in-out);
}

.input::placeholder { color: var(--dsw-alias-label-dimmed); }

.input:focus { outline: none; border-color: var(--dsw-alias-state-business-primary); }
.input:focus-visible { outline: none; }

.input.is-code {
  font-family: var(--ds-font-family-code);
  letter-spacing: 0.16em;
}


.btn {
  box-sizing: border-box;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  height: 36px;
  padding: 0 14px;
  border: none;
  border-radius: var(--dsw-radius-md);
  background: transparent;
  color: var(--dsw-alias-label-primary);
  font-family: inherit;
  font-size: 14px;
  line-height: 22px;
  cursor: pointer;
  transition: background-color var(--ds-transition-duration-fast) var(--ds-ease-in-out),
    color var(--ds-transition-duration-fast) var(--ds-ease-in-out),
    opacity var(--ds-transition-duration-fast) var(--ds-ease-in-out);
}

.btn:disabled { cursor: not-allowed; opacity: 0.4; }
.btn:focus-visible {
  outline: var(--dsw-focus-ring-width) solid var(--dsw-focus-ring-color, var(--dsw-alias-state-business-primary));
  outline-offset: 1px;
}

.btn-primary {
  font-weight: 500;
  background: var(--dsw-alias-button-primary-fill);
  color: var(--dsw-alias-label-primary-foreground);
}

.btn-primary:hover:not(:disabled) { background: var(--dsw-alias-button-primary-hover); }

.btn-outline { border: 0.5px solid var(--dsw-alias-border-l3); }

.btn-outline:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover); }

.btn-ghost { color: var(--dsw-alias-label-secondary); }

.btn-ghost:hover:not(:disabled) {
  background: var(--dsw-alias-interactive-bg-hover);
  color: var(--dsw-alias-label-primary);
}

.btn-block { width: 100%; }


.spinner {
  position: relative;
  flex: none;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  border: 1.5px solid color-mix(in srgb, currentColor 28%, transparent);
  animation: spin 0.8s linear infinite;
}

.spinner::after {
  content: '';
  position: absolute;
  inset: -1.5px;
  border-radius: inherit;
  background: conic-gradient(currentColor 72deg, transparent 0);
  -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 1.5px), #000 0);
  mask: radial-gradient(farthest-side, transparent calc(100% - 1.5px), #000 0);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* ── banner ─────────────────────────────────────────────────────────────── */
.error,
.ok {
  padding: 10px 12px;
  border-radius: var(--dsw-radius-md);
  border: 0.5px solid transparent;
  font-size: 13px;
  line-height: 20px;
}

.error {
  background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 8%, transparent);
  border-color: color-mix(in srgb, var(--dsw-alias-state-error-primary) 30%, transparent);
  color: var(--dsw-alias-state-error-primary);
}

.ok {
  background: color-mix(in srgb, var(--dsw-alias-state-success-primary) 10%, transparent);
  border-color: color-mix(in srgb, var(--dsw-alias-state-success-primary) 30%, transparent);
  color: var(--dsw-alias-state-success-primary);
}


.offer {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding-top: 16px;
  border-top: 0.5px solid var(--dsw-alias-border-l2);
}

.actions { display: flex; gap: 8px; }
.actions > .btn { flex: 1; min-width: 0; }

.qr { display: flex; justify-content: center; padding: 2px 0; }

.qr img {
  display: block;
  width: 168px;
  height: 168px;
  padding: 8px;
  border-radius: var(--dsw-radius-md);
  border: 0.5px solid var(--dsw-alias-border-l2);
  background: #fff;
  image-rendering: pixelated;
}

.code-box {
  padding: 8px 10px;
  border: 0.5px solid var(--dsw-alias-border-l2);
  border-radius: var(--dsw-radius-sm);
  background: var(--dsw-specific-login-input);
  color: var(--dsw-alias-label-secondary);
  font-family: var(--ds-font-family-code);
  font-size: 12px;
  line-height: 18px;
  word-break: break-all;
  user-select: all;
}

.codes { display: flex; flex-wrap: wrap; gap: 6px; }

.codes span {
  padding: 2px 8px;
  border: 0.5px solid var(--dsw-alias-border-l2);
  border-radius: var(--dsw-radius-xs);
  background: var(--dsw-specific-login-input);
  color: var(--dsw-alias-label-primary);
  font-family: var(--ds-font-family-code);
  font-size: 12px;
  line-height: 18px;
  user-select: all;
}

.ttl {
  font-size: 12px;
  line-height: 18px;
  color: var(--dsw-alias-label-tertiary);
}

.ttl.warn { color: var(--dsw-alias-state-warn-label); }

.note {
  margin: 0;
  font-size: 13px;
  line-height: 20px;
  color: var(--dsw-alias-label-tertiary);
  text-align: center;
}


@media (prefers-reduced-motion: reduce) {
  .panel { animation: none; }
  .spinner { animation: none; }
  .input,
  .btn { transition: none; }
}
</style>
</head>
<body>
  <form class="panel" id="form" autocomplete="on" novalidate>
    <div class="panel-head">
      <div class="brand"><svg xmlns="http://www.w3.org/2000/svg" width="182" height="24" viewBox="0 0 182 24" fill="none" aria-hidden="true" focusable="false">
      <path d="M68.416 18.2447H67.0501V16.1272H68.416C69.2619 16.1272 70.1166 15.9163 70.6671 15.3304C71.2181 14.7444 71.426 13.8455 71.426 12.9471C71.426 12.0487 71.2268 11.1498 70.6671 10.5643C70.1083 9.97831 69.2619 9.76744 68.416 9.76744C67.5701 9.76744 66.7154 9.97831 66.1639 10.5643C65.6129 11.1503 65.4049 12.0487 65.4049 12.9471V21.6435H63.009V7.6582H65.4049V8.54883H65.8442C65.8918 8.49393 65.9394 8.44728 65.9875 8.40064C66.5871 7.85353 67.5049 7.6582 68.4072 7.6582C69.8212 7.6582 71.2341 8.00998 72.1607 8.98662C73.0868 9.96325 73.4143 11.4632 73.4143 12.9558C73.4143 14.4485 73.0785 15.9406 72.1607 16.925C71.2424 17.9094 69.8212 18.2457 68.416 18.2457V18.2447Z" fill="currentColor"/>
      <path d="M31.9551 8.03497H33.3204V10.1525H31.9551C31.1087 10.1525 30.2545 10.3633 29.7035 10.9493C29.1525 11.5353 28.945 12.4342 28.945 13.3326C28.945 14.231 29.1447 15.1294 29.7035 15.7154C30.2623 16.3014 31.1087 16.5122 31.9551 16.5122C32.8015 16.5122 33.6562 16.3014 34.2072 15.7154C34.7582 15.1294 34.9657 14.231 34.9657 13.3326V4.62842H37.3611V18.6219H34.9657V17.7313H34.5264C34.4783 17.7857 34.4307 17.8329 34.3826 17.8795C33.7835 18.4261 32.8652 18.6219 31.9629 18.6219C30.5494 18.6219 29.136 18.2707 28.2099 17.294C27.2838 16.3174 26.9563 14.817 26.9563 13.3248C26.9563 11.8327 27.2916 10.34 28.2099 9.35561C29.136 8.37898 30.5494 8.03497 31.9551 8.03497Z" fill="currentColor"/>
      <path d="M49.3786 13.1431V13.9948H42.9984V12.2996H47.2305C47.1348 11.6825 46.9113 11.1043 46.5119 10.682C45.9371 10.0727 45.0503 9.85409 44.1723 9.85409C43.2943 9.85409 42.4076 10.0727 41.8328 10.682C41.258 11.2913 41.05 12.2213 41.05 13.1435C41.05 14.0658 41.2575 15.003 41.8328 15.6046C42.4076 16.2061 43.2939 16.433 44.1723 16.433C45.0508 16.433 45.9371 16.2143 46.5119 15.6046C46.5916 15.5186 46.6635 15.4248 46.7354 15.331H49.0992C48.8918 16.0657 48.5643 16.7299 48.0691 17.2454C47.111 18.2531 45.6339 18.6205 44.1723 18.6205C42.7108 18.6205 41.2337 18.2609 40.2755 17.2454C39.3174 16.2299 38.9661 14.6828 38.9661 13.1435C38.9661 11.6043 39.3096 10.0494 40.2755 9.04168C41.242 8.03396 42.7108 7.66663 44.1723 7.66663C45.6339 7.66663 47.111 8.02618 48.0691 9.04168C49.0351 10.0572 49.3786 11.6043 49.3786 13.1435V13.1431Z" fill="currentColor"/>
      <path d="M61.4045 13.1431V13.9948H55.0243V12.2996H59.2564C59.1602 11.6825 58.9372 11.1043 58.5378 10.682C57.963 10.0727 57.0762 9.85409 56.1982 9.85409C55.3202 9.85409 54.4335 10.0727 53.8587 10.682C53.2839 11.2913 53.0759 12.2213 53.0759 13.1435C53.0759 14.0658 53.2834 15.003 53.8587 15.6046C54.4335 16.2061 55.3202 16.433 56.1982 16.433C57.0762 16.433 57.963 16.2143 58.5378 15.6046C58.6179 15.5186 58.6894 15.4248 58.7608 15.331H61.1251C60.9171 16.0657 60.5897 16.7299 60.0945 17.2454C59.1364 18.2531 57.6593 18.6205 56.1982 18.6205C54.7372 18.6205 53.2596 18.2609 52.3014 17.2454C51.3432 16.2299 50.9919 14.6828 50.9919 13.1435C50.9919 11.6043 51.3355 10.0494 52.3014 9.04168C53.2678 8.03396 54.7367 7.66663 56.1982 7.66663C57.6598 7.66663 59.1364 8.02618 60.0945 9.04168C61.061 10.0572 61.4045 11.6043 61.4045 13.1435V13.1431Z" fill="currentColor"/>
      <path d="M80.242 18.6214C81.7035 18.6214 83.1801 18.4105 84.1383 17.809C85.0965 17.2075 85.4482 16.2931 85.4482 15.3869C85.4482 14.4807 85.1042 13.5585 84.1383 12.9647C83.1801 12.371 81.703 12.1518 80.242 12.1518C79.6186 12.1518 79.0438 12.0658 78.6366 11.8394C78.2294 11.6047 78.0778 11.2534 78.0778 10.9017C78.0778 10.5499 78.2216 10.1908 78.6366 9.9639C79.0438 9.72921 79.6749 9.65147 80.2973 9.65147C80.9198 9.65147 81.5509 9.73747 81.9591 9.9639C82.3663 10.1986 82.5179 10.5499 82.5179 10.9017H84.9531C84.9531 9.99499 84.6421 9.07327 83.7719 8.47951C82.9017 7.88576 81.5679 7.66663 80.2424 7.66663C78.9169 7.66663 77.5837 7.8775 76.713 8.47951C75.8427 9.08104 75.5308 9.99499 75.5308 10.9017C75.5308 11.8083 75.8423 12.73 76.713 13.3238C77.5832 13.9176 78.9165 14.1367 80.2424 14.1367C80.929 14.1367 81.688 14.2227 82.1428 14.4491C82.5985 14.676 82.7579 15.0351 82.7579 15.3869C82.7579 15.7387 82.5985 16.0977 82.1428 16.3246C81.688 16.5511 80.9931 16.6371 80.3066 16.6371C79.62 16.6371 78.9169 16.5511 78.4694 16.3246C78.0224 16.0982 77.8543 15.7387 77.8543 15.3869H75.0435C75.0435 16.2935 75.3865 17.2153 76.3534 17.809C77.3194 18.4028 78.7809 18.6214 80.2424 18.6214H80.242Z" fill="currentColor"/>
      <path d="M97.4733 13.1431V13.9948H91.0932V12.2996H95.3252C95.23 11.6825 95.006 11.1043 94.6071 10.682C94.0313 10.0727 93.1456 9.85409 92.2666 9.85409C91.3876 9.85409 90.5018 10.0727 89.927 10.682C89.3522 11.2913 89.1452 12.2213 89.1452 13.1435C89.1452 14.0658 89.3522 15.003 89.927 15.6046C90.5018 16.2061 91.3886 16.433 92.2666 16.433C93.1446 16.433 94.0313 16.2143 94.6071 15.6046C94.6863 15.5186 94.7587 15.4248 94.8301 15.331H97.1935C96.9855 16.0657 96.6585 16.7299 96.1639 17.2454C95.2057 18.2531 93.7281 18.6205 92.2666 18.6205C90.805 18.6205 89.3284 18.2609 88.3703 17.2454C87.4121 16.2299 87.0613 14.6828 87.0613 13.1435C87.0613 11.6043 87.4043 10.0494 88.3703 9.04168C89.3367 8.03396 90.806 7.66663 92.2666 7.66663C93.7272 7.66663 95.2057 8.02618 96.1639 9.04168C97.1298 10.0572 97.4729 11.6043 97.4729 13.1435L97.4733 13.1431Z" fill="currentColor"/>
      <path d="M109.499 13.1431V13.9948H103.119V12.2996H107.351C107.256 11.6825 107.032 11.1043 106.632 10.682C106.057 10.0727 105.172 9.85409 104.293 9.85409C103.414 9.85409 102.528 10.0727 101.953 10.682C101.378 11.2913 101.17 12.2213 101.17 13.1435C101.17 14.0658 101.378 15.003 101.953 15.6046C102.528 16.2061 103.415 16.433 104.293 16.433C105.171 16.433 106.057 16.2143 106.632 15.6046C106.712 15.5186 106.784 15.4248 106.856 15.331H109.22C109.012 16.0657 108.685 16.7299 108.19 17.2454C107.231 18.2531 105.754 18.6205 104.293 18.6205C102.831 18.6205 101.355 18.2609 100.396 17.2454C99.4382 16.2299 99.0864 14.6828 99.0864 13.1435C99.0864 11.6043 99.4295 10.0494 100.396 9.04168C101.362 8.03396 102.832 7.66663 104.293 7.66663C105.754 7.66663 107.231 8.02618 108.19 9.04168C109.156 10.0572 109.499 11.6043 109.499 13.1435V13.1431Z" fill="currentColor"/>
      <path d="M113.5 4.62817H111.104V18.6217H113.5V4.62817Z" fill="currentColor"/>
      <path d="M117.589 12.8154L121.517 18.6208H118.554L114.625 12.8154L118.554 8.15088H121.517L117.589 12.8154Z" fill="currentColor"/>
      <g clip-path="url(#dsh-wordmark-whale-clip)">
        <path d="M23.0584 4.95203C22.8129 4.83203 22.7074 5.06103 22.5639 5.17704C22.5149 5.21454 22.4734 5.26354 22.4319 5.30854C22.0734 5.69155 21.6543 5.94306 21.1073 5.91306C20.3073 5.86806 19.6243 6.11957 19.0203 6.73158C18.8918 5.97706 18.4652 5.52655 17.8162 5.23754C17.4767 5.08753 17.1332 4.93703 16.8952 4.61052C16.7292 4.37801 16.6837 4.11901 16.6007 3.8635C16.5477 3.70949 16.4952 3.55199 16.3177 3.52549C16.1252 3.49549 16.0497 3.65699 15.9742 3.792C15.6722 4.34401 15.5552 4.95203 15.5667 5.56805C15.5932 6.95359 16.1782 8.05712 17.3407 8.84215C17.4727 8.93215 17.5067 9.02215 17.4652 9.15366C17.3857 9.42416 17.2917 9.68667 17.2087 9.95718C17.1557 10.1297 17.0767 10.1677 16.8917 10.0922C16.2537 9.82568 15.7027 9.43117 15.2156 8.95465C14.3891 8.15513 13.6416 7.2726 12.7096 6.58158C12.4906 6.42007 12.2716 6.27007 12.045 6.12707C11.094 5.20354 12.1696 4.44502 12.4186 4.35501C12.6791 4.26101 12.5091 3.938 11.6675 3.942C10.826 3.9455 10.056 4.22751 9.07446 4.60302C8.93096 4.65952 8.77995 4.70052 8.62545 4.73452C7.73492 4.56552 6.80989 4.52802 5.84386 4.63702C4.02481 4.83953 2.57177 5.69955 1.50373 7.1676C0.220694 8.93215 -0.0813148 10.9372 0.288196 13.0283C0.676708 15.2323 1.80174 17.0569 3.53029 18.4834C5.32285 19.9625 7.38741 20.6875 9.74298 20.5485C11.1735 20.466 12.7661 20.2745 14.5626 18.7539C15.0156 18.9795 15.4912 19.0695 16.2797 19.137C16.8872 19.1935 17.4722 19.107 17.9252 19.013C18.6347 18.8629 18.5857 18.2059 18.3292 18.0854C16.2497 17.1169 16.7062 17.5109 16.2912 17.1919C17.3477 15.9419 18.9618 13.7198 19.4598 10.6942C19.5088 10.3602 19.5713 9.88968 19.5638 9.61917C19.5598 9.45417 19.5978 9.39016 19.7863 9.37116C20.3073 9.31116 20.8128 9.16866 21.2773 8.91315C22.6249 8.17713 23.1684 6.96809 23.2964 5.51905C23.3154 5.29754 23.2924 5.06853 23.0584 4.95203ZM11.3165 17.9954C9.30097 16.4109 8.32344 15.8894 7.91992 15.9119C7.54241 15.9344 7.61042 16.3664 7.69342 16.6479C7.78042 16.9259 7.89342 17.1174 8.05193 17.3614C8.16143 17.5229 8.23694 17.7629 7.94243 17.9434C7.29341 18.3449 6.16487 17.8084 6.11187 17.7819C4.79833 17.0084 3.7003 15.9874 2.92628 14.5908C2.17875 13.2468 1.74474 11.8047 1.67324 10.2657C1.65424 9.89418 1.76374 9.76267 2.13375 9.69517C2.62077 9.60517 3.12278 9.58617 3.6093 9.65767C5.66636 9.95818 7.41741 10.8777 8.88545 12.3348C9.72348 13.1643 10.3575 14.1558 11.0105 15.1243C11.705 16.1529 12.4521 17.1329 13.4036 17.9364C13.7396 18.2179 14.0076 18.4319 14.2641 18.5899C13.4906 18.6764 12.1996 18.6949 11.3165 17.9964V17.9954ZM12.2826 11.7817C12.2826 11.6167 12.4146 11.4852 12.5806 11.4852C12.6181 11.4852 12.6521 11.4927 12.6826 11.5037C12.7241 11.5187 12.7621 11.5412 12.7921 11.5752C12.8451 11.6277 12.8751 11.7027 12.8751 11.7817C12.8751 11.9467 12.7431 12.0782 12.5771 12.0782C12.4111 12.0782 12.2826 11.9467 12.2826 11.7817ZM15.2831 13.3208C15.0906 13.3998 14.8981 13.4673 14.7131 13.4748C14.4261 13.4898 14.1131 13.3733 13.9431 13.2308C13.6791 13.0093 13.4901 12.8853 13.4111 12.4988C13.3771 12.3338 13.3961 12.0782 13.4261 11.9317C13.4941 11.6162 13.4186 11.4137 13.1961 11.2297C13.0151 11.0797 12.7846 11.0382 12.5316 11.0382C12.4371 11.0382 12.3506 10.9967 12.2861 10.9632C12.1806 10.9107 12.0936 10.7792 12.1766 10.6177C12.2031 10.5652 12.3316 10.4377 12.3616 10.4152C12.7051 10.2197 13.1011 10.2837 13.4676 10.4302C13.8071 10.5692 14.0641 10.8242 14.4336 11.1847C14.8111 11.6202 14.8791 11.7402 15.0941 12.0672C15.2641 12.3228 15.4186 12.5853 15.5247 12.8858C15.5887 13.0733 15.5057 13.2268 15.2831 13.3208Z" fill="currentColor"/>
      </g>
      <rect x="129.348" y="5.5" width="52" height="14" rx="2" fill="currentColor"/>
      <g clip-path="url(#dsh-wordmark-badge-clip)">
        <path d="M132.848 8.93205H134.08V16.137H132.848V8.93205ZM136.5 8.93205H137.732V16.137H136.5V8.93205ZM133.365 13.024V11.99H137.193V13.024H133.365Z" fill="var(--dsw-alias-label-primary-inverted)"/>
        <path d="M140.397 14.432L140.672 13.453H143.202L143.532 14.432H140.397ZM140.287 16.137H139.055L141.277 8.93205H142.201L142.146 9.74605L140.947 13.915H140.969L140.287 16.137ZM145.039 16.137H143.741L143.07 13.948L143.081 13.937L141.871 9.74605L141.926 8.93205H142.817L145.039 16.137Z" fill="var(--dsw-alias-label-primary-inverted)"/>
        <path d="M146.846 8.93205H149.068C149.852 8.93205 150.443 9.11538 150.839 9.48205C151.235 9.84138 151.433 10.3327 151.433 10.956C151.433 11.22 151.396 11.4657 151.323 11.693C151.249 11.9204 151.125 12.1257 150.949 12.309C150.773 12.4924 150.531 12.65 150.223 12.782C149.922 12.9067 149.541 13.0057 149.079 13.079V13.321H146.846V12.639L148.023 12.485C148.631 12.4044 149.09 12.298 149.398 12.166C149.706 12.034 149.915 11.8764 150.025 11.693C150.135 11.5024 150.19 11.2934 150.19 11.066C150.19 10.6994 150.083 10.417 149.871 10.219C149.658 10.021 149.324 9.92205 148.87 9.92205H146.846V8.93205ZM146.395 8.93205H147.627V16.137H146.395V8.93205ZM151.917 16.093V16.137H150.366L149.024 14.322C148.87 14.1094 148.73 13.9407 148.606 13.816C148.481 13.684 148.345 13.5887 148.199 13.53C148.052 13.464 147.872 13.42 147.66 13.398C147.447 13.3687 147.176 13.3504 146.846 13.343V13.145H149.079C149.233 13.211 149.368 13.2844 149.486 13.365C149.61 13.4457 149.735 13.5447 149.86 13.662C149.992 13.7794 150.138 13.937 150.3 14.135L151.917 16.093Z" fill="var(--dsw-alias-label-primary-inverted)"/>
        <path d="M153.58 9.57005L153.591 8.93205H154.46L157.584 15.51V16.137H156.704L153.58 9.57005ZM158.024 16.137H156.968L156.88 8.93205H158.024V16.137ZM154.24 16.137H153.096V8.93205H154.152L154.24 16.137Z" fill="var(--dsw-alias-label-primary-inverted)"/>
        <path d="M159.963 8.93205H161.206V16.137H159.963V8.93205ZM160.095 9.96605V8.93205H164.858V9.96605H160.095ZM160.095 16.137V15.103H164.902V16.137H160.095ZM160.095 13.013V11.99H164.374V13.013H160.095Z" fill="var(--dsw-alias-label-primary-inverted)"/>
        <path d="M169.052 15.257C169.543 15.257 169.895 15.1654 170.108 14.982C170.328 14.7987 170.438 14.5457 170.438 14.223C170.438 14.047 170.405 13.8967 170.339 13.772C170.273 13.6474 170.152 13.5337 169.976 13.431C169.807 13.321 169.558 13.2147 169.228 13.112L168.491 12.881C167.846 12.6757 167.38 12.4044 167.094 12.067C166.808 11.7297 166.665 11.3007 166.665 10.78C166.665 10.428 166.76 10.1017 166.951 9.80105C167.142 9.50038 167.428 9.25838 167.809 9.07505C168.19 8.89172 168.663 8.80005 169.228 8.80005C169.631 8.80005 169.998 8.82938 170.328 8.88805C170.665 8.93938 171.039 9.01638 171.45 9.11905L171.274 10.175C170.834 10.0504 170.442 9.96238 170.097 9.91105C169.76 9.85238 169.463 9.82305 169.206 9.82305C168.737 9.82305 168.403 9.90738 168.205 10.076C168.007 10.2374 167.908 10.439 167.908 10.681C167.908 10.857 167.941 11.0147 168.007 11.154C168.073 11.286 168.19 11.407 168.359 11.517C168.535 11.627 168.784 11.7334 169.107 11.836L169.866 12.078C170.526 12.276 170.995 12.5327 171.274 12.848C171.553 13.156 171.692 13.585 171.692 14.135C171.692 14.5604 171.589 14.9344 171.384 15.257C171.179 15.5797 170.878 15.8327 170.482 16.016C170.093 16.1994 169.609 16.291 169.03 16.291C168.627 16.291 168.212 16.247 167.787 16.159C167.362 16.071 166.9 15.9427 166.401 15.774L166.665 14.718C167.156 14.894 167.6 15.0297 167.996 15.125C168.399 15.213 168.751 15.257 169.052 15.257Z" fill="var(--dsw-alias-label-primary-inverted)"/>
        <path d="M175.809 15.257C176.3 15.257 176.652 15.1654 176.865 14.982C177.085 14.7987 177.195 14.5457 177.195 14.223C177.195 14.047 177.162 13.8967 177.096 13.772C177.03 13.6474 176.909 13.5337 176.733 13.431C176.564 13.321 176.315 13.2147 175.985 13.112L175.248 12.881C174.603 12.6757 174.137 12.4044 173.851 12.067C173.565 11.7297 173.422 11.3007 173.422 10.78C173.422 10.428 173.517 10.1017 173.708 9.80105C173.899 9.50038 174.185 9.25838 174.566 9.07505C174.947 8.89172 175.42 8.80005 175.985 8.80005C176.388 8.80005 176.755 8.82938 177.085 8.88805C177.422 8.93938 177.796 9.01638 178.207 9.11905L178.031 10.175C177.591 10.0504 177.199 9.96238 176.854 9.91105C176.517 9.85238 176.22 9.82305 175.963 9.82305C175.494 9.82305 175.16 9.90738 174.962 10.076C174.764 10.2374 174.665 10.439 174.665 10.681C174.665 10.857 174.698 11.0147 174.764 11.154C174.83 11.286 174.947 11.407 175.116 11.517C175.292 11.627 175.541 11.7334 175.864 11.836L176.623 12.078C177.283 12.276 177.752 12.5327 178.031 12.848C178.31 13.156 178.449 13.585 178.449 14.135C178.449 14.5604 178.346 14.9344 178.141 15.257C177.936 15.5797 177.635 15.8327 177.239 16.016C176.85 16.1994 176.366 16.291 175.787 16.291C175.384 16.291 174.969 16.247 174.544 16.159C174.119 16.071 173.657 15.9427 173.158 15.774L173.422 14.718C173.913 14.894 174.357 15.0297 174.753 15.125C175.156 15.213 175.508 15.257 175.809 15.257Z" fill="var(--dsw-alias-label-primary-inverted)"/>
      </g>
      <defs>
        <clip-path id="dsh-wordmark-whale-clip">
          <rect width="23.16" height="17.0435" fill="white" transform="translate(0.141602 3.52185)"/>
        </clip-path>
        <clip-path id="dsh-wordmark-badge-clip">
          <rect width="46" height="14" fill="white" transform="translate(132.348 5.5)"/>
        </clip-path>
      </defs>
    </svg></div>
      <div class="head">
        <h1 id="heading">${heading}</h1>
        <p class="sub" id="sub">${hint}</p>
      </div>
    </div>

    <div class="panel-body">
      <div id="fields">
        <div class="field">
          <label class="field-label" for="username">${s.username}</label>
          <input class="input" type="text" id="username" name="username" autocomplete="username" spellcheck="false" required>
        </div>
        <div class="field">
          <label class="field-label" for="password">${s.password}</label>
          <input class="input" type="password" id="password" name="password" autocomplete="current-password" required>
        </div>
      </div>

      <div id="code-step" hidden>
        <div class="field">
          <label class="field-label" for="code">${s.code}</label>
          <input class="input is-code" type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>
        </div>
        <div class="ttl" id="code-ttl"></div>
      </div>

      <div class="offer" id="offer" hidden>
        <div class="ok">${s.offerOk}</div>
        <div class="actions">
          <button type="button" class="btn btn-outline" id="offer-bind">${s.offerBind}</button>
          <button type="button" class="btn btn-ghost" id="offer-skip">${s.offerSkip}</button>
        </div>
      </div>

      <div id="setup" hidden>
        <p class="sub tight">${s.setupIntro}</p>
        <div class="qr">
          <img id="setup-qr" alt="${s.qrAlt}" hidden>
        </div>
        <div class="field">
          <span class="field-label">${s.setupSecret}</span>
          <div class="code-box" id="setup-secret"></div>
        </div>
        <div class="field">
          <span class="field-label">${s.setupOtpauth}</span>
          <div class="code-box" id="setup-otpauth"></div>
        </div>
        <div class="field">
          <span class="field-label">${s.setupBackup}</span>
          <div class="codes" id="setup-codes"></div>
        </div>
        <div class="field">
          <label class="field-label" for="setup-code">${s.setupVerify}</label>
          <input class="input is-code" type="text" id="setup-code" inputmode="numeric" autocomplete="one-time-code">
        </div>
        <div class="ttl" id="setup-ttl"></div>
      </div>

      ${errorHtml}

      <button type="submit" class="btn btn-primary btn-block" id="submit">
        <span class="spinner" id="submit-spinner" hidden></span>
        <span id="submit-label">${button}</span>
      </button>

      <div class="note" id="note" hidden></div>
    </div>
  </form>

<script>
(function () {
  var STR = ${JSON.stringify(s)};
  var form = document.getElementById("form");
  var submit = document.getElementById("submit");
  var submitSpinner = document.getElementById("submit-spinner");
  var submitLabel = document.getElementById("submit-label");
  var setBusy = function (on) { submit.disabled = on; submitSpinner.hidden = !on; };
  var setSubmitLabel = function (text) { submitLabel.textContent = text; };
  var note = document.getElementById("note");
  var heading = document.getElementById("heading");
  var sub = document.getElementById("sub");
  var fields = document.getElementById("fields");
  var codeStep = document.getElementById("code-step");
  var codeInput = document.getElementById("code");
  var offer = document.getElementById("offer");
  var setup = document.getElementById("setup");
  var endpoint = ${JSON.stringify(endpoint)};
  var next = ${JSON.stringify(next).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026')};
  var mfaToken = null;
  var phase = "password"; // password | code | offer | setup
  // Live TOTP countdown: updates the element with the seconds left in the
  // current 30s window, so a stale code is obvious before submission.
  var startCountdown = function (el) {
    el.className = "ttl";
    var tick = function () {
      var remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
      el.textContent = STR.countdown.replace("{n}", remaining);
      el.classList.toggle("warn", remaining <= 5);
    };
    tick();
    var timer = setInterval(tick, 1000);
    return function () { clearInterval(timer); };
  };
  var stopCountdown = null;
  var showError = function (message) {
    var old = form.querySelector(".error");
    if (old) old.remove();
    var err = document.createElement("div");
    err.className = "error";
    err.setAttribute("role", "alert");
    err.textContent = message;
    submit.parentNode.insertBefore(err, submit);
    setBusy(false);
  };
  var go = function (path) { location.href = path && path.indexOf("/") === 0 ? path : "/"; };
  var bindOffer = function () {
    phase = "offer";
    heading.textContent = STR.offerHeading;
    sub.textContent = STR.offerSub.replace("{user}", (form.querySelector("#username") ? document.getElementById("username").value.trim() : ""));
    fields.hidden = true;
    codeStep.hidden = true;
    offer.hidden = false;
    setup.hidden = true;
    submit.hidden = true;
    setBusy(false);
    note.hidden = true;
  };
  var startSetup = async function () {
    note.hidden = false;
    note.textContent = STR.generating;
    try {
      var res = await fetch("/auth/mfa/setup", {
        method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: "{}"
      });
      var data = null;
      try { data = await res.json(); } catch (e) {}
      if (!res.ok || !data || !data.ok) throw new Error((data && data.error) || "setup failed");
      phase = "setup";
      heading.textContent = STR.offerHeading;
      sub.textContent = STR.setupStep1;
      offer.hidden = true;
      setup.hidden = false;
      submit.hidden = false;
      setBusy(false);
      setSubmitLabel(STR.verifyEnable);
      document.getElementById("setup-secret").textContent = data.secret;
      document.getElementById("setup-otpauth").textContent = data.otpauth;
      var qrImg = document.getElementById("setup-qr");
      if (data.qr) {
        qrImg.src = data.qr;
        qrImg.hidden = false;
      }
      var codes = document.getElementById("setup-codes");
      codes.innerHTML = "";
      (data.backupCodes || []).forEach(function (c) {
        var s = document.createElement("span");
        s.textContent = c;
        codes.appendChild(s);
      });
      note.hidden = true;
      if (stopCountdown) stopCountdown();
      stopCountdown = startCountdown(document.getElementById("setup-ttl"));
      document.getElementById("setup-code").focus();
    } catch (e) {
      note.hidden = true;
      showError(String(e.message || e));
    }
  };
  var verifySetup = async function () {
    var code = document.getElementById("setup-code").value.trim();
    if (!code) return;
    setBusy(true);
    note.hidden = false;
    note.textContent = STR.verifying;
    try {
      var res = await fetch("/auth/mfa/verify", {
        method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
        body: JSON.stringify({ code: code })
      });
      var data = null;
      try { data = await res.json(); } catch (e) {}
      if (!res.ok || !data || !data.ok) throw new Error((data && data.error) || "invalid code");
      setup.hidden = true;
      submit.hidden = true;
      var ok = document.createElement("div");
      ok.className = "ok";
      ok.textContent = STR.enabled;
      submit.parentNode.insertBefore(ok, submit);
      setTimeout(function () { go(next); }, 1500);
    } catch (e) {
      note.hidden = true;
      showError(String(e.message || e));
    }
  };
  document.getElementById("offer-bind").addEventListener("click", startSetup);
  document.getElementById("offer-skip").addEventListener("click", function () { go(next); });
  // Real-time verification: a complete 6-digit TOTP code submits immediately
  // (backup codes contain letters and still use the button).
  var bindAutoVerify = function (input, onComplete) {
    input.addEventListener("input", function () {
      if (/^\\d{6}$/.test(input.value.trim())) onComplete();
    });
  };
  bindAutoVerify(document.getElementById("setup-code"), function () { verifySetup(); });
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    doSubmit();
  });
  var doSubmit = async function () {
    if (phase === "setup") { verifySetup(); return; }
    setBusy(true);
    note.hidden = false;
    var payload;
    if (phase === "code") {
      var code = codeInput.value.trim();
      if (!code) { setBusy(false); note.hidden = true; return; }
      note.textContent = STR.verifying;
      payload = { mfaToken: mfaToken, code: code };
    } else {
      var username = document.getElementById("username").value.trim();
      var password = document.getElementById("password").value;
      if (!username || !password) { setBusy(false); note.hidden = true; return; }
      note.textContent = STR.verifying;
      payload = { username: username, password: password };
    }
    try {
      var res = await fetch(phase === "code" ? "/auth/mfa/login" : endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(payload)
      });
      var data = null;
      try { data = await res.json(); } catch (e) {}
      if (res.ok && data && data.ok && !data.mfaRequired) {
        // Session issued. Accounts without two-factor get the optional binding offer.
        if (data.mfa === false && phase !== "setup") { bindOffer(); return; }
        note.textContent = STR.success;
        go(next);
        return;
      }
      if (res.ok && data && data.mfaRequired && data.mfaToken) {
        phase = "code";
        mfaToken = data.mfaToken;
        heading.textContent = STR.codeHeading;
        sub.textContent = STR.codeSub;
        fields.hidden = true;
        codeStep.hidden = false;
        offer.hidden = true;
        setup.hidden = true;
        codeInput.required = true;
        codeInput.focus();
        if (stopCountdown) stopCountdown();
        stopCountdown = startCountdown(document.getElementById("code-ttl"));
        note.hidden = true;
        setBusy(false);
        setSubmitLabel(STR.verify);
        return;
      }
      var message = (data && (data.error || data.message)) || STR.failed.replace("{status}", res.status);
      note.hidden = true;
      showError(message);
      var target = phase === "code" ? codeInput : document.getElementById("password");
      if (target) target.select();
    } catch (e) {
      note.hidden = true;
      setBusy(false);
    }
  };
  bindAutoVerify(codeInput, function () { doSubmit(); });
})();
</script>
</body>
</html>`;
}
