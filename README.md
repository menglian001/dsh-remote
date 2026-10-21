# dsh-remote

DSH（DeepSeek Harness）Web 面板的远程访问鉴权插件：登录门禁、TOTP 双因素、
审计日志、在线设备管理。

适用于已经能在本机运行 `dsh web` 的环境。插件默认只监听本机回环地址；
公网访问仍需 HTTPS 反向代理或安全隧道。

## 目录

- [功能概览](#功能概览)
- [快速开始](#快速开始)
- [远程访问](#远程访问)
- [配置](#配置)
- [无浏览器服务器](#无浏览器服务器headless)
- [常见问题](#常见问题)
- [数据与备份](#数据与备份)
- [文档](#文档)
- [开发与测试](#开发与测试)
- [卸载](#卸载)
- [已知限制](#已知限制)

## 功能概览

- **登录门禁**：未登录访问任何路径都会进入登录页；`/api` 和 WebSocket 全部要求有效会话。密码使用 scrypt 加密存储（每次独立盐），登录失败限速，首个管理员仅限本机创建。
- **MFA 两步验证**：兼容 Google Authenticator、1Password、Authy 等标准 TOTP 认证器；支持扫码绑定和 10 个一次性备用码。
- **口令强度校验**：至少 10 位、非纯数字、非常见弱口令、不含用户名，中英文提示。
- **会话与权限**：签名会话 Cookie，密钥持久化，重启不掉线。默认单管理员模式。
- **审计日志**：记录登录成功/失败、验证码、限流、登出、账号变更、设备下线，含真实客户端 IP 与 User-Agent。JSONL 格式，2 MB 轮转保留 3 代，可在设置页查看与导出。
- **在线设备**：列出所有活跃会话（IP / 浏览器 / 最后活跃时间），可单独踢下线，该设备登录立即失效。
- **远程文件面板**：在右侧边栏预览代码、Markdown、图片、PDF、视频、音频、文本、目录和 `.docx` 提取文本；不支持预览的文件直接下载。默认只允许 DSH 主目录与工作目录，可在设置中添加目录。
- **远程访问**：适配 nginx、SSH 隧道、Tailscale、Frp、Cloudflare Tunnel 等方式，并完整转发 WebSocket 事件流。
- **浏览器内工作区**：选择或新建工作区使用浏览器内目录对话框，不调用宿主机原生文件窗口。
- **界面与性能**：跟随 DSH 的浅色 / 深色主题和中英文语言；远程响应默认自动 gzip 压缩，静态资源可配合边缘缓存。

## 快速开始

### 1. 安装

未发布到 npm，请从本仓库安装：

```sh
dsh plugin --profile web add github:menglian001/dsh-remote#v0.3.5-dsh1
```

或在 profile 的 `package.json` 里声明：

```json
{
  "dependencies": {
    "@xgone/dsh-remote": "github:menglian001/dsh-remote#v0.3.5-dsh1"
  }
}
```

> **包名必须保持 `@xgone/dsh-remote`** —— DSH 的 profile bundle 列表按这个名字引用插件。

确认装的是加固版：

```sh
grep -c 'dsh1-hardened' ~/.dsh/profiles/web/node_modules/@xgone/dsh-remote/lib/index.js
```

输出 `1` 表示正确。启动日志末尾也会带 `[build dsh1-hardened]`。

### 2. 重启 `dsh web`

补丁不支持热重载，安装或升级后必须重启：

```sh
dsh web
```

### 3. 创建首个管理员

在本机浏览器打开 `http://127.0.0.1:3080`。首次访问会进入引导模式：输入用户名和密码（至少 10 位）创建首个管理员，创建成功后自动登录。

> 服务器没有本地浏览器？见[无浏览器服务器](#无浏览器服务器headless)。

### 4. 绑定 MFA（推荐）

进入 **设置 → 登录与账号 → 双重验证（MFA）→ 启用**，用认证器扫码并输入 6 位动态码。请先保存页面上的 10 个备用码。

### 5. 开放远程访问

确认本机登录和 MFA 工作正常后，按下方[远程访问](#远程访问)配置反向代理或隧道。外部访问必须转发 WebSocket；HTTPS 部署还要设置 `session.secure: true`。

## 远程访问

`dsh web` 默认只监听本机回环地址，请通过反向代理或隧道暴露，不要直接把未加密的服务端口暴露到公网。

下面是 nginx 示例，重点是保留 WebSocket 升级头：

```nginx
server {
  listen 8443 ssl;
  server_name dsh.example.com;
  ssl_certificate     /etc/letsencrypt/live/dsh.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/dsh.example.com/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:3080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header Origin $http_origin;
  }
}
```

`ssh -R` 隧道、Tailscale、Frp 和 Cloudflare Tunnel 同样适用。HTTPS 部署请在配置中把 `session.secure` 设为 `true`。

### 关于客户端 IP

审计日志和限流用到的「客户端 IP」取自 `cf-connecting-ip` / `x-forwarded-for`：

- **Cloudflare**：会自动覆盖为真实 IP，无需额外配置
- **nginx / frp / ngrok**：需要显式转发这两个头，否则审计里记录的 IP 是代理的地址

限流按账号维度计算，不受 IP 伪造影响。

## 配置

编辑 `~/.dsh/profiles/web/cordis.patch.yml` 中 `remote` 行的 `config`。常用配置如下：

```yaml
- id: remote
  config:
    enabled: true          # false = 关闭门禁
    session:
      secure: false        # HTTPS 部署改为 true
      ttlSeconds: 604800   # 会话有效期，默认 7 天
    bootstrap:             # 可选：仅在账号库为空时预置首个管理员
      username: admin
      password: '换成一个强口令'
```

| 配置项 | 默认值 | 作用 |
|---|---:|---|
| `enabled` | `true` | 启用或关闭登录门禁；修改后需重启 `dsh web`。 |
| `session.secure` | `false` | HTTPS 部署时设为 `true`，让会话 Cookie 只通过安全连接发送。 |
| `session.ttlSeconds` | `604800` | 会话有效期（秒），默认 7 天。范围 60 秒 ~ 30 天。 |
| `bootstrap` | 未设置 | 无浏览器服务器预置首个管理员；首次登录后应移除明文口令。 |

> `adminOnly` 固定为 `true`（单管理员模式），不作为配置项暴露。
> 该模式下新建账号功能关闭，需要第二个管理员时手动编辑 `$DSH_HOME/auth/store.json`。

完整配置项（会话、MFA、限速、gzip、文件面板和允许目录）见 [docs/REFERENCE.md](docs/REFERENCE.md)。

### 无浏览器服务器（headless）

在 `cordis.patch.yml` 中加入上面的 `bootstrap` 配置节，重启后即可预置首个管理员，效果等同于本机引导。首次登录后请移除明文口令并绑定 MFA。

## 常见问题

| 现象 | 处理 |
|---|---|
| 安装后没有登录页 | 重启 `dsh web`；确认 bundles 列表里有 `@xgone/dsh-remote`。 |
| 创建管理员时报 403 | 首个管理员仅限本机创建：在本机浏览器操作，或通过 `ssh -L` 访问 `127.0.0.1`；无本地浏览器使用 `bootstrap`。 |
| 加固失效 | 依赖被改回了 npm 源。改回 `github:menglian001/dsh-remote#v0.3.5-dsh1` 后重装。 |
| 被锁在门外 | 将 `cordis.patch.yml` 的 `enabled` 设为 `false` 后重启；或删除 `$DSH_HOME/auth/store.json` 重新引导。 |
| 忘记 MFA / 丢手机 | 用备用码登录；都丢了就手改 `$DSH_HOME/auth/store.json` 清掉该账号的 `totp` 字段。 |
| 文件面板提示 `outside-roots` | 进入 **设置 → 登录与账号 → 允许的目录** 添加该目录，立即生效，无需重启。 |
| 升级 dsh 后登录成功但 `/api` 全部 401 | 重新登录一次，见 [CHANGELOG](CHANGELOG.md)。 |

## 数据与备份

全部在 `$DSH_HOME/auth/`，目录权限 0700、文件 0600：

| 文件 | 内容 |
|---|---|
| `store.json` | 账号、口令哈希、HMAC 签名密钥、TOTP 绑定 |
| `sessions.json` | 在线设备注册表 |
| `audit.jsonl` | 审计日志 |

升级或迁移前建议整目录备份。删除 `store.json` 会重置所有账号（下次访问重新引导）。

## 文档

- **更新记录**：[CHANGELOG.md](CHANGELOG.md)
- **技术参考**：[docs/REFERENCE.md](docs/REFERENCE.md) —— 架构、实现机制、完整配置和端点参考。
- **Cloudflare Tunnel 部署**：[docs/CLOUDFLARE-TUNNEL.md](docs/CLOUDFLARE-TUNNEL.md)

## 开发与测试

```sh
pnpm install
pnpm check
pnpm test
```

`pnpm test` 会执行 Node 语法检查和完整测试集（74 项）。

## 卸载

```sh
dsh plugin --profile web remove @xgone/dsh-remote
```

重启 `dsh web` 后门禁消失；账号数据默认保留在 `$DSH_HOME/auth/`，彻底清除时再手动删除。

## 已知限制

- 修改配置后必须重启 `dsh web`，Web 表面禁用 HMR。
- 单管理员模式：`adminOnly` 固定为 `true`，新建账号功能关闭。
- 多账号共享同一份工作区与会话数据。DSH 核心是单租户，插件层无法隔离；需要隔离时请为每人运行一个 profile 实例，例如 `dsh --profile alice --port 3081`。
- 会话吊销不会断开已建立的 WebSocket 长连接，需重开页面才彻底断开。

## License

[MIT](LICENSE)
