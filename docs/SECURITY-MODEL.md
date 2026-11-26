# 安全威胁模型与边界说明（PAOS v0.1.0 Security Model）

给本地 AI Agent 开放终端、文件系统与出站网络能力后，单靠在提示词里叮嘱「请勿删库、请勿泄密」属于无效防御。PAOS v0.1.0 构建五层确定性纵深防线，同时坦诚声明每层防线的物理边界。

---

## 1. 重点防御的五大真实事故面

1. **配置与审计日志落盘泄密（2026-11 Apiiro 披露模式）**
   - *风险*：内联 `API_KEY=...` 或数据库 URI 密码被写入 `.claude/settings.local.json`、运行日志或出站通知卡片。
   - *PAOS 防线*：
     - `paos harden` 自动将 `.claude/settings.local.json` 写入全局 `core.excludesfile`；
     - `paos doctor` 扫描本地配置中的疑似明文凭据（仅报行号与类别，绝不回显原文）；
     - `lib/paos/audit.py` 与 `lib/paos/notify.py` 对落盘审计记录（`~/.paos/logs/audit.jsonl`）、运行日志和所有出站 Webhook 载荷强制执行 `redact_secrets()` 脱敏擦除。

2. **善意越界公开外传与持久化自改投毒（2026-09 PixelLeak 模式）**
   - *风险*：Agent 调用主账号 `gh` 创建 `--public` 仓库/Gist 外传代码截图，或被注入后篡改 `.claude/hooks/` 与 `.codex/rules/`。
   - *PAOS 防线*：
     - Claude `pre_tool_gate.py` 与 Codex `paos-guardrails.rules` 双端同步封禁公开建库/公开 Gist、危险删库与受保护分支强推；
     - OS 沙盒 `denyWrite` 锁死 `~/.claude`、`~/.ssh`、`~/.aws` 等控制面与根凭证目录；纠偏仅写 `learnings.md` 草稿池，经 `paos promote` 人工审校后方可晋升。

3. **重试死循环与挂死子进程烧穿算力账单**
   - *PAOS 防线*：
     - `hooks/stop_verify.py` 内置 `Stuck-Cap` 熔断器（连续失败达上限即强制停机交回人工，并写入 `audit.jsonl`）；
     - `paos run` 在独立进程组（`start_new_session=True`）内拉起子任务，超时先发 `SIGTERM` 后补 `SIGKILL` 清理整棵进程树，杜绝孤儿后台进程残留。

4. **自审盲区导致带病上线**
   - *PAOS 防线*：`paos review` 采用零记忆金鱼冷启动模型（仅喂纯 Diff，隔离原对话上下文污染），命中 `[P0]` 阻断缺陷直接以退出码 `2` 拦截合入。

5. **常驻网关入站攻击面（ClawJacked 类本地端口劫持）**
   - *PAOS 防线*：`paos cron` 与 `paos notify` 坚持**零常驻守护进程、零入站监听端口**设计，完全依托系统原生 `launchd`/`crontab` 与纯单向出站 Webhook。

---

## 2. 必须清楚的防线边界（Known Limitations）

- **词法钩子与 Starlark 规则是「防呆减速带（Tripwire）」，而非终极内核沙盒**：面对蓄意编码混淆（如 Base64 解码执行或自定义脚本直接读写文件），命令前缀/词法层无法穷举拦截；**真正的机密文件防读取必须依赖操作系统级沙盒**（macOS `Seatbelt` / Linux `bubblewrap`，开启 `failIfUnavailable: true` 与 `allowUnsandboxedCommands: false`）叠加内置 `permissions.deny`。
- **父进程内存环境变量盲区**：文件系统 `denyRead` 无法阻止子进程读取父 Shell 已经 `export` 进内存的环境变量。请勿在启动 Agent 的全局 `.zshrc`/`.bashrc` 中常驻明文生产根密钥。
- **合法白名单域名边界**：当 `github.com` 位于沙盒允许列表内时，网络层允许连接 GitHub；无人值守自动化任务请配置**单仓库细粒度 PAT（Fine-grained Token）**而非全权限个人主账号会话。
