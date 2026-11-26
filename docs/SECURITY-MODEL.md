# 安全威胁模型与边界说明（PAOS v0.1.0 Security Model）

给本地 AI Agent 开放终端、文件系统与出站网络能力后，仅在系统提示词里叮嘱「请勿删库、请勿泄密」属于无效防御。PAOS v0.1.0 构建五层确定性纵深防线，同时明确声明每层防线的物理边界。

---

## 1. 重点防御的五大真实风险面

1. **本地配置、运行日志与出站通知凭据泄露（Configuration & Log Leak Defense，参考行业披露的本地自动批准配置落盘泄密模式）**
   - *风险*：内联 `API_KEY=...`、JSON 配置键值 `{"DB_PASSWORD": "..."}`、PEM 私钥、AWS `AKIA` 密钥或数据库 URI 密码被写入 `.claude/settings.local.json`、审计日志或出站通知卡片。
   - *PAOS 防线*：
     - `paos harden` 自动将 `.claude/settings.local.json` 写入全局 `core.excludesfile`，并将 `~/.paos/config.json` 同时纳入 OS 沙盒 `denyRead` 与内置 `permissions.deny`；
     - `lib/paos/audit.py` 作为全仓唯一 DLP 脱敏引擎，覆盖 PEM 私钥块、云厂商密钥、JSON/Env 键值、Bearer Token、URI 密码与各类 IM Webhook，且严格遵循**先全量脱敏、后定长截断**原则，防止跨切片边界泄露。

2. **误建公开仓库外传与控制面自篡改逃逸（Public Exfiltration & Self-Tampering Defense，防范 Agent 误调用 `gh` 创建公开仓库/Gist 当图床外传敏感代码或截图）**
   - *PAOS 防线*：
     - **Claude Code**：`lib/paos/gate.py` 词法级解析器（支持剥离带参 `sudo -u`/`env -S`、带重定向子 Shell `(...) >/dev/null`、嵌套 `$(...)`/`>(...)` 及结合 `cwd` 的路径归一化）直接硬拦截（`exit 2`）`gh repo/gist create --public/-p`、`gh repo edit --visibility public`、`gh repo delete`、组合短参强推 `git push -uf` 及对 `~/.claude`、`~/.codex`、`~/.paos`、`~/.ssh`、`~/Library/LaunchAgents`、`.git/hooks` 的任何删改写操作；
     - **OpenAI Codex**：`templates/codex-paos.rules` 通过 Starlark `execpolicy` 将高危删库、强推与删除控制面目录设为 `forbidden`，并将任何 `gh repo/gist create` 设为强制人工确认（`decision="prompt"`）；
     - **定时任务防注入**：`lib/paos/cron.py` 严禁通过 `~/.paos/cron_jobs.json` 向内置任务注入自定义 `cmd` 字段，堵死借宿主机 `launchd`/`crontab` 绕过沙盒执行命令的持久化通道。

3. **重试死循环与忽略 `SIGTERM` 的孤儿孙进程泄漏**
   - *PAOS 防线*：
     - 项目级 `stop_verify.py` 先执行验证（修好即刻放行），仅在连续验证失败耗尽 `PAOS_MAX_STOP_RETRIES` 后触发 `Stuck-Cap` 熔断停机交回人工；
     - `exec_with_pgroup_timeout` 在 `SIGTERM` 后通过 `os.killpg(pgid, 0)` 检测整组存活状态，即使组长 `/bin/sh` 提前退出也会向残留孙进程强制补发 `SIGKILL`，并在异常中断 `finally` 块中兜底清场。

4. **同会话自审盲区与超大 Diff 静默截断**
   - *PAOS 防线*：`paos review` 在独立空临时目录下运行零历史上下文进程（不加载被审仓规则防提示词注入），覆盖分支提交、工作区未提交修改与未跟踪新文件；当待审 Diff 超出 120KB 安全上限时按 Fail-Closed 返回退出码 `2` 要求分批审查，绝不静默截断业务代码后放行。

5. **常驻网关本地端口攻击面**
   - *PAOS 防线*：`paos cron` 与 `paos notify` 坚持**零常驻守护进程、零入站监听端口**设计，完全依托系统原生 `launchd`/`crontab`（配 `fcntl.flock` 内核文件锁）与纯单向出站 HTTPS / `osascript`。

---

## 2. 必须清楚的防线边界（Known Limitations）

- **词法钩子与 Starlark 规则是「防呆减速带（Tripwire）」，而非终极内核沙盒**：面对蓄意混淆（如 Base64 解码执行或自定义 Python/Node 脚本直接调用系统调用），命令词法层无法穷举拦截；**真正的机密文件防读取必须依赖操作系统级沙盒**（macOS `Seatbelt` / Linux `bubblewrap`，开启 `failIfUnavailable: true` 与 `allowUnsandboxedCommands: false`）叠加内置 `permissions.deny`。
- **父进程内存环境变量盲区**：文件系统 `denyRead` 无法阻止子进程读取父 Shell 已经 `export` 进内存的环境变量。请勿在启动 Agent 的全局 `.zshrc`/`.bashrc` 中常驻明文生产根密钥。
- **合法白名单域名边界**：当 `github.com` 位于沙盒网络允许列表内时，网络层允许连接 GitHub；无人值守自动化任务请配置**单仓库细粒度 PAT（Fine-grained Token）**而非全权限个人主账号会话。
