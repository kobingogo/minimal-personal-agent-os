# 安全威胁模型与边界说明（Security Model）

给本地 AI Agent 开放终端与联网能力后，单靠在系统提示词里写「请勿泄露密钥、请勿删库」属于无效防御。PAOS 针对 2026 年真实发生的两类高频事故构建纵深防线，同时诚实标明每层防线的能力边界。

## 1. 重点防御的真实攻击/翻车面

1. **配置落盘泄密（2026-11 Apiiro / GitGuardian 披露模式）**
   - *成因*：执行含内联密码/Token 的命令时点击 "Yes, and don't ask again"，导致明文凭据写入 `.claude/settings.local.json` 并被提交至 Git 或打入 Docker 镜像。
   - *PAOS 防线*：
     - `paos harden` 自动将 `.claude/settings.local.json` 写入全局 `core.excludesfile`；
     - 仓库内置 `.gitignore` 与 `.dockerignore` 模板；
     - `paos doctor` 自动扫描本地 `settings.local.json` 中的疑似内联密钥（全程脱敏告警，绝不在终端回显密钥原文）。

2. **善意越界外传与持久化投毒（2026-09 Glow Labs PixelLeak 模式）**
   - *成因*：Agent 为完成 PR 贴图等任务，调用主账号 `gh` 创建公开仓库或公开 Gist 当图床，甚至将该做法保存为复用 Skill。
   - *PAOS 防线*：
     - `hooks/pre_tool_gate.py` 词法级拦停 `gh repo create --public` 与 `gh gist create --public/-p`；
     - 严格禁止 Agent 自动修改 `AGENTS.md`、`.claude/skills/` 与钩子目录，所有纠偏仅可写入 `memory/learnings.md` 草稿区，经人工 `/promote` 审查 Diff 后方可晋升。

3. **误删宿主机与重试死循环烧穿账单**
   - *PAOS 防线*：
     - `pre_tool_gate.py` 基于 `shlex` 词法切分（支持识别 `$(...)`、反引号及 `bash -c` 嵌套），精准拦截根目录/家目录 `rm -rf`、强推受保护分支、远程脚本管道执行及全量 `env`/`printenv` 导出，同时**不误杀** `git commit -m "fix rm -rf /"` 或 `env NODE_ENV=test npm test`；
     - `stop_verify.py` 内置 `Stuck-Cap` 计数器，连续验证失败达到上限（默认 2 次）自动停机交回人工，彻底杜绝无限重试死循环。

## 2. 必须清楚的防线边界（Known Limitations）

- **`PreToolUse` 钩子是「防呆减速带（Tripwire）」，不是终极沙盒**：面对蓄意混淆的命令（如 Base64 解码执行或自定义 Python 脚本读取文件），钩子层无法穷举拦截；**真正的机密文件防读取必须依赖操作系统级沙盒**（macOS `Seatbelt` / Linux `bubblewrap`，开启 `failIfUnavailable: true` 与 `allowUnsandboxedCommands: false`）叠加内置 `permissions.deny`。
- **父进程内存环境变量盲区**：文件系统 `denyRead` 无法阻止子进程读取父 Shell 已经 `export` 进内存的环境变量。请勿在启动 Agent 的全局 `.zshrc`/`.bashrc` 中常驻明文生产密钥。
- **合法域名外传边界**：当 `github.com` 位于沙盒 `allowedDomains` 白名单内时，网络层允许连接 GitHub；自动化代码任务请务必配置**单仓库细粒度 PAT（Fine-grained Token）**而非全权限个人主账号登录态。
