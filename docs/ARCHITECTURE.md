# 架构设计：五大确定性内核子系统（PAOS v0.1.0 Architecture）

`minimal-personal-agent-os`（CLI: `paos`）的核心设计哲学只有一句话：**不要把概率大模型当操作系统本身，而是用零外部依赖的确定性内核原语（包管理、记忆总线、双端门禁、隔离进程调度与原生定时中断），把多厂商 Agent 约束成可随时热插拔的计算部件。**

---

## 1. 控制面、共享大脑与业务工作区三层物理分离

1. **不可变护栏与审计区（`~/.claude/hooks/`、`~/.codex/rules/`、`~/.paos/logs/`）**
   - 部署在业务代码仓之外，通过 `sandbox.filesystem.denyWrite` 与 `permissions.deny` 双重锁死只读，防止 Agent 被提示词注入后篡改门禁。
   - 所有命令拦截（`gate_block`）、验证熔断（`stuck_cap`）、任务调度（`task_run`）与盲审结论（`code_review`）统一经 `lib/paos/audit.py` 正则脱敏后追加写入 `~/.paos/logs/audit.jsonl`（超 5MB 自动轮转）。
2. **跨端统一真源层（`~/.paos/`）**
   - `~/.paos/store/skills/`：全机唯一物理技能真源仓，根治跨客户端二级软链连环暴毙；
   - `~/.paos/brain/`：跨客户端共享的核心契约（`CORE_RULES.md`、`USER.md`）与纯文本记忆层（`MEMORY.md` ≤200 行硬上限、`TODAY.md`、`INBOX.md`、`learnings.md`）。
3. **外部业务数据面（代码仓 / 笔记库）**
   - 按最小权限挂载；后台派发重任务时通过 `paos run --worktree` 在 `~/.paos/worktrees/` 自动拉起隔离 Git Worktree，杜绝踩脏主分支工作树。

---

## 2. 非破坏性跨端记忆编译器（`lib/paos/sync_bus.py`）

不同客户端对全局指令的加载协议各异：Claude Code 支持 `@~/.paos/brain/...` 按需引用，而 Codex（`~/.codex/AGENTS.md`）、Antigravity（`~/.gemini/GEMINI.md`）与 Cursor（`~/.cursor/rules/paos-shared.mdc`）直接内联读取 Markdown / MDC。

`paos sync` 采用**受管标记块（`<!-- PAOS:BEGIN --> ... <!-- PAOS:END -->`）**编译协议：
- **100% 保护用户手写配置**：受管块外部的任何原有指令（如 Codex 的 `@RTK.md` 或 Antigravity 的个人全局规则）原封不动保留；
- **首次触碰强制备份**：首次向已有规则文件注入受管块前，自动完整备份原文件至 `~/.paos/backups/sync-<timestamp>/`；
- **Prompt Cache 友好**：`SessionStart` 钩子 `hooks/load_recent_memory.py` 负责动态注入每日聚焦与日志（硬限流 ≤3,800 字符），当项目无本地 `memory/` 时自动回退读取 `~/.paos/brain/memory/`，避免高频改动静态规则文件击穿缓存。

---

## 3. 一级真源包管理与 `nvm` 式切档（`lib/paos/harnesses.py`）

1. **`paos adopt`**：扫描五大槽位，按最新 `SKILL.md` 修改时间择优收归独立实体目录至 `~/.paos/store/skills/`（外部 Git 仓库技能保持原位软链不搬家，同名分叉版本自动备份至 `~/.paos/backups/`），将五端全部改写为**一级直连软链**并保存快照。
2. **`paos use <profile> [-p]`**：基于 `config/skill-profiles.json` 在 50ms 内同步切换五端技能软链与 Antigravity 插件包（`~/.gemini/config/config.json`），当场输出各端 Token 启动税增减账单。
3. **`paos clean --prune-claude-state`**：清理 `.tmp-*` 崩溃残留文件、治愈二级断链，并在自动备份后原子剔除 `~/.claude.json` 中磁盘路径已不存在的失效项目缓存（沙盒受限路径采用 Fail-Safe 保守保留策略）。

---

## 4. 受控进程调度与金鱼零记忆盲审（`lib/paos/scheduler.py`）

- **`paos run`**：屏蔽 `claude -p`、`codex exec` 与 `agy -p` 的底层 CLI 参数差异，统一提供 `--worktree` 物理分支隔离、`start_new_session=True` + `os.killpg` 整棵子进程树超时强杀（终结孤儿测试进程挂死）以及预算/轮次硬上限。若隔离 Worktree 无任何文件改动与新提交，任务结束后自动无痕回收。
- **`paos review`（Goldfish Cold-Start Gate）**：严格践行「写审分离」——开启全新零上下文子进程，**仅投喂纯 Git Diff 与 P0/P1 两级审查标尺**，绝不喂入原会话的妥协借口；一旦检出可复现的 `[P0]` 阻断级缺陷（算错钱、丢数据、越权、密钥泄露、死循环或崩溃），立即返回退出码 `2` 阻断合并流水线。

---

## 5. 零守护进程定时巡检与单向脱敏通知（`lib/paos/cron.py` & `notify.py`）

- **向 OS 借原生调度器**：拒绝为每天跑 1 分钟的定时巡检维护 24 小时常驻 Python/Node Daemon。`paos cron install` 在 macOS 上用标准库 `plistlib` 生成合法 `~/Library/LaunchAgents/com.paos.<job>.plist`，在 Linux 上幂等写入带 `# PAOS-CRON:<job>` 标签的 `crontab`，执行时通过 `/tmp` 原子目录锁防止重叠并发。
- **零入站端口单向通知总线**：`paos notify` 仅发起纯出站 HTTPS / 本地 `osascript` 调用（无需公网 IP、无需内网穿透、零入站监听端口），且所有标题与正文在出站前强制经过 `redact_secrets()` 脱敏清洗。
