# 架构设计：五大确定性内核子系统（PAOS v0.1.0 Architecture）

`minimal-personal-agent-os`（CLI: `paos`）的核心设计原则只有一句话：**不要把概率大模型当操作系统本身，而是用零外部依赖的确定性内核原语（包管理、记忆总线、双端门禁、隔离进程调度与原生定时中断），把多厂商 Agent 约束成可随时热插拔的计算部件。**

---

## 1. 控制面、共享大脑与业务工作区三层物理分离

1. **不可变护栏与审计区（`~/.claude/hooks/`、`~/.codex/rules/`、`~/.paos/logs/`）**
   - 部署在业务代码仓之外，通过 `templates/claude-user-settings.json`（`harden.py` 的唯一声明式配置真源）锁死 OS 沙盒 `denyRead` / `denyWrite` 与内置 `permissions.deny`，防止 Agent 被提示词注入后读取 `~/.paos/config.json` 或篡改钩子、`cron_jobs.json`、`LaunchAgents` 与 `.git/hooks`。
   - `~/.claude/hooks/` 中的钩子均为轻量级统一入口，100% 委托给 `paos harden` 复制进 `~/.claude/hooks/paos_runtime/` 的 `paos.gate` 与 `paos.audit` 执行（不 import 工作区源码，Agent 无法通过改仓库代码拆掉门禁），门禁钩子带 `"onFailure": "block"`，脚本异常、缺解释器或超时一律拦截；所有门禁拦截（`gate_block`）、验证熔断（`stuck_cap`）、任务调度（`task_run`）与盲审结论（`code_review`）共享同一套 DLP 正则脱敏与 5MB 自动轮转逻辑，彻底杜绝复制粘贴漂移。
2. **跨端统一真源层（`~/.paos/`）**
   - `~/.paos/store/skills/`：全机唯一物理技能真源仓，根治跨客户端二级软链连环暴毙；
   - `~/.paos/brain/`：全机唯一的跨客户端共享核心契约（`CORE_RULES.md`、`USER.md`、`HEARTBEAT.md`）与纯文本记忆层（`MEMORY.md` ≤200 行硬上限、`TODAY.md`、`INBOX.md`、`learnings.md`），消除仓内与全局双轨状态分裂。
3. **外部业务数据面（代码仓 / 笔记库）**
   - 按最小权限挂载；后台派发重任务时通过 `paos run -w` 在 `~/.paos/worktrees/` 自动拉起隔离 Git Worktree（保留调用时的子目录偏移），杜绝踩脏主分支工作树。

---

## 2. 非破坏性跨端记忆编译器（`lib/paos/sync_bus.py`）

不同客户端对全局指令的加载协议不同：Claude Code 支持 `@~/.paos/brain/...` 按需引用，而 Codex（`~/.codex/AGENTS.md`）、Antigravity（`~/.gemini/GEMINI.md`）与 Cursor（`~/.cursor/rules/paos-shared.mdc`）直接内联读取规则文件。

`paos sync` 对四端统一采用**受管标记块（`<!-- PAOS:BEGIN --> ... <!-- PAOS:END -->`）**编译协议：
- **100% 保护手写配置**：受管块外部的任何用户原有规则（含 Cursor `.mdc` 的 YAML Frontmatter 与自定义段落）原封不动保留，自动过滤受管内容中的嵌套标记并使用函数式正则替换防止反斜杠转义破坏；
- **首次触碰强制备份**：首次向任何已有规则文件注入受管块前，自动备份原文件至 `~/.paos/backups/sync-<timestamp>/`，并支持 `paos sync --remove` 无损卸载；
- **Prompt Cache 友好**：`SessionStart` 钩子（`paos harden` 全局注册）动态注入每日聚焦与近两日日志（硬限流 ≤3,800 字符）；钩子已注册时，`paos sync` 写进 `~/.claude/CLAUDE.md` 的受管块只保留静态 `@` 导入，动态内容只在一处注入，静态前缀不随每日待办变化。

---

## 3. 全目录树哈希包管理与安全切档（`lib/paos/harnesses.py`）

1. **`paos adopt`**：先执行纯只读基线快照（`links-00000000-baseline.json`，重复运行绝不冲刷初始基线），再按最新修改时间收归实体技能目录至 `~/.paos/store/skills/`，使用**全目录树 SHA-256**（覆盖 `SKILL.md` 及全部附属 `scripts/` 子文件）精准识别分叉版本并备份至 `~/.paos/backups/`，最后将五端统一改写为一级直连软链。
2. **`paos use <profile> [-p]`**：优先读取用户级 `~/.paos/skill-profiles.json`，在 50ms 内同步切换五端技能软链与 Antigravity 插件配置（当匹配数为 0 时触发防误清空保护）；`paos restore-links` 即使在多次切档后也能完整还原初始实体目录与软链拓扑。
3. **`paos clean --prune-claude-state`**：默认仅清理超过 5 分钟的崩溃残留 `.tmp-*` 文件（防并发写入竞争），并在保留原文件权限（`0600`）与软链目标的前提下剔除 `~/.claude.json` 中已删除路径的陈旧项目缓存（自动跳过含自定义 `mcpServers` 或未挂载 `/Volumes/` 外置盘的项目）。

---

## 4. 进程组级隔离调度与金鱼零记忆盲审（`lib/paos/scheduler.py`）

- **`paos run`**：统一封装 `claude`、`codex` 与 `agy`，在独立会话进程组（`start_new_session=True`）内运行，超时或中断时通过 `os.killpg(pgid, 0)` 探活并在宽限期后向整棵残留孙进程树强制补发 `SIGKILL`，杜绝忽略 `SIGTERM` 的孤儿进程泄漏。
- **`paos review`（Goldfish Cold-Start Gate，源自 Elephant-Goldfish 写审分离模式）**：在全新**空临时目录**（隔离被审仓库的 `CLAUDE.md`/`AGENTS.md` 提示词污染）下启动零历史记忆审查进程，通过 `stdin` 喂入分支提交 + 工作区未提交改动 + NUL 分隔未跟踪新文件的完整 Diff（超 120KB 触发 Fail-Closed 拒绝静默截断），严格锚定输出**最后一行**结论标记，命中任何 `[P0]` 阻断缺陷直接返回退出码 `2`。

---

## 5. 内核 `flock` 定时巡检与单向脱敏通知（`lib/paos/cron.py` & `notify.py`）

- **向 OS 借原生调度器与文件锁**：`paos cron install` 在 macOS 生成 `plistlib` `~/Library/LaunchAgents/com.paos.<job>.plist`，在 Linux 精确按行尾标签维护 `crontab`；执行时采用内核级非阻塞排他锁 `fcntl.flock`（`~/.paos/locks/<job>.flock`，进程被强杀或系统重启由内核自动释放，零死锁竞态），且禁止外部篡改覆盖内置只读任务命令。
- **零入站端口单向通知总线**：`paos notify` 仅发起纯出站请求并校验平台业务状态码（如飞书 `code`/`StatusCode`），出站前对全量文本先行执行 `redact_secrets()` 再做长度截断。
