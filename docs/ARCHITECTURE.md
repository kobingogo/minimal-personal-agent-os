# 架构设计：三层确定性工程（Architecture）

`minimal-personal-agent-os`（CLI 名为 `paos`）的核心主张只有一句话：**不要把概率大模型当操作系统本身，而是用确定性的文件状态、按需工具加载与物理隔离护栏，把大模型约束成一个可替换的执行部件。**

## 1. 控制面与数据面分离（Control Plane vs. Data Plane）

大多数个人 AI 模板失败的原因，是把所有笔记、代码仓库、个人账单和安全脚本塞进同一个 Agent 可写目录：
- 一旦目录结构跟用户现有 Obsidian / 代码仓冲突，3 天必弃坑；
- 一旦 Agent 拥有控制面写权限，被提示词注入后可直接改写 `settings.json` 或删除拦截钩子。

PAOS 强制拆成三个物理边界：
1. **不可变护栏区（`~/.claude/hooks/` & `~/.claude/settings.json`）**：部署在工作区外部，并通过 `sandbox.filesystem.denyWrite` 与 `permissions.deny` 双重锁死只读，Agent 无权自改。
2. **轻量控制面仓（`~/personal-harness/`）**：仅存放 `CLAUDE.md`、`USER.md`、`AGENTS.md`、记忆索引与自定义命令，纯文本 Git 托管，零隐私凭据。
3. **外部业务工作区（Obsidian / 代码仓）**：按最小权限挂载，高敏目录（财务、主账号私钥、生产配置）物理隔离在外。

## 2. 记忆与 Prompt Cache 保护机制

- **静态契约置顶**：`CLAUDE.md` 仅通过 `@USER.md`、`@AGENTS.md`、`@memory/MEMORY.md` 引入低频变动的静态文本，最大化命中大模型的 **Prompt Cache**。
- **200 行硬上限索引**：`memory/MEMORY.md` 严守 ≤200 行 / 25KB，只存 `1 行 1 指针`，正文下沉到 `memory/topics/*.md` 按需读取，`paos doctor` 会自动巡检所有项目的截断风险。
- **动态状态后置注入**：每日变化的 `TODAY.md`、`INBOX.md` 计数和今昨两日日志通过项目级 `SessionStart` 钩子（`hooks/load_recent_memory.py`）动态输出到会话上下文（硬限流 ≤3,800 字符），不污染静态规则文件。

## 3. 渐进式披露与「技能坟场」机制

- Claude Code 启动时会扫描 `~/.claude/skills/` 注入所有技能元数据；界面开关若未移除磁盘软链接，仍会持续消耗数千至上万启动 Token。
- `paos skills` 通过物理目录切换（`~/.claude/skills/` ↔ `~/.claude/skills-off/`）配合 `config/skill-profiles.json` 场景预设（`minimal` / `writing` / `coding` / `video`），让你按当前工作模式在 0.1 秒内切换常驻技能集。

## 4. 跨客户端兼容映射

| 层级 | Claude Code | OpenAI Codex CLI | OpenClaw / 常驻网关 |
| :--- | :--- | :--- | :--- |
| 自动入口 | `CLAUDE.md` (`@import`) | `AGENTS.md` | `SOUL.md` + `USER.md` + `AGENTS.md` |
| 每日命令 | `.claude/commands/{triage,reflect,promote}.md` | 直接读取同目录 Markdown 执行 | 映射为 Gateway 快捷指令 |
| 技能规范 | `.claude/skills/<name>/SKILL.md` | `~/.codex/skills/<name>/SKILL.md` | ClawHub / 本地 `skills/` |
| 定时巡检 | `hooks/heartbeat-run.sh` (`claude -p`) | `codex exec` 替换同脚本命令 | 原生 `HEARTBEAT.md` 守护进程 |
