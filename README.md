# minimal-personal-agent-os (`paos` v0.1.0)

**零依赖个人 AI Agent 操作系统内核（Agent 圈的 `nvm` + `chezmoi` + `systemd` 轻量控制面）**。

100% 基于 **Python 3.9+ 标准库 + POSIX Shell**（零 `pip` / `npm` 供应链依赖、零常驻监听端口、零外部数据库），统一纳管本机 **Claude Code (`~/.claude`)、Codex (`~/.codex`)、Shared Agents (`~/.agents`)、Antigravity (`~/.gemini`) 与 Cursor (`~/.cursor`)** 五大客户端。

---

## 为什么需要 `paos`？

重度多 Agent 玩家在单机同时混用 Claude Code、Codex 与 Antigravity 时，普遍被五个工程痛点反复折磨：
1. **连环二级断链雪崩**：许多安装器把 Cursor / Antigravity 的技能软链指向 `~/.claude/skills/`；一旦把低频技能挪进 `skills-off/` 省上下文，其余四端当场集体断链。
2. **多端上下文税失控**：单端瘦身完，其他端和插件包仍挂载数十个低频技能，且 `~/.claude.json` 积压大量已删除项目的陈旧缓存。
3. **跨端失忆与手改规则漂移**：在 Claude 总结的架构边界和今日 P0，切到 Codex / Antigravity 又得重新交代一遍。
4. **后台跑任务无硬约束、盲审靠自觉**：裸跑 Agent 缺少 Git Worktree 物理隔离与进程组级超时强杀；写完代码让原会话自己审自己形同虚设。
5. **常驻网关攻击面过大**：为了跑每日早报或接收任务完成通知而部署 24 小时开端口的重量级常驻守护进程，极易引入远程代码执行与凭证泄露隐患。

---

## 五大内核子系统全景（`v0.1.0`）

| 内核模块 | 核心命令 | 解决的问题 |
| :--- | :--- | :--- |
| **1. 跨端包管理与切档 (`nvm` + `chezmoi`)** | `paos matrix` / `adopt` / `use -p` / `clean` / `plugins` | 一级物理真源 `~/.paos/store/` 根治二级断链；0.1s 五端技能+插件同步切档；安全瘦身 `.claude.json` 失效项目缓存 |
| **2. 双端物理门禁与脱敏审计 (`seccomp` + `journald`)** | `paos harden --all` / `doctor` / `rollback --all` / `logs` | 幂等加固 Claude OS 沙盒+词法钩子与 Codex Starlark 门禁；拦截与熔断事件自动脱敏记入 `~/.paos/logs/audit.jsonl` |
| **3. 跨端统一记忆同步总线 (`brain sync`)** | `paos init` / `sync` / `capture` / `promote` / `status` | 维护 `~/.paos/brain/` 真源，通过 `<!-- PAOS:BEGIN/END -->` 受管块无损同步至四端规则文件（100% 保留手写内容） |
| **4. 隔离任务调度与金鱼盲审 (`run` + `review`)** | `paos run --worktree` / `paos review --xhigh` | 自动开辟隔离 Git Worktree、预算封顶、`killpg` 强杀超时子进程树；零记忆冷启动 Diff 盲审（检出 `[P0]` 返回退出码 `2`） |
| **5. 零守护进程巡检与单向通知 (`cron` + `notify`)** | `paos cron install` / `paos notify` | 编译为系统原生 `launchd` plist (macOS) 或 `crontab` (Linux) 零后台内存常驻；单向出站通知强制过 DLP 密钥脱敏 |

---

## 30 秒快速上手

```bash
git clone https://github.com/kobingogo/minimal-personal-agent-os.git ~/personal-harness
cd ~/personal-harness
mkdir -p ~/.local/bin && ln -sf "$PWD/bin/paos" ~/.local/bin/paos

# 1. 全景扫描五端上下文税、断链与健康分（零文件改动）
paos matrix
paos doctor

# 2. 初始化跨端共享大脑并预览四端非破坏性挂载 Diff
paos init
paos sync --dry-run

# 3. 预览一级真源收归、跨端切档（含插件）与陈旧状态瘦身
paos adopt --dry-run
paos use writing --include-plugins --dry-run
paos clean --prune-claude-state --dry-run

# 4. 加固 Claude + Codex 双端安全门禁
paos harden --all --dry-run
```

---

## 常用 CLI 速查手册

```bash
# [包管理与切档]
paos matrix                                    # 五端上下文税、断链与分叉拷贝全景账单
paos adopt                                     # 收归 ~/.paos/store/ 一级真源并生成快照
paos restore-links                             # 从快照一键无损还原软链拓扑
paos use coding -p                             # 五端技能 + Antigravity 插件同步切至工程档
paos clean --prune-claude-state                # 清理 .tmp-* 残留、治愈断链并瘦身 ~/.claude.json

# [记忆同步与进化]
paos init                                      # 初始化 ~/.paos/brain/ 共享记忆真源
paos sync                                      # 编译同步至 CLAUDE.md / AGENTS.md / GEMINI.md / Cursor
paos capture "排查 WebSocket 重连超时"          # 毫秒级零 Token 追加至全局 INBOX.md
paos promote                                   # 聚合复发 >=2 次的 [tag:...] 坑点辅助晋升脚本/钩子
paos status                                    # 一屏总览安全分、五端税、定时巡检与今日 P0

# [受控调度与冷启动盲审]
paos run -w --engine codex "补齐 auth 边界单测"  # 在隔离 Git Worktree 中受控派发任务
paos review --base main --xhigh                # 零上下文金鱼盲审当前分支 Diff（P0 阻断退出码 2）
paos logs --blocks-only                        # 查看本地脱敏门禁拦截、熔断与 P0 退回记录

# [零守护进程巡检与通知]
paos cron list                                 # 查看 heartbeat 与 weekly-hygiene 挂载状态
paos cron install weekly-hygiene --dry-run     # 预览生成的 macOS launchd plist / Linux crontab
paos notify "构建完成" "单测全绿" --channel auto # 单向 DLP 脱敏推送（macOS / 飞书卡片 / TG / Webhook）
```

---

## 自动化测试验证

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_paos.py
bash -n install.sh hooks/*.sh
```

## License

MIT
