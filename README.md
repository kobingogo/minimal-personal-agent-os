# minimal-personal-agent-os (`paos` v0.1.0)

**零第三方依赖的个人 AI Agent 操作系统控制面（Agent 圈的 `nvm` + `chezmoi` + `systemd` 轻量内核）**。

100% 基于 **Python 3.9+ 标准库 + POSIX Shell**（零 `pip` / `npm` 供应链依赖、零常驻后台守护进程、零入站监听端口），统一纳管本机 **Claude Code (`~/.claude`)、OpenAI Codex (`~/.codex`)、Shared Agents (`~/.agents`)、Google Antigravity (`~/.gemini`) 与 Cursor (`~/.cursor`)** 五大客户端。

---

## 为什么需要 `paos`？

单机混用多个编码 Agent 时，最常见的五个工程痛点：
1. **连环二级断链雪崩**：安装器常把 Cursor / Antigravity 的技能软链指向 `~/.claude/skills/`；一旦把低频技能挪进 `skills-off/` 省上下文，其余客户端当场集体断链。
2. **多端上下文税与旧缓存失控**：各端重复挂载数十个低频技能，且 `~/.claude.json` 长期积压已删除项目的陈旧缓存。
3. **跨端失忆与规则漂移**：在一个客户端沉淀的核心契约与今日聚焦（P0），切到另一客户端又要重敲一遍。
4. **裸跑任务缺隔离、自审走过场**：后台派任务缺少 Git Worktree 隔离与整棵子进程树超时强杀；让写代码的原会话“自己审自己”极易漏掉阻断级缺陷。
5. **常驻网关攻击面过大**：仅为跑每日定时巡检或推一条完成通知而部署 24 小时开端口的常驻服务，容易引入本地端口劫持与凭证暴露风险。

---

## 五大内核子系统全景（`v0.1.0`）

| 内核子系统 | 核心命令 | 关键能力 |
| :--- | :--- | :--- |
| **1. 跨端包管理与切档** | `paos matrix` / `adopt` / `use -p` / `clean` / `plugins` | 全目录树哈希去重收归 `~/.paos/store/` 一级真源；50ms 跨五端切换技能+插件档位（带 0 匹配防清空保护）；瘦身 `.claude.json` 失效项目缓存 |
| **2. 双端门禁与脱敏审计** | `paos harden --all` / `doctor` / `rollback --all` / `logs` | 幂等加固 Claude OS 沙盒+词法钩子与 Codex Starlark 门禁；所有拦截、熔断与调度记录经 DLP 脱敏写入 `~/.paos/logs/audit.jsonl`（5MB 自动轮转） |
| **3. 跨端记忆同步总线** | `paos init` / `sync` / `capture` / `promote` / `status` | 维护 `~/.paos/brain/` 唯一真源，通过 `<!-- PAOS:BEGIN/END -->` 受管块非破坏性同步至四端规则文件（100% 保留手写内容，首次触碰自动备份） |
| **4. 隔离调度与金鱼盲审** | `paos run -w` / `paos review --xhigh` | 自动创建隔离 Git Worktree、`killpg` 强杀超时孙进程树；**金鱼盲审（Goldfish Review）**在空目录零历史上下文下仅审 Git Diff，命中 `[P0]` 返回退出码 `2` |
| **5. 零守护进程巡检与通知** | `paos cron` / `paos notify` | 编译为系统原生 `launchd` plist (macOS) 或 `crontab` (Linux) 配合内核 `fcntl.flock` 防重入；单向出站通知（macOS / 飞书卡片 / Telegram / Webhook）强制脱敏 |

---

## 前置环境要求

- **操作系统**：macOS 或 Linux（Python `>= 3.9`，自带标准库即可，无需 `pip install`）
- **基础工具**：`git`，以及至少安装并完成登录鉴权以下任一客户端 CLI：`claude`、`codex` 或 `agy`（Antigravity CLI）
- **Linux 沙盒依赖提示**：`paos harden` 会开启 Claude 强制沙盒（`failIfUnavailable: true`），Linux 用户请确保系统已安装 `bubblewrap` (`bwrap`) 与 `socat`（macOS 使用系统内置 `sandbox-exec`，无需额外安装）

---

## 30 秒快速上手

```bash
git clone https://github.com/kobingogo/minimal-personal-agent-os.git ~/paos
cd ~/paos

# 方式 A：先零改动只读预览本机五端现状与加固 Diff
./install.sh --dry-run

# 方式 B：一键完成初始化共享大脑、四端规则挂载、双端门禁加固与自检
./install.sh

# 将 paos 挂入全局 PATH（请确保 ~/.local/bin 已加入你的 ~/.zshrc 或 ~/.bashrc）
mkdir -p ~/.local/bin && ln -sf "$PWD/bin/paos" ~/.local/bin/paos
```

自定义你的技能切档白名单：
- `paos init` 会在 `~/.paos/skill-profiles.json` 生成默认档位文件（亦可参考全栈多领域示例 [skill-profiles.example.json](config/skill-profiles.example.json) 按本机实际技能名修改）。

---

## 常用 CLI 速查手册

```bash
# [1. 包管理与切档]
paos matrix                                    # 五端上下文税、断链与分叉拷贝全景账单
paos adopt                                     # 收归 ~/.paos/store/ 一级真源并保存基线快照
paos restore-links                             # 从基线快照一键无损还原软链与原物理目录
paos use coding -p                             # 五端技能 + Antigravity 插件同步切至工程档
paos clean --prune-claude-state                # 清理 >5min 残留临时文件、治愈断链并瘦身 ~/.claude.json

# [2. 记忆同步与复发坑点晋升]
paos init                                      # 初始化 ~/.paos/brain/ 真源与 ~/.paos/skill-profiles.json
paos sync                                      # 非破坏性同步受管块至 CLAUDE.md / AGENTS.md / GEMINI.md / Cursor
paos capture "排查 WebSocket 重连超时"          # 毫秒级零 Token 追加至 ~/.paos/brain/memory/INBOX.md
paos promote                                   # 聚合复发 >=2 次的 [tag:...] 坑点辅助晋升脚本/钩子
paos status                                    # 一屏总览安全分、五端税、定时巡检与今日 P0

# [3. 隔离调度与金鱼冷启动盲审]
paos run -w --engine codex "补齐 auth 边界单测"  # 在隔离 Git Worktree 中受控派发任务
paos review --base main --xhigh                # 零上下文盲审分支提交+未提交改动+新文件（P0 返回退出码 2）
paos logs --blocks-only                        # 查看本地脱敏门禁拦截、熔断与 P0 退回记录

# [4. 零守护进程巡检与通知]
paos cron list                                 # 查看 heartbeat 与 weekly-hygiene 挂载状态
paos cron install weekly-hygiene               # 注册每周日晚自动清理与体检周报
paos notify "构建完成" "单测全绿" --channel auto # 单向脱敏推送（macOS / 飞书卡片 / Telegram / Webhook）
```

---

## 可选进阶配置

### 1. 配置飞书 / Telegram / Webhook 通知（`~/.paos/config.json`）
由于 macOS `launchd` 与 Linux `crontab` 默认不加载交互式 `~/.zshrc` 环境变量，**推荐将通知凭证写入权限为 `0600` 的 `~/.paos/config.json`**（已被 PAOS 自动纳入沙盒 `denyRead`/`denyWrite` 保护）：

```bash
install -m 600 /dev/null ~/.paos/config.json
cat > ~/.paos/config.json <<'EOF'
{
  "notify": {
    "default_channel": "auto",
    "feishu_webhook": "https://open.feishu.cn/open-apis/bot/v2/hook/你的机器人Token",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "webhook_url": ""
  }
}
EOF
```
*(临时命令行也可通过环境变量 `PAOS_FEISHU_WEBHOOK`、`PAOS_TELEGRAM_BOT_TOKEN`、`PAOS_TELEGRAM_CHAT_ID`、`PAOS_WEBHOOK_URL`、`PAOS_NOTIFY_CHANNEL` 覆盖；若需在开启网络白名单的 Claude 沙盒内部直接发飞书/TG 通知，请将 `open.feishu.cn` 或 `api.telegram.org` 加入 `~/.claude/settings.json` 的 `sandbox.network.allowedDomains`。)*

### 2. 在具体代码仓开启 `Stop` 自动测试与防死循环熔断（`stop_verify.py`）
切勿在用户全局配置 `Stop` 钩子。若希望某个代码仓每次修改后自动跑测试并在连续失败达上限（默认 2 次）时自动停机交回人工，可在**该项目根目录** `.claude/settings.json` 中配置：

```json
{
  "hooks": {
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "PAOS_VERIFY_CMD='pytest -q' PAOS_MAX_STOP_RETRIES=2 ~/.claude/hooks/stop_verify.py"
          }
        ]
      }
    ]
  }
}
```

---

## 自动化测试验证

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_paos.py
bash -n install.sh hooks/*.sh
```

## License

MIT
