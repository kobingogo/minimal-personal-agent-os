# minimal-personal-agent-os (`paos`)

一套**零第三方依赖、拒绝玩具化、5 秒即可对本机真机排雷**的 **三层确定性个人 AI 操作系统（Personal Agent OS）** 控制面工具包与工作区内核。

> 核心理念：90% 的网红「Personal Agent OS」正在沦为更贵的新型电子坟墓。真正能长期稳跑的个人系统，靠的不是堆网关、挂十几个 MCP、拉五个 Agent 互相闲聊，而是用 **纯文本状态控噪 + 按需技能切换 + 操作系统级物理硬护栏** 给概率模型戴上镣铐。

---

## 它真正解决什么问题？（不是空壳 Markdown 模板）

1. **真机一键排雷（`paos doctor`）**：5 秒只读扫描你本机现有的 Claude Code / Codex 环境——揪出吃灰却仍在消耗数千启动 Token 的软链接 Skill、超出 200 行/25KB 被静默截断的 `MEMORY.md`、未关闭默认逃生舱的沙盒、写错三层嵌套静默失效的 Hooks Schema，以及 `.claude/settings.local.json` 里不慎留下的明文密钥（全程脱敏不回显凭据）。
2. **技能坟场与 0.1 秒场景切换（`paos skills`）**：解决「界面关了 Skill 但磁盘软链接照样白吃 `/context` 上下文」的真实痛点。支持一键把低频技能移入 `~/.claude/skills-off/`，并按 `minimal` / `writing` / `coding` / `video` 场景预设随时切换常驻技能集。
3. **非破坏性安全加固与一键回滚（`paos harden` / `paos rollback`）**：绝不粗暴覆盖你已有的 `~/.claude/settings.json`——自动深度合并 OS 沙盒（封死 `allowUnsandboxedCommands` 逃生舱）、内置 `permissions.deny` 双锁、全局 gitignore 防泄密，支持 `--dry-run` 预览 Unified Diff 与时间戳备份一键回滚。
4. **词法级 Fail-Closed 钩子与防死循环熔断（零 `jq` 依赖）**：
   - `hooks/pre_tool_gate.py`：基于 `shlex` 词法切分并递归检查 `$(...)` / `bash -c` 子命令，精准拦停根目录/家目录 `rm -rf`、`git push -f`、PixelLeak 式 `gh repo/gist create --public`、远程管道执行与全量 `env` 打印；**不误杀** `git commit -m "never run git push -f"` 或 `env NODE_ENV=test npm test`。
   - `hooks/stop_verify.py`：内置 `Stuck-Cap` 熔断器，无文件改动不跑测试，连续失败达上限自动停机交回人工，拒绝无限死循环烧穿额度。
5. **早中晚日常运转闭环**：开箱自带 `SessionStart` 动态记忆自举（≤3.8KB 预算保 Prompt Cache）、`paos capture` 毫秒级零 Token 速记、`/triage` 晨间分诊（硬卡今日 ≤3 件 P0）、`/reflect` 晚间复盘与 `/promote` 周末人工 Diff 规则晋升。

---

## 30 秒快速上手

环境要求：**macOS 或 Linux / WSL2，Python 3.9+ 标准库**（零 `pip` / `npm` 依赖；Linux 开启系统沙盒需 `sudo apt install bubblewrap socat`）。

```bash
git clone https://github.com/kobingogo/minimal-personal-agent-os.git ~/personal-harness
cd ~/personal-harness

# 先只读预览将对 ~/.claude/settings.json 做的安全合并（不改任何文件）
./install.sh --dry-run

# 确认无误后一键部署钩子、合并沙盒配置、执行 8 项词法拦截自检并跑真机体检
./install.sh

# 可选：把 paos CLI 挂进全局 PATH，随时随地用
mkdir -p ~/.local/bin && ln -sf "$PWD/bin/paos" ~/.local/bin/paos
```

---

## 核心 CLI 命令速查（`paos`）

```bash
# 1. 真机 5 维体检（上下文膨胀 / 沙盒逃生舱 / Hooks Schema / 明文密钥泄漏面 / 纠偏积压）
paos doctor
paos doctor --json

# 2. 技能坟场管理（解决 60+ Skill 塞爆启动 /context 痛点）
paos skills list                         # 查看当前启用与 skills-off 停放清单及预估 Token 税
paos skills clean-broken                 # 自动把失效软链接清入 skills-off/
paos skills park toy-skill-a toy-skill-b # 物理停放低频技能
paos skills enable toy-skill-a           # 随时恢复启用
paos skills profile writing --dry-run    # 预览切换到「内容创作档」常驻技能集
paos skills profile writing              # 0.1 秒切换生效（新开会话即享干净上下文）

# 3. 日常个人 OS 运转（零 Token 开销）
paos capture "调研某开源仓库并整理进周报"  # 毫秒级速记进 memory/INBOX.md
paos status                              # 一屏查看安全分、今日 P0、收件箱计数与记忆行预算

# 4. 安全加固与回滚
paos harden --dry-run                    # 预览安全配置 Diff
paos harden                              # 幂等合并配置并自动备份原文件
paos rollback                            # 一键恢复最近一次备份的 settings.json
```

---

## 在 Claude Code / Codex 中运转的一天

1. **09:00 开机定盘**：`cd ~/personal-harness && claude` —— 项目级 `SessionStart` 钩子自动把 `TODAY.md`、`INBOX.md` 待办数和今昨日志推入上下文；输入 `/triage`，对照 `USER.md` 季度双主线把碎片压成今天最多 **3 件带验收标准的 P0**。
2. **10:00–18:00 专注执行**：按需激活 `.claude/skills/` 中的渐进式技能（附 `daily-intel` 标准样板），繁重检索下放给只读低价子代理，每阶段进度落盘 `PROGRESS.md`。
3. **22:00 收工沉淀**：输入 `/reflect` 归档 `memory/daily/YYYY-MM-DD.md`，并将今日纠偏带 `[tag:xxx]` 记入 `memory/learnings.md` 草稿箱。
4. **周末 10 分钟进化**：当 `paos status` 提示某类标签复发 ≥2 次，输入 `/promote` 生成晋升为脚本/钩子的 Diff 提案，人工批准落地后删除旧文字规则。

---

## 仓库结构与文档

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — 控制面与数据面解耦、Prompt Cache 保护与多工具（Claude Code / Codex / OpenClaw）兼容映射
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) — 威胁模型（PixelLeak / Apiiro 泄密防御）与已知安全边界说明
- `tests/test_paos.py` — 全量零依赖单元与集成测试套件（`python3 tests/test_paos.py`）

## 运行测试

```bash
python3 tests/test_paos.py
bash -n install.sh hooks/*.sh
```

## License

MIT
