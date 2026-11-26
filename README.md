# minimal-personal-agent-os (`paos` v0.2)

**Agent 圈的 `nvm` + `chezmoi`**：一套**零第三方依赖、跨客户端统一技能切档、物理真源防断链与确定性安全门禁**的个人 AI 操作系统（Personal Agent OS）控制面工具。

支持一键统管本机 **Claude Code (`~/.claude`)、Codex (`~/.codex`)、Shared Agents (`~/.agents`)、Antigravity (`~/.gemini/antigravity-cli`) 与 Cursor (`~/.cursor`)** 五大客户端槽位。

---

## 为什么做 `v0.2`？（多客户端重度玩家的三个真痛点）

1. **连环二级断链雪崩（Daisy-Chain Symlink Rot）**：很多安装器把 Cursor / Antigravity 的技能软链指向 `~/.claude/skills/`；一旦你为了省 Claude 上下文把低频技能挪进 `skills-off/`，其他客户端的十几根二级软链当场集体暴毙。
2. **五端启动税各自失控**：Claude 刚瘦完身，结果 `.agents/skills` 里还常驻着 50+ 个飞书与视频技能，`.codex/skills` 里躺着 30 个技能外加十几份崩溃残留的 `.tmp-*` 状态垃圾。
3. **安全护栏单腿裸奔**：给 Claude 配好了 `PreToolUse` 钩子，切到 Codex 跑命令时却忘了配对应的 Starlark `execpolicy` 拦截规则。

---

## 核心能力速览（100% Python 3.9+ 标准库，零 `pip` / `npm` 依赖）

- **`paos matrix`（1 秒五端全景账单）**：一眼看清五大客户端的常驻技能数、预估启动 Token 税、**脆弱二级软链/死链**、同名分叉副本与客户端崩溃残留垃圾文件。
- **`paos adopt` + `paos restore-links`（一级物理真源收归，根治断链）**：自动将分散技能收归/索引至 `~/.paos/store/skills/`（外部 Git 仓库技能保持原位软链不搬家，分叉副本自动备份至 `~/.paos/backups/`），把所有客户端改写为**一级直连软链**，自动治愈断链，并支持快照一键无损回滚。
- **`paos use <profile>`（真正的 Agent 圈 `nvm use`）**：0.1 秒在五端（或指定 `--targets claude,codex`）同步切换 `minimal` / `writing` / `coding` / `video` / `lark` / `all` 技能包，当场打印各端启动 Token 税增减账单。
- **`paos clean`（跨端状态去肿与断链自愈）**：安全清理 `.codex` / `.claude` 崩溃残留的孤儿 `.tmp-*` 文件与 `.DS_Store`，自动从真源修复可恢复断链并将无源死链移入隔离区。
- **`paos harden --all`（Claude + Codex 双端统一物理门禁）**：
  - **Claude Code**：非破坏性深度合并 OS 沙盒（封死 `allowUnsandboxedCommands` 逃生舱）、内置 `Read(.env)` 双锁与 `shlex` 词法级 `pre_tool_gate.py`（支持 `paos rollback` 回滚）；
  - **Codex CLI/App**：生成独立的 `~/.codex/rules/paos-guardrails.rules`（绝不覆盖原有的 `default.rules`），自动调本机 `codex execpolicy check` 编译器核验拦截规则。

---

## 30 秒快速上手

```bash
git clone https://github.com/kobingogo/minimal-personal-agent-os.git ~/personal-harness
cd ~/personal-harness

# 1. 零改动只读扫描本机五大客户端现状与启动 Token 税账单
./bin/paos matrix

# 2. 预览多端状态清理、一级真源收归与跨端切档（全程 --dry-run 不改磁盘）
./bin/paos clean --dry-run
./bin/paos adopt --dry-run
./bin/paos use writing --dry-run

# 3. 预览并启用 Claude + Codex 双端安全护栏
./bin/paos harden --all --dry-run
./bin/paos harden --all
```

可选挂载进全局 `PATH`：
```bash
mkdir -p ~/.local/bin && ln -sf "$PWD/bin/paos" ~/.local/bin/paos
```

---

## 常用 CLI 命令速查

```bash
paos matrix                              # 五端全景上下文税、断链与重复拷贝矩阵报告
paos use                                 # 列出所有可用场景预设档位
paos use writing                         # 五端同步切换至「内容创作档」
paos use coding --targets claude,codex   # 仅对 Claude 与 Codex 切换至「软件工程档」
paos use all                             # 一键恢复挂载全部已知技能

paos adopt --dry-run                     # 预览一级物理真源收归与二级断链自动治愈
paos adopt                               # 执行收归（自动生成 ~/.paos/snapshots/ 快照）
paos restore-links                       # 一键回滚最近一次 adopt 前的软链拓扑

paos clean --dry-run                     # 预览孤儿 .tmp-* 清理与断链修复
paos clean                               # 执行跨端无损清理

paos harden --all                        # 幂等加固 Claude 沙盒钩子 + Codex Starlark 门禁
paos rollback                            # 回滚 Claude settings.json 备份
paos doctor                              # 单工作区 5 维深度健康评分 (0–100)
paos capture "待办灵感..."               # 零 Token 毫秒级速记进 memory/INBOX.md
paos status                              # 一屏总览安全分、五端累计税与今日 P0
```

---

## 运行自动化测试

```bash
python3 -B tests/test_paos.py
bash -n install.sh hooks/*.sh
```

## License

MIT
