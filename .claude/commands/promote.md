执行规则进化晋升审阅（`/promote`）：

1. 运行 `paos promote`（或读取 `~/.paos/brain/memory/learnings.md`）查看未带 `[promoted:...]` 标记且复发 ≥2 次的 `[tag:...]` 摩擦点。
2. 按「确定性代码优先于纯文字叮嘱」铁律，为每个高频标签生成晋升 Diff 提案：
   - **第一优先级（写成钩子/单测/Lint）**：优先落入守卫测试或 `lib/paos/gate.py` 确定性拦截；
   - **第二优先级（写入垂直 Skill）**：仅属特定领域的工序写入对应 `SKILL.md`；
   - **第三优先级（写入 `~/.paos/brain/CORE_RULES.md`）**：控制在一句话以内，并删除已被脚本守住的旧文字规则。
3. **硬门禁**：先仅输出 Unified Diff 等待人工确认；确认落地后，运行 `paos promote --apply && paos sync` 将对应条目打上 `[promoted:YYYY-MM-DD]` 标记并同步四端。
