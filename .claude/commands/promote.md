执行周末规则进化审阅（`/promote`）：

1. 读取 `memory/learnings.md`、`AGENTS.md` 和 `.claude/skills/` 目录清单。
2. 统计 `learnings.md` 中带有 `[tag:xxx]` 或同语义重复出现 **≥2 次** 的摩擦点。
3. 按「确定性优先于文字」铁律，为每个高频摩擦生成晋升提案：
   - **第一优先级（写成代码/Hook）**：能否在 `hooks/pre_tool_gate.py`、测试脚本或 Lint 中硬拦截？
   - **第二优先级（封进专项 Skill）**：是否只属于某类垂直工序，应写入对应 `.claude/skills/<name>/SKILL.md` 的验收清单？
   - **第三优先级（最后才写进 `AGENTS.md`）**：若必须写全局规则，控制在一句话以内，并检查 `AGENTS.md` 里是否有已被自动化守住、可以**立刻删除**的旧文字规则。
4. **硬门禁**：先仅输出拟议的 **Unified Diff 预览与清理计划**，严禁未经我明确确认直接修改 `AGENTS.md`、`.claude/skills/` 或钩子脚本。待我批准后，执行写入并将 `learnings.md` 中已晋升条目移至「已归档」区。
