执行晚间复盘（`/reflect`）：

1. 对照 `~/.paos/brain/memory/TODAY.md` 和今日对话进展，用 5–10 行精简要点把「已完成 / 关键决策 / 明天接手断点」追加写入 `~/.paos/brain/memory/daily/YYYY-MM-DD.md`。
2. 复盘今天我人工纠正过你的所有错误、跑偏或踩坑，**必须包含 `[tag:类别标识]`**（如 `[tag:cache-bust]` 或 `[tag:权限边界]`），按以下格式追加到 `~/.paos/brain/memory/learnings.md`：
   `- [YYYY-MM-DD] [tag:类别标识] 现象 -> 根因 -> 候选防复发动作（钩子/单测/规则）`
3. **硬门禁**：禁止直接修改 `CORE_RULES.md`、技能目录或钩子脚本；若某 `[tag:...]` 累计未归档复发 ≥2 次，提醒我运行 `paos promote` 审阅晋升。
