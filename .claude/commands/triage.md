执行晨间分诊（`/triage`）：

1. 读取 `~/.paos/brain/memory/INBOX.md`、`~/.paos/brain/memory/TODAY.md` 和最近一份 `~/.paos/brain/memory/daily/` 日志（若尚未运行 `paos init`，再回退读取当前目录下的 `memory/`）。
2. 对照 `~/.paos/brain/USER.md` 里的本季度 2 条主线，将 `INBOX.md` 中每条信息归类为：
   - **今日必做（P0）**
   - **延后（Later）**
   - **直接丢弃（Drop）**
3. **硬性约束**：今日 P0 严格不超过 **3 件**（每件以 `- [ ] ` 开头并附 1 句可核验的完成标准）。
4. 先输出分诊表格与取舍理由等待我确认；我确认后更新 `TODAY.md`、清理 `INBOX.md` 已分诊项，并提示运行 `paos sync` 同步今日聚焦至多客户端。
