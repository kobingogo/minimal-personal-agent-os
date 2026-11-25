# 工程与基础设施避坑

- **macOS `date` 差异**：macOS BSD `date` 用 `-v-1d`，Linux GNU `date` 用 `-d yesterday`；脚本里必须双兼容。
- **Hooks 三层嵌套**：Claude Code `settings.json` 中每个 matcher 对象内必须嵌套 `"hooks": [...]` 数组。
- **沙盒默认逃生舱**：务必显式设置 `allowUnsandboxedCommands: false` 与 `failIfUnavailable: true`，并用 `permissions.deny` 同步锁住内置 `Read(.env)`。
- **长任务落盘**：多阶段任务每完结一步立刻更新 `PROGRESS.md`，防止切模型撞 `401` 或限流断档。
