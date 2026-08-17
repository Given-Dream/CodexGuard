# Codex 本地记录路径隔离

本机没有云端工作区或可依赖的云端记录同步，因此 Codex Guard 采用一个明确边界：**未来的 Codex 任务和本地记录只有一个写入身份——`CodexWorker`**。ChatGPT/Codex 必须在 `CodexWorker` 自己的 Windows 交互式桌面运行；`admin` 不再承载 Worker 版界面。

## 为什么移除 admin 桌面启动

0.5.2 曾尝试先在 admin 桌面用备用凭据运行 Worker 辅助进程，再通过 Windows 包接口激活 ChatGPT/Codex。实机核查发现，辅助进程可以是 Worker，但打包版 ChatGPT/Codex 最终仍可能由当前 admin 交互式会话创建。身份复核虽然能拒绝结果，却不能把它安全转换为 Worker 进程。

0.5.3 因此删除了这条启动链：

- 不再创建公共桌面的 `Codex (CodexWorker)`；
- 不再接受旧的 Worker 启动命令行开关；
- 不再通过 Codex Guard 激活 ChatGPT/Codex 包；
- 安装/修复只按固定目标和固定旧参数只读识别并报告旧快捷方式，由 admin 人工处理；
- 同名但目标或参数不同的快捷方式不会被删除。

## 正确的日常身份

1. 登录 `CodexWorker` 的 Windows 桌面。
2. 从该桌面启动官方 ChatGPT/Codex。
3. 在任务管理器“详细信息”页显示“用户名”列，确认 ChatGPT/Codex/codex 都属于 `<机器名>\CodexWorker`。
4. Worker 桌面的 Codex Guard 只用于查看状态、软件复用等独立流程和提交删除申请；不能提交 NTFS 权限变更。
5. 需要激活、撤销、默认只读、绑定/修复或策略导入时，切换到非提升 admin 控制面提交，再在 Windows UAC 安全桌面确认；无需、也不应在 admin 桌面运行 Codex。

`admin` 用于 CodexWorker 权限管理、人工删除、系统维护和恢复。若在 admin 桌面启动 ChatGPT/Codex，它就是 admin 应用，不能视为 Worker 隔离已经生效。

## 本地记录规则

- 未来任务只写 `C:\Users\CodexWorker\.codex`。
- `admin` 的既有 `.codex` 保留为旧档，不自动导入、复制、合并或覆盖。
- 不复制 `auth.json`、SQLite、WAL、会话 JSONL、插件秘密或缓存。
- 不用联接点、符号链接或硬链接把两个 `.codex` 指向同一位置。
- 若确需迁移历史，只对已经完全退出的离线副本进行一次性、可回滚、人工核查的迁移；Codex Guard 当前不提供数据库合并器。

## 快速人工核查

1. 在 `CodexWorker` 桌面启动 ChatGPT/Codex。
2. 确认任务管理器中的 ChatGPT/Codex/codex 用户名为 `<机器名>\CodexWorker`。
3. 新建一条无敏感信息的测试任务。
4. 确认 Worker `.codex` 的修改时间更新，而 admin `.codex` 不更新。
5. 打开 Codex Guard 的“安全审计”页；本地记录路径隔离项必须没有红色失败，然后导出统一人工核查包留档。
6. 确认公共桌面不再存在 Codex Guard 创建的旧 `Codex (CodexWorker)` 快捷方式。

脱敏报告只统计路径、存在性、数量、大小、时间和链接属性；不打开登录令牌或对话正文，也不修改任何 Codex 数据。
