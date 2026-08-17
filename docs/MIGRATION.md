# Codex Guard 新电脑迁移指南

迁移的原则是：**迁移策略，不迁移身份和受保护状态。**

## 旧电脑

1. 关闭 Codex、终端、Git 和 WSL。
2. 在 Codex Guard 的“迁移与部署”页选择“导出可移植策略”。
3. 保存 `.codexguard.json`，并单独备份真实项目数据。
4. 保留旧电脑上的 Codex Guard 和 ACL，直到新电脑验证完成；导出不会撤销任何已激活目录。

不要复制以下内容到新电脑或另一个 Windows 用户：

- `C:\ProgramData\Codex Guard\state.json`
- `History` 中的原始 SDDL
- Worker 或沙箱 SID
- Windows/ChatGPT 密码、登录令牌和 `.codex` 目录

状态文件包含本机 NTFS 文件 ID 和 SID，复制后会被拒绝。

## 新电脑

1. 使用 OpenAI 官方安装方式部署 ChatGPT/Codex；Codex Guard 不包含或替代官方客户端安装程序。
2. 核对 Codex Guard 发布包 SHA-256，在管理员会话双击运行。
3. 创建新的本地标准账户 `CodexWorker`，完成 UAC、管理员资料和 requirements 配置。
4. 登录一次新的 `CodexWorker`，完成官方 Windows elevated 沙箱初始化，使本机创建新的沙箱账户和 `CodexSandboxUsers` 组。
5. 关闭 Codex/终端，运行 Codex Guard 的“UAC 绑定 / 修复全部权限”。
6. 把项目数据恢复到新电脑的目标 NTFS 路径。
7. 打开“默认只读”，核对并通过 UAC 应用这台新电脑重新生成的固定盘、Worker 目录、根锁和允许列表。默认只读基线不写入 `.codexguard.json`，因为磁盘、Worker 资料和 Windows 布局必须以新机器事实为准。
8. 导入 `.codexguard.json`。若盘符或目录改变，在映射窗口设置“旧根”和“新根”，例如 `D:\` → `E:\`。
9. 一次 UAC 只累加映射后的激活项目；管理员资料保护和默认只读边界不从策略导入，而由新电脑安装与本机计划生成。管理员必须检查每条最终路径和确认码。
10. 运行安全审计，并用**测试副本**分别验证：默认只读区拒绝新建/写入；激活区可读取、覆盖、新建，同时拒绝删除和重命名。不要用唯一原件测试。
11. 登录新电脑的 `CodexWorker` 桌面并启动官方 ChatGPT/Codex；用任务管理器核对进程用户名，并用无敏感信息的测试任务确认只有 Worker `.codex` 更新。不要迁移、联接或自动合并旧电脑/admin 的 `.codex`。

## 可快速携带的内容

- `CodexGuard.exe` 及其 `SHA256SUMS.txt`
- 本文档和安全说明
- 通过应用导出的 `.codexguard.json`
- 项目本身的独立备份

不携带管理员辅助服务，因为 Codex Guard 没有常驻高权限服务。每台机器都从同一个经过核验的 EXE 安装到受保护的 Program Files 目录，再由该机器的 UAC 和新 SID 建立边界。
