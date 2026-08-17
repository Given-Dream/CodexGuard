# Codex Guard 运行手册

## 应用和复核默认只读

1. 先在 Worker 桌面完成 ChatGPT/Codex 初始化，确保 `C:\Users\CodexWorker\AppData` 与 `.codex` 已存在。
2. 保存工作并完全退出 ChatGPT/Codex、所有终端、Git GUI/CLI 和 WSL。
3. 切到 `admin` 桌面，普通启动 Codex Guard（不要“以管理员身份运行”），打开“默认只读”并逐项预览：允许列表只能是 Worker 的 `AppData`、`.codex` 和既有 `.cache`；固定 NTFS 数据盘和 Worker 普通顶层目录必须进入默认只读；Windows 管理目录不由 Guard 重写。
4. 红色阻断未清零前不要提交。准备独立备份后点击“UAC 应用默认只读”，在安全桌面核对管理员端重新生成的路径、SID、根锁和允许列表；重新输入四位码并点击“确认执行”。提升端随后显示不定进度、当前阶段/路径和已用时间；保持窗口开启，不得通过任务管理器强制结束、关机或重启，必须等到成功结果窗口。
5. 返回“安全审计”和“NTFS 权限”复核。新磁盘、新 Worker 顶层目录或未知重解析点出现后必须重新预览、UAC 应用并在副本上验收。

该操作只向 Worker/Sandbox 写主体定向 ACL；admin 和 SYSTEM 不受该 Deny。`AppData`、`.codex`、既有 `.cache` 仍可正常删除，因此不能保存唯一原件。

## 激活项目

1. 保存工作并完全退出 ChatGPT/Codex、所有终端、Git GUI/CLI 和 WSL。
2. 切到 `admin` 桌面，以非提升方式打开 Codex Guard。
3. 确认项目是已应用默认只读边界或固定 `C:\Users\admin` 边界的严格后代。项目目录需由 admin 预先建立，Worker 不能在未激活区域自行建立项目根；0.6.1 起不再提供手工保护根。
4. 将一个或多个互不嵌套的项目加入待激活列表。
5. 选择“UAC 追加激活”，只在 Windows 安全桌面输入管理员密码。
6. 在管理员确认窗口逐条检查最终路径、机器、请求 SID 和作用 SID，然后输入显示的四位确认码。
7. 返回主界面，在“NTFS 权限”页核对该目录的 Guard 分类和 Windows 原始 DACL，再运行安全审计。

随后点击“导出人工核查包”，再用原发布包中的 `CodexGuard.ReadOnlyVerifier.exe` 交叉比较 SID、UAC、哈希和 SDDL。首次部署还必须在专用副本上运行 `CodexGuard.AcceptanceProbe.exe`；完整流程见 [MANUAL_REVIEW.md](MANUAL_REVIEW.md)。

激活是永久累加的；开始新任务时不需要撤销旧项目。

## 在 CodexWorker 桌面运行 Codex

1. 登录 `CodexWorker` 自己的 Windows 桌面，启动并登录官方 ChatGPT/Codex。
2. 打开任务管理器“详细信息”页并显示“用户名”列，确认 ChatGPT/Codex/codex 进程为 `<机器名>\CodexWorker`。
3. 新建一条无敏感信息的测试任务；确认 `C:\Users\CodexWorker\.codex` 的修改时间更新，而 `C:\Users\admin\.codex` 不更新。
4. 打开 Codex Guard 的“安全审计”页，确认本地记录路径隔离项没有红色失败，再导出人工核查包。
5. 日常保持在 Worker 桌面运行 Codex；需要激活、撤销、默认只读、绑定/修复或导入策略时，切到非提升 admin 控制面提交，再在 Windows UAC 安全桌面确认。软件映射和离线复用是独立流程。

0.5.3 不再尝试从 admin 交互式桌面跨用户激活打包版 ChatGPT/Codex。未来记录只写 Worker 的 `.codex`；admin 既有本地记录保持旧档，不复制或合并。项目和工作树继续使用已激活的共同工作目录。完整边界见 [RECORD_SYNC.md](RECORD_SYNC.md)。

## 撤销项目写权限

撤销不会删除文件，也不会恢复未知的历史 ACL。它移除 Codex 身份的显式写授权，添加只读授权，并继续拒绝删除、重命名和 ACL 更改。只有确实不再需要修改某项目时，才从非提升 admin 控制面提交撤销。

## 删除申请

1. 在“迁移与部署”页打开“提交删除申请”。
2. 选择已激活项目内的文件/目录并填写原因。
3. 申请保存到 `C:\ProgramData\Codex Guard\DeleteRequests`。
4. `admin` 打开该目录，人工核对 JSON 中的机器、账户、SID、时间和每个当前路径。
5. 由 `admin` 自行移动或处理真实目标。Codex Guard 不会代为执行。

申请文件可以由低权限请求者修改，因此它只是一份待核查信息，绝不能成为自动删除队列。

## 快速核查目录权限

在“NTFS 权限”页选择目标目录并点击“只读核查”。先确认它属于已激活、默认只读、允许列表、保护未激活、管理员敏感区或明确的未受管理类别，再检查下方原始 DACL 中的 Allow/Deny 与显式/继承来源。该页面不修改 ACL，也不等于完整有效权限证明；发现红色“未受管理”或潜在宽泛写入授权时，停止把重要数据交给 Codex，先由 admin 核对默认基线并在副本上验收。

## 审计异常

- `UAC_*`：不要继续激活；以管理员运行“安装 / 修复”。
- 标题显示“需安装/修复”或旧版提示“Only the configured CodexWorker…”：便携界面与 Program Files 受保护辅助程序版本不一致；从当前发布包运行安装/修复，完成后关闭便携窗口并从公共快捷方式重开。
- `CODEX_REQUIREMENTS_*`：若已有 requirements 文件，Codex Guard 会保留它并生成一个 fragment；人工合并审核后的键值，再重启客户端并修复。
- `WORKER_MISSING` / SID changed：不要手工复制旧 SID；重新运行安装/修复并检查所有目录。
- 发现旧的 `Codex (CodexWorker)` 快捷方式：运行 0.6.7“安装 / 修复”可只读核对它是否为 Codex Guard 旧入口；程序不会自动删除，由 admin 人工移到待删除目录或删除。不要用 WindowsApps、内部 `codex.exe` 或 `PATH` 绕过 Worker 桌面边界。
- `ADMIN_PROFILE_*` / `LEGACY_PROTECTION_ROOT`：固定管理员资料边界必须是 `C:\Users\admin`；旧版额外保护根不再参与激活或修复，先保存状态和原始 SDDL，由 admin 单独核查。
- `DELETE_DENY_MISSING`、`ACTIVE_ALLOW_MISSING`：关闭相关进程后运行“UAC 绑定 / 修复全部权限”。
- `DEFAULT_READONLY_NOT_ENABLED`、默认边界/根锁缺失或发现新目标：停止使用未受保护位置，重新打开“默认只读”预览并通过 UAC 应用；随后分别做默认只读和激活目录黑盒验收。
- `OWNER_RIGHTS_RULE_MISSING`：对象所有者可能保留隐式改 DACL 权，按失败处理；关闭相关进程后修复，并在随机探针对象上复测“写回 DACL”。
- `PATH_IDENTITY_CHANGED`：路径已被替换或重新创建。停止使用，检查数据来源和备份，不要直接点修复。
- 回滚失败：保持 Codex 和终端关闭，由管理员逐目录检查高级安全设置和历史 SDDL。

## 紧急恢复

Codex Guard 故意不提供一键卸载或批量 ACL 重置，因为错误的递归重置可能破坏系统和项目权限。

若业务被锁住：

1. 保持 `CodexWorker`、Codex 和终端退出。
2. 使用仍可登录的受信任管理员账户。
3. 先备份项目及 `C:\ProgramData\Codex Guard`，不要删除状态或历史。
4. 在目标目录“属性 → 安全 → 高级”中只处理 `CodexWorker` 和 `CodexSandboxUsers` 的 Codex Guard ACE；不要对盘根执行通用“替换所有权限”或递归 reset。
5. 如需恢复历史 SDDL，应由熟悉 NTFS 的管理员逐目录核对状态历史后操作。
6. 恢复后重新运行审计，并在副本上测试。

不要删除 `CodexWorker` 或沙箱组来代替 ACL 恢复；这样只会留下孤立 SID，无法证明其他授权已经安全。
