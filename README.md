# Codex Guard

Codex Guard 是一个面向 Windows 的本地权限管理器，用来把 Codex 的日常运行身份与管理员数据隔离，并为项目目录提供“可读取、可写入、可新建，但不可删除、不可重命名、不可改 ACL”的持久 NTFS 防护。

当前版本：`0.6.7-preview`。它已经完成编译和自动测试，但**尚未由本次构建在真实账户/目录上完成端到端验收**。首次使用应先在可回滚的测试机或测试目录验证。固定数据盘、系统盘上的非 Windows 数据目录以及 Worker 顶层数据目录默认拒绝 Worker/Sandbox 写入、新建、删除、重命名和改 ACL；仅 Worker 的 `AppData`、`.codex`、已经存在的 `.cache` 以及显式激活项目保留写入。Windows、Program Files 与 ProgramData 继续由 Windows ACL 管理。0.6.7 将全部 NTFS 权限管理集中到非提升 `admin` 控制面：激活、撤销、默认只读、绑定/修复和策略导入都只能由安装时登记的 admin SID 提交，并再次经过 UAC 安全桌面与提升端复核；`CodexWorker` 只能查看状态和运行 Codex，无法提交 ACL 变更。写入 ACL 的受限主体仍只有 Worker 与 Sandbox，admin SID 不进入限制集合。便携界面与 `C:\Program Files\Codex Guard` 受保护辅助程序的版本必须完全一致；不一致时所有提升操作会在 UAC 前停止，并要求先安装/修复升级。最终确认后，UAC 提升端会显示不可取消的不定进度条、当前阶段、当前路径和已用时间；Windows 传播继承 ACL 时不伪造完成百分比，事务完成或自动回滚前不得强制结束。只有日志出现确认接受和操作成功两条证据，才视为 ACL 已应用。

## 安全模型

| 层 | 身份 / 位置 | Codex 能做什么 |
|---|---|---|
| Windows 交互账户 | `CodexWorker` | 运行桌面应用；不是管理员，也不属于备份操作员等内置特权组 |
| 官方 Windows 沙箱 | `CodexSandboxUsers` 组中的专用账户 | Agent 命令在官方 `elevated` 沙箱及私有桌面中运行 |
| 管理员资料 | 固定 `C:\Users\admin` | 只读；`AppData`、`.ssh`、`.gnupg`、`.aws`、`.azure`、`.codex` 默认无访问 |
| 默认只读基线 | 固定数据盘、Worker 顶层数据目录、系统盘非 Windows 数据目录 | 对 Worker/Sandbox 只读，并拒绝写入、新建、删除、重命名、改权限和取得所有权 |
| 已激活项目 | 例如 `D:\Projects\MineruFlow` | 可读、可写、可新建；仍拒绝删除、重命名、改权限和取得所有权 |
| Worker 写入允许列表 | `AppData`、`.codex`、已存在的 `.cache` | 保留正常写入和清理，包括 ChatGPT/Codex 资料、用户缓存和用户级更新；不能存放唯一原件 |
| Windows 管理目录 | Windows、Program Files、ProgramData | 不由默认基线重写；沿用 Windows ACL，系统级更新由 admin/SYSTEM 执行 |

`CodexSandboxUsers` 是一个本地组，不是“上位用户”，也不管理 `admin`。Codex Guard 分别把 `CodexWorker` SID 和该沙箱组 SID 写入目标目录 ACL；若解析到的 admin SID 意外出现在限制集合中，或 admin 被加入 `CodexSandboxUsers`，权限操作会失败关闭，不写 ACL。

项目必须是固定管理员资料边界或已应用默认只读边界的**严格子目录**。激活会在项目自身授予写入，同时保留 `Delete`、父目录 `Delete child` 和改 ACL 的拒绝规则；只在项目内部添加规则不足以阻止从父目录删除它。

受保护和激活目录还会添加可继承的 `OWNER RIGHTS`（`S-1-3-4`）只读 ACE。Windows 对文件所有者默认隐式授予 `WRITE_DAC`；缺少这条规则时，CodexWorker 可能利用自己新建文件的所有者身份改 DACL。该 ACE 关闭隐式授权，但不会阻断管理员从 `Administrators` ACE 获得的权限。

激活采用累加模式。新增项目不会把以前激活的项目恢复为只读；只有人工选择“撤销”才会移除该项目的写权限。

## 首次部署

1. 关闭 ChatGPT/Codex、PowerShell、命令提示符、Git Bash、Windows Terminal、Git 和 WSL。已有进程可能持有修改或删除句柄，Codex Guard 会拒绝在这些进程运行时改 ACL。
2. 将发布包放在本机 NTFS 目录，核对包内 `SHA256SUMS.txt`。
3. 保持发布包内三个 EXE 在同一目录，在管理员 Windows 会话中双击 `CodexGuard.exe`，选择“安装 / 修复 Codex Guard”。不要从终端启动；安装会把主程序、独立核查器和验收探针一起复制到受保护的 Program Files 目录。
4. 安装向导创建标准账户 `CodexWorker`，安装受保护的程序文件，并配置 UAC 安全桌面。输入的是新建 Worker 的密码；管理员密码只应输入 Windows 自己的 UAC 安全桌面，Codex Guard 从不接收或保存管理员密码。
5. 若结果窗口提示必须重启 Windows，先执行“重新启动”（不要只关机再开机）；重启前 Codex Guard 会拒绝权限操作。随后登录一次 `CodexWorker`，启动并登录官方 ChatGPT 桌面应用、选择 Codex，完成该用户的应用包注册和官方 Windows `elevated` 沙箱初始化。
6. 再次关闭 ChatGPT/Codex 和所有终端，切回 `admin` 桌面，以普通方式（不要右键“以管理员身份运行”）启动 Codex Guard，运行“UAC 绑定 / 修复全部权限”，把新建的 `CodexSandboxUsers` 组绑定到 ACL。
7. 在非提升 admin 会话打开“默认只读”，逐项核对预览。红色阻断表示不会提交 UAC；“UAC 核验”表示 admin 当前令牌不可见，提升端会重新严格盘点，失败则不写 ACL。尤其要确认 `AppData` 和 `.codex` 已存在、没有未知重解析点、所有固定数据盘均已列出。先做好独立备份，再点击“UAC 应用默认只读”。
8. 返回“安全审计”确认默认只读边界已记录且 ACL 通过。以后新增固定盘、Worker 顶层目录或未知重解析点都会触发审计失败，必须重新预览并由 admin 审核。
9. 添加一个或多个**已经存在**的项目目录，通过 UAC 追加激活。项目必须位于固定 `C:\Users\admin` 边界或已应用的默认只读边界之下；不再提供手工添加保护根。管理员在 Windows 安全桌面输入凭据后，还要核对规范路径并重新输入四位人工确认码。
10. 打开“NTFS 权限”，依次核查一个已激活目录、一个默认只读目录和一个写入允许列表目录；确认分类、策略表和原始 DACL 符合预期。
11. 打开“安全审计”，导出 HTML/JSON 人工核查包，再用发布包中的独立只读核查器交叉核对；最后只在验收副本上分别运行“激活目录”和“默认只读/非激活”探针。详见 [快速人工核查](docs/MANUAL_REVIEW.md)。
12. 保持登录在 `CodexWorker` 桌面，启动官方 ChatGPT/Codex；在任务管理器核对 ChatGPT/Codex/codex 进程用户名为 `<机器名>\CodexWorker`，再用无敏感信息的测试任务确认只有 Worker 的 `.codex` 时间更新。详见 [本地记录隔离](docs/RECORD_SYNC.md)。

日常工作保持登录 `CodexWorker`，从该桌面运行 ChatGPT/Codex 和工作软件；需要改变 NTFS 权限时再切到 `admin` 控制面。激活、撤销、默认只读、绑定/修复和策略导入均由非提升 admin 提交，并再次经过 Windows UAC 安全桌面；Worker 端对应按钮为灰色，后台也按请求 SID 拒绝绕过。软件映射、离线复用和删除申请属于独立流程，不等同于 ACL 权限管理。

官方文档说明 Windows 原生 `elevated` 沙箱使用专用低权限账户和文件系统边界；系统要求文件位于 `%ProgramData%\OpenAI\Codex\requirements.toml`。Codex Guard 会要求仅允许 `elevated` 实现、启用私有桌面，并禁用登录 Shell。参见 [Windows sandbox](https://learn.chatgpt.com/docs/windows/windows-sandbox)、[Managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration) 和 [Configuration Reference](https://learn.chatgpt.com/docs/config-file/config-reference)。

## 日常使用

- 激活新项目：切到非提升 admin 控制面 → 先建立项目目录 → 关闭 Codex/终端 → 确认其位于默认只读边界或固定 `C:\Users\admin` 边界下 → 添加项目 → UAC → 核对最终路径及确认码。Worker 不能提交激活请求，也不能自行在未激活位置建立新项目根。
- 多选项目：待激活列表可一次提交多个互不嵌套的目录。
- 默认只读核查：仅非提升 admin 可提交；先看计划、红色阻断和“UAC 核验”项。该页的“重新只读预览”不改 ACL，只有明确点击 UAC 操作、提升端严格重扫并在安全桌面确认后才会应用。
- 权限事务进度：输入四位码并确认后，提升端会显示不定进度条、当前阶段/路径和已用时间。整盘继承 ACL 传播可能持续数十分钟；进度窗口会禁用普通关闭，但无法阻止任务管理器强制结束，因此仍须遵守窗口警告。
- 权限核查：打开“NTFS 权限”，选择任意目录后点击“只读核查”。该页不写 ACL；绿色表示 Guard 状态和可见 DACL 校验通过，黄色表示需人工判断，红色表示未管理、路径不可读或存在潜在宽泛写入授权。
- 删除临时文件：使用“迁移与部署 → 提交删除申请”。Codex Guard 只生成 JSON 申请记录，不移动、不删除目标；`admin` 人工核查后自行处理。
- Agent 也可提交单个或多个申请：

  ```text
  "C:\Program Files\Codex Guard\CodexGuard.exe" --request-delete "D:\Projects\MineruFlow\temp.bin"
  ```

- 策略迁移：导出 `.codexguard.json`；它只包含已激活项目路径，不导出管理员资料保护、默认只读边界、密码、登录令牌、本机 SID 或原始 ACL。具体见 [迁移指南](docs/MIGRATION.md)。
- 快速核查：应用内“导出人工核查包”提供带结论的证据；`CodexGuard.ReadOnlyVerifier.exe` 独立读取原始事实；`CodexGuard.AcceptanceProbe.exe` 仅在随机测试目录内做黑盒验收。
- 启动 Codex：登录 `CodexWorker` 自己的 Windows 桌面，从官方 ChatGPT/Codex 图标启动。Codex Guard 不再从 admin 桌面跨用户激活打包应用，也不提供内部 `codex.exe` 或 WindowsApps 绕过。
- 本地记录：未来任务只写 `C:\Users\CodexWorker\.codex`；`admin` 的既有记录保持原样，不自动复制或合并。绝不复制 `auth.json`、SQLite、JSONL，也不建立 `.codex` 联接。
- 软件映射：打开“软件映射”页执行只读扫描，点击“勾选全部可映射”后可通过一次 UAC 批量创建公共开始菜单 `.lnk`。Program Files 以及父路径直至盘根均通过 ACL 核验的固定 NTFS 共享 EXE 均可纳入；WindowsApps、用户资料、未知主 EXE 和不安全 ACL 显示为技术阻断。详见 [软件映射说明](docs/SOFTWARE_MAPPING.md)。
- 离线复用：打开“离线复用”页区分直接复用、本地安装介质、Store 注册和 AppData 程序。只有 `admin\AppData\Local\Programs` 下的单一程序目录可以经 UAC 只复制到 Worker 的 `Local\Programs`；目标必须不存在，不迁移注册表、不执行安装器、不覆盖或删除。详见 [离线复用说明](docs/OFFLINE_REUSE.md)。

## 重要限制

- **禁止删除不等于禁止覆盖。** 已激活目录允许覆盖、截断和改写文件内容。Codex Guard 不能替代离线备份、版本控制和卷快照。
- `AppData`、`.codex` 和已存在的 `.cache` 是完整的正常写入/清理例外，其中的文件可以被 Worker 删除、覆盖或损坏；它们只用于应用状态、缓存和更新，不能保存项目唯一原件。0.6.7 不允许用户任意添加新的可写例外。
- Worker 资料根使用“不继承、仅当前对象”的根锁，以免破坏 `NTUSER.DAT` 等 Windows 用户配置文件；它会阻止新建顶层对象和删除直接子项，但已有的资料根直属系统文件仍沿用 Windows ACL。不要把项目或唯一文件直接放在 `C:\Users\CodexWorker` 根下。
- “Windows 管理”不是 Codex Guard 的可写承诺。Windows、Program Files、ProgramData 沿用操作系统 DACL；普通 Worker 通常不可写，系统级缓存和更新由 Windows 服务、admin 或 SYSTEM 处理。若某软件要求 Worker 直接写 ProgramData，应停止启用该软件并先单独评估，不能扩大整个盘的允许列表。
- ChatGPT/Codex 是按 Windows 用户和交互式会话注册的打包应用。`runas` 可以运行普通 Win32 辅助程序，但在本机实测中不能可靠地把打包版 ChatGPT/Codex 作为 Worker 显示在 admin 桌面；0.5.3 已移除此路径。
- 日常必须直接登录 `CodexWorker` 桌面。若在 admin 桌面启动 ChatGPT/Codex，它就是 admin 进程，不受 Worker 身份边界保护。
- Codex Guard 不捆绑、不复制官方客户端或 WindowsApps，也不会从 admin 缓存、内部 `codex.exe` 或 `PATH` 回退启动。
- 软件映射不会让两套用户设置完全一致。独立的离线复用功能可以制作受限的 Worker 程序副本，但不复制整个 AppData、HKCU、登录令牌或许可证，不自动执行安装器；Store/MSIX 和复杂用户级安装仍需注册。
- Git、编译器、编辑器的原子保存和清理流程常依赖删除或重命名；严格模式下这些操作会返回“拒绝访问”。需要删除的内容应提交申请，临时缓存应留在 Worker 自己的用户资料或工具自己的沙箱缓存中。
- 默认只读基线只为 `CodexWorker` 和 `CodexSandboxUsers` 写入显式 Deny，不移除 admin/SYSTEM 或其他账户的授权。固定数据盘边界通过可继承 ACE 约束后代；激活项目再以更具体的显式 Allow 恢复写入，但保留显式删除/改 ACL Deny。必须在真实 Worker 与 Sandbox 身份下用可丢弃副本证明该优先级符合预期。
- Windows 管理目录、非固定盘、非 NTFS 卷、网络位置和之后插入但尚未重新应用的磁盘不在默认只读保证内；新增固定盘或未知重解析点会使审计失败关闭。不要把“计划已记录”当作新设备自动受保护。
- “NTFS 权限”页显示的是 Guard 状态边界和 Windows 原始 DACL，不是对任意进程令牌执行完整 `AccessCheck` 后的最终有效权限证明。“Guard 未授予写入”不等于 Windows 已拒绝所有其他来源的写权限；应同时检查原始 Allow/Deny、继承来源，并在可丢弃副本上用真实 Worker/Sandbox 身份验收。
- 激活前会拒绝 UNC、设备路径、ADS、符号链接、联接点、重解析点、硬链接及超过 500,000 个条目的目录。激活后没有常驻内核驱动持续拦截新建链接，因此仍应保留官方沙箱和备份。
- 管理员、内核级恶意软件、具有备份/还原特权的自定义账户以及脱机磁盘访问不在本工具的防护边界内。
- 本预览版未签名，UAC 会显示“未知发布者”。生产部署前应使用组织的 Authenticode 证书签名并重新核对哈希。
- Windows 11 是官方推荐基线；更新到最新补丁的 Windows 10 仅为 best-effort 支持。

第一次使用请从 [完整操作说明书](docs/USER_MANUAL.md) 开始。完整威胁模型与恢复注意事项见 [安全说明](docs/SECURITY.md)、[运行手册](docs/OPERATIONS.md)、[软件映射说明](docs/SOFTWARE_MAPPING.md)、[离线复用说明](docs/OFFLINE_REUSE.md) 和 [本地记录隔离](docs/RECORD_SYNC.md)。

## 从源码构建

要求 Windows 10/11 和 .NET Framework 4.8：

```powershell
powershell -ExecutionPolicy Bypass -File .\Build.ps1 -Configuration Release
.\artifacts\CodexGuard.Tests.exe
```

构建脚本使用系统自带的 .NET Framework C# 编译器，不下载第三方依赖。测试和界面回归说明见 [TESTING.md](docs/TESTING.md)。
