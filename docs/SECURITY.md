# Codex Guard 安全说明

## 防护目标

Codex Guard 假设 `admin` 仍是唯一受信任的管理员，日常桌面应用运行在标准账户 `CodexWorker`，Agent 命令运行在官方 elevated Windows 沙箱的专用低权限账户中。它要降低以下风险：

- PowerShell、Command Prompt、Git Bash、WSL 之间的路径/转义错误把删除目标扩大到父目录或盘根；
- Agent 或宿主进程直接删除、重命名项目和管理员文件；
- Codex 身份通过修改 DACL 或取得所有权解除防护；
- 未经人工核对的目录激活或策略导入。

## 写入的 ACL

对激活目录，Codex Guard 为 `CodexWorker` 与 `CodexSandboxUsers` 添加：

- Allow：`ReadAndExecute | Write | Synchronize`
- Deny：`Delete | DeleteSubdirectoriesAndFiles | ChangePermissions | TakeOwnership`

对固定管理员资料目录 `C:\Users\admin` 和已撤销目录，它移除 Codex 身份的显式写 Allow，添加只读 Allow，并保留相同的 Deny；管理员敏感子目录另设无访问。0.6.1 起不再允许用户建立其他保护根。

默认只读边界使用更窄的主体定向规则：只为记录的 `CodexWorker` SID 和 `CodexSandboxUsers` SID 添加可继承的只读 Allow，以及 `Write | Delete | Delete child | WRITE_DAC | WRITE_OWNER` Deny；不移除 admin、SYSTEM 或其他账户的 Allow。固定 NTFS 数据盘根、Worker 普通顶层目录、Public 资料和系统盘非 Windows 数据目录使用该边界。`C:\` 与 Worker 资料根只添加“不继承、仅当前对象”的根锁，避免把根规则未经审查地传播到 Windows 或允许列表。

admin SID 不属于 Guard Actor。每次解析限制集合后，程序都会把它与 `C:\Users\admin` 在 Windows ProfileList 中登记的 SID 比较，并核对 admin 不属于 `CodexSandboxUsers`；无法解析、发生 SID 碰撞或发现组成员关系时，操作失败关闭。预览和 UAC 确认会明确显示这一边界。“Guard 不限制 admin”表示 Codex Guard 不为 admin SID 写只读或拒绝 ACE；admin 的最终有效权限仍由 Windows 登录令牌、组成员、所有者和原始 DACL 决定。

写入允许列表固定为 Worker 的 `AppData`、`.codex` 和已经存在的 `.cache`。默认只读操作不会创建这些目录，也不允许请求者追加自定义例外；`AppData` 与 `.codex` 不存在会阻断整次操作。它们保留原 Windows 写入和删除权限，因此只能存放应用资料、缓存和用户级更新，不能存放唯一项目原件。Windows、Program Files、ProgramData 由 Windows 原生 DACL 管理，系统级更新使用 admin/SYSTEM/服务身份，不被 Worker 专属 Deny 影响。

激活目录位于默认只读边界的严格后代时，激活目录上的显式 Write Allow 比祖先继承的默认写入 Deny 更具体；显式 Delete/WRITE_DAC/WRITE_OWNER Deny仍保留。该 Windows ACE 优先级必须在目标机器上分别用真实 Worker 与 Sandbox 令牌做黑盒验收，不能只凭静态 DACL 判定。

显式 Deny 同时落在目录及后代对象；默认只读或固定管理员资料边界在父目录拒绝 `DeleteSubdirectoriesAndFiles`，用于覆盖 Windows 重命名/删除时可能使用的两种授权路径。

所有受保护/激活目录同时获得可继承的 `OWNER RIGHTS`（`S-1-3-4`）Allow：`ReadPermissions | Synchronize`。一旦 DACL 中存在该 SID，Windows 不再向对象所有者隐式授予 `READ_CONTROL`/`WRITE_DAC`；所有者只能从普通 ACE 获权。这样新文件即使由 `CodexWorker` 创建并归其所有，也不能绕过 `ChangePermissions` Deny。这里使用窄 Allow 而非 OWNER RIGHTS Deny，因此管理员仍可从 `Administrators` 的独立 Allow 获得管理权限。

## 管理员边界

- 普通进程只生成短时效 `.cgr` 请求文件。
- 权限变更只能由 `C:\Program Files\Codex Guard\CodexGuard.exe` 通过 Windows `runas` 启动。
- UAC 必须启用、在安全桌面显示，并要求标准用户输入管理员凭据。
- 请求文件必须位于请求者固定的 LocalAppData 收件箱，文件所有者、机器名、请求 ID、时间戳和路径都会验证。
- 激活、撤销、默认只读、绑定/修复和策略导入只接受由 `C:\Users\admin` 的 ProfileList 记录解析出的 admin SID；Worker SID、Sandbox 身份和其他账户提交的权限请求全部拒绝。admin 只是控制面请求者，不会因此进入受限 Actor 集合。
- 只有激活、撤销和策略导入等路径型操作可以携带路径，提升端仍会规范化并重新执行边界、重解析点、文件身份和范围检查；默认只读与修复请求不能注入目标路径，提升端必须从受保护状态和本机卷重新生成完整计划。
- 受保护状态文件归 `Administrators` 所有，广泛主体不得拥有写权限；状态机器名和 Worker SID 必须与本机一致。
- 管理员辅助程序再次显示规范化后的最终路径、作用 SID、警告和四位人工确认码。
- 确认窗口打开期间如果状态或安全策略改变，或 Codex/终端/Git/WSL 重新启动，操作失败关闭。
- 每次 ACL 事务先保存 SDDL；任一步失败会逆序回滚。回滚失败会明确要求停止 Codex 并进行人工审计。

## 路径防护

激活路径必须是存在的本地 NTFS 盘符绝对路径，并且是已应用默认只读边界或固定 `C:\Users\admin` 边界的严格后代。以下内容被拒绝：

- 盘根、相对路径、`D:folder`、UNC、`\\?\` / `\\.\` 设备路径和 ADS；
- Windows、Program Files、ProgramData、回收站、恢复目录、WindowsApps；
- 完整用户资料、AppData 及常见凭据目录；
- 任一祖先或后代中的符号链接、目录联接和重解析点；
- 链接数大于 1 的硬链接文件；
- 超过 500,000 个条目或无法完整扫描的目录；
- 与其他已激活目录嵌套或重复的目录。

目录会记录卷序列号和 NTFS 文件 ID，并在特权操作前后复核，降低路径被替换的 TOCTOU 风险。

默认只读计划不接受请求携带的路径。提升后的安装副本从受保护状态中的 Worker SID/资料路径和当前本机卷重新生成计划；发现必需允许目录缺失、非 NTFS 固定盘、不可枚举路径或未知重解析点时整次失败关闭。非提升 admin 预览若因 Windows DACL 无法读取 Worker 路径，只显示“UAC 核验”，不会把不可见误写成安全；提升端仍按严格模式重新扫描。Windows 兼容联接只按受控名称表识别，0.6.2 补充了 `「开始」菜单` 等本地化名称；其他 Worker 顶层重解析点仍按红色阻断处理。新接入的固定盘或新出现的 Worker 顶层目录不会被静默视为已保护，而会使后续审计报告失败并要求重新预览、UAC 应用和验收。网络位置、可移动盘与非 NTFS 卷不在默认基线范围。

激活项目的完整后代还会在管理员确认前、执行前和应用 ACL 后检查：任何关闭 DACL 继承的后代，或对 Codex Actor、`Everyone`、`Authenticated Users`、`Users`、`OWNER RIGHTS` 显式授予 Delete/Delete-child/WRITE_DAC/WRITE_OWNER 的后代都会使激活失败。Codex Guard 不会擅自递归“修好”这种历史 ACL，因为那可能破坏项目原有授权；应由管理员在副本上逐项处理。

## 删除申请

删除申请是低权限、不可自动执行的 JSON 记录。它只能引用当前激活项目内存在的目标。申请内容应被视为不受信任输入；`admin` 必须再次核对当前真实路径。Codex Guard 没有处理申请、移动目标或删除目标的功能。

## 软件映射边界

“软件映射”是只读清单加受控快捷方式创建器，不是安装器。扫描器只读取计算机/用户卸载注册表以及公共、admin 开始菜单和桌面的 `.lnk` 元数据；它不读取应用数据，不调用卸载字符串，也不启动发现的 EXE。

自动创建快捷方式只接受本地绝对 `.exe`。Program Files 目标从相应 Program Files 根核查；其他位置必须位于本机固定 NTFS 卷，并从目标父目录一直核查到盘根。WindowsApps、Windows、ProgramData、临时目录、所有已注册用户资料、卷系统目录、重解析点、多硬链接 EXE、安装器、卸载器、更新器以及包含启动参数的入口均被排除。目标文件和全部受检父目录不能向 `CodexWorker`、Worker 所属本地组、`CodexSandboxUsers`、`Users`、`Authenticated Users`、交互式/本地令牌或 `Everyone` 授予写类权限。

普通进程只生成短时效 `.cgs` 申请。提升后的受保护安装副本会重新扫描清单、核对申请文件所有者/机器/时效/请求者 SID，并在四位人工确认后再次检查受保护状态和 EXE 边界。输出只能是管理员控制的公共开始菜单子目录中的无参数 `.lnk`；不会复制、安装、移动或删除程序文件。Store/MSIX 与 admin 专属软件只显示人工建议。

## 离线复用边界

“离线复用”与软件映射分离。它只对 `admin\AppData\Local\Programs` 下一个顶层应用目录提供程序主体复制，固定目标为记录 SID 对应的 `CodexWorker\AppData\Local\Programs`。申请使用短时效 `.cgr`，并核对文件所有者、机器、请求者 SID、状态时间、清单 ID、名称、发布者、源根和相对主 EXE。

提升阶段会拒绝源祖先/后代重解析点、多硬链接、目标已存在、Worker ProfileList 不一致、磁盘余量不足和批量上限超出。源文件以拒绝并发写入的只读句柄打开；目标目录与文件使用 CreateNew。复制期间目标先保持 Administrators/SYSTEM 控制，完整成功后才授予 Worker 修改权限和 Sandbox 只读执行权限，并创建 Worker 专属快捷方式。

离线复用不执行安装器、不复制 WindowsApps、不导入注册表、不读取或迁移令牌/许可证，也不调用移动、覆盖或删除 API。失败不自动回滚或清理，部分目标保持管理员控制并写入 `OfflineReuse` 审计清单。这是为了避免异常处理中的递归删除再次扩大路径范围。

程序副本不等于完整用户安装。HKCU、COM、服务、驱动、MSIX 注册和许可证仍需厂商支持的步骤。Docker/Podman 等宿主控制软件不会被当作普通直接复用对象；向 Worker 授予守护进程控制组可能绕过文件边界。

## ChatGPT/Codex 交互式桌面边界

ChatGPT/Codex 是按 Windows 用户和交互式会话注册的打包应用。本机实测证明：从 admin 桌面先以 `runas` 启动 Worker 辅助进程，再通过包接口激活 ChatGPT/Codex，Windows 仍可能把最终应用创建为当前交互式桌面的 admin 进程。因此这条路径不能作为安全身份边界。

0.5.3 已删除对应的 MSIX 激活服务和主界面按钮，不再创建 `Codex (CodexWorker)` 快捷方式。旧命令行开关只保留一个“功能已移除”提示，不启动任何 ChatGPT/Codex 进程。安装/修复仅在快捷方式目标和参数都精确匹配旧入口时报告路径，不会自动删除或移动；由 admin 人工处理。

完整桌面端必须在 `CodexWorker` 自己的 Windows 交互式桌面运行。admin 仅用于 UAC 管理辅助、人工删除和恢复。普通 Win32 辅助程序可使用备用身份运行这一事实，不代表打包版 ChatGPT/Codex 可以安全跨用户显示。

## Codex 本地记录边界

本方案不假设云端工作区或账户记录同步。`CodexWorker` 的 `%USERPROFILE%\.codex` 是未来任务的唯一写入源；`admin` 既有 `.codex` 保留为旧档，不自动导入、复制、合并或覆盖。两套资料必须保持为普通、互不联接的本地目录；`auth.json`、SQLite/WAL、会话 JSONL、插件、缓存和沙箱秘密永不共享。

“安全审计”中的本地记录路径检查只读取文件系统元数据，不打开 `auth.json`，不读取对话正文，也不修改任何 Codex 文件。静态检查不能证明 Worker 桌面中的最终 GUI 进程身份，因此任务管理器用户名和两个 `.codex` 的修改时间仍是人工验收项。

## 只读 NTFS 权限表征

0.5.4 的“NTFS 权限”页把两类事实并排展示：一类是根据受保护状态文件和路径边界得到的 Guard 分类与预期授予；另一类是由 Windows 读取的目录 Owner、继承状态和原始 DACL。读取过程不调用 `SetAccessControl`，也不创建、移动、重命名或删除任何文件。

该页故意不把“Guard 未授予”写成“Windows 最终拒绝”。Windows 最终有效权限还可能来自嵌套组、继承 ACE、特权、已打开句柄和运行令牌；页面会突出常见宽泛主体的潜在写入/删除 Allow，但不是完整的 `AccessCheck` 或真实令牌黑盒证明。保护范围外路径会明确标为未受管理；重要目录只有加入保护边界并完成真实 Worker/Sandbox 验收后才能视为受本方案保护。

0.6.2 会显示“admin 不限制”“管理员资料保护”“默认只读”“仅锁根目录”“允许写/清理”和“Windows 管理”分类。“允许写/清理”明确意味着可以删除；“Windows 管理”只说明 Guard 不重写系统树，不代表任意 Worker 进程拥有写权限。

## 明确不提供的保证

- 激活目录内允许覆盖和截断，内容仍可能损坏或被勒索软件加密。
- NTFS ACL 不是版本历史；必须保留独立、离线或不可变备份。
- 默认只读使用祖先上的可继承、主体定向 Deny，但不会递归规范化每个后代目录的所有自定义 ACL。关闭继承、先前已打开的句柄、未知重解析点和异常显式 ACL 都可能改变结果；官方沙箱、静态审计与真实令牌黑盒验收仍必须同时存在。
- Windows、Program Files、ProgramData 以及非固定/非 NTFS/网络位置不由默认基线重写；它们的最终权限仍由 Windows 原生 DACL 和服务身份决定。
- 已经打开且预先获得 DELETE/WRITE 访问的句柄可能继续有效，因此每次安装和权限变更都要求先关闭相关进程。
- 激活后新建的重解析点或硬链接不是由常驻驱动实时监控的；标准账户 ACL、官方沙箱和安全审计仍必须同时存在。
- Windows 允许创建者为新对象提供安全描述符；不同系统/令牌是否接受 `SE_DACL_PROTECTED` 的自定义 DACL 必须由验收探针实测。若该高级测试成功，ACL-only 模型只可视为防误操作，不能视为抗刻意绕过；需要文件系统微型筛选驱动、隔离虚拟机或不可变存储等更强边界。
- 管理员、SYSTEM、内核驱动、具有 `SeBackupPrivilege`/`SeRestorePrivilege` 的自定义主体、磁盘脱机挂载、固件和物理攻击不在范围内。
- 云端或企业管理的更高优先级 requirements 层可能覆盖本地设置；本工具只能审计本机文件和可见状态。
- 本工具不提供本地 Codex 数据库合并器，也不承诺导入恢复软件找回的 SQLite/JSONL。既有 admin 记录与未来 Worker 记录不会自动合并。
- 备用身份运行普通 Win32 程序不能替代真实的 Worker 交互式登录，也不能作为打包版 ChatGPT/Codex 的身份边界。
- 本预览二进制未进行 Authenticode 签名。不要把“未知发布者”提示当成正式生产发布的正常终态。

## 密码处理

管理员密码只输入 Windows UAC 安全桌面，由 Windows 处理。Codex Guard 不接收、不记录、不导出该密码。新建 `CodexWorker` 时输入的 Worker 密码只在提升后的安装窗口内短暂传给 Windows `NetUserAdd`，随后清空引用和输入框，不写磁盘。日常直接登录 Worker 桌面时，Worker 密码由 Windows 登录界面处理，Codex Guard 不读取或保存它。

## 当前验证状态

开发阶段没有创建真实用户、修改注册表、复制真实 AppData 程序或应用真实目录 ACL。已经完成纯逻辑测试、NTFS 路径分类与只读源码禁用清单、受限临时目录源盘点测试、内存 DACL 规则往返测试、Debug/Release 编译和 WinForms 渲染检查。发布包同时提供独立只读核查器和限定随机测试对象的验收探针；首次实际 ACL 与离线复用验证应在快照可回滚的虚拟机上进行，详见 [TESTING.md](TESTING.md) 与 [MANUAL_REVIEW.md](MANUAL_REVIEW.md)。
