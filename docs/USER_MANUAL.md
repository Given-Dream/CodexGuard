# Codex Guard 操作说明书

适用版本：`0.6.7-preview`  
适用系统：Windows 10/11，NTFS 本地磁盘  
目标：日常登录低权限账户 `CodexWorker` 运行 Codex、Agent 命令和集成终端；所有 NTFS 权限管理由 `admin` 控制面提交并经 UAC 复核，人工删除和恢复也只由 admin 处理。共同工作目录允许读取、写入和新建，同时拒绝删除、重命名和修改权限。

> 本说明书以图形界面操作为主，不要求使用 PowerShell、Command Prompt、Git Bash 或 WSL。Codex Guard 不执行删除命令，也不会自动处理删除申请。

## 1. 先理解四个身份和位置

| 身份或位置 | 用途 | 主要权限 |
|---|---|---|
| `admin` | 唯一受信任管理员；处理 UAC、人工删除和紧急恢复 | 保留完整管理员权限 |
| `CodexWorker` | 运行 Codex 桌面应用和集成终端 | 标准用户；不得属于管理员、备份操作员等特权组 |
| `CodexSandboxUsers` | OpenAI 官方 Windows `elevated` 沙箱使用的低权限账户组 | Agent 命令的额外沙箱边界；它是组，不是上位用户 |
| 默认只读区域 | 固定数据盘、Worker 普通数据目录和系统盘非 Windows 数据目录 | Worker/Sandbox 可读；拒绝写入、新建、删除、重命名和改 ACL |
| 已激活项目 | admin 与 Worker 共用的真实工作目录 | Worker/Sandbox 可读、可写、可新建；拒绝删除、重命名、改 ACL 和取得所有权 |
| 写入允许列表 | Worker 的 `AppData`、`.codex`、已存在的 `.cache` | 保留正常写入和清理，用于 ChatGPT/Codex、用户缓存和用户级更新；不得保存唯一原件 |

必须同时保留三层防护：

1. Codex 桌面进程使用 `CodexWorker` 身份；
2. Agent 命令使用 OpenAI 官方 `elevated` Windows 沙箱；
3. 项目和 admin 数据使用 Codex Guard 的 NTFS ACL。

OpenAI Docs 将 `elevated` 列为首选的 Windows 原生沙箱；它使用专用低权限沙箱用户、文件系统权限边界、防火墙规则和本地策略。Codex Guard 会把系统要求限制为只允许该模式。

## 2. 安装前红线

安装或修改真实 ACL 前，必须做到：

- 已把重要项目、恢复档案和 `C:\Users\admin\.codex` 备份到独立位置；
- 最好先在可回滚虚拟机或无重要数据测试目录验收；
- 完全退出 Codex/ChatGPT、PowerShell、命令提示符、Windows Terminal、Git、Git GUI 和 WSL；
- 不把唯一原件作为删除、重命名或权限测试对象；
- 不对系统盘根目录 `C:\` 执行保护或递归权限操作；
- 不手工删除 `CodexWorker`、`CodexSandboxUsers` 或 `C:\ProgramData\Codex Guard`；
- 不使用 `icacls /reset`、递归接管或其他整盘权限重置方式。

还应知道两个限制：

- 禁止删除不等于禁止覆盖。已激活项目中的文件仍可被覆盖、截断或写坏，因此备份和版本控制仍不可省略。
- 只有 Worker 的 `AppData`、`.codex` 和已经存在的 `.cache` 保留正常删除临时文件的能力；这些例外不能保存唯一原件。Worker 的 Desktop、Documents、Downloads 等普通目录会进入默认只读计划。
- Worker 资料根只锁当前对象，以保留 `NTUSER.DAT` 等 Windows 用户配置文件的原生行为；不要把项目或唯一文件直接放在 `C:\Users\CodexWorker` 根下。
- Windows、Program Files、ProgramData 沿用 Windows 原生 ACL，不由默认基线重写；系统级缓存和更新应由 Windows 服务、admin 或 SYSTEM 完成。某软件若要求 Worker 直接写 ProgramData，必须先单独评估，不能为此开放整个盘。

## 3. 首次安装

### 3.1 准备发布包

1. 将 `CodexGuard-0.6.7-preview-*.zip` 保存到非系统盘，例如 `D:\codex\CodexGuard\release`。
2. 核对发布时给出的 ZIP SHA-256。
3. 解压到一个固定目录，不要只在压缩软件预览窗口里运行。
4. 确认以下文件位于同一目录：
   - `CodexGuard.exe`
   - `CodexGuard.ReadOnlyVerifier.exe`
   - `CodexGuard.AcceptanceProbe.exe`
   - `SHA256SUMS.txt`
   - `README.md`
   - `docs` 文件夹

当前预览版未使用 Codex Guard 自己的 Authenticode 证书，UAC 可能显示“未知发布者”。只有在发布包来源和 SHA-256 都核对无误后才继续。

### 3.2 创建 Worker 并安装

1. 登录 `admin`。
2. 完全关闭 Codex 和所有终端/Git/WSL 进程。
3. 双击解压目录中的 `CodexGuard.exe`。
4. 打开“迁移与部署”页，点击“安装 / 修复 Codex Guard”。
5. Windows UAC 出现在安全桌面时，确认目标为 Codex Guard，再输入 admin 凭据。
6. 在“Codex Guard — 安装与修复”窗口核对：
   - Worker 账户为 `<本机名>\CodexWorker`；
   - 新建 Worker 时输入至少 12 个字符的独立密码并再次确认；
   - “移除 CodexWorker 的特权组成员资格”为强制选中；
   - “应用 UAC 安全桌面策略”为强制项；
   - “只允许 elevated 沙箱”为强制项；
   - 管理员资料保护固定为 `C:\Users\admin`，不可在常规界面改成其他目录；
   - `C:\Users\admin` 对 Codex 身份只读，敏感目录无访问。
7. 点击“创建并安装”或“安装 / 修复”。
8. 在最终确认窗口再次核对账户名、Program Files 安装位置和 admin 资料路径，然后选择继续。
9. 保存结果窗口内容。若提示需要重新启动 Windows，应执行“重新启动”，不要只关机再开机。

安装会建立：

- `C:\Program Files\Codex Guard\CodexGuard.exe`
- `C:\ProgramData\Codex Guard\state.json`
- 公共桌面的 `Codex Guard` 快捷方式

0.5.3 不再创建 `Codex (CodexWorker)`。从 0.5.2 修复升级时，程序只读核对它是否精确匹配 Codex Guard 旧入口并报告路径；不会自动删除或移动。请由 admin 人工移到待删除目录或删除。

## 4. 切换到日常 Worker 桌面

1. 从 Windows 开始菜单切换用户，登录 `CodexWorker`。
2. 启动官方 ChatGPT 桌面应用，在 Worker 身份下完成登录并选择 Codex；Windows 会为 Worker 注册现有 `OpenAI.Codex` 程序主体，不要复制 WindowsApps。
3. 让官方 Windows 沙箱完成初始化；应选择或保留 `elevated` 模式。
4. 确认 Codex 能正常打开后，为首次权限绑定暂时完全退出 Codex 和所有终端。
5. 保持登录在 `CodexWorker`；以后日常都从这个 Windows 桌面运行 ChatGPT/Codex。

这一步让 Worker 获得官方 ChatGPT/Codex 应用包注册、独立应用资料和官方沙箱账户。Codex Guard 不复制 admin 的 WindowsApps、内部 EXE、登录令牌或 `.codex` 数据。不要从 admin 桌面尝试跨用户启动打包版 ChatGPT/Codex。

## 5. 首次绑定与权限验收

### 5.1 从 admin 桌面打开权限控制面

1. 切换到 `admin` 桌面，普通双击公共的“Codex Guard”快捷方式；不要右键“以管理员身份运行”。
2. 窗口右上角应显示当前身份为 `admin`，并注明“可管理 CodexWorker 权限”。
3. Worker 桌面仍可打开 Codex Guard 查看状态，但添加、激活、撤销、默认只读、绑定/修复和策略导入按钮必须为灰色；后台也会按请求 SID 拒绝绕过。

非提升 admin 是唯一 NTFS 权限管理请求来源。若右键“以管理员身份运行”，全部权限管理按钮会禁用，因为这会绕过预期的 UAC 再确认入口；请关闭后按普通方式重新启动。

### 5.2 绑定官方沙箱账户

1. 在 Codex Guard 中打开“安全审计”。
2. 点击“UAC 绑定 / 修复全部权限”。
3. UAC 安全桌面出现后，输入 admin 凭据。
4. 返回审计页点击“重新审计”。
5. `CodexWorker` SID 和 `CodexSandboxUsers` SID 必须与受保护状态一致；Worker 不得属于任何特权组。

### 5.3 预览并应用默认只读基线

0.6.1 起不再提供手工保护根。0.6.2 会把本地化的 Windows `「开始」菜单` 兼容联接识别为“Windows 管理”，并单列“admin 不限制”。0.6.7 只允许安装时登记的非提升 admin 提交权限请求；程序先生成一份**只读计划**，UAC 提升端再独立重新生成同一计划，请求者不能把任意路径塞进申请。最终确认后，提升端会显示不定进度条、当前阶段/路径和已用时间。

1. 打开“默认只读”。
2. 逐行核对以下类型：
   - “允许写/清理”：只应是 Worker 的 `AppData`、`.codex` 和已存在的 `.cache`；
   - “默认只读”：所有固定 NTFS 数据盘、Worker 的普通顶层目录、Public 资料和系统盘非 Windows 顶层目录；
   - “仅锁根目录”：`C:\` 和 `C:\Users\CodexWorker` 只锁当前对象，不把该规则继承进 Windows 或允许列表；
   - “Windows 管理”：Windows、Program Files、ProgramData 沿用操作系统 DACL，系统级更新由 admin/SYSTEM 完成。
   - “admin 不限制”：限制集合只有 Worker/Sandbox；admin SID 不应出现在任何 Guard 只读或拒绝规则中。
3. 有红色“阻断”时不要继续。常见原因是 Worker 尚未初始化 `AppData`/`.codex`、固定盘不是 NTFS、路径不可读，或发现未知重解析点。
   - 在 admin 会话看到黄色“UAC 核验”不是通过结论，只表示当前非提升令牌不可见；可以提交 UAC，由提升端重新核验，真实缺失或不可读仍会停止。
4. 先确认独立备份、关闭 Codex/终端/Git/WSL，再点击“UAC 应用默认只读”。
5. 在 Windows 安全桌面输入 admin 凭据；管理员确认页必须再次显示规范路径、Worker/Sandbox SID、根锁和允许列表。
6. 重新输入管理员确认页显示的四位码，点击“确认执行”；按钮会显式记录接受状态。
7. 最终确认后保持进度窗口开启。它会显示当前 NTFS 边界和已用时间；Windows 不提供可靠传播百分比，因此滚动条只代表程序仍在工作。普通关闭在事务期间被禁用，也不要用任务管理器强制结束、关机或重启。
8. 必须等待“操作成功”结果窗口。若只返回主界面、显示取消或没有成功窗口，一律视为未应用。
9. 应用后打开“安全审计”。默认只读边界、根锁或新增固定盘只要有一项不一致，都按失败处理。

这一步不会给 admin 或 SYSTEM 添加 Deny，也不允许 Worker/admin 自定义写入例外。它只约束记录的 Worker SID 与 `CodexSandboxUsers` SID。admin 是唯一权限管理请求来源，但不是受限 Actor。以后新增磁盘、Worker 顶层目录或未知联接点时，审计会失败关闭，需重新预览和 UAC 应用。

### 5.4 固定管理员资料保护

安装/修复只维护 `C:\Users\admin` 这一项管理员资料边界；常规界面没有“添加保护根”。其他盘和目录是否允许激活，完全由本机“默认只读”计划决定。旧版状态若还包含额外手工保护根，安全审计会标红；它们不会参与新激活或自动修复，必须由 admin 根据原始 SDDL 单独核查。

### 5.5 激活测试项目

首次只用无重要数据目录，例如：

```text
D:\CodexGuard-Acceptance\Active
```

1. 点击“添加目录”，将测试项目加入“待追加激活”。
2. 可一次添加多个互不嵌套的目录。
3. 点击“UAC 追加激活”。
4. 在安全桌面输入 admin 凭据。
5. 在管理员确认窗口逐项核对：
   - 当前机器；
   - 请求者 SID；
   - Worker 和 Sandbox 作用 SID；
   - 最终规范路径；
   - 目录位于已应用默认只读边界或固定 `C:\Users\admin` 边界的严格子路径中。
6. 输入四位确认码并应用。

激活采用累加模式。以后激活新项目不会自动撤销旧项目。

### 5.6 用“NTFS 权限”页核查任意目录

该页只读取状态和 ACL，不会添加、删除、重排或继承任何 ACE。

1. 打开“NTFS 权限”。
2. 选择目录，或在路径框中输入本地绝对路径，再点击“只读核查”。
3. 先看顶部分类：
   - “已激活”：Guard 允许读取、写入和新建，继续拒绝删除、重命名、改 ACL 和取得所有权；
   - “默认只读”或“管理员资料保护”：Guard 只授予读取，并拒绝写入、新建、删除、重命名和权限接管；
   - “允许列表”：AppData、.codex 或既有 .cache 保留正常写入/清理，里面的内容可以被覆盖或删除；
   - “管理员敏感目录”：Guard 预期无访问；
   - “Worker 用户资料”“系统/应用目录”或“未受管理”：该路径不由 Guard 工作目录规则兜底，Windows ACL 可能允许写入或删除。
4. 再看“Guard 策略表征”。这里表达 Guard 对 Worker、Sandbox 和 admin 的授予/拒绝；“Guard 未授予”不能单独证明 Windows 最终拒绝。
5. 最后看“Windows 原始 DACL”。重点核对 Allow/Deny、显式/继承、作用范围，以及 Worker、Sandbox、Users、Authenticated Users、Everyone 是否存在潜在写入或删除 Allow。
6. 对已激活目录、默认只读目录和写入允许列表各核查一次。出现“未受管理”的重要目录时，不能交给 Codex 保存数据；先由 admin 确认其为何未进入基线。

页面不是完整的 Windows 有效访问模拟器，不能替代“安全审计”、独立核查器和真实身份黑盒验收。

### 5.7 三类验收证据

1. 应用内“安全审计”：不能有红色“失败”；黄色“人工”不是自动通过。
2. 双击发布包中的 `CodexGuard.ReadOnlyVerifier.exe`：交叉核对 SID、UAC、哈希、路径和原始 SDDL。
3. 只在可丢弃测试目录运行 `CodexGuard.AcceptanceProbe.exe`：
   - 读取、新建、写入、原位覆盖应成功；
   - 写回 DACL、重命名、删除文件、删除目录应被拒绝；
   - 默认只读或非激活保护区的新建应被拒绝。

探针残留由 admin 使用资源管理器人工处理。不要对真实项目运行首次黑盒测试。

## 6. 日常在 CodexWorker 桌面运行 Codex

1. 登录 `CodexWorker` 的 Windows 桌面。
2. 从官方 ChatGPT/Codex 图标启动应用。
3. 从该桌面选择工作目录、使用 Agent 和集成终端。
4. 需要激活目录或执行其他管理动作时，由 Codex Guard 触发 Windows UAC 安全桌面；只在这里输入 admin 凭据。

不要在 admin 桌面运行日常 Codex。0.5.3 已移除跨用户桌面启动按钮和包激活服务；旧命令行开关只显示停用提示。安装/修复只读报告精确匹配的旧快捷方式，由 admin 人工处理。

### 6.1 人工确认真实身份

首次启动、升级 Codex、升级 Windows 或修复权限后，都执行：

1. 打开任务管理器。
2. 进入“详细信息”。
3. 右键表头，选择“选择列”。
4. 勾选“用户名”。
5. 确认 ChatGPT、Codex 和 `codex.exe` 均显示 `<本机名>\CodexWorker`，并属于当前 Worker 交互式会话。

如果显示 `admin`：立即退出该 Codex，不要打开项目、Agent 或集成终端；切换到 `CodexWorker` 的 Windows 桌面再启动官方应用。

### 6.2 让 Worker 使用已有系统级软件

1. 使用 admin 或 `CodexWorker` 打开 Codex Guard，进入“软件映射”。
2. 点击“重新扫描”。扫描只读取卸载注册表和开始菜单 `.lnk` 元数据，不启动任何软件。
3. 人工查看四类结论：
   - “直接共用”：公共快捷方式和安全的系统级 EXE 已存在；
   - “创建快捷方式”：EXE 位于 Program Files，或位于父路径直至盘根均通过 ACL 核验的本机固定 NTFS 位置；
   - “现有包需注册”：Store/MSIX 应用必须为 Worker 建立用户注册，但不代表重新下载程序主体；
   - “技术阻断”：只存在于 admin 资料、主 EXE 缺失、带启动参数或目标/父路径可被低权限写入。
4. 点击“勾选全部可映射”，然后点击“UAC 创建勾选快捷方式”。技术阻断项不会被勾选。
5. 在安全桌面输入 admin 凭据；再次核对软件名、发布者和完整 EXE 路径，再输入四位码。
6. 快捷方式保存到公共开始菜单的 `Codex Guard - Shared Software` 文件夹；重新登录 Worker 后也可见。
7. 首次启动软件时，仍可能需要为 Worker 单独登录、接受许可证或生成配置。这不代表重新下载了程序主体。

“软件映射”绝不把 `C:\Users\admin\AppData\Local\Programs` 直接开放给 Worker，也不复制 `WindowsApps`、注册表用户配置或许可证秘密。快捷方式不能绕过 NTFS 拒绝或 MSIX 用户注册。完整规则见 `docs/SOFTWARE_MAPPING.md`。

### 6.3 最大限度复用本地程序和安装介质

1. 在 admin 会话打开 Codex Guard，进入“离线复用”；普通沙箱身份看不到 admin AppData，盘点可能不完整。
2. 点击“重新盘点”，先导出“模拟迁移 CSV”。清单会区分直接复用、AppData 可提取、本地介质可用、现有包注册、权限/路径核查和载荷待定位。
3. “直接复用”项目回到“软件映射”处理；“本地介质可用”项目保存其 E/F/D 盘或系统缓存路径，只有直接启动失败时才人工离线修复。
4. 只有 `admin\AppData\Local\Programs\<单一应用>` 项可以勾选自动复制。完全关闭 Codex、终端、Git 和 WSL后，点击“UAC 准备 Worker 本地副本”。
5. 在确认窗口逐项核对只读源、固定 Worker 目标、文件数和大小；目标必须不存在。勾选边界声明并重新输入四位码。
6. 复制使用 CreateNew，不覆盖、不合并、不移动、不删除；不执行安装器，不迁移整个 AppData、HKCU、令牌或许可证。
7. 完成后以 CodexWorker 首次运行软件。若程序依赖注册表，优先用清单中的本地安装源完成厂商支持的离线注册/修复，而不是下载。
8. 失败不会自动清理，部分副本保持管理员控制并记录在 `C:\ProgramData\Codex Guard\OfflineReuse`，由 admin 人工核查。

不要为 Docker Desktop/Podman Desktop 自动授予 Worker 宿主控制组权限；这可能绕过 NTFS 边界。完整规则见 `docs/OFFLINE_REUSE.md`。

## 7. 日常项目操作

### 7.1 已激活项目

CodexWorker 和 Sandbox 可以：

- 读取文件；
- 新建文件和目录；
- 写入、覆盖、截断现有文件。

它们应被拒绝：

- 删除文件或目录；
- 重命名或移动文件/目录；
- 修改 DACL；
- 取得所有权；
- 从父目录删除整个项目。

因此 Git checkout、clean、reset、分支切换、自动格式化器、编辑器原子保存和构建清理可能返回“拒绝访问”。这不一定是故障：这些操作常依赖删除或重命名。先保存工作，再由 admin 判断是否需要人工处理。

### 7.2 激活新项目

1. 由 admin 先建立真实项目目录；默认只读应用后，Worker 不能在未激活区域自行建立项目根。
2. 保存工作并完全退出 Codex、终端、Git 和 WSL。
3. 切换到 `admin` 桌面，以普通方式打开“Codex Guard”。
4. 确认项目是某个已应用默认只读边界或固定 `C:\Users\admin` 边界的**严格后代**；边界外路径不能激活。
5. 添加一个或多个互不嵌套项目并点击“UAC 追加激活”。
6. 在 UAC 安全桌面确认提升，并核对最终路径和四位码。
7. 返回“NTFS 权限”和“安全审计”复核，再在可丢弃副本上验证写入成功、删除拒绝。

### 7.3 撤销写权限

1. 完全退出 Codex、终端、Git 和 WSL。
2. 以非提升 admin 身份打开 Codex Guard。
3. 在“已永久激活的目录”中选中项目。
4. 点击“人工撤销选中”。
5. 通过 UAC 并核对路径。

撤销不会删除文件，也不会恢复未知历史 ACL；它会移除 Worker/Sandbox 写入权限并继续拒绝删除、重命名和改权限。

## 8. 删除申请和 admin 人工处理

Codex、Worker 和 Codex Guard 都不得自动删除项目内容。

### 8.1 提交申请

1. 以 Worker 身份打开 Codex Guard。
2. 打开“迁移与部署”。
3. 点击“提交删除申请”。
4. 选择当前已激活项目内的真实目标，填写原因。
5. 申请保存到：

```text
C:\ProgramData\Codex Guard\DeleteRequests
```

申请只是待核查 JSON，不是自动执行队列。

### 8.2 admin 处理

1. 完全退出 Codex、终端、Git 和 WSL。
2. 用 admin 打开删除申请目录。
3. 核对机器、请求账户、SID、时间、原因和每个目标的当前真实路径。
4. 用资源管理器把批准的目标移动到专用人工复核目录，例如：

```text
D:\CodexDeleteReview\2026-08-16
```

5. 保留一段观察时间；确认项目仍可正常使用后，再由 admin 人工决定最终删除。

不要根据 JSON 自动生成或执行删除命令；路径可能已经变化，申请内容本身也应视为不受信任输入。

## 9. 本地记录规则

- 未来 Codex 任务只由 Worker 版 Codex 创建和继续。
- Worker 记录写入 `C:\Users\CodexWorker\.codex`。
- admin 原有记录保留在 `C:\Users\admin\.codex`，作为旧档。
- 两套记录不自动复制、导入、合并或覆盖。
- 禁止复制或联接 `auth.json`、JSONL、SQLite、WAL/SHM、插件、缓存和沙箱秘密。
- 恢复软件找回的本地记录只保留为只读取证副本，不写回正在使用的 `.codex`。

核查方法：创建一条无敏感信息的 Worker 测试任务；Worker `.codex` 修改时间应更新，admin `.codex` 不应更新。

## 10. 日常三分钟核查

每次安装、修复、目录激活、Windows/Codex 大版本更新后：

1. 确认任务管理器中的 Codex/codex 用户名为 `CodexWorker`。
2. 以 Worker 身份打开 Codex Guard。
3. “默认只读”→“重新只读预览”：不能出现红色阻断；新增固定盘、Worker 顶层目录或未知重解析点必须先处理。
4. “NTFS 权限”→依次核查当前项目、一个默认只读位置和一个允许列表目录；三种分类都应与实际用途一致。
5. “安全审计”→“重新审计”：红色项目必须为零；本地记录路径隔离已经包含在这里。
6. “软件映射”→“重新扫描”：抽查所有已映射项目仍指向 Program Files 中的真实 EXE。
7. 点击“导出人工核查包”，保存 HTML/JSON；软件清单可另行导出 CSV。
8. 运行独立只读核查器，比较 SID、哈希、路径、UAC 和 SDDL。
9. 抽查 Worker `.codex` 更新、admin `.codex` 不更新。

## 11. 常见故障

### 11.1 仍看见旧的 `Codex (CodexWorker)` 快捷方式

- 不要继续使用该入口；
- 用 0.6.7 运行“安装 / 修复”；
- 安装器只会清理目标为受保护安装副本、且参数精确匹配旧开关的快捷方式；
- 如果提示同名快捷方式事实不匹配，先打开属性核查目标和参数，再由 admin 人工处理。

### 11.2 Worker 桌面无法启动官方 ChatGPT/Codex

- 保持登录 `CodexWorker` 桌面；
- 启动并登录官方 ChatGPT 桌面应用，在左上角选择 Codex；
- 不要复制 admin 的 WindowsApps 或内部 `codex.exe`，不要改用 PATH 绕过。

### 11.3 ChatGPT/Codex 进程显示为 admin

- 立即退出该应用，不要继续打开项目、Agent 或终端；
- 确认当前 Windows 交互式桌面属于 `CodexWorker`，而不是只对快捷方式使用了备用身份；
- 在 Worker 桌面重新启动官方 ChatGPT/Codex；
- 重新运行“安全审计”中的本地记录路径隔离核查。

### 11.4 Worker 或 Sandbox SID 不一致

- 立即停止 Codex；
- 不要手工复制旧 SID；
- 用 admin 运行“安装 / 修复”；
- 关闭相关进程后重新执行“UAC 绑定 / 修复全部权限”；
- 重新审计所有激活项目。

### 11.5 `CodexSandboxUsers` 尚不存在

- 登录 Worker，运行一次官方 `elevated` Windows 沙箱初始化；
- 完全退出 Codex 和终端；
- 切回 admin 桌面，普通启动 Codex Guard，再执行 UAC 绑定/修复。

### 11.6 编辑、Git 或构建返回“拒绝访问”

先核对目录分类。默认只读位置连新建和写入都应拒绝；已激活项目允许写入，但依赖删除或重命名的 Git/构建步骤仍会被拒绝。不要给 Worker 临时增加 Delete 权限；提交删除申请，由 admin 用资源管理器人工处理。必要缓存应放在 `AppData`、既有 `.cache` 或软件经过评估的用户缓存中，其中不能存唯一原件。

### 11.7 “默认只读”出现阻断或新磁盘

- 不要绕过页面直接运行权限命令；
- 缺少 `AppData` 或 `.codex` 时，先在 Worker 桌面完成一次官方 ChatGPT/Codex 初始化；
- 非 NTFS、网络或可移动卷不能进入此基线，不在该卷存放 Codex 可接触的重要数据；
- 未知重解析点由 admin 核对真实目标，不能只保护联接的字面路径；
- 新增固定盘后重新预览并 UAC 应用，再运行安全审计和默认只读黑盒探针。

### 11.8 admin `.codex` 修改时间仍在更新

说明可能启动了 admin 版 Codex：

1. 立即退出所有 Codex 窗口；
2. 在任务管理器确认进程全部结束；
3. 切换到 `CodexWorker` 自己的 Windows 桌面，再启动官方 ChatGPT/Codex；
4. 再次核对进程用户名和两个 `.codex` 时间。

### 11.9 `PATH_IDENTITY_CHANGED` 或路径文件 ID 变化

目录可能被删除后重新创建、替换或指向了其他对象。不要直接点击修复来覆盖证据；停止使用，先检查恢复来源、备份、创建时间和项目内容，再由 admin 决定是否重新纳入。

### 11.10 提示旧版只允许 CodexWorker 提交，或标题显示“需安装/修复”

这表示当前打开的便携界面与 `C:\Program Files\Codex Guard\CodexGuard.exe` 不是同一版本。不要继续点击权限操作，也不要手工替换 Program Files 文件：

1. 在当前版本的“迁移与部署”页点击“安装 / 修复 Codex Guard”；
2. 在 UAC 安全桌面确认升级；
3. 完成后关闭当前便携窗口；
4. 从公共桌面的 Codex Guard 快捷方式重新打开；
5. 右上角必须显示“已安装”且版本与发布包一致，才继续应用权限。

0.6.5 起程序会在 UAC 前比较版本；不一致时权限、软件映射和离线复用按钮保持禁用，避免新界面调用旧权限逻辑。

## 12. 紧急恢复

如果真实业务目录被锁住：

1. 完全退出 CodexWorker、Codex、终端、Git 和 WSL。
2. 使用仍可登录的受信任 admin。
3. 先备份项目以及整个 `C:\ProgramData\Codex Guard`；不要删除状态和历史。
4. 打开目标目录“属性 → 安全 → 高级”。
5. 只核对与 `CodexWorker`、`CodexSandboxUsers`、`OWNER RIGHTS` 相关的 Codex Guard ACE。
6. 不对磁盘根或用户资料执行递归 reset/接管。
7. 如需恢复历史 SDDL，应逐目录核对 `History` 后由熟悉 NTFS 的管理员处理。
8. 恢复后重新安装/修复、审计，并在副本上做黑盒验收。

不要通过删除 Worker 或沙箱组来“恢复权限”；那会留下孤立 SID，也无法证明其他 ACL 已恢复正确。

## 13. 一页验收清单

安装完成后逐项打勾：

- [ ] 已有独立备份或快照；
- [ ] `CodexWorker` 是标准用户且不在任何特权组；
- [ ] UAC 使用安全桌面；
- [ ] OpenAI Windows 沙箱为 `elevated`；
- [ ] `CodexSandboxUsers` 已绑定；
- [ ] `C:\Users\admin` 对 Codex 身份只读，敏感区无访问；
- [ ] “默认只读”页无阻断，所有固定 NTFS 数据盘与 Worker 普通数据目录均已列出并应用；
- [ ] 写入允许列表只有 Worker 的 `AppData`、`.codex` 和已存在的 `.cache`；
- [ ] Windows 管理目录的边界已理解：系统级更新由 admin/SYSTEM 完成，不把它误称为 Guard 可写例外；
- [ ] 真实项目是已应用默认只读边界或固定 `C:\Users\admin` 边界的严格子目录；
- [ ] 激活项目允许读取、新建、写入和覆盖；
- [ ] 激活项目拒绝删除、重命名、改 ACL 和取得所有权；
- [ ] 默认只读/非激活区域不能写入或新建；
- [ ] “NTFS 权限”页已分别核查激活、默认只读和允许列表目录，并检查了原始 DACL；
- [ ] ChatGPT/Codex 只在 Worker 桌面运行，进程用户名为 `CodexWorker`；
- [ ] 公共桌面不再存在 Codex Guard 创建的旧 `Codex (CodexWorker)` 入口；
- [ ] Worker `.codex` 更新，admin `.codex` 不更新；
- [ ] 软件映射只产生公共 `.lnk`，没有开放 admin AppData；离线复用只复制经确认的单一 `Local\Programs` 应用且目标原先不存在；
- [ ] 应用审计无红色失败；
- [ ] 独立核查器与应用报告中的 SID、哈希、路径和 SDDL 一致；
- [ ] 黑盒探针只在可丢弃副本上通过；
- [ ] 删除申请只由 admin 使用资源管理器人工处理。

## 14. 参考资料

- [OpenAI Docs：Windows sandbox](https://learn.chatgpt.com/docs/windows/windows-sandbox)
- [Microsoft：IApplicationActivationManager](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iapplicationactivationmanager-activateapplication)
- `README.md`
- `docs/SECURITY.md`
- `docs/MANUAL_REVIEW.md`
- `docs/OPERATIONS.md`
- `docs/RECORD_SYNC.md`
- `docs/SOFTWARE_MAPPING.md`
- `docs/OFFLINE_REUSE.md`
