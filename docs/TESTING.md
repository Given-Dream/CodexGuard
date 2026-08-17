# Codex Guard 测试说明

## 已自动验证

- 拒绝盘根激活、相对路径、盘符相对路径、UNC、系统目录、完整用户资料和凭据目录；
- 拒绝重复或嵌套激活目录；只识别固定 `C:\Users\admin` 管理员资料边界，忽略并审计旧版额外保护根；
- 路径前缀边界与删除申请范围；
- NTFS 权限页对激活、保护未激活、管理员敏感区、Worker 用户资料、系统目录和未受管理路径的纯逻辑分类；
- 默认只读允许列表使用路径边界精确匹配：只接受 Worker 的 `AppData`、`.codex` 和 `.cache` 后代，拒绝 Desktop 以及名称前缀相似的兄弟目录；
- 默认只读计划器源码静态检查为只读，不调用 ACL 写入、创建、移动、删除、进程或注册表修改 API；低权限请求不提供计划路径，提升端必须重新枚举；
- 默认只读 Deny 覆盖 Write/Create/Delete/Delete child/WRITE_DAC/WRITE_OWNER，激活 Allow 包含 Write 但不包含 Delete；根锁 ACE 不继承；
- 新状态字段可往返记录默认只读边界、根锁和允许列表；NTFS 权限页能区分默认只读、根锁和正常清理例外；
- NTFS 核查实现的源码禁用清单：不得调用 ACL 写入、创建、移动、重命名、删除、进程启动或注册表写入 API；
- Active Allow 不包含 Delete，Deny 包含 Delete/Delete child/WRITE_DAC/WRITE_OWNER；
- 可继承 `OWNER RIGHTS` 窄 Allow 存在，以关闭对象所有者的隐式 WRITE_DAC；
- 激活后代拒绝关闭 ACL 继承及显式危险宽泛 Allow，同时允许不含删除/接管权的普通 Write；
- 只读权限不会被错误识别为写权限；
- Windows DACL 规则在内存安全描述符中的往返；
- Windows 命令行参数引号和末尾反斜杠；
- `config.toml` 的 elevated 设置、注释处理及重复表拒绝；
- `requirements.toml` 只接受登录 Shell 禁用、仅 elevated、私有桌面的精确策略；
- 可移植策略不导出 SID；
- 请求 JSON 往返；
- 权限请求身份矩阵：激活、撤销、默认只读、绑定/修复和策略导入只接受登记的 admin SID，拒绝 Worker SID、Sandbox 身份、无登记 admin 和无关账户；受限 Actor 集合仍排除 admin；
- 便携界面与受保护安装辅助程序的版本比较必须精确到修订号；旧版、新版、不同修订和非法版本均拒绝提升，匹配版本才可继续；
- 管理员最终确认按钮自动点击回归：输入正确四位码后按钮启用，点击必须显式设置接受状态和 `DialogResult.OK`；仅窗口结果或仅文本匹配都不足以执行 ACL 事务；
- 提升端 ACL 事务通过后台工作线程执行；静态回归确认使用不定进度条、报告默认只读当前边界，并在事务运行时移除关闭按钮和拒绝普通用户关闭；进度窗口另做离屏渲染核查；
- 所有主要 WinForms 窗口的离屏渲染和可读性，包括受管理与未受管理路径的 NTFS 权限页。
- 独立只读核查器不引用 Core，并由源码禁用清单检查其不包含账户、注册表、ACL、移动或删除 API；
- 验收探针的所有潜在改 ACL/移动/删除目标必须是本次随机 GUID 测试目录的严格后代。
- 本地记录核查只统计元数据，不读取 `auth.json` 或会话正文，不复制/移动数据；相同资料路径会被判为失败；
- admin 桌面 Worker 启动服务、命令行入口和 MSIX 激活实现必须不存在；主界面不得暴露对应按钮；
- 旧 `Codex (CodexWorker)` 快捷方式只在目标精确等于受保护安装副本、且参数精确等于旧开关时标记为旧入口；检测过程不删除或移动快捷方式；
- 本地记录报告明确要求在 Worker 自己的交互式桌面运行 ChatGPT/Codex，不再声称 admin 桌面可以承载 Worker 版界面；
- 软件映射只把重新核验的 Program Files 或安全固定 NTFS 共享 EXE 标为可创建快捷方式；admin AppData、WindowsApps、启动参数、安装器和卸载器均被拒绝自动映射；
- 软件映射名称会移除路径字符，CSV 会中和电子表格公式前缀，映射核心静态检查禁止执行安装器或复制/移动/删除软件；
- 离线复用只接受 admin `AppData\Local\Programs` 下单一顶层应用，拒绝 Roaming 和相邻用户前缀逃逸，目标固定在 Worker `Local\Programs`；
- 离线复用 CSV 中和公式前缀，分类优先利用共享程序和现有安装源，并把 Docker 宿主控制列为人工权限核查；
- 离线复用复制核心静态检查禁止删除、移动、执行安装器和写注册表，强制目标 `FileMode.CreateNew`，源句柄拒绝并发写入；
- 临时普通源目录的有界文件/字节盘点测试；

运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\Build.ps1 -Configuration Debug
.\artifacts\CodexGuard.Tests.exe
.\artifacts\CodexGuard.UiRender.exe
```

界面截图输出到 `artifacts\ui`。

## 尚未在本机执行

- 创建/删除真实 `CodexWorker`；
- 修改 UAC 注册表策略；
- 修改 `%ProgramData%\OpenAI\Codex\requirements.toml`；
- 向 `C:\Users\admin`、盘根或真实项目写 ACL；
- 向固定数据盘、Worker 顶层目录或系统盘根应用默认只读 ACL；
- 在祖先默认写入 Deny 存在时，用真实 Worker/Sandbox 令牌验证激活子目录的显式 Write Allow 仍可写、Delete 仍被拒绝；
- 用真实 `CodexSandboxUsers` 令牌验证有效访问；
- 在 `CodexWorker` 自己的交互式桌面启动官方 ChatGPT/Codex，并核对 GUI/CLI 进程令牌；
- Authenticode 签名与企业分发。
- 真实 admin `Local\Programs` 到 Worker `Local\Programs` 的 UAC 复制、权限、哈希、首次启动和失败残留检查；

## 首次 VM 验收清单

1. 创建系统快照。
2. 用无重要数据的 NTFS 测试根和项目安装。
3. 先在“默认只读”预览中确认允许列表只有 Worker `AppData`、`.codex` 和既有 `.cache`，全部固定 NTFS 数据盘均出现，非 NTFS/未知重解析点会阻断；应用后重新预览和审计。
4. 在 Worker 会话确认添加/激活、撤销、默认只读、绑定/修复和策略导入按钮均禁用，并确认手工构造的 Worker 权限请求也被提升端拒绝。在非提升 admin 会话确认这些权限管理入口可用且都会进入 UAC 安全桌面；右键“以管理员身份运行”时入口应禁用。admin 无法读取的 Worker 路径只能显示“UAC 核验”，提升端若确认目录缺失必须失败关闭。
   另保留一个旧版安装辅助程序，使用新版便携界面打开时必须显示“需安装/修复”，全部提升入口禁用；安装/修复到同版并重新打开后才恢复。
5. 在“NTFS 权限”页分别检查激活、默认只读、允许列表和未受管理路径的分类及原始 DACL，再以 `admin`、`CodexWorker` 和真实沙箱命令账户测试有效权限。
6. 对**副本**测试：默认只读区拒绝新建/写入/删除；激活区允许读取、覆盖、新建，同时拒绝删除、重命名、改 ACL、父目录删除 child；AppData/.codex 测试对象允许正常创建与清理。
7. 测试带空格和非 ASCII 路径。
8. 测试 Codex、PowerShell、Git、WSL 运行时操作被拒绝。
9. 测试取消 UAC、取消四位码、状态并发改变和目录文件 ID 改变。
10. 测试新增一个空固定盘或 Worker 顶层目录后审计失败，重新预览/UAC 应用后才恢复；非 NTFS、网络盘和未知重解析点必须保持阻断/范围外。
11. 测试策略导出、盘符映射、全新 SID 导入。
12. 测试管理员人工恢复后再部署到生产数据。
13. 登录 Worker 桌面启动官方 ChatGPT/Codex，用任务管理器确认进程用户名；测试任务后只允许 Worker `.codex` 更新时间，同时确认两套 `.codex` 未建立联接且安全审计报告不含令牌或正文。再运行 0.6.7 安装/修复，确认它只读报告旧公共桌面 Worker 入口，最后由 admin 人工移动或删除。
14. 在测试机选择一个 Program Files 软件创建公共快捷方式；核对 Worker 可启动、快捷方式无参数、目标和父目录对 Worker 不可写，并确认 admin AppData/WindowsApps 项无法勾选。
15. 选择一个可丢弃的 admin `Local\Programs` 测试应用执行离线复用：确认源哈希/时间不变、目标原先不存在、复制后 Worker 可运行；再准备一个目标冲突与重解析点样本，确认均失败关闭且不清理任何内容。

在完成这一清单前，本构建应视为安全架构预览，而不是已认证的生产防护产品。

日常三分钟核查和无终端路径参数的黑盒探针流程见 [MANUAL_REVIEW.md](MANUAL_REVIEW.md)。
