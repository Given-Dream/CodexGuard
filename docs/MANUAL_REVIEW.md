# Codex Guard 快速人工核查

这套核查刻意分为三种证据。任何一种都不能代替另外两种：

1. **应用内静态审计**：解释预期、实际值和失败原因；
2. **独立原始事实**：`CodexGuard.ReadOnlyVerifier.exe` 不引用 Codex Guard 的权限代码，直接读取 UAC、SID、哈希和 SDDL；
3. **真实身份黑盒验收**：`CodexGuard.AcceptanceProbe.exe` 只对自己刚创建的随机测试对象尝试写入、改 ACL、重命名和删除。

## 日常三分钟核查

每次安装、修复、激活目录、Windows/Codex 大版本更新后执行：

1. 用 `CodexWorker` 打开 Codex Guard → **默认只读** → **重新只读预览**。不能有红色阻断；固定 NTFS 数据盘、Worker 普通顶层目录和允许列表必须完整。
2. 打开 **NTFS 权限**，依次只读核查当前项目、一个默认只读位置和一个允许列表目录；核对分类与原始 DACL。
3. 打开 **安全审计** → **重新审计**。任何“失败”立即停止；“警告”必须解释清楚。`MANUAL` 不是通过，只表示静态检查无法证明。
4. 点击 **导出人工核查包**，保存 HTML 和同名 JSON。
5. 从原发布包双击 `CodexGuard.ReadOnlyVerifier.exe`，核对下表，并把文本报告与 HTML 放在一起。

| 红线 | 应看到的事实 | 否则怎么办 |
|---|---|---|
| UAC | `EnableLUA=1`、`PromptOnSecureDesktop=1`、`ConsentPromptBehaviorUser=1` | 停止权限操作；管理员修复并重启 |
| 身份 | Worker/Sandbox SID 与 `state.json` 一致；Worker 不在任何特权组 | 账户可能被重建或提权，停止使用 |
| 官方沙箱 | `allow_login_shell=false`；只允许 `elevated`；private desktop=true | 不允许退回 unelevated |
| 受信任文件 | EXE、state、requirements 的路径、SHA、Owner 和 SDDL 两份报告一致 | 视为程序或状态被替换 |
| 激活路径 | 每个激活目录都是默认只读边界或固定管理员资料边界的严格后代，文件 ID 未变化 | 先取证，不要直接点修复 |
| 默认只读基线 | 固定 NTFS 数据盘和 Worker 普通目录均已记录；根锁、Worker/Sandbox Deny 与状态一致 | 新盘、新目录或 ACL 缺失时停止使用并重新预览 |
| 写入允许列表 | 只有 Worker `AppData`、`.codex` 和已经存在的 `.cache` | 不接受临时开放 Desktop、Downloads 或整盘写入 |
| 不删除 ACL | 两个 Actor 都有 Delete/Delete child/WRITE_DAC/WRITE_OWNER Deny | 禁止使用真实数据 |
| 所有者绕过 | 有可继承 `OWNER RIGHTS`（`S-1-3-4`）Allow，且只有 ReadPermissions/Synchronize | 新建文件的所有者可能绕过改 ACL 禁令 |

两份报告中的 SID、哈希、路径或 SDDL 只要不一致，就按失败处理。报告包含本机路径和 SID，不要上传到公开位置。

## 首次部署的黑盒验收

只在空目录或可丢弃副本上做一次；不要选择真实项目根、磁盘根或恢复档案。

1. `admin` 用资源管理器建立专用目录，例如 `D:\CodexGuard-Acceptance\Active` 和 `D:\CodexGuard-Acceptance\Outside`。
2. 应用默认只读基线；确认 `D:\` 已列为默认只读边界，只激活 `Active`。未启用基线时不得激活，不能用手工保护根替代。
3. 登录 `CodexWorker`，双击发布包内 `CodexGuard.AcceptanceProbe.exe`。
4. 选择 `Active`，使用“激活目录”模式。必须同时满足：
   - 新建目录、写标记、新建文件、读取、原位覆盖：**成功**；
   - 写回 DACL、创建时指定受保护 FullControl DACL、重命名、删除文件、删除空目录：**拒绝访问**。
5. 选择 `Outside`，使用“默认只读/非激活区域”模式。新建随机测试目录必须**拒绝访问**。
6. 在 Codex 的 Agent 命令环境中，对另一个专用验收副本重复测试，以覆盖真实 `CodexSandboxUsers` 令牌；不要用真实项目。
7. 保存两次结果截图。由 `admin` 人工移动/删除探针残留，Codex Guard 和探针都不会自动清理。

探针没有命令行路径参数。所有潜在改 ACL、重命名和删除调用之前，都会再次验证目标是本次随机 GUID 目录的严格后代，且范围标记仍存在。

“创建时指定受保护 FullControl DACL”是刻意测试 Windows 新对象安全描述符边界；若它成功，说明该系统上的 ACL-only 方案只能阻止普通删除命令，不能阻止进程刻意构造新对象权限。此时即使普通删除测试均被拒绝，也不能标记为完整验收通过。

## 结论分级

- **静态失败**：立即停止，不能运行黑盒验收来“冲掉”失败。
- **静态通过、黑盒未做**：只说明配置看起来一致，仍是预览状态。
- **Worker 通过、Sandbox 未做**：可证明宿主账户边界，不能证明 Agent 命令边界。
- **三类证据全部一致**：该机器的当前版本验收通过；Windows、Codex 或 ACL 发生变化后重新核查。

即使全部通过，激活目录仍允许覆盖和截断内容，因此离线备份、版本控制和卷快照仍是必要的。
