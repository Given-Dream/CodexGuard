using System;
using System.Collections.Generic;
using System.IO;

namespace CodexGuard.Core
{
    internal enum DefaultReadOnlyItemKind
    {
        Boundary,
        RootOnlyLock,
        WritableException,
        AdministratorUnrestricted,
        SystemManaged,
        ManualReview
    }

    internal sealed class DefaultReadOnlyItem
    {
        public DefaultReadOnlyItemKind Kind { get; set; }
        public string Status { get; set; }
        public string Path { get; set; }
        public string Effect { get; set; }
        public string Reason { get; set; }
        public bool CanApply { get; set; }
    }

    internal sealed class DefaultReadOnlyReport
    {
        public string Status { get; set; }
        public string Summary { get; set; }
        public string WorkerProfilePath { get; set; }
        public bool CanApply { get; set; }
        public List<DefaultReadOnlyItem> Items { get; set; }
        public List<string> Warnings { get; set; }

        public DefaultReadOnlyReport()
        {
            Items = new List<DefaultReadOnlyItem>();
            Warnings = new List<string>();
        }
    }

    internal static class DefaultReadOnlyPolicyService
    {
        private enum DirectoryProbe
        {
            Exists,
            Missing,
            Inaccessible,
            Error
        }

        private static readonly string[] WritableExceptionNames = { "AppData", ".codex", ".cache" };
        private static readonly string[] LegacyProfileAliases =
        {
            "Application Data", "Cookies", "Local Settings", "My Documents", "NetHood", "PrintHood",
            "Recent", "SendTo", "Start Menu", "\u300c\u5f00\u59cb\u300d\u83dc\u5355", "\u300c\u958b\u59cb\u300d\u529f\u80fd\u8868",
            "\u30b9\u30bf\u30fc\u30c8 \u30e1\u30cb\u30e5\u30fc", "\uc2dc\uc791 \uba54\ub274", "Startmen\u00fc", "Menu D\u00e9marrer", "Templates"
        };
        private static readonly string[] SystemRootNames =
        {
            "$Recycle.Bin", "Config.Msi", "Documents and Settings", "PerfLogs", "Program Files",
            "Program Files (x86)", "ProgramData", "Recovery", "System Volume Information", "Users", "Windows"
        };

        public static DefaultReadOnlyReport Capture()
        {
            if (!StateStore.Exists) throw new InvalidOperationException("Codex Guard 尚未安装，无法建立默认只读计划。");
            return Capture(StateStore.Load());
        }

        internal static DefaultReadOnlyReport Capture(GuardState state)
        {
            return CaptureCore(state, false);
        }

        internal static DefaultReadOnlyReport CapturePreview(GuardState state, bool deferInaccessibleWorkerPathsToUac)
        {
            return CaptureCore(state, deferInaccessibleWorkerPathsToUac);
        }

        private static DefaultReadOnlyReport CaptureCore(GuardState state, bool deferInaccessibleWorkerPathsToUac)
        {
            if (state == null) throw new ArgumentNullException("state");
            state.Normalize();
            DefaultReadOnlyReport report = new DefaultReadOnlyReport();
            string workerProfile = ResolveWorkerProfile(state);
            report.WorkerProfilePath = workerProfile;
            string workerProfileProbeError;
            DirectoryProbe workerProfileProbe = string.IsNullOrWhiteSpace(workerProfile)
                ? DirectoryProbe.Missing
                : ProbeDirectory(workerProfile, out workerProfileProbeError);
            if (string.IsNullOrWhiteSpace(workerProfile) || workerProfileProbe == DirectoryProbe.Missing || workerProfileProbe == DirectoryProbe.Error)
            {
                report.Status = "BLOCK";
                report.Summary = "无法定位 CodexWorker 用户资料；不能安全生成允许列表。";
                report.CanApply = false;
                return report;
            }
            if (workerProfileProbe == DirectoryProbe.Inaccessible && !deferInaccessibleWorkerPathsToUac)
            {
                report.Status = "BLOCK";
                report.Summary = "当前身份无法读取 CodexWorker 用户资料；不能安全生成允许列表。";
                report.CanApply = false;
                return report;
            }
            if (workerProfileProbe == DirectoryProbe.Inaccessible)
                AddDeferredVerification(report, workerProfile, "当前非提升 admin 令牌无法读取 Worker 资料根；UAC 提升端必须重新核验，失败则不写 ACL。");

            report.Items.Add(new DefaultReadOnlyItem
            {
                Kind = DefaultReadOnlyItemKind.AdministratorUnrestricted,
                Status = "ADMIN",
                Path = state.AdminProfilePath ?? AppInfo.AdminProfilePath,
                Effect = "Codex Guard 不把 admin SID 写入只读或拒绝规则",
                Reason = "限制对象仅为 CodexWorker 与 CodexSandboxUsers；admin 的最终权限沿用 Windows 令牌和原始 DACL。",
                CanApply = true
            });

            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string systemRoot = AppPaths.NormalizeDirectoryPath(Path.GetPathRoot(windows));
            AddRootLock(report, state, systemRoot, "只锁当前盘根：阻止 Codex 身份在系统盘根新建、写入、删除子项或改 ACL；不继承到 Windows。", "系统盘根只锁当前对象");
            AddRootLock(report, state, workerProfile, "只锁当前资料根：阻止新建任意顶层目录；下方允许列表不继承此锁。", "Worker 资料根只锁当前对象");

            AddRequiredException(report, workerProfile, "AppData", true, deferInaccessibleWorkerPathsToUac,
                "Windows、ChatGPT/MSIX、WebView、临时文件和用户级应用更新需要正常写入与清理。若应用把唯一数据放在这里，仍需独立备份。");
            AddRequiredException(report, workerProfile, ".codex", true, deferInaccessibleWorkerPathsToUac,
                "Codex 登录、设置、任务记录、插件和本地运行状态需要正常写入与清理。该目录不得与 admin 联接或同步。");
            AddRequiredException(report, workerProfile, ".cache", false, deferInaccessibleWorkerPathsToUac,
                "仅当该缓存目录已经存在时保留正常写入与清理；新顶层缓存目录需由 admin 重新审核。" );

            AddFixedDataVolumes(report, state, systemRoot);
            AddSystemDriveCustomDirectories(report, state, systemRoot);
            AddPublicProfile(report, state, workerProfile);
            AddWorkerProfileChildren(report, state, workerProfile, deferInaccessibleWorkerPathsToUac);

            int blockers = 0;
            int ready = 0;
            int applied = 0;
            int boundaries = 0;
            foreach (DefaultReadOnlyItem item in report.Items)
            {
                if (item.Kind == DefaultReadOnlyItemKind.Boundary || item.Kind == DefaultReadOnlyItemKind.RootOnlyLock)
                {
                    boundaries++;
                    if (string.Equals(item.Status, "APPLIED", StringComparison.OrdinalIgnoreCase)) applied++;
                    else if (item.CanApply) ready++;
                }
                if (string.Equals(item.Status, "BLOCK", StringComparison.OrdinalIgnoreCase)) blockers++;
            }

            report.CanApply = blockers == 0 && boundaries > 0;
            if (blockers > 0)
            {
                report.Status = "BLOCK";
                report.Summary = "默认只读计划存在 " + blockers + " 个阻断项；不会提交 UAC。先处理红色路径。";
            }
            else if (state.DefaultReadOnlyEnabled && ready == 0 && applied == boundaries)
            {
                report.Status = "PASS";
                report.Summary = "默认只读基线已记录；固定数据盘、Worker 数据目录和两个根锁均已纳入审计。";
            }
            else
            {
                report.Status = "READY";
                report.Summary = "计划就绪：" + boundaries + " 个只读/根锁边界，" + ready + " 个待应用。应用后仍须在可丢弃副本上验收。";
            }
            if (report.Warnings.Count > 0) report.Summary += " 另有 " + report.Warnings.Count + " 项人工提示。";
            return report;
        }

        internal static bool IsWritableExceptionPath(string workerProfile, string path)
        {
            if (string.IsNullOrWhiteSpace(workerProfile) || string.IsNullOrWhiteSpace(path)) return false;
            string profile = AppPaths.NormalizeDirectoryPath(workerProfile);
            string full = AppPaths.NormalizeDirectoryPath(path);
            foreach (string name in WritableExceptionNames)
            {
                string exception = Path.Combine(profile, name);
                if (AppPaths.IsPathInside(full, exception)) return true;
            }
            return false;
        }

        internal static bool IsSystemManagedTopLevelName(string name)
        {
            return ContainsName(SystemRootNames, name);
        }

        internal static bool IsLegacyProfileAliasName(string name)
        {
            return ContainsName(LegacyProfileAliases, name);
        }

        internal static string KindText(DefaultReadOnlyItemKind kind)
        {
            switch (kind)
            {
                case DefaultReadOnlyItemKind.Boundary: return "默认只读";
                case DefaultReadOnlyItemKind.RootOnlyLock: return "仅锁根目录";
                case DefaultReadOnlyItemKind.WritableException: return "允许写/清理";
                case DefaultReadOnlyItemKind.AdministratorUnrestricted: return "admin 不限制";
                case DefaultReadOnlyItemKind.SystemManaged: return "Windows 管理";
                default: return "人工核查";
            }
        }

        private static string ResolveWorkerProfile(GuardState state)
        {
            if (!string.IsNullOrWhiteSpace(state.WorkerProfilePath))
            {
                try { return AppPaths.NormalizeDirectoryPath(state.WorkerProfilePath); }
                catch { }
            }
            if (!string.IsNullOrWhiteSpace(state.WorkerSid))
            {
                string value = IdentityService.GetProfilePathForSid(state.WorkerSid);
                if (!string.IsNullOrWhiteSpace(value)) return AppPaths.NormalizeDirectoryPath(value);
            }
            return null;
        }

        private static void AddRequiredException(DefaultReadOnlyReport report, string profile, string name, bool required,
            bool deferInaccessibleWorkerPathsToUac, string reason)
        {
            string path = Path.Combine(profile, name);
            string probeError;
            DirectoryProbe probe = ProbeDirectory(path, out probeError);
            bool exists = probe == DirectoryProbe.Exists;
            bool deferred = probe == DirectoryProbe.Inaccessible && deferInaccessibleWorkerPathsToUac;
            bool optionalMissing = !required && probe == DirectoryProbe.Missing;
            DefaultReadOnlyItem item = new DefaultReadOnlyItem
            {
                Kind = DefaultReadOnlyItemKind.WritableException,
                Status = exists ? "ALLOW" : deferred ? "VERIFY" : optionalMissing ? "ABSENT" : "BLOCK",
                Path = path,
                Effect = exists ? "保留现有 Windows 写入/删除权限"
                    : deferred ? "仅提交 UAC 核验；提升端确认存在后才继续"
                    : optionalMissing ? "不存在，不会自动创建" : "无法确认必需目录，不会修改 ACL",
                Reason = reason + (probe == DirectoryProbe.Error && !string.IsNullOrWhiteSpace(probeError) ? " 核验错误：" + probeError : string.Empty),
                CanApply = exists || deferred || optionalMissing
            };
            report.Items.Add(item);
            if (deferred)
                report.Warnings.Add("待 UAC 严格核验必需写入目录：" + path + "。若目录不存在或仍不可读，提升端会停止。" );
            else if (!exists && required)
                report.Warnings.Add("必需写入目录不存在：" + path + "。先在 Worker 桌面完成一次 ChatGPT/Codex 初始化。");
        }

        private static void AddFixedDataVolumes(DefaultReadOnlyReport report, GuardState state, string systemRoot)
        {
            DriveInfo[] drives;
            try { drives = DriveInfo.GetDrives(); }
            catch (Exception ex)
            {
                AddBlock(report, null, "无法枚举本机卷：" + ex.Message);
                return;
            }
            foreach (DriveInfo drive in drives)
            {
                try
                {
                    if (!drive.IsReady || drive.DriveType != DriveType.Fixed) continue;
                    string root = AppPaths.NormalizeDirectoryPath(drive.RootDirectory.FullName);
                    if (AppPaths.PathsEqual(root, systemRoot)) continue;
                    if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                    {
                        AddBlock(report, root, "固定数据盘不是 NTFS，Codex Guard 无法施加持久 ACL。");
                        continue;
                    }
                    AddBoundary(report, state, root, "固定数据盘默认只读；只有显式激活目录获得写入且仍禁止删除。", "数据盘根");
                }
                catch (Exception ex)
                {
                    AddBlock(report, drive.Name, "无法核查固定数据盘：" + ex.Message);
                }
            }
        }

        private static void AddSystemDriveCustomDirectories(DefaultReadOnlyReport report, GuardState state, string systemRoot)
        {
            string[] directories;
            try { directories = Directory.GetDirectories(systemRoot); }
            catch (Exception ex)
            {
                AddBlock(report, systemRoot, "无法枚举系统盘顶层目录：" + ex.Message);
                return;
            }
            foreach (string path in directories)
            {
                string name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
                if (IsSystemManagedTopLevelName(name))
                {
                    AddSystemManaged(report, path,
                        "Windows 系统树不由 Guard 重写；普通 Worker 继续服从原生 DACL，系统级缓存、安装和更新由服务、admin 或 SYSTEM 完成。");
                    continue;
                }
                if (IsReparsePoint(path))
                {
                    AddManualReparse(report, path, "系统盘自定义顶层重解析点不能自动纳入字面路径边界。");
                    continue;
                }
                AddBoundary(report, state, path, "系统盘上的非 Windows 顶层目录默认只读。", "系统盘自定义目录");
            }
        }

        private static void AddPublicProfile(DefaultReadOnlyReport report, GuardState state, string workerProfile)
        {
            string users = Path.GetDirectoryName(workerProfile.TrimEnd(Path.DirectorySeparatorChar));
            if (string.IsNullOrWhiteSpace(users)) return;
            string path = Path.Combine(users, "Public");
            if (!Directory.Exists(path)) return;
            if (IsReparsePoint(path))
            {
                AddManualReparse(report, path, "Public 用户资料是重解析点，不能自动保护。");
                return;
            }
            AddBoundary(report, state, path, "公共用户资料默认只读，避免把 Public 当作绕过目录。", "公共用户资料");
        }

        private static void AddWorkerProfileChildren(DefaultReadOnlyReport report, GuardState state, string workerProfile,
            bool deferInaccessibleWorkerPathsToUac)
        {
            string[] directories;
            try { directories = Directory.GetDirectories(workerProfile); }
            catch (UnauthorizedAccessException ex)
            {
                if (deferInaccessibleWorkerPathsToUac)
                {
                    AddDeferredVerification(report, workerProfile, "当前非提升 admin 令牌不能枚举 Worker 顶层目录；UAC 提升端将严格重扫。" );
                    report.Warnings.Add(ex.Message);
                    return;
                }
                AddBlock(report, workerProfile, "无法枚举 Worker 顶层目录：" + ex.Message);
                return;
            }
            catch (Exception ex)
            {
                AddBlock(report, workerProfile, "无法枚举 Worker 顶层目录：" + ex.Message);
                return;
            }
            foreach (string path in directories)
            {
                string name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
                if (IsWritableExceptionPath(workerProfile, path)) continue;
                if (IsReparsePoint(path))
                {
                    if (IsLegacyProfileAliasName(name))
                    {
                        report.Items.Add(new DefaultReadOnlyItem
                        {
                            Kind = DefaultReadOnlyItemKind.SystemManaged,
                            Status = "SYSTEM",
                            Path = path,
                            Effect = "不按字面路径修改 ACL",
                            Reason = "Windows 兼容性联接；真实目标由允许列表或实际目录边界管理。",
                            CanApply = true
                        });
                    }
                    else AddManualReparse(report, path, "Worker 顶层重解析点可能绕过默认只读边界。");
                    continue;
                }
                AddBoundary(report, state, path, "Worker 顶层数据目录默认只读；需要写入的项目必须作为其严格子目录激活。", "Worker 数据目录");
            }
        }

        private static void AddBoundary(DefaultReadOnlyReport report, GuardState state, string path, string reason, string label)
        {
            string normalized = AppPaths.NormalizeDirectoryPath(path);
            if (ContainsItem(report, normalized, DefaultReadOnlyItemKind.Boundary)) return;
            bool applied = ContainsGuarded(state.DefaultReadOnlyDirectories, normalized);
            report.Items.Add(new DefaultReadOnlyItem
            {
                Kind = DefaultReadOnlyItemKind.Boundary,
                Status = applied ? "APPLIED" : "READY",
                Path = normalized,
                Effect = "Worker/Sandbox 只读；拒绝写入、新建、删除、重命名和改 ACL",
                Reason = label + "：" + reason,
                CanApply = true
            });
        }

        private static void AddRootLock(DefaultReadOnlyReport report, GuardState state, string path, string reason, string label)
        {
            string normalized = AppPaths.NormalizeDirectoryPath(path);
            bool applied = ContainsGuarded(state.DefaultReadOnlyRootLocks, normalized);
            report.Items.Add(new DefaultReadOnlyItem
            {
                Kind = DefaultReadOnlyItemKind.RootOnlyLock,
                Status = applied ? "APPLIED" : "READY",
                Path = normalized,
                Effect = "仅当前目录拒绝新建/写入/删除子项/改 ACL；不向子目录继承",
                Reason = label + "：" + reason,
                CanApply = true
            });
        }

        private static void AddBlock(DefaultReadOnlyReport report, string path, string reason)
        {
            report.Items.Add(new DefaultReadOnlyItem
            {
                Kind = DefaultReadOnlyItemKind.ManualReview,
                Status = "BLOCK",
                Path = path,
                Effect = "不会自动修改",
                Reason = reason,
                CanApply = false
            });
        }

        private static void AddDeferredVerification(DefaultReadOnlyReport report, string path, string reason)
        {
            report.Items.Add(new DefaultReadOnlyItem
            {
                Kind = DefaultReadOnlyItemKind.ManualReview,
                Status = "VERIFY",
                Path = path,
                Effect = "仅提交 UAC 严格核验；核验失败则不写 ACL",
                Reason = reason,
                CanApply = true
            });
        }

        private static DirectoryProbe ProbeDirectory(string path, out string error)
        {
            error = null;
            try
            {
                FileAttributes attributes = File.GetAttributes(path);
                return (attributes & FileAttributes.Directory) != 0 ? DirectoryProbe.Exists : DirectoryProbe.Error;
            }
            catch (UnauthorizedAccessException ex)
            {
                error = ex.Message;
                return DirectoryProbe.Inaccessible;
            }
            catch (FileNotFoundException)
            {
                return DirectoryProbe.Missing;
            }
            catch (DirectoryNotFoundException)
            {
                return DirectoryProbe.Missing;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return DirectoryProbe.Error;
            }
        }

        private static void AddManualReparse(DefaultReadOnlyReport report, string path, string reason)
        {
            AddBlock(report, path, reason + " 请由 admin 核对真实目标后移除联接或另行保护。");
        }

        private static void AddSystemManaged(DefaultReadOnlyReport report, string path, string reason)
        {
            report.Items.Add(new DefaultReadOnlyItem
            {
                Kind = DefaultReadOnlyItemKind.SystemManaged,
                Status = "SYSTEM",
                Path = AppPaths.NormalizeDirectoryPath(path),
                Effect = "沿用 Windows 原生 DACL；Guard 不增加 Worker 写权限",
                Reason = reason,
                CanApply = true
            });
        }

        private static bool IsReparsePoint(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
            catch { return true; }
        }

        private static bool ContainsGuarded(IEnumerable<GuardedDirectory> values, string path)
        {
            if (values == null) return false;
            foreach (GuardedDirectory item in values)
            {
                if (item == null) continue;
                string value = string.IsNullOrWhiteSpace(item.CanonicalPath) ? item.Path : item.CanonicalPath;
                if (!string.IsNullOrWhiteSpace(value) && AppPaths.PathsEqual(value, path)) return true;
            }
            return false;
        }

        private static bool ContainsItem(DefaultReadOnlyReport report, string path, DefaultReadOnlyItemKind kind)
        {
            foreach (DefaultReadOnlyItem item in report.Items)
                if (item.Kind == kind && !string.IsNullOrWhiteSpace(item.Path) && AppPaths.PathsEqual(item.Path, path)) return true;
            return false;
        }

        private static bool ContainsName(IEnumerable<string> values, string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return false;
            foreach (string value in values)
                if (string.Equals(value, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
}
