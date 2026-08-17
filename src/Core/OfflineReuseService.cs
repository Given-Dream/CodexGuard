using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CodexGuard.Core
{
    internal static class OfflineReuseService
    {
        public static OfflineReuseReport Capture()
        {
            GuardState state = null;
            try { if (StateStore.Exists) state = StateStore.Load(); }
            catch { }
            return Capture(state);
        }

        internal static OfflineReuseReport Capture(GuardState state)
        {
            SoftwareInventoryReport software = SoftwareMappingService.Capture(state);
            OfflineReuseReport report = new OfflineReuseReport
            {
                GeneratedAtUtc = AppInfo.UtcNow(),
                AdminProfilePath = state == null ? null : state.AdminProfilePath,
                WorkerProfilePath = state == null ? null : state.WorkerProfilePath
            };
            report.Warnings.AddRange(software.Warnings);
            foreach (SoftwareInventoryItem source in software.Items)
                report.Items.Add(Classify(source, state));
            report.Items.Sort(delegate(OfflineReuseItem left, OfflineReuseItem right)
            {
                int category = left.Category.CompareTo(right.Category);
                if (category != 0) return category;
                return string.Compare(left.DisplayName, right.DisplayName, StringComparison.CurrentCultureIgnoreCase);
            });
            return report;
        }

        internal static OfflineReuseItem Classify(SoftwareInventoryItem software, GuardState state)
        {
            if (software == null) throw new ArgumentNullException("software");
            OfflineReuseItem item = new OfflineReuseItem
            {
                InventoryId = software.InventoryId,
                DisplayName = software.DisplayName,
                Version = software.Version,
                Publisher = software.Publisher,
                ExistingExecutable = software.ExecutablePath,
                LocalInstallSource = software.LocalInstallSource,
                Scope = software.Scope
            };

            if (software.IsStoreLike || software.Category == SoftwareMappingCategory.WorkerRegistrationRequired)
            {
                item.Category = OfflineReuseCategory.ExistingPackageRegistration;
                item.Reason = "这是按 Windows 用户注册的 Store/MSIX 应用。";
                item.RecommendedAction = "由管理员确认本机包载荷后为 CodexWorker 注册；不复制 WindowsApps，也不直接指向受保护 EXE。";
                return item;
            }

            if (IsHostControlSoftware(software.DisplayName))
            {
                item.Category = OfflineReuseCategory.PermissionReview;
                item.Reason = "该软件可控制容器/虚拟化宿主；授予 CodexWorker 守护进程或特权用户组访问可能绕过 NTFS 文件边界。";
                item.RecommendedAction = "程序文件无需重新下载，但不要自动把 CodexWorker 加入 docker-users 等宿主控制组；应使用隔离虚拟机或人工管理的远程执行端。";
                return item;
            }

            string sourceDirectory;
            string relativeExecutable;
            string adminProfile = state == null ? null : state.AdminProfilePath;
            if (TryGetAdminLocalProgramsSource(software.ExecutablePath, adminProfile, out sourceDirectory, out relativeExecutable))
            {
                item.SourceDirectory = sourceDirectory;
                item.RelativeExecutablePath = relativeExecutable;
                item.Category = OfflineReuseCategory.AdminProgramCopy;
                item.CanPrepareCopy = Directory.Exists(sourceDirectory) && File.Exists(software.ExecutablePath);
                item.RequiresWorkerFirstRun = true;
                item.Reason = "程序主体位于 admin 的 AppData\\Local\\Programs，可制作不含用户数据的 Worker 本地副本。";
                item.RecommendedAction = item.CanPrepareCopy
                    ? "UAC 只复制该程序目录到 CodexWorker 的 Local\\Programs；不覆盖目标、不迁移注册表，之后由 Worker 首次运行生成配置。"
                    : "源程序目录当前不可读或主 EXE 已缺失；优先使用现有本地安装源。";
                return item;
            }

            if (software.Category == SoftwareMappingCategory.SharedReady || software.Category == SoftwareMappingCategory.ShortcutRequired)
            {
                item.Category = OfflineReuseCategory.DirectReuse;
                item.Reason = "现有机器级/共享程序文件可以直接复用。";
                item.RecommendedAction = software.Category == SoftwareMappingCategory.ShortcutRequired
                    ? "在“软件映射”页创建快捷方式；CodexWorker 首次运行时生成自己的设置。"
                    : "无需复制或安装；直接以 CodexWorker 身份运行。";
                return item;
            }

            if (software.LocalInstallSourceExists)
            {
                item.Category = OfflineReuseCategory.LocalMedia;
                item.Reason = "注册表记录的本地安装源仍然存在。";
                item.RecommendedAction = "如直接运行失败，使用该本地介质离线注册/修复；Codex Guard 不自动执行安装器。";
                return item;
            }

            if (!string.IsNullOrWhiteSpace(software.ExecutablePath) && File.Exists(software.ExecutablePath))
            {
                item.Category = OfflineReuseCategory.PermissionReview;
                item.Reason = software.Reason ?? "现有程序存在，但路径、ACL 或启动参数尚未通过共享核验。";
                item.RecommendedAction = "不需要重新下载；由 admin 核对真实 EXE、厂商参数及父目录权限后重新扫描。";
                return item;
            }

            item.Category = OfflineReuseCategory.LocalPayloadMissing;
            item.Reason = software.Reason ?? "没有找到现存主 EXE或本地安装介质。";
            item.RecommendedAction = "先在 E/F/D 盘安装包目录及厂商缓存中定位原介质；只有本地载荷确实缺失时才下载。";
            return item;
        }

        internal static bool TryGetAdminLocalProgramsSource(
            string executablePath,
            string adminProfile,
            out string sourceDirectory,
            out string relativeExecutablePath)
        {
            sourceDirectory = null;
            relativeExecutablePath = null;
            if (string.IsNullOrWhiteSpace(executablePath) || string.IsNullOrWhiteSpace(adminProfile)) return false;
            string executable;
            string programs;
            try
            {
                executable = Path.GetFullPath(executablePath);
                programs = AppPaths.NormalizeDirectoryPath(Path.Combine(adminProfile, "AppData", "Local", "Programs"));
            }
            catch { return false; }
            if (!executable.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !AppPaths.IsPathInside(executable, programs)
                || AppPaths.PathsEqual(executable, programs)) return false;
            string prefix = programs.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? programs : programs + Path.DirectorySeparatorChar;
            if (!executable.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            string relative = executable.Substring(prefix.Length);
            int separator = relative.IndexOfAny(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar });
            if (separator <= 0 || separator >= relative.Length - 1) return false;
            string topLevel = relative.Substring(0, separator);
            if (topLevel == "." || topLevel == ".." || topLevel.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return false;
            string source = Path.GetFullPath(Path.Combine(programs, topLevel));
            if (!AppPaths.IsPathInside(executable, source) || !AppPaths.IsPathInside(source, programs) || AppPaths.PathsEqual(source, programs)) return false;
            string executableRelative = executable.Substring(source.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (string.IsNullOrWhiteSpace(executableRelative) || Path.IsPathRooted(executableRelative)) return false;
            sourceDirectory = source;
            relativeExecutablePath = executableRelative;
            return true;
        }

        internal static string BuildWorkerTargetDirectory(string workerProfile, string sourceDirectory)
        {
            if (string.IsNullOrWhiteSpace(workerProfile) || string.IsNullOrWhiteSpace(sourceDirectory))
                throw new ArgumentException("Worker profile and source directory are required.");
            string source = AppPaths.NormalizeDirectoryPath(sourceDirectory);
            string leaf = Path.GetFileName(source);
            if (string.IsNullOrWhiteSpace(leaf) || leaf.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                throw new InvalidDataException("源程序目录名称无效。");
            string root = AppPaths.NormalizeDirectoryPath(Path.Combine(workerProfile, "AppData", "Local", "Programs"));
            string target = Path.GetFullPath(Path.Combine(root, leaf));
            if (!AppPaths.IsPathInside(target, root) || AppPaths.PathsEqual(target, root))
                throw new InvalidDataException("Worker 程序目标越过固定 Local\\Programs 边界。");
            return target;
        }

        public static string CategoryText(OfflineReuseCategory category)
        {
            switch (category)
            {
                case OfflineReuseCategory.DirectReuse: return "直接复用";
                case OfflineReuseCategory.AdminProgramCopy: return "AppData 可提取";
                case OfflineReuseCategory.LocalMedia: return "本地介质可用";
                case OfflineReuseCategory.ExistingPackageRegistration: return "现有包需注册";
                case OfflineReuseCategory.PermissionReview: return "权限/路径待核查";
                default: return "本地载荷待定位";
            }
        }

        public static string ToCsv(OfflineReuseReport report)
        {
            if (report == null) throw new ArgumentNullException("report");
            StringBuilder csv = new StringBuilder();
            csv.AppendLine("分类,软件,版本,发布者,现有EXE,可复制源目录,本地安装源,范围,原因,无下载处理方式");
            foreach (OfflineReuseItem item in report.Items)
            {
                string[] values =
                {
                    CategoryText(item.Category), item.DisplayName, item.Version, item.Publisher,
                    item.ExistingExecutable, item.SourceDirectory, item.LocalInstallSource, item.Scope,
                    item.Reason, item.RecommendedAction
                };
                for (int index = 0; index < values.Length; index++)
                {
                    if (index > 0) csv.Append(',');
                    csv.Append(CsvValue(values[index]));
                }
                csv.AppendLine();
            }
            return csv.ToString();
        }

        private static string CsvValue(string value)
        {
            string text = value ?? string.Empty;
            if (text.Length > 0 && (text[0] == '=' || text[0] == '+' || text[0] == '-' || text[0] == '@')) text = "'" + text;
            return "\"" + text.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ") + "\"";
        }

        private static bool IsHostControlSoftware(string displayName)
        {
            string name = (displayName ?? string.Empty).Trim();
            return name.IndexOf("Docker Desktop", StringComparison.OrdinalIgnoreCase) >= 0
                || name.IndexOf("Podman Desktop", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
