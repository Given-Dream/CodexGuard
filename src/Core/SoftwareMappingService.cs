using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace CodexGuard.Core
{
    internal static class SoftwareMappingService
    {
        private const int MaximumShortcutsToInspect = 5000;
        private const int MaximumExecutablesPerInstallDirectory = 256;

        private sealed class Candidate
        {
            public string DisplayName;
            public string Version;
            public string Publisher;
            public string ExecutablePath;
            public string InstallLocation;
            public string LocalInstallSource;
            public string Source;
            public string Scope;
            public bool HasCommonShortcut;
            public bool StoreLike;
            public bool AdminScoped;
            public bool RequiresArguments;
            public bool FromRegistry;
            public bool IsWindowsInstaller;
        }

        private sealed class ShortcutFacts
        {
            public string TargetPath;
            public string Arguments;
        }

        public static SoftwareInventoryReport Capture()
        {
            GuardState state = null;
            try { if (StateStore.Exists) state = StateStore.Load(); }
            catch { }
            return Capture(state);
        }

        internal static SoftwareInventoryReport Capture(GuardState state)
        {
            SoftwareInventoryReport report = new SoftwareInventoryReport
            {
                GeneratedAtUtc = AppInfo.UtcNow(),
                AdminProfilePath = state == null ? null : state.AdminProfilePath
            };
            List<Candidate> candidates = new List<Candidate>();

            ScanMachineRegistry(candidates, report.Warnings);

            string adminSid = FindProfileSid(report.AdminProfilePath);
            if (!string.IsNullOrWhiteSpace(adminSid))
            {
                ScanUserRegistry(adminSid, "admin 用户注册表", true, candidates, report.Warnings);
            }
            else
            {
                string currentSid = IdentityService.CurrentSid();
                ScanCurrentUserRegistry(currentSid, candidates, report.Warnings);
                if (!string.IsNullOrWhiteSpace(report.AdminProfilePath))
                    report.Warnings.Add("无法把管理员资料路径解析为已加载的用户 SID；admin 专属软件可能未完整列出。");
            }

            ScanShortcutDirectory(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "公共开始菜单", true, false, candidates, report.Warnings);
            ScanShortcutDirectory(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "公共桌面", true, false, candidates, report.Warnings);
            if (!string.IsNullOrWhiteSpace(report.AdminProfilePath))
            {
                ScanShortcutDirectory(Path.Combine(report.AdminProfilePath, "Desktop"), "admin 桌面", false, true, candidates, report.Warnings);
                ScanShortcutDirectory(
                    Path.Combine(report.AdminProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs"),
                    "admin 开始菜单",
                    false,
                    true,
                    candidates,
                    report.Warnings);
            }

            List<Candidate> merged = MergeCandidates(candidates);
            Dictionary<string, string> safetyCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Candidate candidate in merged)
            {
                SoftwareInventoryItem item = BuildInventoryItem(candidate, report.AdminProfilePath, state, safetyCache);
                if (item != null) report.Items.Add(item);
            }
            report.Items.Sort(delegate(SoftwareInventoryItem left, SoftwareInventoryItem right)
            {
                int category = left.Category.CompareTo(right.Category);
                if (category != 0) return category;
                return string.Compare(left.DisplayName, right.DisplayName, StringComparison.CurrentCultureIgnoreCase);
            });
            return report;
        }

        private static void ScanMachineRegistry(List<Candidate> output, List<string> warnings)
        {
            RegistryView[] views = { RegistryView.Registry64, RegistryView.Registry32 };
            foreach (RegistryView view in views)
            {
                try
                {
                    using (RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                    {
                        ScanUninstallKey(machine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "计算机级注册表 " + view, false, output);
                    }
                }
                catch (Exception ex)
                {
                    warnings.Add("读取计算机级软件清单失败（" + view + "）：" + ex.Message);
                }
            }
        }

        private static void ScanCurrentUserRegistry(string currentSid, List<Candidate> output, List<string> warnings)
        {
            try
            {
                using (RegistryKey current = Registry.CurrentUser)
                {
                    ScanUninstallKey(current, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "当前用户注册表", false, output);
                }
            }
            catch (Exception ex)
            {
                warnings.Add("读取当前用户软件清单失败（" + currentSid + "）：" + ex.Message);
            }
        }

        private static void ScanUserRegistry(string sid, string source, bool adminScoped, List<Candidate> output, List<string> warnings)
        {
            try
            {
                using (RegistryKey users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default))
                {
                    ScanUninstallKey(users, sid + @"\Software\Microsoft\Windows\CurrentVersion\Uninstall", source, adminScoped, output);
                    ScanUninstallKey(users, sid + @"\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", source + " WOW6432", adminScoped, output);
                }
            }
            catch (Exception ex)
            {
                warnings.Add("读取 " + source + " 失败：" + ex.Message);
            }
        }

        private static void ScanUninstallKey(RegistryKey root, string subPath, string source, bool adminScoped, List<Candidate> output)
        {
            using (RegistryKey uninstall = root.OpenSubKey(subPath, false))
            {
                if (uninstall == null) return;
                foreach (string keyName in uninstall.GetSubKeyNames())
                {
                    try
                    {
                        using (RegistryKey entry = uninstall.OpenSubKey(keyName, false))
                        {
                            if (entry == null) continue;
                            string displayName = ReadString(entry, "DisplayName");
                            if (string.IsNullOrWhiteSpace(displayName)) continue;
                            if (ReadInt(entry, "SystemComponent") == 1) continue;
                            if (!string.IsNullOrWhiteSpace(ReadString(entry, "ParentKeyName"))) continue;
                            string releaseType = ReadString(entry, "ReleaseType");
                            if (!string.IsNullOrWhiteSpace(releaseType)
                                && (releaseType.IndexOf("Update", StringComparison.OrdinalIgnoreCase) >= 0
                                    || releaseType.IndexOf("Hotfix", StringComparison.OrdinalIgnoreCase) >= 0)) continue;

                            string installLocation = NormalizePossiblePath(ReadString(entry, "InstallLocation"));
                            string localInstallSource = NormalizePossiblePath(ReadString(entry, "InstallSource"));
                            string displayIcon = ParseDisplayIconPath(ReadString(entry, "DisplayIcon"));
                            string executable = FindExecutable(displayName, displayIcon, installLocation);
                            bool storeLike = IsStoreLikePath(displayIcon) || IsStoreLikePath(installLocation)
                                || keyName.IndexOf("_", StringComparison.Ordinal) >= 0 && keyName.IndexOf("__", StringComparison.Ordinal) >= 0;
                            output.Add(new Candidate
                            {
                                DisplayName = displayName.Trim(),
                                Version = ReadString(entry, "DisplayVersion"),
                                Publisher = ReadString(entry, "Publisher"),
                                ExecutablePath = executable,
                                InstallLocation = installLocation,
                                LocalInstallSource = localInstallSource,
                                Source = source,
                                Scope = adminScoped ? "admin 专属" : source.StartsWith("计算机级", StringComparison.Ordinal) ? "计算机级" : "当前用户",
                                StoreLike = storeLike,
                                AdminScoped = adminScoped,
                                FromRegistry = true,
                                IsWindowsInstaller = ReadInt(entry, "WindowsInstaller") == 1
                            });
                        }
                    }
                    catch
                    {
                        // One malformed vendor key must not hide the rest of the inventory.
                    }
                }
            }
        }

        private static void ScanShortcutDirectory(string root, string source, bool common, bool adminScoped, List<Candidate> output, List<string> warnings)
        {
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root)) return;
            int inspected = 0;
            Queue<string> pending = new Queue<string>();
            pending.Enqueue(root);
            try
            {
                while (pending.Count > 0 && inspected < MaximumShortcutsToInspect)
                {
                    string current = pending.Dequeue();
                    try
                    {
                        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) continue;
                        foreach (string directory in Directory.GetDirectories(current)) pending.Enqueue(directory);
                        foreach (string shortcutPath in Directory.GetFiles(current, "*.lnk", SearchOption.TopDirectoryOnly))
                        {
                            if (++inspected > MaximumShortcutsToInspect) break;
                            ShortcutFacts facts = ReadShortcut(shortcutPath);
                            if (facts == null) continue;
                            string target = NormalizePossiblePath(facts.TargetPath);
                            string shortcutName = Path.GetFileNameWithoutExtension(shortcutPath);
                            if (IsUnsafeLauncher(shortcutName, target)) continue;
                            bool storeLike = IsStoreLikePath(target)
                                || (!string.IsNullOrWhiteSpace(facts.Arguments) && facts.Arguments.IndexOf("shell:AppsFolder", StringComparison.OrdinalIgnoreCase) >= 0);
                            if (!storeLike && (string.IsNullOrWhiteSpace(target) || !target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))) continue;
                            if (!string.IsNullOrWhiteSpace(target) && AppPaths.PathsEqual(target, AppPaths.InstalledExecutable)) continue;
                            output.Add(new Candidate
                            {
                                DisplayName = shortcutName,
                                ExecutablePath = target,
                                InstallLocation = string.IsNullOrWhiteSpace(target) ? null : Path.GetDirectoryName(target),
                                Source = source,
                                Scope = common ? "公共" : adminScoped ? "admin 专属" : "当前用户",
                                HasCommonShortcut = common,
                                StoreLike = storeLike,
                                AdminScoped = adminScoped,
                                RequiresArguments = !string.IsNullOrWhiteSpace(facts.Arguments),
                                FromRegistry = false
                            });
                        }
                    }
                    catch
                    {
                        // Skip inaccessible vendor folders and keep scanning the rest.
                    }
                }
                if (inspected >= MaximumShortcutsToInspect)
                    warnings.Add(source + " 的快捷方式数量超过核查上限，清单可能不完整。");
            }
            catch (Exception ex)
            {
                warnings.Add("读取 " + source + " 失败：" + ex.Message);
            }
        }

        private static ShortcutFacts ReadShortcut(string shortcutPath)
        {
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return null;
            object shell = null;
            object shortcut = null;
            try
            {
                shell = Activator.CreateInstance(shellType);
                shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { shortcutPath });
                Type type = shortcut.GetType();
                return new ShortcutFacts
                {
                    TargetPath = Convert.ToString(type.InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, null)),
                    Arguments = Convert.ToString(type.InvokeMember("Arguments", BindingFlags.GetProperty, null, shortcut, null))
                };
            }
            catch
            {
                return null;
            }
            finally
            {
                if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
                if (shell != null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
            }
        }

        private static List<Candidate> MergeCandidates(List<Candidate> candidates)
        {
            Dictionary<string, Candidate> merged = new Dictionary<string, Candidate>(StringComparer.OrdinalIgnoreCase);
            foreach (Candidate candidate in candidates)
            {
                if (candidate == null || string.IsNullOrWhiteSpace(candidate.DisplayName)) continue;
                string target = NormalizePossiblePath(candidate.ExecutablePath);
                candidate.ExecutablePath = target;
                string key = !string.IsNullOrWhiteSpace(target)
                    ? "PATH|" + target
                    : "NAME|" + candidate.DisplayName.Trim() + "|" + (candidate.Publisher ?? string.Empty).Trim();
                Candidate existing;
                if (!merged.TryGetValue(key, out existing))
                {
                    merged.Add(key, candidate);
                    continue;
                }

                bool common = existing.HasCommonShortcut || candidate.HasCommonShortcut;
                bool store = existing.StoreLike || candidate.StoreLike;
                bool admin = existing.AdminScoped || candidate.AdminScoped;
                bool arguments = existing.RequiresArguments || candidate.RequiresArguments;
                if (!existing.FromRegistry && candidate.FromRegistry)
                {
                    candidate.HasCommonShortcut = common;
                    candidate.StoreLike = store;
                    candidate.AdminScoped = admin;
                    candidate.RequiresArguments = arguments;
                    if (string.IsNullOrWhiteSpace(candidate.Source)) candidate.Source = existing.Source;
                    merged[key] = candidate;
                }
                else
                {
                    existing.HasCommonShortcut = common;
                    existing.StoreLike = store;
                    existing.AdminScoped = admin;
                    existing.RequiresArguments = arguments;
                    if (string.IsNullOrWhiteSpace(existing.Version)) existing.Version = candidate.Version;
                    if (string.IsNullOrWhiteSpace(existing.Publisher)) existing.Publisher = candidate.Publisher;
                    if (string.IsNullOrWhiteSpace(existing.InstallLocation)) existing.InstallLocation = candidate.InstallLocation;
                    if (string.IsNullOrWhiteSpace(existing.LocalInstallSource)) existing.LocalInstallSource = candidate.LocalInstallSource;
                    existing.IsWindowsInstaller = existing.IsWindowsInstaller || candidate.IsWindowsInstaller;
                    if (!string.IsNullOrWhiteSpace(candidate.Source) && existing.Source.IndexOf(candidate.Source, StringComparison.OrdinalIgnoreCase) < 0)
                        existing.Source += " + " + candidate.Source;
                }
            }
            return new List<Candidate>(merged.Values);
        }

        private static SoftwareInventoryItem BuildInventoryItem(Candidate candidate, string adminProfile, GuardState state, Dictionary<string, string> safetyCache)
        {
            string target = NormalizePossiblePath(candidate.ExecutablePath);
            bool exists = !string.IsNullOrWhiteSpace(target) && File.Exists(target);
            string safetyReason = null;
            bool safeShared = false;
            if (exists)
            {
                if (!safetyCache.TryGetValue(target, out safetyReason))
                {
                    safeShared = IsSafeSharedExecutablePath(target, state, out safetyReason);
                    safetyCache[target] = safeShared ? string.Empty : (safetyReason ?? "共享执行文件未通过安全核验。");
                }
                else
                {
                    safeShared = string.IsNullOrEmpty(safetyReason);
                }
            }

            SoftwareInventoryItem item = new SoftwareInventoryItem
            {
                DisplayName = candidate.DisplayName.Trim(),
                Version = candidate.Version,
                Publisher = candidate.Publisher,
                ExecutablePath = target,
                InstallLocation = candidate.InstallLocation,
                LocalInstallSource = candidate.LocalInstallSource,
                Source = candidate.Source,
                Scope = candidate.Scope,
                HasCommonShortcut = candidate.HasCommonShortcut,
                LocalInstallSourceExists = LocalSourceExists(candidate.LocalInstallSource),
                IsWindowsInstaller = candidate.IsWindowsInstaller,
                IsStoreLike = candidate.StoreLike,
                IsAdminScoped = candidate.AdminScoped,
                RequiresArguments = candidate.RequiresArguments
            };
            ClassifyFacts(
                item,
                adminProfile,
                exists,
                safeShared,
                candidate.HasCommonShortcut,
                candidate.StoreLike,
                candidate.AdminScoped,
                candidate.RequiresArguments,
                safetyReason);
            item.InventoryId = ComputeInventoryId(item.DisplayName, item.Publisher, item.ExecutablePath, item.Source);
            return item;
        }

        internal static void ClassifyFacts(
            SoftwareInventoryItem item,
            string adminProfile,
            bool targetExists,
            bool safeShared,
            bool commonShortcut,
            bool storeLike,
            bool adminScoped,
            bool requiresArguments,
            string safetyReason)
        {
            if (storeLike)
            {
                item.Category = SoftwareMappingCategory.WorkerRegistrationRequired;
                item.Reason = "这是 Microsoft Store/MSIX 风格的按用户注册应用。";
                item.RecommendedAction = "使用本机现有软件包为 CodexWorker 完成注册；不复制 WindowsApps，也不要求重新下载程序主体。";
                return;
            }

            if (targetExists && safeShared && commonShortcut)
            {
                item.Category = SoftwareMappingCategory.SharedReady;
                item.Reason = requiresArguments
                    ? "共享 EXE 与厂商创建的公共快捷方式均已存在；保留原快捷方式参数。"
                    : "共享 EXE 与公共快捷方式均已存在。";
                item.RecommendedAction = "CodexWorker 可直接使用；登录、插件和设置仍按用户分开。";
                return;
            }

            if (targetExists && safeShared && !requiresArguments)
            {
                item.Category = SoftwareMappingCategory.ShortcutRequired;
                item.Reason = "共享 EXE 已通过位置、重解析点、硬链接和宽泛写权限检查，但没有公共快捷方式。";
                item.RecommendedAction = "可由 admin 通过 UAC 创建公共开始菜单快捷方式。";
                item.CanCreateShortcut = true;
                return;
            }

            bool insideAdmin = !string.IsNullOrWhiteSpace(item.ExecutablePath)
                && !string.IsNullOrWhiteSpace(adminProfile)
                && AppPaths.IsPathInside(item.ExecutablePath, adminProfile);
            item.Category = SoftwareMappingCategory.SeparateInstallRequired;
            if (insideAdmin || adminScoped)
            {
                item.Reason = "程序或注册信息属于 admin 用户资料，不能在不破坏隔离的前提下直接共享。";
                item.RecommendedAction = "技术阻断：现有 admin AppData 无访问规则优先；快捷方式不能绕过，Codex Guard 不自动放宽。";
            }
            else if (requiresArguments)
            {
                item.Reason = "现有快捷方式包含启动参数；Codex Guard 不复制未经解释的命令字符串。";
                item.RecommendedAction = "由 admin 核对厂商说明后人工决定注册或安装方式。";
            }
            else if (!targetExists)
            {
                item.Reason = "没有找到可验证且仍存在的主 EXE。";
                item.RecommendedAction = "技术阻断：先人工查明真实主 EXE；未知目标不会生成可能失效的快捷方式。";
            }
            else
            {
                item.Reason = string.IsNullOrWhiteSpace(safetyReason) ? "EXE 不在允许的系统级共享安装边界内。" : safetyReason;
                item.RecommendedAction = "技术阻断：由 admin 核对并收紧目标及其父目录 ACL 后可重新扫描；不需要重新下载。";
            }
        }

        internal static bool IsSafeSharedExecutablePath(string executablePath, GuardState state, out string reason)
        {
            reason = null;
            string full;
            try { full = Path.GetFullPath(executablePath); }
            catch (Exception ex) { reason = "EXE 路径无效：" + ex.Message; return false; }
            if (!Path.IsPathRooted(full) || !full.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                reason = "共享目标必须是本地绝对 EXE 路径。";
                return false;
            }
            if (!File.Exists(full)) { reason = "EXE 已不存在。"; return false; }
            if (IsStoreLikePath(full)) { reason = "WindowsApps 需要按用户注册，不能创建直接 EXE 映射。"; return false; }

            List<string> allowedRoots = SharedProgramRoots();
            string matchedRoot = null;
            foreach (string root in allowedRoots)
            {
                if (AppPaths.IsPathInside(full, root)) { matchedRoot = root; break; }
            }
            if (matchedRoot == null)
            {
                if (IsForbiddenSharedLocation(full, state, out reason)) return false;
                string volumeRoot = Path.GetPathRoot(full);
                try
                {
                    DriveInfo drive = new DriveInfo(volumeRoot);
                    if (drive.DriveType != DriveType.Fixed || !string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                    {
                        reason = "非 Program Files 目标必须位于本机固定 NTFS 磁盘。";
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    reason = "无法核验共享软件所在卷：" + ex.Message;
                    return false;
                }
                matchedRoot = volumeRoot;
            }

            try
            {
                List<SecurityIdentifier> unsafeSids = BuildUnsafeWriteSids(state);
                string current = Path.GetDirectoryName(full);
                while (!string.IsNullOrWhiteSpace(current) && AppPaths.IsPathInside(current, matchedRoot))
                {
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    {
                        reason = "共享路径包含目录联接或其他重解析点：" + current;
                        return false;
                    }
                    string aclIssue = FindUnsafeWriteAllow(current, true, unsafeSids);
                    if (aclIssue != null) { reason = aclIssue; return false; }
                    if (AppPaths.PathsEqual(current, matchedRoot)) break;
                    current = Path.GetDirectoryName(current);
                }
                if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
                {
                    reason = "共享 EXE 是重解析点。";
                    return false;
                }
                if (NativePath.GetFileLinkCount(full) != 1)
                {
                    reason = "共享 EXE 具有多个硬链接，拒绝自动映射。";
                    return false;
                }
                string fileIssue = FindUnsafeWriteAllow(full, false, unsafeSids);
                if (fileIssue != null) { reason = fileIssue; return false; }
            }
            catch (Exception ex)
            {
                reason = "无法完成共享 EXE 的 ACL/重解析点核查：" + ex.Message;
                return false;
            }
            return true;
        }

        internal static bool IsForbiddenSharedLocation(string executablePath, GuardState state, out string reason)
        {
            reason = null;
            string full;
            try { full = Path.GetFullPath(executablePath); }
            catch (Exception ex) { reason = "EXE 路径无效：" + ex.Message; return true; }
            if (full.StartsWith("\\\\", StringComparison.Ordinal) || full.StartsWith("\\?\\", StringComparison.Ordinal))
            {
                reason = "不允许从 UNC 或设备路径建立共享软件映射。";
                return true;
            }
            if (IsStoreLikePath(full))
            {
                reason = "WindowsApps 需要 Worker 的包注册，快捷方式不能绕过。";
                return true;
            }

            List<string> forbidden = new List<string>();
            AddForbiddenPath(forbidden, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            AddForbiddenPath(forbidden, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            AddForbiddenPath(forbidden, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            AddForbiddenPath(forbidden, Path.GetTempPath());
            string systemDrive = Environment.GetEnvironmentVariable("SystemDrive");
            if (!string.IsNullOrWhiteSpace(systemDrive)) AddForbiddenPath(forbidden, Path.Combine(systemDrive + Path.DirectorySeparatorChar, "Users"));
            if (state != null)
            {
                AddForbiddenPath(forbidden, state.AdminProfilePath);
                AddForbiddenPath(forbidden, state.WorkerProfilePath);
            }
            AddRegisteredProfilePaths(forbidden);
            foreach (string path in forbidden)
            {
                if (AppPaths.IsPathInside(full, path))
                {
                    reason = "EXE 位于 Windows、ProgramData、临时目录或用户资料中，快捷方式不能作为权限绕过：" + path;
                    return true;
                }
            }

            string relative = full.Substring((Path.GetPathRoot(full) ?? string.Empty).Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string first = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)[0];
            string[] protectedNames = { "$Recycle.Bin", "System Volume Information", "Recovery" };
            foreach (string name in protectedNames)
            {
                if (string.Equals(first, name, StringComparison.OrdinalIgnoreCase))
                {
                    reason = "EXE 位于受保护的卷系统目录：" + first;
                    return true;
                }
            }
            return false;
        }

        private static void AddForbiddenPath(List<string> paths, string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            try
            {
                string full = AppPaths.NormalizeDirectoryPath(value);
                foreach (string existing in paths) if (AppPaths.PathsEqual(existing, full)) return;
                paths.Add(full);
            }
            catch { }
        }

        private static void AddRegisteredProfilePaths(List<string> paths)
        {
            const string profileList = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
            try
            {
                using (RegistryKey root = Registry.LocalMachine.OpenSubKey(profileList, false))
                {
                    if (root == null) return;
                    foreach (string sid in root.GetSubKeyNames())
                    {
                        using (RegistryKey entry = root.OpenSubKey(sid, false))
                        {
                            if (entry == null) continue;
                            object raw = entry.GetValue("ProfileImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                            if (raw != null) AddForbiddenPath(paths, Environment.ExpandEnvironmentVariables(Convert.ToString(raw)));
                        }
                    }
                }
            }
            catch { }
        }

        private static List<SecurityIdentifier> BuildUnsafeWriteSids(GuardState state)
        {
            List<SecurityIdentifier> unsafeSids = new List<SecurityIdentifier>
            {
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
                new SecurityIdentifier(WellKnownSidType.LocalSid, null),
                IdentityService.BuiltinUsersSid()
            };
            if (state != null && !string.IsNullOrWhiteSpace(state.WorkerSid)) AddUniqueSid(unsafeSids, new SecurityIdentifier(state.WorkerSid));
            if (state != null && !string.IsNullOrWhiteSpace(state.SandboxGroupSid)) AddUniqueSid(unsafeSids, new SecurityIdentifier(state.SandboxGroupSid));
            if (state != null && !string.IsNullOrWhiteSpace(state.WorkerSid))
            {
                foreach (string groupName in LocalAccountService.GetLocalGroupMemberships(AppInfo.WorkerAccountName))
                {
                    SecurityIdentifier groupSid;
                    string account = groupName.IndexOf('\\') >= 0 ? groupName : IdentityService.MachineAccount(groupName);
                    if (IdentityService.TryResolveSid(account, out groupSid)) AddUniqueSid(unsafeSids, groupSid);
                }
            }
            return unsafeSids;
        }

        private static string FindUnsafeWriteAllow(string path, bool directory, List<SecurityIdentifier> unsafeSids)
        {
            AuthorizationRuleCollection rules = directory
                ? Directory.GetAccessControl(path, AccessControlSections.Access).GetAccessRules(true, true, typeof(SecurityIdentifier))
                : File.GetAccessControl(path, AccessControlSections.Access).GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow || !AclService.RightsContainWriteLike(rule.FileSystemRights)) continue;
                SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                foreach (SecurityIdentifier unsafeSid in unsafeSids)
                {
                    if (ruleSid.Equals(unsafeSid))
                        return "共享目标或其父目录可被低权限/宽泛身份写入，拒绝建立快捷方式：" + path + "（" + ruleSid.Value + "）";
                }
            }
            return null;
        }

        private static void AddUniqueSid(List<SecurityIdentifier> values, SecurityIdentifier candidate)
        {
            if (candidate == null) return;
            foreach (SecurityIdentifier existing in values) if (existing.Equals(candidate)) return;
            values.Add(candidate);
        }

        private static List<string> SharedProgramRoots()
        {
            List<string> roots = new List<string>();
            AddUniqueExistingRoot(roots, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            AddUniqueExistingRoot(roots, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            AddUniqueExistingRoot(roots, Environment.GetEnvironmentVariable("ProgramW6432"));
            return roots;
        }

        private static void AddUniqueExistingRoot(List<string> roots, string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;
            string full = AppPaths.NormalizeDirectoryPath(path);
            foreach (string existing in roots) if (AppPaths.PathsEqual(existing, full)) return;
            roots.Add(full);
        }

        internal static string FindProfileSid(string profilePath)
        {
            return IdentityService.FindProfileSid(profilePath);
        }

        internal static string ParseDisplayIconPath(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            string text = Environment.ExpandEnvironmentVariables(value.Trim());
            if (text.StartsWith("@", StringComparison.Ordinal)) text = text.Substring(1).TrimStart();
            if (text.StartsWith("\"", StringComparison.Ordinal))
            {
                int close = text.IndexOf('\"', 1);
                if (close > 1) text = text.Substring(1, close - 1);
            }
            else
            {
                int exe = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                if (exe >= 0) text = text.Substring(0, exe + 4);
                else
                {
                    int comma = text.LastIndexOf(',');
                    if (comma > 0) text = text.Substring(0, comma);
                }
            }
            return NormalizePossiblePath(text);
        }

        private static string FindExecutable(string displayName, string displayIcon, string installLocation)
        {
            if (!string.IsNullOrWhiteSpace(displayIcon)
                && displayIcon.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                && File.Exists(displayIcon)
                && !IsUnsafeLauncher(displayName, displayIcon)) return displayIcon;
            if (string.IsNullOrWhiteSpace(installLocation) || !Directory.Exists(installLocation)) return null;
            try
            {
                List<string> viable = new List<string>();
                string normalizedName = NormalizeProductName(displayName);
                int inspected = 0;
                foreach (string path in Directory.GetFiles(installLocation, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    if (++inspected > MaximumExecutablesPerInstallDirectory) break;
                    string file = Path.GetFileNameWithoutExtension(path);
                    string lower = file.ToLowerInvariant();
                    if (lower.StartsWith("unins", StringComparison.Ordinal) || lower.Contains("uninstall")
                        || lower == "setup" || lower.Contains("updater") || lower.Contains("crash")
                        || lower.EndsWith("service", StringComparison.Ordinal) || lower.Contains("helper")) continue;
                    if (NormalizeProductName(file) == normalizedName) return path;
                    viable.Add(path);
                }
                return viable.Count == 1 ? viable[0] : null;
            }
            catch { return null; }
        }

        private static string NormalizeProductName(string value)
        {
            StringBuilder result = new StringBuilder();
            foreach (char c in value ?? string.Empty) if (char.IsLetterOrDigit(c)) result.Append(char.ToLowerInvariant(c));
            return result.ToString();
        }

        internal static bool IsUnsafeLauncher(string displayName, string executablePath)
        {
            string name = (displayName ?? string.Empty).Trim().ToLowerInvariant();
            string file = string.IsNullOrWhiteSpace(executablePath)
                ? string.Empty
                : Path.GetFileNameWithoutExtension(executablePath).ToLowerInvariant();
            string[] displayTokens = { "uninstall", "installer", "setup", "repair", "updater", "卸载", "安装程序", "修复程序", "更新程序" };
            foreach (string token in displayTokens) if (name.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            string[] fileTokens = { "unins", "uninstall", "installer", "setup", "repair", "updater", "update" };
            foreach (string token in fileTokens)
            {
                if (file == token || file.StartsWith(token, StringComparison.OrdinalIgnoreCase)
                    || file.EndsWith(token, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static string NormalizePossiblePath(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            string text = Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
            try { return Path.IsPathRooted(text) ? Path.GetFullPath(text) : text; }
            catch { return text; }
        }

        private static bool IsStoreLikePath(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;
            return value.IndexOf("\\WindowsApps\\", StringComparison.OrdinalIgnoreCase) >= 0
                || value.StartsWith("shell:AppsFolder", StringComparison.OrdinalIgnoreCase);
        }

        private static string ReadString(RegistryKey key, string name)
        {
            object raw = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return raw == null ? null : Environment.ExpandEnvironmentVariables(Convert.ToString(raw)).Trim();
        }

        private static int ReadInt(RegistryKey key, string name)
        {
            object raw = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            int result;
            return raw != null && int.TryParse(Convert.ToString(raw), out result) ? result : 0;
        }

        private static string ComputeInventoryId(string name, string publisher, string target, string source)
        {
            string input = (name ?? string.Empty).Trim().ToUpperInvariant() + "\n"
                + (publisher ?? string.Empty).Trim().ToUpperInvariant() + "\n"
                + (target ?? string.Empty).Trim().ToUpperInvariant() + "\n"
                + (source ?? string.Empty).Trim().ToUpperInvariant();
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
                StringBuilder text = new StringBuilder(24);
                for (int index = 0; index < 12; index++) text.Append(hash[index].ToString("x2"));
                return text.ToString();
            }
        }

        public static string CategoryText(SoftwareMappingCategory category)
        {
            switch (category)
            {
                case SoftwareMappingCategory.SharedReady: return "直接共用";
                case SoftwareMappingCategory.ShortcutRequired: return "创建快捷方式";
                case SoftwareMappingCategory.WorkerRegistrationRequired: return "现有包需注册";
                default: return "技术阻断";
            }
        }

        public static string ToCsv(SoftwareInventoryReport report)
        {
            if (report == null) throw new ArgumentNullException("report");
            StringBuilder csv = new StringBuilder();
            csv.AppendLine("分类,软件,版本,发布者,EXE,安装位置,本地安装源,本地安装源存在,安装技术,来源,范围,原因,建议");
            foreach (SoftwareInventoryItem item in report.Items)
            {
                string[] values =
                {
                    CategoryText(item.Category), item.DisplayName, item.Version, item.Publisher,
                    item.ExecutablePath, item.InstallLocation, item.LocalInstallSource,
                    item.LocalInstallSourceExists ? "是" : "否", item.IsWindowsInstaller ? "MSI" : "EXE/其他",
                    item.Source, item.Scope,
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

        private static bool LocalSourceExists(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try { return Directory.Exists(path) || File.Exists(path); }
            catch { return false; }
        }
    }
}
