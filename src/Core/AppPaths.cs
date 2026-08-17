using System;
using System.IO;
using System.Reflection;

namespace CodexGuard.Core
{
    internal static class AppPaths
    {
        public static string InstallDirectory
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), AppInfo.ProductName); }
        }

        public static string InstalledExecutable
        {
            get { return Path.Combine(InstallDirectory, AppInfo.ExecutableName); }
        }

        public static string InstalledReviewerExecutable
        {
            get { return Path.Combine(InstallDirectory, AppInfo.ReviewerExecutableName); }
        }

        public static string InstalledAcceptanceExecutable
        {
            get { return Path.Combine(InstallDirectory, AppInfo.AcceptanceExecutableName); }
        }

        public static string DataDirectory
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppInfo.ProductName); }
        }

        public static string StateFile
        {
            get { return Path.Combine(DataDirectory, "state.json"); }
        }

        public static string HistoryDirectory
        {
            get { return Path.Combine(DataDirectory, "History"); }
        }

        public static string LogsDirectory
        {
            get { return Path.Combine(DataDirectory, "Logs"); }
        }

        public static string DeleteRequestsDirectory
        {
            get { return Path.Combine(DataDirectory, "DeleteRequests"); }
        }

        public static string OfflineReuseHistoryDirectory
        {
            get { return Path.Combine(DataDirectory, "OfflineReuse"); }
        }

        public static string MappedSoftwareProgramsDirectory
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
                    "Codex Guard - Shared Software");
            }
        }

        public static string CurrentRequestDirectory
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppInfo.ProductName, "Requests"); }
        }

        public static string WorkerLocalProgramsDirectory(GuardState state)
        {
            string profile = ValidateWorkerProfile(state);
            return Path.Combine(profile, "AppData", "Local", "Programs");
        }

        public static string WorkerOfflineReuseProgramsDirectory(GuardState state)
        {
            string profile = ValidateWorkerProfile(state);
            return Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Codex Guard - Offline Reuse");
        }

        private static string ValidateWorkerProfile(GuardState state)
        {
            if (state == null || string.IsNullOrWhiteSpace(state.WorkerSid))
                throw new InvalidOperationException("Codex Guard 尚未记录 CodexWorker SID。");
            string registered = IdentityService.GetProfilePathForSid(state.WorkerSid);
            string expected = string.IsNullOrWhiteSpace(state.WorkerProfilePath) ? registered : state.WorkerProfilePath;
            if (string.IsNullOrWhiteSpace(registered) || string.IsNullOrWhiteSpace(expected) || !PathsEqual(registered, expected))
                throw new InvalidOperationException("CodexWorker 用户资料路径缺失或与 Windows 注册信息不一致；请先安装/修复 Codex Guard。");
            return NormalizeDirectoryPath(expected);
        }

        public static string CurrentExecutable
        {
            get { return Path.GetFullPath(Assembly.GetExecutingAssembly().Location); }
        }

        public static string SystemRequirementsFile
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OpenAI", "Codex", "requirements.toml"); }
        }

        public static bool IsInstalledExecutable()
        {
            return PathsEqual(CurrentExecutable, InstalledExecutable);
        }

        public static bool PathsEqual(string left, string right)
        {
            if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right)) return false;
            string a = NormalizeDirectoryPath(left);
            string b = NormalizeDirectoryPath(right);
            return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsPathInside(string child, string parent)
        {
            if (string.IsNullOrWhiteSpace(child) || string.IsNullOrWhiteSpace(parent)) return false;
            string normalizedChild = NormalizeDirectoryPath(child);
            string normalizedParent = NormalizeDirectoryPath(parent);
            if (string.Equals(normalizedChild, normalizedParent, StringComparison.OrdinalIgnoreCase)) return true;
            string prefix = normalizedParent.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? normalizedParent
                : normalizedParent + Path.DirectorySeparatorChar;
            return normalizedChild.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        public static string NormalizeDirectoryPath(string value)
        {
            string full = Path.GetFullPath(value);
            string root = Path.GetPathRoot(full);
            string trimmed = full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string trimmedRoot = (root ?? string.Empty).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (string.Equals(trimmed, trimmedRoot, StringComparison.OrdinalIgnoreCase)) return root;
            return trimmed;
        }
    }
}
