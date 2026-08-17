using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace CodexGuard.Core
{
    internal static class ShortcutService
    {
        internal const string ObsoleteWorkerCodexShortcutName = "Codex (CodexWorker).lnk";
        internal const string ObsoleteWorkerCodexArguments = "--launch-codex-as-worker";

        public static string CreateStartMenuShortcut()
        {
            string programs = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
            string folder = Path.Combine(programs, AppInfo.ProductName);
            Directory.CreateDirectory(folder);
            string shortcutPath = Path.Combine(folder, AppInfo.ProductName + ".lnk");
            return CreateShortcut(shortcutPath, AppPaths.InstalledExecutable, string.Empty, "Codex Guard workspace permission manager");
        }

        public static string CreateCommonDesktopShortcut()
        {
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
            if (string.IsNullOrWhiteSpace(desktop)) throw new InvalidOperationException("The common Windows desktop directory is unavailable.");
            Directory.CreateDirectory(desktop);
            return CreateShortcut(Path.Combine(desktop, AppInfo.ProductName + ".lnk"), AppPaths.InstalledExecutable, string.Empty, "Codex Guard workspace permission manager");
        }

        public static string FindObsoleteWorkerCodexCommonDesktopShortcut()
        {
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
            if (string.IsNullOrWhiteSpace(desktop)) throw new InvalidOperationException("The common Windows desktop directory is unavailable.");
            string shortcutPath = Path.Combine(desktop, ObsoleteWorkerCodexShortcutName);
            if (!File.Exists(shortcutPath)) return null;

            string target;
            string arguments;
            if (!TryResolveShortcutFacts(shortcutPath, out target, out arguments)
                || !IsObsoleteWorkerCodexShortcutFacts(target, arguments))
                throw new InvalidDataException("同名快捷方式不是 Codex Guard 创建的旧 Worker 启动入口；已保留，请 admin 人工核查：" + shortcutPath);
            if ((File.GetAttributes(shortcutPath) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("旧 Worker 启动快捷方式是重解析点；已保留，请 admin 人工核查：" + shortcutPath);

            return shortcutPath;
        }

        internal static bool IsObsoleteWorkerCodexShortcutFacts(string targetPath, string arguments)
        {
            if (string.IsNullOrWhiteSpace(targetPath)) return false;
            return AppPaths.PathsEqual(targetPath, AppPaths.InstalledExecutable)
                && string.Equals((arguments ?? string.Empty).Trim(), ObsoleteWorkerCodexArguments, StringComparison.Ordinal);
        }

        public static string CreateMappedSoftwareCommonStartMenuShortcut(string displayName, string targetPath, string publisher)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required to create a public software shortcut.");
            string safeName = SanitizeShortcutName(displayName);
            string target = Path.GetFullPath(targetPath);
            if (!File.Exists(target)) throw new FileNotFoundException("The mapped software executable no longer exists.", target);

            AclService.SecureApplicationDirectory(AppPaths.MappedSoftwareProgramsDirectory, true);
            string shortcutPath = FindAvailableShortcutPath(safeName, target);
            if (File.Exists(shortcutPath))
            {
                AclService.SecureApplicationFile(shortcutPath, true);
                return shortcutPath;
            }

            string description = "Shared for CodexWorker by Codex Guard";
            if (!string.IsNullOrWhiteSpace(publisher)) description += " — " + publisher.Trim();
            string created = CreateShortcut(shortcutPath, target, string.Empty, description);
            AclService.SecureApplicationFile(created, true);
            return created;
        }

        public static string CreateWorkerOfflineReuseShortcut(GuardState state, string displayName, string targetPath, string publisher)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required to create a Worker shortcut.");
            if (state == null || string.IsNullOrWhiteSpace(state.WorkerSid)) throw new InvalidOperationException("CodexWorker identity is missing from protected state.");
            SecurityIdentifier worker = new SecurityIdentifier(state.WorkerSid);
            SecurityIdentifier sandbox = string.IsNullOrWhiteSpace(state.SandboxGroupSid) ? null : new SecurityIdentifier(state.SandboxGroupSid);
            string target = Path.GetFullPath(targetPath);
            string workerPrograms = AppPaths.WorkerLocalProgramsDirectory(state);
            if (!File.Exists(target) || !AppPaths.IsPathInside(target, workerPrograms))
                throw new InvalidDataException("Worker 快捷方式目标不在固定 Local\\Programs 边界内。");

            string folder = AppPaths.WorkerOfflineReuseProgramsDirectory(state);
            Directory.CreateDirectory(folder);
            AclService.SecureWorkerApplicationDirectory(folder, worker, sandbox);
            string safeName = SanitizeShortcutName(displayName);
            string shortcutPath = Path.Combine(folder, safeName + ".lnk");
            if (File.Exists(shortcutPath))
            {
                string existing = TryResolveShortcutTarget(shortcutPath);
                if (string.IsNullOrWhiteSpace(existing) || !AppPaths.PathsEqual(existing, target))
                    throw new IOException("Worker 快捷方式名称已被其他目标占用；Codex Guard 不会覆盖：" + shortcutPath);
                AclService.SecureWorkerApplicationFile(shortcutPath, worker, sandbox);
                return shortcutPath;
            }

            string description = "Offline application copy prepared for CodexWorker by Codex Guard";
            if (!string.IsNullOrWhiteSpace(publisher)) description += " — " + publisher.Trim();
            string created = CreateShortcut(shortcutPath, target, string.Empty, description);
            AclService.SecureWorkerApplicationFile(created, worker, sandbox);
            return created;
        }

        internal static string SanitizeShortcutName(string value)
        {
            string input = string.IsNullOrWhiteSpace(value) ? "Shared software" : value.Trim();
            StringBuilder output = new StringBuilder(input.Length);
            foreach (char character in input)
            {
                bool invalid = character < 32 || Array.IndexOf(Path.GetInvalidFileNameChars(), character) >= 0;
                output.Append(invalid ? '_' : character);
            }
            string result = output.ToString().Trim().TrimEnd('.');
            if (result.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) result = result.Substring(0, result.Length - 4).TrimEnd();
            if (result.Length == 0) result = "Shared software";
            if (result.Length > 96) result = result.Substring(0, 96).TrimEnd();
            string upper = result.ToUpperInvariant();
            string[] reserved = { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
            foreach (string name in reserved)
                if (upper == name) return result + " application";
            return result;
        }

        internal static string TryResolveShortcutTarget(string shortcutPath)
        {
            string target;
            string arguments;
            return TryResolveShortcutFacts(shortcutPath, out target, out arguments) ? target : null;
        }

        internal static bool TryResolveShortcutFacts(string shortcutPath, out string target, out string arguments)
        {
            target = null;
            arguments = null;
            if (string.IsNullOrWhiteSpace(shortcutPath) || !File.Exists(shortcutPath)) return false;
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return false;
            object shell = null;
            object shortcut = null;
            try
            {
                shell = Activator.CreateInstance(shellType);
                shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { shortcutPath });
                Type shortcutType = shortcut.GetType();
                object rawTarget = shortcutType.InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, null);
                object rawArguments = shortcutType.InvokeMember("Arguments", BindingFlags.GetProperty, null, shortcut, null);
                string resolvedTarget = Convert.ToString(rawTarget);
                if (string.IsNullOrWhiteSpace(resolvedTarget)) return false;
                target = Environment.ExpandEnvironmentVariables(resolvedTarget.Trim());
                arguments = Convert.ToString(rawArguments) ?? string.Empty;
                return true;
            }
            catch
            {
                target = null;
                arguments = null;
                return false;
            }
            finally
            {
                if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
                if (shell != null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
            }
        }

        private static string FindAvailableShortcutPath(string displayName, string targetPath)
        {
            for (int index = 0; index <= 100; index++)
            {
                string suffix = index == 0 ? string.Empty : " (" + (index + 1) + ")";
                string path = Path.Combine(AppPaths.MappedSoftwareProgramsDirectory, displayName + suffix + ".lnk");
                if (!File.Exists(path)) return path;
                string existing = TryResolveShortcutTarget(path);
                if (!string.IsNullOrWhiteSpace(existing) && AppPaths.PathsEqual(existing, targetPath)) return path;
            }
            throw new IOException("Too many public shortcut name collisions for: " + displayName);
        }

        private static string CreateShortcut(string shortcutPath, string targetPath, string arguments, string description)
        {
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) throw new InvalidOperationException("Windows Script Host shortcut support is unavailable.");
            object shell = null;
            object shortcut = null;
            try
            {
                shell = Activator.CreateInstance(shellType);
                shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { shortcutPath });
                Type shortcutType = shortcut.GetType();
                shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { targetPath });
                shortcutType.InvokeMember("Arguments", BindingFlags.SetProperty, null, shortcut, new object[] { arguments ?? string.Empty });
                shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { Path.GetDirectoryName(targetPath) });
                shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { description ?? string.Empty });
                shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { targetPath + ",0" });
                shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
                return shortcutPath;
            }
            finally
            {
                if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
                if (shell != null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
            }
        }
    }
}
