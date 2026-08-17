using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace CodexGuard.Core
{
    internal static class ElevationService
    {
        public static int RunInstalledRequest(string requestPath)
        {
            AssertInstalledExecutableMatchesCurrentVersion("changing permissions");
            return RunElevated(AppPaths.InstalledExecutable, "--admin-request " + QuoteArgument(Path.GetFullPath(requestPath)));
        }

        public static int RunAdminInstall()
        {
            return RunElevated(AppPaths.CurrentExecutable, "--admin-install");
        }

        public static int RunInstalledSoftwareMappingRequest(string requestPath)
        {
            AssertInstalledExecutableMatchesCurrentVersion("creating public software shortcuts");
            return RunElevated(AppPaths.InstalledExecutable, "--admin-map-software " + QuoteArgument(Path.GetFullPath(requestPath)));
        }

        public static int RunInstalledOfflineReuseRequest(string requestPath)
        {
            AssertInstalledExecutableMatchesCurrentVersion("preparing local application copies");
            return RunElevated(AppPaths.InstalledExecutable, "--admin-offline-reuse " + QuoteArgument(Path.GetFullPath(requestPath)));
        }

        public static bool InstalledExecutableMatchesCurrentVersion(out string installedVersion)
        {
            installedVersion = null;
            if (!File.Exists(AppPaths.InstalledExecutable)) return false;
            try
            {
                installedVersion = FileVersionInfo.GetVersionInfo(AppPaths.InstalledExecutable).FileVersion;
                return VersionMatches(installedVersion, AppInfo.Version);
            }
            catch
            {
                return false;
            }
        }

        internal static bool VersionMatches(string installedVersion, string currentVersion)
        {
            Version installed;
            Version current;
            if (!Version.TryParse(installedVersion, out installed) || !Version.TryParse(currentVersion, out current)) return false;
            return installed.Major == current.Major
                && installed.Minor == current.Minor
                && installed.Build == current.Build
                && Math.Max(installed.Revision, 0) == Math.Max(current.Revision, 0);
        }

        private static void AssertInstalledExecutableMatchesCurrentVersion(string action)
        {
            if (!File.Exists(AppPaths.InstalledExecutable))
                throw new FileNotFoundException("Install Codex Guard before " + action + ".", AppPaths.InstalledExecutable);
            string installedVersion;
            if (InstalledExecutableMatchesCurrentVersion(out installedVersion)) return;
            throw new InvalidOperationException(
                "当前界面版本为 " + AppInfo.Version + "，受保护安装版为 " + (string.IsNullOrWhiteSpace(installedVersion) ? "未知版本" : installedVersion) + "。\r\n\r\n"
                + "为防止新旧权限逻辑混用，本次操作已停止。请打开“迁移与部署”，点击“安装 / 修复 Codex Guard”完成升级，然后关闭当前窗口并从公共快捷方式重新打开。");
        }

        private static int RunElevated(string executable, string arguments)
        {
            ProcessStartInfo start = new ProcessStartInfo
            {
                FileName = executable,
                Arguments = arguments,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(executable),
                WindowStyle = ProcessWindowStyle.Normal
            };
            try
            {
                using (Process process = Process.Start(start))
                {
                    process.WaitForExit();
                    return process.ExitCode;
                }
            }
            catch (Win32Exception ex)
            {
                if (ex.NativeErrorCode == 1223) throw new OperationCanceledException("Windows UAC elevation was canceled.", ex);
                throw;
            }
        }

        internal static string QuoteArgument(string value)
        {
            if (value == null) return "\"\"";
            if (value.IndexOf('\0') >= 0) throw new ArgumentException("Command-line arguments cannot contain NUL characters.", "value");

            // Follow the CommandLineToArgvW/CRT quoting rules. In particular, normal
            // path separators must not be doubled, while a run of backslashes before
            // a quote (or the closing quote) must be doubled.
            StringBuilder quoted = new StringBuilder(value.Length + 2);
            quoted.Append('"');
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }

                if (character == '"')
                {
                    quoted.Append('\\', backslashes * 2 + 1);
                    quoted.Append('"');
                }
                else
                {
                    quoted.Append('\\', backslashes);
                    quoted.Append(character);
                }
                backslashes = 0;
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }
    }
}
