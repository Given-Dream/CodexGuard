using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("Codex Guard Direct-Use Package")]
[assembly: AssemblyDescription("Self-extracting verified launcher for Codex Guard")]
[assembly: AssemblyCompany("Local")]
[assembly: AssemblyProduct("Codex Guard")]
[assembly: AssemblyCopyright("Copyright © 2026")]
[assembly: AssemblyVersion("0.6.7.0")]
[assembly: AssemblyFileVersion("0.6.7.0")]

namespace CodexGuard.Release
{
    internal static class ReleaseLauncher
    {
        private const string PayloadResourceName = "CodexGuard.Payload";
        private const string ProductVersion = "0.6.7";
        private const string MainExecutableName = "CodexGuard.exe";

        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                bool selfTest = args.Length == 2
                    && string.Equals(args[0], "--self-test", StringComparison.OrdinalIgnoreCase);
                string overrideCacheRoot = selfTest ? args[1] : null;
                string extractionDirectory = PreparePayload(overrideCacheRoot);
                string executable = Path.Combine(extractionDirectory, MainExecutableName);
                string childArguments = selfTest ? "--package-self-test" : JoinArguments(args);

                ProcessStartInfo start = new ProcessStartInfo();
                start.FileName = executable;
                start.Arguments = childArguments;
                start.WorkingDirectory = extractionDirectory;
                start.UseShellExecute = true;
                Process child = Process.Start(start);
                if (child == null) throw new InvalidOperationException("Codex Guard 主程序未能启动。");
                child.WaitForExit();
                return child.ExitCode;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "完整发布包无法启动。\r\n\r\n" + ex.Message
                    + "\r\n\r\n请重新下载 Release，并核对 SHA-256。",
                    "Codex Guard",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return 1;
            }
        }

        private static string PreparePayload(string overrideCacheRoot)
        {
            byte[] payload = ReadPayload();
            string payloadHash = ComputeHash(payload);
            string cacheRoot = string.IsNullOrWhiteSpace(overrideCacheRoot)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Codex Guard", "ReleaseCache")
                : Path.GetFullPath(overrideCacheRoot);
            Directory.CreateDirectory(cacheRoot);
            RejectReparsePoint(cacheRoot);

            string preferred = Path.Combine(cacheRoot, ProductVersion + "-" + payloadHash.Substring(0, 16));
            if (Directory.Exists(preferred))
            {
                if (ValidatePayload(payload, preferred)) return preferred;
                preferred += "-recovery-" + Guid.NewGuid().ToString("N");
            }

            Directory.CreateDirectory(preferred);
            RejectReparsePoint(preferred);
            ExtractPayload(payload, preferred);
            if (!ValidatePayload(payload, preferred))
                throw new InvalidDataException("自解压后的文件校验失败；未启动任何程序。");
            return preferred;
        }

        private static byte[] ReadPayload()
        {
            using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(PayloadResourceName))
            {
                if (input == null) throw new InvalidDataException("发布程序不包含完整载荷。");
                using (MemoryStream output = new MemoryStream())
                {
                    input.CopyTo(output);
                    return output.ToArray();
                }
            }
        }

        private static void ExtractPayload(byte[] payload, string destinationRoot)
        {
            string canonicalRoot = Path.GetFullPath(destinationRoot).TrimEnd(Path.DirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            HashSet<string> targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            using (MemoryStream memory = new MemoryStream(payload, false))
            using (ZipArchive archive = new ZipArchive(memory, ZipArchiveMode.Read, false))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                    if (string.IsNullOrWhiteSpace(relative)) continue;
                    if (Path.IsPathRooted(relative) || relative.IndexOf(':') >= 0)
                        throw new InvalidDataException("发布包包含不安全的绝对路径：" + entry.FullName);

                    string target = Path.GetFullPath(Path.Combine(destinationRoot, relative));
                    if (!target.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("发布包包含越界路径：" + entry.FullName);
                    if (!targets.Add(target))
                        throw new InvalidDataException("发布包包含重复路径：" + entry.FullName);

                    if (string.IsNullOrEmpty(entry.Name))
                    {
                        Directory.CreateDirectory(target);
                        RejectReparsePoint(target);
                        continue;
                    }

                    string parent = Path.GetDirectoryName(target);
                    if (string.IsNullOrEmpty(parent)) throw new InvalidDataException("发布文件没有父目录。");
                    Directory.CreateDirectory(parent);
                    RejectReparsePoint(parent);
                    using (Stream input = entry.Open())
                    using (FileStream output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        input.CopyTo(output);
                        output.Flush(true);
                    }
                }
            }
        }

        private static bool ValidatePayload(byte[] payload, string destinationRoot)
        {
            try
            {
                RejectReparsePoint(destinationRoot);
                string canonicalRoot = Path.GetFullPath(destinationRoot).TrimEnd(Path.DirectorySeparatorChar)
                    + Path.DirectorySeparatorChar;
                using (MemoryStream memory = new MemoryStream(payload, false))
                using (ZipArchive archive = new ZipArchive(memory, ZipArchiveMode.Read, false))
                {
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        if (string.IsNullOrEmpty(entry.Name)) continue;
                        string relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                        if (Path.IsPathRooted(relative) || relative.IndexOf(':') >= 0) return false;
                        string target = Path.GetFullPath(Path.Combine(destinationRoot, relative));
                        if (!target.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase)) return false;
                        if (!File.Exists(target) || (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0) return false;
                        FileInfo file = new FileInfo(target);
                        if (file.Length != entry.Length) return false;
                        using (Stream expected = entry.Open())
                        using (FileStream actual = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            if (!HashesEqual(expected, actual)) return false;
                        }
                    }
                }
                return File.Exists(Path.Combine(destinationRoot, MainExecutableName))
                    && File.Exists(Path.Combine(destinationRoot, "CodexGuard.ReadOnlyVerifier.exe"))
                    && File.Exists(Path.Combine(destinationRoot, "CodexGuard.AcceptanceProbe.exe"))
                    && File.Exists(Path.Combine(destinationRoot, "SHA256SUMS.txt"));
            }
            catch
            {
                return false;
            }
        }

        private static bool HashesEqual(Stream left, Stream right)
        {
            using (SHA256 algorithm = SHA256.Create())
            {
                byte[] leftHash = algorithm.ComputeHash(left);
                byte[] rightHash = algorithm.ComputeHash(right);
                if (leftHash.Length != rightHash.Length) return false;
                int difference = 0;
                for (int index = 0; index < leftHash.Length; index++) difference |= leftHash[index] ^ rightHash[index];
                return difference == 0;
            }
        }

        private static string ComputeHash(byte[] bytes)
        {
            using (SHA256 algorithm = SHA256.Create())
            {
                byte[] hash = algorithm.ComputeHash(bytes);
                StringBuilder text = new StringBuilder(hash.Length * 2);
                foreach (byte value in hash) text.Append(value.ToString("x2"));
                return text.ToString();
            }
        }

        private static void RejectReparsePoint(string path)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("发布缓存目录不能是符号链接或联接点：" + path);
        }

        private static string JoinArguments(string[] args)
        {
            if (args == null || args.Length == 0) return string.Empty;
            StringBuilder result = new StringBuilder();
            for (int index = 0; index < args.Length; index++)
            {
                if (index > 0) result.Append(' ');
                result.Append(QuoteArgument(args[index]));
            }
            return result.ToString();
        }

        private static string QuoteArgument(string value)
        {
            if (value == null) value = string.Empty;
            if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return value;

            StringBuilder result = new StringBuilder();
            result.Append('"');
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
                    result.Append('\\', backslashes * 2 + 1);
                    result.Append('"');
                    backslashes = 0;
                    continue;
                }
                result.Append('\\', backslashes);
                backslashes = 0;
                result.Append(character);
            }
            result.Append('\\', backslashes * 2);
            result.Append('"');
            return result.ToString();
        }
    }
}
