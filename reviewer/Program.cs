using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace CodexGuard.ReadOnlyVerifier
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ReviewerForm());
        }
    }

    internal sealed class ReviewerForm : Form
    {
        private readonly TextBox _report;
        private readonly Label _status;

        public ReviewerForm()
        {
            Text = "Codex Guard 独立只读核查器";
            Width = 1040;
            Height = 760;
            MinimumSize = new Size(820, 580);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9F);

            Label explanation = new Label
            {
                Dock = DockStyle.Top,
                Height = 76,
                Padding = new Padding(16, 10, 16, 8),
                BackColor = Color.FromArgb(236, 244, 252),
                ForeColor = Color.FromArgb(21, 37, 61),
                Text = "本程序不引用 Codex Guard 的权限/审计代码，只读取固定系统位置、注册表、SID、文件哈希和 ACL。\r\n"
                    + "它不会创建账户、修改 UAC、写 ACL、移动、重命名或删除任何目标；只有点击“保存报告”才写入您选择的新报告文件。"
            };
            _report = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Both,
                WordWrap = false,
                Font = new Font("Consolas", 9F),
                BackColor = Color.White
            };
            Button refresh = new Button { Text = "重新读取", AutoSize = true, MinimumSize = new Size(100, 34) };
            Button save = new Button { Text = "保存报告", AutoSize = true, MinimumSize = new Size(100, 34) };
            _status = new Label { AutoSize = true, Padding = new Padding(10, 8, 10, 0), ForeColor = Color.FromArgb(92, 104, 120) };
            refresh.Click += delegate { RefreshReport(); };
            save.Click += SaveReport;
            FlowLayoutPanel footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 54, Padding = new Padding(10, 9, 10, 7) };
            footer.Controls.Add(refresh);
            footer.Controls.Add(save);
            footer.Controls.Add(_status);
            Controls.Add(_report);
            Controls.Add(footer);
            Controls.Add(explanation);
            Shown += delegate { RefreshReport(); };
        }

        private void RefreshReport()
        {
            try
            {
                _report.Text = RawFactReader.Capture();
                _status.Text = "只读快照已刷新：" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch (Exception ex)
            {
                _report.Text = "独立核查器读取失败。没有修改系统。\r\n\r\n" + ex;
                _status.Text = "读取失败";
            }
        }

        private void SaveReport(object sender, EventArgs e)
        {
            using (SaveFileDialog dialog = new SaveFileDialog())
            {
                dialog.Filter = "文本核查报告 (*.txt)|*.txt";
                dialog.FileName = "CodexGuard-independent-review-" + Environment.MachineName + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt";
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllText(dialog.FileName, _report.Text, new UTF8Encoding(false));
                MessageBox.Show("报告已保存到：\r\n" + dialog.FileName, "保存完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
    }

    internal static class RawFactReader
    {
        private const string WorkerName = "CodexWorker";
        private const string SandboxGroupName = "CodexSandboxUsers";
        private const string UacKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        private const int MaximumStateBytes = 16 * 1024 * 1024;

        public static string Capture()
        {
            StringBuilder text = new StringBuilder();
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string executable = Path.Combine(programFiles, "Codex Guard", "CodexGuard.exe");
            string reviewer = Path.Combine(programFiles, "Codex Guard", "CodexGuard.ReadOnlyVerifier.exe");
            string probe = Path.Combine(programFiles, "Codex Guard", "CodexGuard.AcceptanceProbe.exe");
            string statePath = Path.Combine(programData, "Codex Guard", "state.json");
            string requirements = Path.Combine(programData, "OpenAI", "Codex", "requirements.toml");

            Line(text, "CODEX GUARD INDEPENDENT READ-ONLY FACT SNAPSHOT");
            Line(text, "Generated UTC : " + DateTime.UtcNow.ToString("o"));
            Line(text, "Machine       : " + Environment.MachineName);
            Line(text, "Current user  : " + Environment.UserDomainName + "\\" + Environment.UserName);
            Line(text, "Current SID   : " + CurrentSid());
            Line(text, "Scope         : READ ONLY. No access attempt and no safety conclusion is made.");
            Section(text, "人工比较基准（不要只看 Codex Guard 自己的绿色结论）");
            Line(text, "1. UAC raw values must be EnableLUA=1, PromptOnSecureDesktop=1, ConsentPromptBehaviorUser=1.");
            Line(text, "2. CodexWorker must not belong to Administrators, Backup Operators, Power Users, Account Operators, Server Operators, or Print Operators.");
            Line(text, "3. requirements.toml must actively contain allow_login_shell=false, elevated-only, and sandbox_private_desktop=true.");
            Line(text, "4. state machine/SIDs must equal the independently resolved machine/SIDs.");
            Line(text, "5. Active paths need explicit Allow(ReadAndExecute|Write|Synchronize) and Deny(Delete|DeleteChild|WRITE_DAC|WRITE_OWNER) for both actors.");
            Line(text, "6. Every guarded root needs inheritable OWNER RIGHTS (S-1-3-4) Allow(ReadPermissions|Synchronize only), which suppresses an owner's implicit WRITE_DAC.");
            Line(text, "7. The only administrator-profile boundary is C:\\Users\\admin. Any other legacy ProtectedRoots entry is disabled and requires manual ACL review.");
            Line(text, "8. DefaultReadOnlyEnabled must be true. Default boundaries need actor-specific inheritable Deny(Write|Delete|DeleteChild|WRITE_DAC|WRITE_OWNER); root locks must be this-folder-only.");
            Line(text, "9. Writable exceptions must be exactly Worker AppData, .codex, and an already-existing .cache. No Desktop, Downloads, drive, or custom exception is valid.");
            Line(text, "10. This snapshot is not an effective-access test. Complete both probe modes in docs/MANUAL_REVIEW.md on disposable copies.");

            Section(text, "UAC RAW REGISTRY VALUES");
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(UacKey, false))
            {
                Line(text, "EnableLUA=" + RegistryValue(key, "EnableLUA"));
                Line(text, "PromptOnSecureDesktop=" + RegistryValue(key, "PromptOnSecureDesktop"));
                Line(text, "ConsentPromptBehaviorUser=" + RegistryValue(key, "ConsentPromptBehaviorUser"));
            }

            Section(text, "INDEPENDENT IDENTITY RESOLUTION");
            SecurityIdentifier worker = ResolveMachineSid(WorkerName, text);
            SecurityIdentifier sandbox = ResolveMachineSid(SandboxGroupName, text);
            if (worker != null)
            {
                List<string> groups = LocalGroups.Read(WorkerName);
                Line(text, "CodexWorker local groups: " + (groups.Count == 0 ? "<none>" : string.Join(", ", groups.ToArray())));
                foreach (string group in groups)
                {
                    SecurityIdentifier groupSid = TryResolve(Environment.MachineName + "\\" + group);
                    Line(text, "  group SID: " + group + " = " + (groupSid == null ? "<unresolved>" : groupSid.Value)
                        + (IsPrivileged(groupSid) ? "  <<< PRIVILEGED" : string.Empty));
                }
            }

            Section(text, "FIXED FILE FACTS");
            AppendFile(text, Assembly.GetExecutingAssembly().Location);
            AppendFile(text, executable);
            AppendFile(text, reviewer);
            AppendFile(text, probe);
            AppendFile(text, statePath);
            AppendFile(text, requirements);

            Section(text, "REQUIREMENTS ACTIVE LINES");
            if (File.Exists(requirements))
            {
                foreach (string raw in File.ReadAllLines(requirements, Encoding.UTF8))
                {
                    string line = StripComment(raw).Trim();
                    if (line.Length > 0) Line(text, line);
                }
            }
            else Line(text, "<missing>");

            ReviewerState state = ReadState(statePath, text);
            if (state != null)
            {
                Section(text, "STATE IDENTITY FACTS");
                Line(text, "MachineName=" + NullText(state.MachineName));
                Line(text, "WorkerSid=" + NullText(state.WorkerSid) + CompareSid(state.WorkerSid, worker));
                Line(text, "SandboxGroupSid=" + NullText(state.SandboxGroupSid) + CompareSid(state.SandboxGroupSid, sandbox));
                Line(text, "AdminProfilePath=" + NullText(state.AdminProfilePath));
                Line(text, "WorkerProfilePath=" + NullText(state.WorkerProfilePath));
                ReviewerDirectory adminBoundary = FixedAdminBoundary(state);
                int legacyRoots = Count(state.ProtectedRoots) - (adminBoundary == null ? 0 : 1);
                Line(text, "FixedAdminBoundary=" + (adminBoundary == null ? "MISSING" : NullText(adminBoundary.CanonicalPath))
                    + "; LegacyProtectedRoots=" + legacyRoots + "; ActivatedDirectories=" + Count(state.ActivatedDirectories));
                Line(text, "DefaultReadOnlyEnabled=" + state.DefaultReadOnlyEnabled + "; AppliedAtUtc=" + NullText(state.DefaultReadOnlyAppliedAtUtc));
                Line(text, "DefaultReadOnlyDirectories=" + Count(state.DefaultReadOnlyDirectories)
                    + "; DefaultReadOnlyRootLocks=" + Count(state.DefaultReadOnlyRootLocks)
                    + "; WritableExceptionPaths=" + Count(state.WritableExceptionPaths));

                Section(text, "FIXED ADMINISTRATOR-PROFILE ACL FACTS");
                AppendDirectory(text, adminBoundary == null ? null : adminBoundary.CanonicalPath);
                Section(text, "DISABLED LEGACY PROTECTION-ROOT FACTS");
                foreach (ReviewerDirectory item in state.ProtectedRoots ?? new List<ReviewerDirectory>())
                {
                    if (item == adminBoundary) continue;
                    AppendDirectory(text, item == null ? null : item.CanonicalPath);
                }
                Section(text, "DEFAULT READ-ONLY BOUNDARY ACL FACTS");
                foreach (ReviewerDirectory item in state.DefaultReadOnlyDirectories ?? new List<ReviewerDirectory>()) AppendDirectory(text, item == null ? null : item.CanonicalPath);
                Section(text, "ROOT-ONLY LOCK ACL FACTS");
                foreach (ReviewerDirectory item in state.DefaultReadOnlyRootLocks ?? new List<ReviewerDirectory>()) AppendDirectory(text, item == null ? null : item.CanonicalPath);
                Section(text, "WRITABLE EXCEPTION FACTS");
                foreach (string path in state.WritableExceptionPaths ?? new List<string>())
                    Line(text, "WRITABLE " + NullText(path) + " | fixed allowlist=" + FixedWritableException(path, state.WorkerProfilePath));
                Section(text, "ACTIVE DIRECTORY ACL FACTS");
                foreach (ReviewerDirectory item in state.ActivatedDirectories ?? new List<ReviewerDirectory>())
                {
                    string active = item == null ? null : item.CanonicalPath;
                    string boundary = StrictlyInside(active, adminBoundary == null ? null : adminBoundary.CanonicalPath);
                    if (string.Equals(boundary, "NO", StringComparison.Ordinal)) boundary = StrictlyInsideAny(active, state.DefaultReadOnlyDirectories);
                    Line(text, "Strict descendant of the fixed admin/default boundary: " + boundary);
                    AppendDirectory(text, active);
                }
            }
            Section(text, "END");
            Line(text, "Compare this raw snapshot with the HTML/JSON generated by Codex Guard. Any mismatch is a STOP condition.");
            return text.ToString();
        }

        private static ReviewerState ReadState(string path, StringBuilder text)
        {
            if (!File.Exists(path))
            {
                Section(text, "STATE JSON");
                Line(text, "<missing>");
                return null;
            }
            FileInfo info = new FileInfo(path);
            if (info.Length <= 0 || info.Length > MaximumStateBytes)
            {
                Section(text, "STATE JSON");
                Line(text, "<invalid size: " + info.Length + ">");
                return null;
            }
            try
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(ReviewerState));
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    return (ReviewerState)serializer.ReadObject(stream);
            }
            catch (Exception ex)
            {
                Section(text, "STATE JSON");
                Line(text, "<parse failed: " + ex.Message + ">");
                return null;
            }
        }

        private static void AppendFile(StringBuilder text, string path)
        {
            Line(text, "FILE " + path);
            if (!File.Exists(path))
            {
                Line(text, "  <missing>");
                return;
            }
            try
            {
                FileSecurity security = File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
                Line(text, "  SHA256=" + Hash(path));
                AppendSecurity(text, security);
            }
            catch (Exception ex) { Line(text, "  <read failed: " + ex.Message + ">"); }
        }

        private static void AppendDirectory(StringBuilder text, string path)
        {
            Line(text, "DIR " + NullText(path));
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
            {
                Line(text, "  <missing>");
                return;
            }
            try
            {
                DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
                AppendSecurity(text, security);
            }
            catch (Exception ex) { Line(text, "  <read failed: " + ex.Message + ">"); }
        }

        private static void AppendSecurity(StringBuilder text, FileSystemSecurity security)
        {
            IdentityReference owner = security.GetOwner(typeof(SecurityIdentifier));
            Line(text, "  Owner=" + owner.Value);
            Line(text, "  SDDL=" + security.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access));
            AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                Line(text, "  ACE " + rule.AccessControlType + " SID=" + rule.IdentityReference.Value
                    + " Rights=" + ((long)rule.FileSystemRights) + " [" + rule.FileSystemRights + "]"
                    + " Inheritance=" + rule.InheritanceFlags + " Propagation=" + rule.PropagationFlags
                    + " IsInherited=" + rule.IsInherited);
            }
        }

        private static string Hash(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                byte[] bytes = sha.ComputeHash(stream);
                StringBuilder value = new StringBuilder(bytes.Length * 2);
                foreach (byte item in bytes) value.Append(item.ToString("x2"));
                return value.ToString();
            }
        }

        private static SecurityIdentifier ResolveMachineSid(string name, StringBuilder text)
        {
            SecurityIdentifier sid = TryResolve(Environment.MachineName + "\\" + name);
            Line(text, name + " SID=" + (sid == null ? "<unresolved>" : sid.Value));
            return sid;
        }

        private static SecurityIdentifier TryResolve(string account)
        {
            try { return (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier)); }
            catch { return null; }
        }

        private static bool IsPrivileged(SecurityIdentifier sid)
        {
            if (sid == null) return false;
            WellKnownSidType[] types =
            {
                WellKnownSidType.BuiltinAdministratorsSid,
                WellKnownSidType.BuiltinPowerUsersSid,
                WellKnownSidType.BuiltinBackupOperatorsSid,
                WellKnownSidType.BuiltinAccountOperatorsSid,
                WellKnownSidType.BuiltinSystemOperatorsSid,
                WellKnownSidType.BuiltinPrintOperatorsSid
            };
            foreach (WellKnownSidType type in types) if (sid.Equals(new SecurityIdentifier(type, null))) return true;
            return false;
        }

        private static string StrictlyInsideAny(string child, List<ReviewerDirectory> roots)
        {
            if (string.IsNullOrWhiteSpace(child) || roots == null) return "NO";
            foreach (ReviewerDirectory item in roots)
            {
                if (item == null || string.IsNullOrWhiteSpace(item.CanonicalPath)) continue;
                string normalizedChild = Normalize(child);
                string normalizedRoot = Normalize(item.CanonicalPath);
                if (string.Equals(normalizedChild, normalizedRoot, StringComparison.OrdinalIgnoreCase)) continue;
                string prefix = normalizedRoot.EndsWith("\\", StringComparison.Ordinal) ? normalizedRoot : normalizedRoot + "\\";
                if (normalizedChild.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return "YES (root=" + normalizedRoot + ")";
            }
            return "NO";
        }

        private static string StrictlyInside(string child, string root)
        {
            if (string.IsNullOrWhiteSpace(child) || string.IsNullOrWhiteSpace(root)) return "NO";
            try
            {
                string normalizedChild = Normalize(child);
                string normalizedRoot = Normalize(root);
                if (string.Equals(normalizedChild, normalizedRoot, StringComparison.OrdinalIgnoreCase)) return "NO";
                string prefix = normalizedRoot.EndsWith("\\", StringComparison.Ordinal) ? normalizedRoot : normalizedRoot + "\\";
                return normalizedChild.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? "YES (root=" + normalizedRoot + ")" : "NO";
            }
            catch { return "NO"; }
        }

        private static ReviewerDirectory FixedAdminBoundary(ReviewerState state)
        {
            if (state == null || !string.Equals(NormalizeOrNull(state.AdminProfilePath), @"C:\Users\admin", StringComparison.OrdinalIgnoreCase)) return null;
            foreach (ReviewerDirectory item in state.ProtectedRoots ?? new List<ReviewerDirectory>())
            {
                if (item != null && string.Equals(NormalizeOrNull(item.CanonicalPath), @"C:\Users\admin", StringComparison.OrdinalIgnoreCase)) return item;
            }
            return null;
        }

        private static string NormalizeOrNull(string path)
        {
            try { return string.IsNullOrWhiteSpace(path) ? null : Normalize(path); }
            catch { return null; }
        }

        private static string Normalize(string path)
        {
            string full = Path.GetFullPath(path).TrimEnd('\\', '/');
            string root = (Path.GetPathRoot(full) ?? string.Empty).TrimEnd('\\', '/');
            return string.Equals(full, root, StringComparison.OrdinalIgnoreCase) ? Path.GetPathRoot(full) : full;
        }

        private static string FixedWritableException(string path, string workerProfile)
        {
            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(workerProfile)) return "NO";
            try
            {
                string actual = Normalize(path);
                string profile = Normalize(workerProfile);
                string[] names = { "AppData", ".codex", ".cache" };
                foreach (string name in names)
                    if (string.Equals(actual, Normalize(Path.Combine(profile, name)), StringComparison.OrdinalIgnoreCase)) return "YES";
            }
            catch { }
            return "NO";
        }

        private static string StripComment(string line)
        {
            if (line == null) return string.Empty;
            bool single = false;
            bool quoted = false;
            bool escaped = false;
            for (int index = 0; index < line.Length; index++)
            {
                char value = line[index];
                if (quoted && value == '\\' && !escaped) { escaped = true; continue; }
                if (value == '"' && !single && !escaped) quoted = !quoted;
                else if (value == '\'' && !quoted) single = !single;
                else if (value == '#' && !single && !quoted) return line.Substring(0, index);
                escaped = false;
            }
            return line;
        }

        private static string RegistryValue(RegistryKey key, string name)
        {
            if (key == null) return "<key missing>";
            object value = key.GetValue(name, null);
            return value == null ? "<missing>" : Convert.ToString(value);
        }

        private static string CurrentSid()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) return identity.User == null ? "<none>" : identity.User.Value;
        }

        private static string CompareSid(string recorded, SecurityIdentifier actual)
        {
            if (actual == null) return " [actual unresolved]";
            return string.Equals(recorded, actual.Value, StringComparison.OrdinalIgnoreCase) ? " [MATCH]" : " [MISMATCH actual=" + actual.Value + "]";
        }

        private static int Count<T>(List<T> values)
        {
            return values == null ? 0 : values.Count;
        }

        private static string NullText(string value)
        {
            return string.IsNullOrEmpty(value) ? "<empty>" : value;
        }

        private static void Section(StringBuilder text, string name)
        {
            text.AppendLine();
            text.AppendLine("===== " + name + " =====");
        }

        private static void Line(StringBuilder text, string value)
        {
            text.AppendLine(value ?? string.Empty);
        }
    }

    internal static class LocalGroups
    {
        private const int MaxPreferredLength = -1;
        private const int IncludeIndirect = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct LocalGroupUsersInfo0
        {
            public IntPtr Name;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetUserGetLocalGroups(string serverName, string userName, int level, int flags, out IntPtr buffer, int preferredMaximumLength, out int entriesRead, out int totalEntries);

        [DllImport("Netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        public static List<string> Read(string userName)
        {
            IntPtr buffer = IntPtr.Zero;
            int read;
            int total;
            int result = NetUserGetLocalGroups(null, userName, 0, IncludeIndirect, out buffer, MaxPreferredLength, out read, out total);
            if (result != 0) throw new Win32Exception(result, "NetUserGetLocalGroups failed for " + userName + ".");
            List<string> groups = new List<string>();
            try
            {
                int size = Marshal.SizeOf(typeof(LocalGroupUsersInfo0));
                for (int index = 0; index < read; index++)
                {
                    IntPtr current = new IntPtr(buffer.ToInt64() + (long)(index * size));
                    LocalGroupUsersInfo0 value = (LocalGroupUsersInfo0)Marshal.PtrToStructure(current, typeof(LocalGroupUsersInfo0));
                    string name = Marshal.PtrToStringUni(value.Name);
                    if (!string.IsNullOrWhiteSpace(name)) groups.Add(name);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
            groups.Sort(StringComparer.OrdinalIgnoreCase);
            return groups;
        }
    }

    [DataContract]
    internal sealed class ReviewerState
    {
        [DataMember] public string MachineName { get; set; }
        [DataMember] public string WorkerSid { get; set; }
        [DataMember] public string SandboxGroupSid { get; set; }
        [DataMember] public string AdminProfilePath { get; set; }
        [DataMember] public string WorkerProfilePath { get; set; }
        [DataMember] public List<ReviewerDirectory> ActivatedDirectories { get; set; }
        [DataMember] public List<ReviewerDirectory> ProtectedRoots { get; set; }
        [DataMember] public bool DefaultReadOnlyEnabled { get; set; }
        [DataMember] public string DefaultReadOnlyAppliedAtUtc { get; set; }
        [DataMember] public List<ReviewerDirectory> DefaultReadOnlyDirectories { get; set; }
        [DataMember] public List<ReviewerDirectory> DefaultReadOnlyRootLocks { get; set; }
        [DataMember] public List<string> WritableExceptionPaths { get; set; }
    }

    [DataContract]
    internal sealed class ReviewerDirectory
    {
        [DataMember] public string CanonicalPath { get; set; }
    }
}
