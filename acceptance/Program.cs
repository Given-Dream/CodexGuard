using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace CodexGuard.AcceptanceProbe
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ProbeForm());
        }
    }

    internal sealed class ProbeForm : Form
    {
        private readonly TextBox _target;
        private readonly ComboBox _mode;
        private readonly ListView _results;
        private readonly Label _summary;

        public ProbeForm()
        {
            Text = "Codex Guard 验收探针（仅作用于新建随机测试对象）";
            Width = 1040;
            Height = 720;
            MinimumSize = new Size(820, 580);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9F);

            Label warning = new Label
            {
                Dock = DockStyle.Top,
                Height = 86,
                Padding = new Padding(16, 10, 16, 8),
                BackColor = Color.FromArgb(255, 245, 223),
                ForeColor = Color.FromArgb(120, 70, 0),
                Text = "只选择无重要数据的 NTFS 验收目录。探针不读取或修改任何已有子项，只创建 .codexguard-acceptance-<GUID>。\r\n"
                    + "在“激活目录”模式下，它会对自己创建的对象尝试覆盖、改 ACL、重命名和删除；不会自动清理，最后由 admin 人工处理。"
            };

            _target = new TextBox { Dock = DockStyle.Fill, ReadOnly = true };
            Button browse = new Button { Text = "选择验收目录", AutoSize = true, MinimumSize = new Size(120, 32) };
            browse.Click += Browse;
            _mode = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 250 };
            _mode.Items.Add("激活目录：创建/覆盖应成功，删除类应拒绝");
            _mode.Items.Add("默认只读/非激活区域：创建测试子目录应拒绝");
            _mode.SelectedIndex = 0;
            Button run = new Button { Text = "明确确认后运行一次", AutoSize = true, MinimumSize = new Size(150, 32), BackColor = Color.FromArgb(38, 113, 190), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            run.Click += RunProbe;

            TableLayoutPanel selector = new TableLayoutPanel { Dock = DockStyle.Top, Height = 124, Padding = new Padding(10), ColumnCount = 3, RowCount = 3 };
            selector.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            selector.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            selector.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            selector.Controls.Add(new Label { Text = "目标由文件夹选择器产生；不接受命令行路径", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
            selector.SetColumnSpan(selector.GetControlFromPosition(0, 0), 3);
            selector.Controls.Add(_target, 0, 1);
            selector.Controls.Add(browse, 1, 1);
            selector.Controls.Add(_mode, 2, 1);
            selector.Controls.Add(run, 2, 2);

            _results = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true };
            _results.Columns.Add("结果", 82);
            _results.Columns.Add("操作", 210);
            _results.Columns.Add("预期", 250);
            _results.Columns.Add("实际", 430);
            _summary = new Label { Dock = DockStyle.Bottom, Height = 58, Padding = new Padding(14, 10, 14, 8), BackColor = Color.FromArgb(236, 244, 252), Text = "尚未运行。当前身份：" + Environment.UserDomainName + "\\" + Environment.UserName };

            Controls.Add(_results);
            Controls.Add(_summary);
            Controls.Add(selector);
            Controls.Add(warning);
        }

        private void Browse(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog())
            {
                dialog.Description = "选择专门用于 Codex Guard 验收、且没有重要数据的目录";
                dialog.ShowNewFolderButton = false;
                if (dialog.ShowDialog(this) == DialogResult.OK) _target.Text = dialog.SelectedPath;
            }
        }

        private void RunProbe(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_target.Text))
            {
                MessageBox.Show("请先用文件夹选择器选择验收目录。", "尚未选择", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string description = _mode.SelectedIndex == 0
                ? "将在所选目录中新建随机测试子目录，并对探针自己的文件尝试改 ACL、重命名和删除。"
                : "只尝试在所选默认只读或非激活区域创建一个随机测试子目录；若创建被拒绝，不会再执行其他操作。";
            if (MessageBox.Show(description + "\r\n\r\n确认该目录没有重要数据并继续？", "验收探针确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

            _results.Items.Clear();
            try
            {
                ProbeReport report = ProbeRunner.Run(_target.Text, _mode.SelectedIndex == 0);
                foreach (ProbeResult result in report.Results)
                {
                    ListViewItem item = new ListViewItem(new[] { result.Passed ? "符合" : "失败", result.Operation, result.Expected, result.Actual });
                    item.ForeColor = result.Passed ? Color.FromArgb(31, 132, 91) : Color.FromArgb(190, 57, 57);
                    _results.Items.Add(item);
                }
                _summary.Text = (report.AllPassed ? "验收结果符合预期。" : "验收失败：禁止用于真实数据。")
                    + " 探针残留位置：" + (report.ProbePath ?? "未创建") + "；由 admin 人工处理。";
                _summary.ForeColor = report.AllPassed ? Color.FromArgb(31, 132, 91) : Color.FromArgb(190, 57, 57);
            }
            catch (Exception ex)
            {
                _summary.Text = "探针自身失败：" + ex.Message + "。禁止据此判定安全。";
                _summary.ForeColor = Color.FromArgb(190, 57, 57);
            }
        }
    }

    internal static class ProbeRunner
    {
        private const string Prefix = ".codexguard-acceptance-";
        private const string MarkerName = "codexguard-probe.marker";

        public static ProbeReport Run(string selectedDirectory, bool activeMode)
        {
            string selected = ValidateSelectedDirectory(selectedDirectory);
            string probe = Path.Combine(selected, Prefix + Guid.NewGuid().ToString("N"));
            ProbeReport report = new ProbeReport { ProbePath = probe };

            string createActual;
            bool created = Try(delegate { Directory.CreateDirectory(probe); }, out createActual);
            report.Add("新建随机探针目录", activeMode ? "成功" : "拒绝访问", createActual, activeMode ? created : !created);
            if (!created || !activeMode) return report;

            string marker = Path.Combine(probe, MarkerName);
            string markerActual;
            bool markerCreated = Try(delegate { File.WriteAllText(marker, "Codex Guard acceptance probe\r\n", new UTF8Encoding(false)); }, out markerActual);
            report.Add("写入范围标记", "成功", markerActual, markerCreated);
            if (!markerCreated) return report;

            string content = Path.Combine(probe, "content-test.txt");
            string fileActual;
            bool fileCreated = Try(delegate { File.WriteAllText(content, "created", new UTF8Encoding(false)); }, out fileActual);
            report.Add("新建文件", "成功", fileActual, fileCreated);
            if (!fileCreated) return report;

            string readValue = null;
            string readActual;
            bool read = Try(delegate { readValue = File.ReadAllText(content, Encoding.UTF8); }, out readActual);
            report.Add("读取文件", "成功", read ? "成功，内容=" + readValue : readActual, read);

            string overwriteActual;
            bool overwrite = Try(delegate
            {
                using (FileStream stream = new FileStream(content, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    stream.SetLength(0);
                    byte[] bytes = Encoding.UTF8.GetBytes("overwritten");
                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush(true);
                }
            }, out overwriteActual);
            report.Add("原位覆盖文件", "成功", overwriteActual, overwrite);

            string aclActual;
            bool aclChanged = Try(delegate
            {
                EnsureProbeObject(content, probe, marker);
                FileSecurity security = File.GetAccessControl(content, AccessControlSections.Access);
                File.SetAccessControl(content, security);
            }, out aclActual);
            report.Add("以文件所有者身份写回 DACL", "拒绝访问", aclActual, !aclChanged);

            string protectedDaclTarget = Path.Combine(probe, "protected-dacl-create-test.txt");
            EnsureProbeObject(protectedDaclTarget, probe, marker);
            string protectedDaclActual;
            bool protectedDaclCreated = NativeCustomDaclProbe.TryCreate(protectedDaclTarget, out protectedDaclActual);
            report.Add("创建时指定受保护 FullControl DACL", "拒绝访问", protectedDaclActual, !protectedDaclCreated);

            string renamed = Path.Combine(probe, "content-renamed.txt");
            string renameActual;
            bool renamedFile = Try(delegate
            {
                EnsureProbeObject(content, probe, marker);
                File.Move(content, renamed);
            }, out renameActual);
            report.Add("重命名探针文件", "拒绝访问", renameActual, !renamedFile);
            if (renamedFile) content = renamed;

            string deleteTarget = Path.Combine(probe, "delete-test.txt");
            string deleteCreateActual;
            bool deleteTargetCreated = Try(delegate { File.WriteAllText(deleteTarget, "delete probe", new UTF8Encoding(false)); }, out deleteCreateActual);
            report.Add("新建删除目标", "成功", deleteCreateActual, deleteTargetCreated);
            if (deleteTargetCreated)
            {
                string deleteActual;
                bool deletedFile = Try(delegate
                {
                    EnsureProbeObject(deleteTarget, probe, marker);
                    File.Delete(deleteTarget);
                }, out deleteActual);
                report.Add("删除探针文件", "拒绝访问", deleteActual, !deletedFile);
            }

            string empty = Path.Combine(probe, "empty-delete-test");
            string emptyCreateActual;
            bool emptyCreated = Try(delegate { Directory.CreateDirectory(empty); }, out emptyCreateActual);
            report.Add("新建空测试子目录", "成功", emptyCreateActual, emptyCreated);
            if (emptyCreated)
            {
                string directoryDeleteActual;
                bool deletedDirectory = Try(delegate
                {
                    EnsureProbeObject(empty, probe, marker);
                    Directory.Delete(empty, false);
                }, out directoryDeleteActual);
                report.Add("删除空测试子目录", "拒绝访问", directoryDeleteActual, !deletedDirectory);
            }

            return report;
        }

        internal static bool IsSafeProbePath(string candidate, string probeRoot)
        {
            if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(probeRoot)) return false;
            string fullCandidate = Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string fullRoot = Path.GetFullPath(probeRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string prefix = fullRoot + Path.DirectorySeparatorChar;
            return fullCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                && Path.GetFileName(fullRoot).StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
        }

        private static string ValidateSelectedDirectory(string path)
        {
            string full = Path.GetFullPath(path);
            if (!Directory.Exists(full)) throw new DirectoryNotFoundException("所选验收目录不存在。");
            string root = Path.GetPathRoot(full);
            if (string.Equals(full.TrimEnd('\\', '/'), (root ?? string.Empty).TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("不能直接选择磁盘根目录；请先由 admin 建立专用验收目录。");
            if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("验收目录不能是符号链接、联接点或其他重解析点。");
            return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        private static void EnsureProbeObject(string candidate, string probeRoot, string marker)
        {
            if (!IsSafeProbePath(candidate, probeRoot)) throw new InvalidDataException("安全边界拒绝：目标不是本次随机探针的严格后代。");
            if (!File.Exists(marker)) throw new InvalidDataException("安全边界拒绝：本次探针范围标记不存在。");
        }

        private static bool Try(Action action, out string actual)
        {
            try
            {
                action();
                actual = "成功";
                return true;
            }
            catch (UnauthorizedAccessException ex)
            {
                actual = "拒绝访问：" + ex.Message;
                return false;
            }
            catch (IOException ex)
            {
                actual = "I/O 拒绝或冲突：" + ex.Message;
                return false;
            }
        }
    }

    internal static class NativeCustomDaclProbe
    {
        private const uint GenericWrite = 0x40000000;
        private const uint CreateNew = 1;
        private const uint FileAttributeNormal = 0x80;
        private const uint SddlRevision1 = 1;
        private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            public bool InheritHandle;
        }

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor,
            uint stringSDRevision,
            out IntPtr securityDescriptor,
            out uint securityDescriptorSize);

        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            ref SecurityAttributes securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("Kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static bool TryCreate(string path, out string actual)
        {
            string sid;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (identity.User == null)
                {
                    actual = "当前身份没有可用 SID";
                    return false;
                }
                sid = identity.User.Value;
            }

            IntPtr descriptor = IntPtr.Zero;
            uint descriptorSize;
            string sddl = "D:P(A;;FA;;;" + sid + ")";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SddlRevision1, out descriptor, out descriptorSize))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法构造测试安全描述符。");
            try
            {
                SecurityAttributes attributes = new SecurityAttributes
                {
                    Length = Marshal.SizeOf(typeof(SecurityAttributes)),
                    SecurityDescriptor = descriptor,
                    InheritHandle = false
                };
                IntPtr handle = CreateFile(path, GenericWrite, 0, ref attributes, CreateNew, FileAttributeNormal, IntPtr.Zero);
                if (handle == InvalidHandleValue)
                {
                    int error = Marshal.GetLastWin32Error();
                    actual = "拒绝或失败（Win32 " + error + "）：" + new Win32Exception(error).Message;
                    return false;
                }
                try
                {
                    actual = "成功（危险：创建者绕过了继承规则）";
                    return true;
                }
                finally { CloseHandle(handle); }
            }
            finally
            {
                if (descriptor != IntPtr.Zero) LocalFree(descriptor);
            }
        }
    }

    internal sealed class ProbeReport
    {
        public string ProbePath { get; set; }
        public List<ProbeResult> Results { get; private set; }
        public bool AllPassed
        {
            get
            {
                if (Results.Count == 0) return false;
                foreach (ProbeResult result in Results) if (!result.Passed) return false;
                return true;
            }
        }

        public ProbeReport()
        {
            Results = new List<ProbeResult>();
        }

        public void Add(string operation, string expected, string actual, bool passed)
        {
            Results.Add(new ProbeResult { Operation = operation, Expected = expected, Actual = actual, Passed = passed });
        }
    }

    internal sealed class ProbeResult
    {
        public string Operation { get; set; }
        public string Expected { get; set; }
        public string Actual { get; set; }
        public bool Passed { get; set; }
    }
}
