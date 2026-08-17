using CodexGuard.Core;
using System;
using System.Drawing;
using System.Security.Principal;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class InstallForm : Form
    {
        private readonly TextBox _password;
        private readonly TextBox _passwordConfirm;
        private readonly CheckBox _removeAdmin;
        private readonly CheckBox _applyUac;
        private readonly CheckBox _requirements;
        private readonly Label _status;
        private readonly bool _workerExists;

        public bool OperationSucceeded { get; private set; }

        public InstallForm()
        {
            UiStyles.PrepareForm(this);
            Text = "Codex Guard — 安装与修复";
            Width = 760;
            Height = 760;
            MinimumSize = new Size(700, 680);

            SecurityIdentifier existing;
            _workerExists = LocalAccountService.AccountExists(AppInfo.WorkerAccountName, out existing);
            UacStatus uac = UacPolicy.Read();

            Panel header = new Panel { Dock = DockStyle.Top, Height = 105, BackColor = UiStyles.Navy, Padding = new Padding(22, 16, 22, 12) };
            Label title = new Label { Text = "Codex Guard", ForeColor = Color.White, Font = UiStyles.TitleFont(), AutoSize = true, Location = new Point(18, 14) };
            Label subtitle = new Label
            {
                Text = "一次性部署低权限账户、UAC 边界和持久 NTFS 防护",
                ForeColor = Color.FromArgb(205, 218, 234),
                Font = UiStyles.BodyFont(),
                AutoSize = true,
                Location = new Point(21, 62)
            };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);

            TableLayoutPanel body = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                Padding = new Padding(22, 18, 22, 12),
                ColumnCount = 2,
                RowCount = 9
            };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 210));
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            for (int row = 1; row <= 6; row++) body.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 66));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 104));

            _status = UiStyles.Label(
                (_workerExists ? "已检测到 CodexWorker。" : "尚未创建 CodexWorker。") + "  " +
                (uac.MeetsRequirements ? "UAC 安全桌面符合要求。" : "UAC 安全桌面需要修复。"),
                false);
            _status.ForeColor = uac.MeetsRequirements ? UiStyles.Green : UiStyles.Amber;
            _status.AutoSize = false;
            _status.Height = 44;
            _status.Dock = DockStyle.Fill;
            body.Controls.Add(_status, 0, 0);
            body.SetColumnSpan(_status, 2);

            AddRow(body, 1, "Worker 账户", new Label { Text = Environment.MachineName + "\\" + AppInfo.WorkerAccountName, AutoSize = true, ForeColor = UiStyles.Navy, Font = UiStyles.BodyFont() });

            _password = CreatePasswordBox();
            _passwordConfirm = CreatePasswordBox();
            _password.Enabled = !_workerExists;
            _passwordConfirm.Enabled = !_workerExists;
            AddRow(body, 2, "Worker 密码", _password);
            AddRow(body, 3, "确认 Worker 密码", _passwordConfirm);

            _removeAdmin = new CheckBox
            {
                Text = "移除 CodexWorker 的 Administrators / 备份操作员等特权组成员资格（强制）",
                Checked = true,
                Enabled = false,
                AutoSize = true,
                Font = UiStyles.BodyFont()
            };
            AddWide(body, 4, _removeAdmin);

            _applyUac = new CheckBox
            {
                Text = "应用 UAC 安全桌面策略：标准用户必须输入管理员凭据",
                Checked = !uac.MeetsRequirements,
                Enabled = false,
                AutoSize = true,
                Font = UiStyles.BodyFont()
            };
            AddWide(body, 5, _applyUac);

            _requirements = new CheckBox
            {
                Text = "创建/验证 OpenAI Codex 系统 requirements.toml（只允许 elevated 沙箱）",
                Checked = true,
                Enabled = false,
                AutoSize = true,
                Font = UiStyles.BodyFont()
            };
            AddWide(body, 6, _requirements);

            Label adminProtection = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Padding = new Padding(12, 8, 12, 6),
                BackColor = Color.FromArgb(248, 250, 253),
                ForeColor = UiStyles.Navy,
                Font = UiStyles.BodyFont(),
                Text = "管理员资料保护（固定）：" + AppInfo.AdminProfilePath
                    + "\r\nCodex 身份只读并禁止删除/重命名；AppData、.ssh、.gnupg、.aws、.azure、.codex 无访问。"
            };
            body.Controls.Add(adminProtection, 0, 7);
            body.SetColumnSpan(adminProtection, 2);

            Label warning = new Label
            {
                Text = "安全说明：安装不会保存任何密码，也不会创建可执行任意命令的高权限服务。现有 requirements.toml 不会被覆盖。安装完成后仍需在 CodexWorker 首次登录并完成官方 elevated 沙箱初始化。",
                AutoSize = false,
                Dock = DockStyle.Fill,
                Height = 82,
                Padding = new Padding(12),
                BackColor = UiStyles.PaleBlue,
                ForeColor = UiStyles.Navy,
                Font = UiStyles.BodyFont()
            };
            body.Controls.Add(warning, 0, 8);
            body.SetColumnSpan(warning, 2);

            FlowLayoutPanel footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 62,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(16, 12, 16, 8),
                BackColor = Color.FromArgb(247, 249, 252)
            };
            Button install = UiStyles.PrimaryButton(_workerExists ? "安装 / 修复" : "创建并安装");
            Button cancel = UiStyles.SecondaryButton("取消");
            cancel.DialogResult = DialogResult.Cancel;
            install.Click += InstallClick;
            footer.Controls.Add(install);
            footer.Controls.Add(cancel);

            Controls.Add(body);
            Controls.Add(footer);
            Controls.Add(header);
            CancelButton = cancel;
        }

        private void InstallClick(object sender, EventArgs e)
        {
            try
            {
                if (!_workerExists)
                {
                    if (_password.Text.Length < 12) throw new InvalidOperationException("Worker 密码至少需要 12 个字符。");
                    if (!string.Equals(_password.Text, _passwordConfirm.Text, StringComparison.Ordinal))
                        throw new InvalidOperationException("两次输入的 Worker 密码不一致。");
                }
                if (!UacPolicy.Read().MeetsRequirements && !_applyUac.Checked)
                    throw new InvalidOperationException("Codex Guard 要求 UAC 在安全桌面向标准用户索取管理员凭据。");

                string summary = "Codex Guard 将执行以下管理员操作：\r\n\r\n"
                    + "• " + (_workerExists ? "检查并修复" : "创建") + "标准账户 " + AppInfo.WorkerAccountName + "\r\n"
                    + "• 安装到 " + AppPaths.InstallDirectory + "\r\n"
                    + (_applyUac.Checked ? "• 应用 UAC 安全桌面策略\r\n" : string.Empty)
                    + "• 保护固定管理员资料目录 " + AppInfo.AdminProfilePath + "\r\n"
                    + "\r\n是否继续？";
                if (MessageBox.Show(summary, "最终安装确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                    return;

                UseWaitCursor = true;
                InstallOptions options = new InstallOptions
                {
                    WorkerPassword = _workerExists ? null : _password.Text,
                    RemoveExistingWorkerFromPrivilegedGroups = _removeAdmin.Checked,
                    ApplyRecommendedUacPolicy = _applyUac.Checked,
                    ConfigureCodexRequirements = _requirements.Checked,
                    AdminProfilePath = AppInfo.AdminProfilePath
                };
                OperationResult result = InstallerService.Install(options);
                options.WorkerPassword = null;
                _password.Clear();
                _passwordConfirm.Clear();
                OperationSucceeded = result.Success;
                using (ResultForm resultForm = new ResultForm(result)) resultForm.ShowDialog(this);
                if (result.Success) Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Codex Guard 安装失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                _password.Clear();
                _passwordConfirm.Clear();
                UseWaitCursor = false;
            }
        }

        private static TextBox CreatePasswordBox()
        {
            return new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, Font = UiStyles.BodyFont(), MaxLength = 127 };
        }

        private static void AddRow(TableLayoutPanel panel, int row, string label, Control control)
        {
            Label caption = UiStyles.Label(label, true);
            caption.Anchor = AnchorStyles.Left;
            control.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            panel.Controls.Add(caption, 0, row);
            panel.Controls.Add(control, 1, row);
        }

        private static void AddWide(TableLayoutPanel panel, int row, Control control)
        {
            control.Anchor = AnchorStyles.Left;
            panel.Controls.Add(control, 0, row);
            panel.SetColumnSpan(control, 2);
        }
    }
}
