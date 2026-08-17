using CodexGuard.Core;
using System;
using System.Drawing;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class AdminConfirmationForm : Form
    {
        private readonly string _challenge;
        private readonly TextBox _challengeInput;
        private readonly Button _confirm;
        private bool _confirmationAccepted;

        internal bool ConfirmationAccepted
        {
            get { return _confirmationAccepted; }
        }

        public AdminConfirmationForm(PreparedGuardOperation prepared)
        {
            UiStyles.PrepareForm(this);
            Text = "Codex Guard — 管理员最终确认";
            Width = 880;
            Height = 660;
            MinimumSize = new Size(760, 560);

            _challenge = new Random(unchecked(Environment.TickCount * 397) ^ System.Diagnostics.Process.GetCurrentProcess().Id).Next(1000, 9999).ToString();

            Panel header = new Panel { Dock = DockStyle.Top, Height = 90, BackColor = UiStyles.Navy, Padding = new Padding(20, 14, 20, 10) };
            Label title = new Label
            {
                Text = OperationTitle(prepared.Request.Operation),
                ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 17F, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(18, 13)
            };
            Label subtitle = new Label
            {
                Text = "已通过 UAC。请人工核对最终规范路径；Codex Guard 不接受命令字符串。",
                ForeColor = Color.FromArgb(206, 220, 236),
                AutoSize = true,
                Font = UiStyles.BodyFont(),
                Location = new Point(21, 54)
            };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);

            ListView paths = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                Font = UiStyles.BodyFont()
            };
            paths.Columns.Add("类型", 130);
            paths.Columns.Add("最终路径", 620);
            foreach (PathValidationResult item in prepared.RootLockPaths)
                paths.Items.Add(new ListViewItem(new[] { "仅锁根目录", item.Identity.CanonicalPath }));
            foreach (string item in prepared.WritableExceptionPaths)
            {
                ListViewItem row = new ListViewItem(new[] { "允许写/清理", item });
                row.ForeColor = UiStyles.Green;
                paths.Items.Add(row);
            }
            foreach (PathValidationResult item in prepared.Paths)
            {
                string type = prepared.Request.Operation == GuardOperation.Revoke ? "撤销激活"
                    : prepared.Request.Operation == GuardOperation.ApplyDefaultReadOnly ? "默认只读"
                    : prepared.Request.Operation == GuardOperation.Repair || prepared.Request.Operation == GuardOperation.BindSandbox ? "修复验证"
                    : "激活目录";
                paths.Items.Add(new ListViewItem(new[] { type, item.Identity == null ? item.FullPath : item.Identity.CanonicalPath }));
            }
            if (paths.Items.Count == 0)
                paths.Items.Add(new ListViewItem(new[] { "系统操作", prepared.Request.Operation.ToString() }));

            StringBuilder warningText = new StringBuilder();
            warningText.Append("请求来源：").Append(prepared.Request.RequesterMachine).Append(" / ").Append(prepared.Request.RequesterSid);
            warningText.Append("\r\n作用身份：");
            foreach (SecurityIdentifier sid in prepared.ActorSids) warningText.Append("\r\n  • ").Append(sid.Value);
            warningText.Append("\r\nadmin 保证：admin SID 不在上述限制集合中；本操作不会为 admin 写入只读或拒绝 ACE。");
            foreach (string warning in prepared.Warnings) warningText.Append("\r\n警告：").Append(warning);
            if (prepared.Request.Operation == GuardOperation.Revoke)
                warningText.Append("\r\n警告：撤销不会删除文件，但会移除写入权限；必须已关闭 Codex、终端、Git 和 WSL。");
            if (prepared.Request.Operation == GuardOperation.ApplyDefaultReadOnly)
                warningText.Append("\r\n警告：应用后，未激活目录的创建、写入、删除、重命名和改 ACL 会立即被拒绝。缓存允许列表仍可正常清理。请先确认备份和激活目录。");

            TextBox warnings = new TextBox
            {
                Dock = DockStyle.Bottom,
                Height = 112,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Text = warningText.ToString(),
                BackColor = Color.FromArgb(255, 249, 235),
                ForeColor = UiStyles.Navy,
                Font = UiStyles.BodyFont()
            };

            Panel center = new Panel { Dock = DockStyle.Fill, Padding = new Padding(18, 16, 18, 8) };
            center.Controls.Add(paths);
            center.Controls.Add(warnings);

            FlowLayoutPanel challengePanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 58,
                FlowDirection = FlowDirection.LeftToRight,
                Padding = new Padding(18, 9, 18, 6),
                BackColor = UiStyles.PaleBlue
            };
            challengePanel.Controls.Add(UiStyles.Label("人工确认码：" + _challenge, true));
            challengePanel.Controls.Add(UiStyles.Label("请重新输入", false));
            _challengeInput = new TextBox { Width = 90, MaxLength = 4, Font = new Font("Consolas", 12F), TextAlign = HorizontalAlignment.Center };
            _challengeInput.TextChanged += delegate { _confirm.Enabled = string.Equals(_challengeInput.Text, _challenge, StringComparison.Ordinal); };
            challengePanel.Controls.Add(_challengeInput);

            FlowLayoutPanel footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 60,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(16, 11, 16, 8)
            };
            _confirm = UiStyles.PrimaryButton("确认执行");
            _confirm.Enabled = false;
            _confirm.Click += ConfirmClick;
            Button cancel = UiStyles.SecondaryButton("取消");
            cancel.DialogResult = DialogResult.Cancel;
            footer.Controls.Add(_confirm);
            footer.Controls.Add(cancel);

            Controls.Add(center);
            Controls.Add(challengePanel);
            Controls.Add(footer);
            Controls.Add(header);
            AcceptButton = _confirm;
            CancelButton = cancel;
            Shown += delegate { _challengeInput.Focus(); };
        }

        private void ConfirmClick(object sender, EventArgs e)
        {
            if (!_confirm.Enabled || !string.Equals(_challengeInput.Text, _challenge, StringComparison.Ordinal)) return;
            _confirmationAccepted = true;
            DialogResult = DialogResult.OK;
            Close();
        }

        private static string OperationTitle(GuardOperation operation)
        {
            switch (operation)
            {
                case GuardOperation.Activate: return "永久追加激活目录";
                case GuardOperation.Revoke: return "人工撤销目录激活";
                case GuardOperation.ApplyDefaultReadOnly: return "应用 CodexWorker 默认只读基线";
                case GuardOperation.ImportPolicy: return "导入并应用可移植策略";
                case GuardOperation.BindSandbox: return "绑定 CodexSandboxUsers";
                case GuardOperation.Repair: return "修复 Codex Guard 权限";
                default: return "执行 Codex Guard 管理操作";
            }
        }
    }
}
