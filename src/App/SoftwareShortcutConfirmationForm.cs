using CodexGuard.Core;
using System;
using System.Drawing;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class SoftwareShortcutConfirmationForm : Form
    {
        private readonly string _challenge;
        private readonly TextBox _challengeInput;
        private readonly Button _confirm;

        public SoftwareShortcutConfirmationForm(PreparedSoftwareShortcutRequest prepared)
        {
            if (prepared == null) throw new ArgumentNullException("prepared");
            UiStyles.PrepareForm(this);
            Text = "Codex Guard — 软件映射管理员确认";
            Width = 940;
            Height = 650;
            MinimumSize = new Size(780, 560);

            _challenge = new Random(unchecked(Environment.TickCount * 397) ^ System.Diagnostics.Process.GetCurrentProcess().Id).Next(1000, 9999).ToString();

            Panel header = new Panel { Dock = DockStyle.Top, Height = 94, BackColor = UiStyles.Navy, Padding = new Padding(20, 14, 20, 10) };
            header.Controls.Add(new Label
            {
                Text = "创建公共软件快捷方式",
                ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 17F, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(18, 13)
            });
            header.Controls.Add(new Label
            {
                Text = "只创建 .lnk；不复制、不安装、不移动、不删除程序文件，也不包含启动参数。",
                ForeColor = Color.FromArgb(206, 220, 236),
                AutoSize = true,
                Font = UiStyles.BodyFont(),
                Location = new Point(21, 55)
            });

            ListView items = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                Font = UiStyles.BodyFont()
            };
            items.Columns.Add("软件", 230);
            items.Columns.Add("发布者", 190);
            items.Columns.Add("已重新核验的 EXE", 450);
            foreach (SoftwareInventoryItem item in prepared.Items)
                items.Items.Add(new ListViewItem(new[] { item.DisplayName, item.Publisher ?? string.Empty, item.ExecutablePath }));

            TextBox boundary = new TextBox
            {
                Dock = DockStyle.Bottom,
                Height = 104,
                Multiline = true,
                ReadOnly = true,
                BackColor = Color.FromArgb(255, 249, 235),
                ForeColor = UiStyles.Navy,
                Font = UiStyles.BodyFont(),
                Text = "请求来源：" + prepared.Request.RequesterMachine + " / " + prepared.Request.RequesterSid + "\r\n"
                    + "输出目录：" + AppPaths.MappedSoftwareProgramsDirectory + "\r\n"
                    + "安全限制：目标必须位于 Program Files，或位于父路径直至盘根均不可被低权限身份写入的固定 NTFS 卷；用户资料和 WindowsApps 永久阻断。"
            };

            Panel body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(18, 16, 18, 8) };
            body.Controls.Add(items);
            body.Controls.Add(boundary);

            FlowLayoutPanel challengePanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 58,
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
            _confirm = UiStyles.PrimaryButton("确认创建");
            _confirm.Enabled = false;
            _confirm.DialogResult = DialogResult.OK;
            Button cancel = UiStyles.SecondaryButton("取消");
            cancel.DialogResult = DialogResult.Cancel;
            footer.Controls.Add(_confirm);
            footer.Controls.Add(cancel);

            Controls.Add(body);
            Controls.Add(challengePanel);
            Controls.Add(footer);
            Controls.Add(header);
            AcceptButton = _confirm;
            CancelButton = cancel;
            Shown += delegate { _challengeInput.Focus(); };
        }
    }
}
