using CodexGuard.Core;
using System;
using System.Drawing;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class OfflineReuseConfirmationForm : Form
    {
        private readonly string _challenge;
        private readonly TextBox _challengeInput;
        private readonly CheckBox _acknowledge;
        private readonly Button _confirm;

        public OfflineReuseConfirmationForm(PreparedOfflineReuseRequest prepared)
        {
            if (prepared == null) throw new ArgumentNullException("prepared");
            UiStyles.PrepareForm(this);
            Text = "Codex Guard — 离线复用管理员确认";
            Width = 1080;
            Height = 700;
            MinimumSize = new Size(860, 610);

            _challenge = new Random(unchecked(Environment.TickCount * 397) ^ System.Diagnostics.Process.GetCurrentProcess().Id).Next(1000, 9999).ToString();
            Panel header = new Panel { Dock = DockStyle.Top, Height = 100, BackColor = UiStyles.Navy, Padding = new Padding(20, 14, 20, 10) };
            header.Controls.Add(new Label
            {
                Text = "准备 CodexWorker 本地程序副本",
                ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 17F, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(18, 13)
            });
            header.Controls.Add(new Label
            {
                Text = "源目录只读；目标采用 CreateNew。不会移动、覆盖、删除、运行安装器或导入注册表。",
                ForeColor = Color.FromArgb(206, 220, 236),
                AutoSize = true,
                Font = UiStyles.BodyFont(),
                Location = new Point(21, 56)
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
            items.Columns.Add("软件", 190);
            items.Columns.Add("只读源目录", 330);
            items.Columns.Add("新建目标目录", 330);
            items.Columns.Add("文件/大小", 150);
            long totalBytes = 0;
            long totalFiles = 0;
            foreach (OfflineReuseCopyPlan plan in prepared.Plans)
            {
                totalBytes += plan.TotalBytes;
                totalFiles += plan.FileCount;
                items.Items.Add(new ListViewItem(new[]
                {
                    plan.Item.DisplayName ?? string.Empty,
                    plan.SourceDirectory,
                    plan.TargetDirectory,
                    plan.FileCount + " / " + FormatBytes(plan.TotalBytes)
                }));
            }

            TextBox boundary = new TextBox
            {
                Dock = DockStyle.Bottom,
                Height = 126,
                Multiline = true,
                ReadOnly = true,
                BackColor = Color.FromArgb(255, 249, 235),
                ForeColor = UiStyles.Navy,
                Font = UiStyles.BodyFont(),
                Text = "请求来源：" + prepared.Request.RequesterMachine + " / " + prepared.Request.RequesterSid + "\r\n"
                    + "总计：" + totalFiles + " 个文件，" + FormatBytes(totalBytes) + "\r\n"
                    + "失败处理：不回滚、不清理；任何部分副本保留为管理员不可执行的核查材料。\r\n"
                    + "后续：复制完成后需以 CodexWorker 首次启动；登录、许可证和用户配置不会从 admin 自动迁移。"
            };
            Panel body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(18, 16, 18, 8) };
            body.Controls.Add(items);
            body.Controls.Add(boundary);

            FlowLayoutPanel challengePanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 82,
                Padding = new Padding(18, 8, 18, 6),
                BackColor = UiStyles.PaleBlue,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = true
            };
            _acknowledge = new CheckBox
            {
                AutoSize = true,
                Font = UiStyles.BodyFont(),
                Text = "我确认这是程序副本，不包含 admin 设置；目标若已存在必须停止，不能覆盖。",
                Margin = new Padding(4, 5, 20, 4)
            };
            _acknowledge.CheckedChanged += delegate { UpdateConfirm(); };
            challengePanel.Controls.Add(_acknowledge);
            challengePanel.Controls.Add(UiStyles.Label("人工确认码：" + _challenge, true));
            challengePanel.Controls.Add(UiStyles.Label("请重新输入", false));
            _challengeInput = new TextBox { Width = 90, MaxLength = 4, Font = new Font("Consolas", 12F), TextAlign = HorizontalAlignment.Center };
            _challengeInput.TextChanged += delegate { UpdateConfirm(); };
            challengePanel.Controls.Add(_challengeInput);

            FlowLayoutPanel footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 60,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(16, 11, 16, 8)
            };
            _confirm = UiStyles.PrimaryButton("确认只复制");
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
            Shown += delegate { _acknowledge.Focus(); };
        }

        private void UpdateConfirm()
        {
            _confirm.Enabled = _acknowledge.Checked && string.Equals(_challengeInput.Text, _challenge, StringComparison.Ordinal);
        }

        private static string FormatBytes(long value)
        {
            if (value >= 1024L * 1024L * 1024L) return (value / (1024d * 1024d * 1024d)).ToString("0.00") + " GB";
            if (value >= 1024L * 1024L) return (value / (1024d * 1024d)).ToString("0.00") + " MB";
            if (value >= 1024L) return (value / 1024d).ToString("0.00") + " KB";
            return value + " B";
        }
    }
}
