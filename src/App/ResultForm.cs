using CodexGuard.Core;
using System;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class ResultForm : Form
    {
        public ResultForm(OperationResult result)
        {
            UiStyles.PrepareForm(this);
            Text = "Codex Guard — 操作结果";
            Width = 760;
            Height = 520;
            MinimizeBox = false;
            MaximizeBox = false;

            Label heading = UiStyles.Label(result.Success ? "操作成功" : "操作未完成", true);
            heading.Font = new Font("Microsoft YaHei UI", 16F, FontStyle.Bold);
            heading.ForeColor = result.Success ? UiStyles.Green : UiStyles.Red;
            heading.Dock = DockStyle.Top;
            heading.Padding = new Padding(18, 18, 18, 8);
            heading.Height = 62;

            StringBuilder details = new StringBuilder();
            details.AppendLine(result.Summary ?? string.Empty);
            details.AppendLine();
            foreach (string line in result.Messages) details.AppendLine("• " + line);
            TextBox text = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Both,
                WordWrap = false,
                Text = details.ToString(),
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Font = new Font("Consolas", 9F),
                BorderStyle = BorderStyle.FixedSingle
            };

            Button close = UiStyles.PrimaryButton("关闭");
            close.DialogResult = DialogResult.OK;
            FlowLayoutPanel footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 56,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(12, 10, 12, 8)
            };
            footer.Controls.Add(close);

            Panel body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(18, 4, 18, 4) };
            body.Controls.Add(text);
            Controls.Add(body);
            Controls.Add(footer);
            Controls.Add(heading);
            AcceptButton = close;
        }
    }
}
