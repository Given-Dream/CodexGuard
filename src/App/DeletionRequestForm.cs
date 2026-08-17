using CodexGuard.Core;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class DeletionRequestForm : Form
    {
        private readonly ListBox _paths;
        private readonly TextBox _reason;

        public DeletionRequestForm()
        {
            UiStyles.PrepareForm(this);
            Text = "Codex Guard — 提交删除申请";
            Width = 820;
            Height = 610;
            MinimumSize = new Size(700, 520);

            Panel header = new Panel { Dock = DockStyle.Top, Height = 94, BackColor = UiStyles.Navy, Padding = new Padding(20, 14, 20, 10) };
            header.Controls.Add(new Label
            {
                Text = "只提交申请，不移动、不删除",
                ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 17F, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(18, 13)
            });
            header.Controls.Add(new Label
            {
                Text = "目标必须位于已激活项目内；申请文件仅供 admin 人工核查。",
                ForeColor = Color.FromArgb(206, 220, 236),
                Font = UiStyles.BodyFont(),
                AutoSize = true,
                Location = new Point(21, 55)
            });

            _paths = new ListBox
            {
                Dock = DockStyle.Fill,
                SelectionMode = SelectionMode.MultiExtended,
                HorizontalScrollbar = true,
                Font = UiStyles.BodyFont()
            };
            Button addFiles = UiStyles.SecondaryButton("添加文件");
            Button addDirectory = UiStyles.SecondaryButton("添加目录");
            Button remove = UiStyles.SecondaryButton("移除选中");
            addFiles.Click += AddFilesClick;
            addDirectory.Click += AddDirectoryClick;
            remove.Click += delegate
            {
                while (_paths.SelectedIndices.Count > 0) _paths.Items.RemoveAt(_paths.SelectedIndices[0]);
            };
            GroupBox targets = CreateGroup("申请由管理员处理的目标", _paths, new[] { addFiles, addDirectory, remove });

            _reason = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                MaxLength = 2000,
                Font = UiStyles.BodyFont()
            };
            GroupBox reasonGroup = new GroupBox
            {
                Text = "原因 / 备注（可选，最多 2000 字）",
                Dock = DockStyle.Bottom,
                Height = 126,
                Padding = new Padding(10),
                Font = UiStyles.HeadingFont()
            };
            reasonGroup.Controls.Add(_reason);

            Panel body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(18, 14, 18, 8) };
            body.Controls.Add(targets);
            body.Controls.Add(reasonGroup);

            FlowLayoutPanel footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 62,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(16, 12, 16, 8),
                BackColor = Color.FromArgb(247, 249, 252)
            };
            Button submit = UiStyles.PrimaryButton("提交给 admin 审核");
            Button cancel = UiStyles.SecondaryButton("取消");
            submit.Click += SubmitClick;
            cancel.DialogResult = DialogResult.Cancel;
            footer.Controls.Add(submit);
            footer.Controls.Add(cancel);

            Controls.Add(body);
            Controls.Add(footer);
            Controls.Add(header);
            CancelButton = cancel;
        }

        private void AddFilesClick(object sender, EventArgs e)
        {
            using (OpenFileDialog dialog = new OpenFileDialog { Multiselect = true, CheckFileExists = true, Title = "选择要申请删除的文件" })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                foreach (string path in dialog.FileNames) AddUnique(path);
            }
        }

        private void AddDirectoryClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择要申请删除的目录", ShowNewFolderButton = false })
            {
                if (dialog.ShowDialog(this) == DialogResult.OK) AddUnique(dialog.SelectedPath);
            }
        }

        private void SubmitClick(object sender, EventArgs e)
        {
            try
            {
                List<string> paths = new List<string>();
                foreach (object item in _paths.Items) paths.Add(Convert.ToString(item));
                string output = DeletionRequestService.Submit(paths, _reason.Text);
                MessageBox.Show("删除申请已保存：\r\n" + output + "\r\n\r\nCodex Guard 没有移动或删除任何目标。", "申请已提交", MessageBoxButtons.OK, MessageBoxIcon.Information);
                DialogResult = DialogResult.OK;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "无法提交删除申请", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AddUnique(string path)
        {
            foreach (object current in _paths.Items)
                if (AppPaths.PathsEqual(Convert.ToString(current), path)) return;
            _paths.Items.Add(path);
        }

        private static GroupBox CreateGroup(string title, Control content, Button[] buttons)
        {
            GroupBox group = new GroupBox { Text = title, Dock = DockStyle.Fill, Padding = new Padding(10), Font = UiStyles.HeadingFont() };
            FlowLayoutPanel footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 48, Padding = new Padding(0, 7, 0, 3), Font = UiStyles.BodyFont() };
            foreach (Button button in buttons) footer.Controls.Add(button);
            group.Controls.Add(content);
            group.Controls.Add(footer);
            return group;
        }
    }
}
