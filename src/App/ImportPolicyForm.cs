using CodexGuard.Core;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class ImportPolicyForm : Form
    {
        private readonly DataGridView _grid;
        private readonly TextBox _oldRoot;
        private readonly TextBox _newRoot;

        public List<string> ActivePaths { get; private set; }

        public ImportPolicyForm(PortablePolicy policy)
        {
            UiStyles.PrepareForm(this);
            Text = "Codex Guard — 导入策略路径映射";
            Width = 940;
            Height = 620;
            MinimumSize = new Size(780, 500);
            ActivePaths = new List<string>();

            Panel header = new Panel { Dock = DockStyle.Top, Height = 84, BackColor = UiStyles.Navy, Padding = new Padding(18) };
            header.Controls.Add(new Label
            {
                Text = "路径映射与人工确认",
                ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 16F, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(17, 13)
            });
            header.Controls.Add(new Label
            {
                Text = "策略只包含激活项目路径；管理员资料保护和默认只读边界不会导入。",
                ForeColor = Color.FromArgb(205, 218, 234),
                Font = UiStyles.BodyFont(),
                AutoSize = true,
                Location = new Point(20, 49)
            });

            _grid = new DataGridView
            {
                Dock = DockStyle.Fill,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AutoGenerateColumns = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = false,
                BackgroundColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = UiStyles.BodyFont()
            };
            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Kind", HeaderText = "类型", Width = 95, ReadOnly = true });
            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Source", HeaderText = "来源路径", Width = 330, ReadOnly = true });
            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Target", HeaderText = "目标路径（可编辑）", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Exists", HeaderText = "存在", Width = 58, ReadOnly = true });

            if (policy.ActivatedPaths != null)
                foreach (string path in policy.ActivatedPaths) AddRow("激活", path);

            TableLayoutPanel mapping = new TableLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 96,
                ColumnCount = 5,
                Padding = new Padding(14, 10, 14, 8),
                BackColor = UiStyles.PaleBlue
            };
            mapping.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 65));
            mapping.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
            mapping.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 65));
            mapping.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
            mapping.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 115));
            mapping.Controls.Add(UiStyles.Label("旧根", true), 0, 0);
            _oldRoot = new TextBox { Dock = DockStyle.Fill, Font = UiStyles.BodyFont() };
            _newRoot = new TextBox { Dock = DockStyle.Fill, Font = UiStyles.BodyFont() };
            mapping.Controls.Add(_oldRoot, 1, 0);
            mapping.Controls.Add(UiStyles.Label("新根", true), 2, 0);
            mapping.Controls.Add(_newRoot, 3, 0);
            Button applyMap = UiStyles.SecondaryButton("应用映射");
            applyMap.Click += ApplyMapping;
            mapping.Controls.Add(applyMap, 4, 0);
            Label hint = UiStyles.Label("示例：旧根 D:\\，新根 E:\\；只改变前缀，不复制任何文件。", false);
            mapping.Controls.Add(hint, 0, 1);
            mapping.SetColumnSpan(hint, 5);

            FlowLayoutPanel footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 60,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(14, 11, 14, 8)
            };
            Button accept = UiStyles.PrimaryButton("验证并导入");
            Button browse = UiStyles.SecondaryButton("浏览选中目标");
            Button cancel = UiStyles.SecondaryButton("取消");
            accept.Click += AcceptClick;
            browse.Click += BrowseClick;
            cancel.DialogResult = DialogResult.Cancel;
            footer.Controls.Add(accept);
            footer.Controls.Add(cancel);
            footer.Controls.Add(browse);

            Panel body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(16, 14, 16, 8) };
            body.Controls.Add(_grid);
            Controls.Add(body);
            Controls.Add(mapping);
            Controls.Add(footer);
            Controls.Add(header);
            CancelButton = cancel;
        }

        private void AddRow(string kind, string source)
        {
            int index = _grid.Rows.Add(kind, source, source, Directory.Exists(source) ? "是" : "否");
            if (!Directory.Exists(source)) _grid.Rows[index].DefaultCellStyle.BackColor = Color.FromArgb(255, 242, 232);
        }

        private void ApplyMapping(object sender, EventArgs e)
        {
            try
            {
                string oldRoot = AppPaths.NormalizeDirectoryPath(_oldRoot.Text);
                string newRoot = AppPaths.NormalizeDirectoryPath(_newRoot.Text);
                foreach (DataGridViewRow row in _grid.Rows)
                {
                    string source = Convert.ToString(row.Cells["Source"].Value);
                    if (!AppPaths.IsPathInside(source, oldRoot)) continue;
                    string suffix = AppPaths.NormalizeDirectoryPath(source).Substring(oldRoot.Length).TrimStart('\\');
                    string mapped = suffix.Length == 0 ? newRoot : Path.Combine(newRoot, suffix);
                    row.Cells["Target"].Value = mapped;
                    row.Cells["Exists"].Value = Directory.Exists(mapped) ? "是" : "否";
                    row.DefaultCellStyle.BackColor = Directory.Exists(mapped) ? Color.White : Color.FromArgb(255, 242, 232);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "路径映射失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BrowseClick(object sender, EventArgs e)
        {
            if (_grid.SelectedRows.Count == 0) return;
            using (FolderBrowserDialog dialog = new FolderBrowserDialog())
            {
                dialog.Description = "选择该策略项在本机对应的目录";
                dialog.ShowNewFolderButton = false;
                string current = Convert.ToString(_grid.SelectedRows[0].Cells["Target"].Value);
                if (Directory.Exists(current)) dialog.SelectedPath = current;
                if (dialog.ShowDialog(this) == DialogResult.OK)
                {
                    _grid.SelectedRows[0].Cells["Target"].Value = dialog.SelectedPath;
                    _grid.SelectedRows[0].Cells["Exists"].Value = "是";
                    _grid.SelectedRows[0].DefaultCellStyle.BackColor = Color.White;
                }
            }
        }

        private void AcceptClick(object sender, EventArgs e)
        {
            ActivePaths.Clear();
            foreach (DataGridViewRow row in _grid.Rows)
            {
                string target = Convert.ToString(row.Cells["Target"].Value);
                if (!Directory.Exists(target))
                {
                    MessageBox.Show("目标目录不存在：\r\n" + target, "无法导入", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                ActivePaths.Add(target);
            }
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
