using CodexGuard.Core;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class OperationProgressForm : Form
    {
        private readonly PreparedGuardOperation _prepared;
        private readonly bool _executeOperation;
        private readonly BackgroundWorker _worker;
        private readonly Stopwatch _stopwatch;
        private readonly Timer _elapsedTimer;
        private readonly Label _stage;
        private readonly TextBox _path;
        private readonly Label _detail;
        private readonly Label _elapsed;
        private bool _running;

        public OperationProgressForm(PreparedGuardOperation prepared)
            : this(prepared, true)
        {
        }

        internal OperationProgressForm(PreparedGuardOperation prepared, bool executeOperation)
        {
            if (prepared == null || prepared.Request == null) throw new ArgumentNullException("prepared");
            _prepared = prepared;
            _executeOperation = executeOperation;
            _worker = new BackgroundWorker();
            _stopwatch = new Stopwatch();
            _elapsedTimer = new Timer { Interval = 1000 };

            UiStyles.PrepareForm(this);
            Text = "Codex Guard — 权限事务进行中";
            Width = 760;
            Height = 470;
            MinimumSize = new Size(680, 440);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            ControlBox = false;
            MinimizeBox = false;
            MaximizeBox = false;
            ShowInTaskbar = true;
            UseWaitCursor = true;

            Panel header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 96,
                BackColor = UiStyles.Navy,
                Padding = new Padding(24, 16, 24, 12)
            };
            Label title = new Label
            {
                Text = OperationHeading(prepared.Request.Operation),
                AutoSize = true,
                Font = new Font("Microsoft YaHei UI", 18F, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(22, 16)
            };
            Label subtitle = new Label
            {
                Text = "UAC 提升端正在执行受保护的 NTFS 权限事务",
                AutoSize = true,
                Font = UiStyles.BodyFont(),
                ForeColor = Color.FromArgb(211, 224, 240),
                Location = new Point(24, 59)
            };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);

            TableLayoutPanel content = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 8,
                Padding = new Padding(24, 16, 24, 14),
                BackColor = Color.White
            };
            content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 28F));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 27F));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 36F));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 64F));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 28F));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 82F));
            content.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

            _stage = new Label
            {
                Text = "正在准备权限事务…",
                Dock = DockStyle.Fill,
                AutoEllipsis = true,
                Font = UiStyles.HeadingFont(),
                ForeColor = UiStyles.Navy,
                TextAlign = ContentAlignment.MiddleLeft
            };
            ProgressBar progress = new ProgressBar
            {
                Name = "TransactionProgressBar",
                Dock = DockStyle.Fill,
                Style = ProgressBarStyle.Marquee,
                MarqueeAnimationSpeed = 28
            };
            Label pathCaption = new Label
            {
                Text = "当前路径",
                Dock = DockStyle.Fill,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Muted,
                TextAlign = ContentAlignment.BottomLeft
            };
            _path = new TextBox
            {
                Text = "等待事务报告路径",
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BackColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9F),
                TabStop = false
            };
            _detail = new Label
            {
                Text = "确认窗口已关闭；正在启动受保护操作。",
                Dock = DockStyle.Fill,
                AutoEllipsis = true,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Muted,
                Padding = new Padding(0, 8, 0, 4)
            };
            _elapsed = new Label
            {
                Text = "已用时间：00:00:00",
                Dock = DockStyle.Fill,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Navy,
                TextAlign = ContentAlignment.MiddleLeft
            };

            Panel warningPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(255, 247, 230),
                Padding = new Padding(14, 10, 14, 8),
                Margin = new Padding(0, 6, 0, 0)
            };
            Label warning = new Label
            {
                Text = "请勿强制关闭：事务期间窗口关闭已禁用。不要通过任务管理器结束进程，也不要关机或重启。\r\n"
                    + "发生可捕获错误时，Codex Guard 会自动按快照回滚；强制结束可能留下只应用一部分的 ACL。",
                Dock = DockStyle.Fill,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Amber
            };
            warningPanel.Controls.Add(warning);

            content.Controls.Add(_stage, 0, 0);
            content.Controls.Add(progress, 0, 1);
            content.Controls.Add(pathCaption, 0, 2);
            content.Controls.Add(_path, 0, 3);
            content.Controls.Add(_detail, 0, 4);
            content.Controls.Add(_elapsed, 0, 5);
            content.Controls.Add(warningPanel, 0, 6);

            Controls.Add(content);
            Controls.Add(header);

            _elapsedTimer.Tick += delegate { UpdateElapsed(); };
            _worker.DoWork += delegate(object sender, DoWorkEventArgs e)
            {
                e.Result = GuardOperationService.Execute(_prepared, ReceiveProgress);
            };
            _worker.RunWorkerCompleted += WorkerCompleted;

            if (!_executeOperation)
            {
                ApplyProgress(new GuardOperationProgress
                {
                    Stage = "正在应用默认只读边界",
                    Path = "D:\\",
                    Detail = "边界 1/2；Windows 正在向现有子项传播继承 ACL，文件较多时可能耗时较长。"
                });
                _elapsed.Text = "已用时间：00:12:34（界面预览）";
            }
        }

        internal OperationResult OperationResult { get; private set; }
        internal Exception OperationError { get; private set; }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (!_executeOperation) return;
            _running = true;
            _stopwatch.Start();
            _elapsedTimer.Start();
            _worker.RunWorkerAsync();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (_running && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                _detail.Text = "权限事务仍在执行，窗口不能关闭。请等待成功结果或自动回滚完成。";
                System.Media.SystemSounds.Exclamation.Play();
                return;
            }
            base.OnFormClosing(e);
        }

        private void ReceiveProgress(GuardOperationProgress value)
        {
            if (value == null || IsDisposed) return;
            if (InvokeRequired)
            {
                try
                {
                    BeginInvoke((MethodInvoker)delegate { ApplyProgress(value); });
                }
                catch (ObjectDisposedException) { }
                catch (InvalidOperationException) { }
                return;
            }
            ApplyProgress(value);
        }

        private void ApplyProgress(GuardOperationProgress value)
        {
            if (value == null || IsDisposed) return;
            _stage.Text = string.IsNullOrWhiteSpace(value.Stage) ? "正在执行权限事务" : value.Stage;
            _path.Text = string.IsNullOrWhiteSpace(value.Path) ? "（当前阶段没有单一路径）" : value.Path;
            _detail.Text = string.IsNullOrWhiteSpace(value.Detail) ? "请等待当前阶段完成。" : value.Detail;
        }

        private void WorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            _elapsedTimer.Stop();
            _stopwatch.Stop();
            UpdateElapsed();
            _running = false;
            if (e.Error != null) OperationError = e.Error;
            else OperationResult = e.Result as OperationResult;
            DialogResult = OperationError == null && OperationResult != null ? DialogResult.OK : DialogResult.Abort;
            Close();
        }

        private void UpdateElapsed()
        {
            TimeSpan value = _stopwatch.Elapsed;
            _elapsed.Text = "已用时间：" + ((int)value.TotalHours).ToString("00") + ":" + value.Minutes.ToString("00") + ":" + value.Seconds.ToString("00");
        }

        private static string OperationHeading(GuardOperation operation)
        {
            switch (operation)
            {
                case GuardOperation.ApplyDefaultReadOnly: return "正在应用默认只读基线";
                case GuardOperation.Activate: return "正在激活工作目录";
                case GuardOperation.Revoke: return "正在撤销工作目录";
                case GuardOperation.Repair:
                case GuardOperation.BindSandbox: return "正在修复 Codex Guard 权限";
                case GuardOperation.ImportPolicy: return "正在导入工作目录策略";
                default: return "正在执行权限事务";
            }
        }
    }
}
