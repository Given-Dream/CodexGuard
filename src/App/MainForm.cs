using CodexGuard.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal sealed class MainForm : Form
    {
        private readonly Label _installationStatus;
        private readonly Label _identityStatus;
        private readonly ListView _activeList;
        private readonly ListBox _pendingList;
        private readonly ListView _defaultReadOnlyList;
        private readonly Label _defaultReadOnlySummary;
        private readonly Button _applyDefaultReadOnlyButton;
        private readonly TextBox _ntfsPathText;
        private readonly Label _ntfsSummary;
        private readonly ListView _ntfsPolicyList;
        private readonly ListView _ntfsAclList;
        private readonly ListView _auditList;
        private readonly Label _auditSummary;
        private readonly ListView _softwareList;
        private readonly Label _softwareSummary;
        private readonly ListView _offlineReuseList;
        private readonly Label _offlineReuseSummary;
        private readonly Button _addPendingButton;
        private readonly Button _removePendingButton;
        private readonly Button _activateButton;
        private readonly Button _revokeButton;
        private readonly Button _repairButton;
        private readonly Button _exportButton;
        private readonly Button _importButton;
        private readonly Button _submitDeleteRequestButton;
        private readonly Button _openReviewerButton;
        private readonly Button _openProbeButton;
        private readonly Button _createSoftwareShortcutsButton;
        private readonly Button _prepareOfflineCopiesButton;
        private ReviewReport _lastReviewReport;
        private SoftwareInventoryReport _softwareReport;
        private OfflineReuseReport _offlineReuseReport;
        private DefaultReadOnlyReport _defaultReadOnlyReport;
        private bool _canManagePermissionRequests;
        private bool _canSubmitDeletionRequests;

        public MainForm()
        {
            UiStyles.PrepareForm(this);
            Text = "Codex Guard";
            Width = 1120;
            Height = 790;
            MinimumSize = new Size(920, 680);

            Panel header = new Panel { Dock = DockStyle.Top, Height = 112, BackColor = UiStyles.Navy, Padding = new Padding(22, 15, 22, 12) };
            header.Controls.Add(new Label
            {
                Text = "Codex Guard",
                ForeColor = Color.White,
                Font = UiStyles.TitleFont(),
                AutoSize = true,
                Location = new Point(18, 12)
            });
            header.Controls.Add(new Label
            {
                Text = "持久激活 · 禁止删除与重命名 · 管理员人工授权",
                ForeColor = Color.FromArgb(205, 218, 234),
                Font = UiStyles.BodyFont(),
                AutoSize = true,
                Location = new Point(21, 57)
            });
            _installationStatus = new Label { AutoSize = false, Dock = DockStyle.Fill, Font = UiStyles.BodyFont(), ForeColor = Color.White, TextAlign = ContentAlignment.MiddleLeft };
            _identityStatus = new Label { AutoSize = false, Dock = DockStyle.Fill, Font = UiStyles.BodyFont(), ForeColor = Color.FromArgb(205, 218, 234), TextAlign = ContentAlignment.MiddleLeft };
            TableLayoutPanel identityPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Right,
                Width = 445,
                RowCount = 2,
                ColumnCount = 1,
                Padding = new Padding(8, 8, 8, 8),
                BackColor = UiStyles.Navy
            };
            identityPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            identityPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            identityPanel.Controls.Add(_installationStatus, 0, 0);
            identityPanel.Controls.Add(_identityStatus, 0, 1);
            header.Controls.Add(identityPanel);

            TabControl tabs = new TabControl { Dock = DockStyle.Fill, Font = UiStyles.BodyFont(), Padding = new Point(14, 5) };
            TabPage workspaceTab = new TabPage("工作目录") { BackColor = Color.White, Padding = new Padding(12) };
            TabPage defaultReadOnlyTab = new TabPage("默认只读") { BackColor = Color.White, Padding = new Padding(12) };
            TabPage ntfsTab = new TabPage("NTFS 权限") { BackColor = Color.White, Padding = new Padding(12) };
            TabPage auditTab = new TabPage("安全审计") { BackColor = Color.White, Padding = new Padding(12) };
            TabPage softwareTab = new TabPage("软件映射") { BackColor = Color.White, Padding = new Padding(12) };
            TabPage offlineReuseTab = new TabPage("离线复用") { BackColor = Color.White, Padding = new Padding(12) };
            TabPage migrationTab = new TabPage("迁移与部署") { BackColor = Color.White, Padding = new Padding(12) };
            tabs.TabPages.Add(workspaceTab);
            tabs.TabPages.Add(defaultReadOnlyTab);
            tabs.TabPages.Add(ntfsTab);
            tabs.TabPages.Add(auditTab);
            tabs.TabPages.Add(softwareTab);
            tabs.TabPages.Add(offlineReuseTab);
            tabs.TabPages.Add(migrationTab);

            _activeList = CreatePathList("激活时间");
            _pendingList = new ListBox { Dock = DockStyle.Fill, SelectionMode = SelectionMode.MultiExtended, Font = UiStyles.BodyFont(), HorizontalScrollbar = true };
            _activateButton = UiStyles.PrimaryButton("UAC 追加激活");
            _revokeButton = UiStyles.SecondaryButton("人工撤销选中");
            _addPendingButton = UiStyles.SecondaryButton("添加目录");
            _removePendingButton = UiStyles.SecondaryButton("移除");
            _addPendingButton.Click += AddPendingClick;
            _removePendingButton.Click += delegate
            {
                while (_pendingList.SelectedIndices.Count > 0) _pendingList.Items.RemoveAt(_pendingList.SelectedIndices[0]);
                UpdateButtonState();
            };
            _activateButton.Click += ActivateClick;
            _revokeButton.Click += RevokeClick;
            _pendingList.SelectedIndexChanged += delegate { UpdateButtonState(); };
            _activeList.SelectedIndexChanged += delegate { UpdateButtonState(); };

            TableLayoutPanel workspaceLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
            workspaceLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55));
            workspaceLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
            workspaceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 66));
            workspaceLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Label workspaceBoundary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Navy,
                BackColor = UiStyles.PaleBlue,
                Padding = new Padding(14, 11, 14, 8),
                Text = "固定边界：" + AppInfo.AdminProfilePath + " 由安装/修复维护；其他项目必须位于已应用的默认只读边界下。仅非提升 admin 可管理激活目录，CodexWorker 只读查看。"
            };
            workspaceLayout.Controls.Add(workspaceBoundary, 0, 0);
            workspaceLayout.SetColumnSpan(workspaceBoundary, 2);
            workspaceLayout.Controls.Add(CreateGroup("已永久激活的目录", _activeList, new[] { _revokeButton }), 0, 1);
            workspaceLayout.Controls.Add(CreateGroup("待追加激活（可多选）", _pendingList, new[] { _addPendingButton, _removePendingButton, _activateButton }), 1, 1);
            workspaceTab.Controls.Add(workspaceLayout);

            _defaultReadOnlyList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                Font = UiStyles.BodyFont()
            };
            _defaultReadOnlyList.Columns.Add("状态", 112);
            _defaultReadOnlyList.Columns.Add("类型", 115);
            _defaultReadOnlyList.Columns.Add("路径", 315);
            _defaultReadOnlyList.Columns.Add("应用后的效果", 330);
            _defaultReadOnlyList.Columns.Add("原因 / 下一步", 430);
            Button refreshDefaultReadOnly = UiStyles.SecondaryButton("重新只读预览");
            _applyDefaultReadOnlyButton = UiStyles.PrimaryButton("UAC 应用默认只读");
            refreshDefaultReadOnly.Click += delegate { RefreshDefaultReadOnly(); UpdateButtonState(); };
            _applyDefaultReadOnlyButton.Click += ApplyDefaultReadOnlyClick;
            _defaultReadOnlySummary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.HeadingFont(),
                ForeColor = UiStyles.Navy,
                BackColor = UiStyles.PaleBlue,
                Padding = new Padding(16, 12, 16, 10),
                TextAlign = ContentAlignment.MiddleLeft,
                Text = "正在只读盘点固定数据盘、Worker 数据目录和运行时写入允许列表……"
            };
            Label defaultReadOnlyBoundary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Navy,
                BackColor = Color.FromArgb(248, 250, 253),
                Padding = new Padding(16, 9, 16, 7),
                Text = "允许列表基线\r\n\r\n"
                    + "• AppData、.codex 和已存在的 .cache：保留正常写入与清理，不能保存唯一原件。\r\n"
                    + "• 已激活工作目录：允许写入/新建，仍拒绝删除、重命名和改 ACL。\r\n"
                    + "• 其他固定数据盘和 Worker 顶层数据目录：默认只读，并拒绝写入、新建和删除。\r\n"
                    + "• Windows、Program Files、ProgramData：沿用 Windows 管理；系统级更新由 admin/SYSTEM 完成。\r\n"
                    + "• admin SID 不进入 Guard 限制集合；admin 权限沿用 Windows 原始 DACL。\r\n"
                    + "• 本页预览不改权限；仅非提升 admin 可提交，仍须在 UAC 安全桌面确认后才应用。"
            };
            TableLayoutPanel defaultReadOnlyLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            defaultReadOnlyLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 92));
                defaultReadOnlyLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 168));
            defaultReadOnlyLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            defaultReadOnlyLayout.Controls.Add(_defaultReadOnlySummary, 0, 0);
            defaultReadOnlyLayout.Controls.Add(defaultReadOnlyBoundary, 0, 1);
            defaultReadOnlyLayout.Controls.Add(CreateGroup("本机默认只读计划（只读生成；红色阻断时不会提交 UAC）", _defaultReadOnlyList,
                new[] { refreshDefaultReadOnly, _applyDefaultReadOnlyButton }), 0, 2);
            defaultReadOnlyTab.Controls.Add(defaultReadOnlyLayout);

            _ntfsPathText = new TextBox
            {
                Dock = DockStyle.Fill,
                Font = UiStyles.BodyFont(),
                Margin = new Padding(0, 9, 8, 7)
            };
            Button chooseNtfsPath = UiStyles.SecondaryButton("选择目录");
            Button inspectNtfsPath = UiStyles.PrimaryButton("只读核查");
            chooseNtfsPath.Click += BrowseNtfsPathClick;
            inspectNtfsPath.Click += delegate { RefreshNtfsInspection(); };
            _ntfsPathText.KeyDown += delegate(object sender, KeyEventArgs e)
            {
                if (e.KeyCode != Keys.Enter) return;
                e.SuppressKeyPress = true;
                RefreshNtfsInspection();
            };
            FlowLayoutPanel ntfsButtons = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 2, 0, 2)
            };
            ntfsButtons.Controls.Add(chooseNtfsPath);
            ntfsButtons.Controls.Add(inspectNtfsPath);
            TableLayoutPanel ntfsSelector = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
            ntfsSelector.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            ntfsSelector.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 285));
            ntfsSelector.Controls.Add(_ntfsPathText, 0, 0);
            ntfsSelector.Controls.Add(ntfsButtons, 1, 0);
            GroupBox ntfsSelectorGroup = new GroupBox
            {
                Dock = DockStyle.Fill,
                Text = "待核查目录（只读，不修改 ACL）",
                Font = UiStyles.HeadingFont(),
                ForeColor = UiStyles.Navy,
                Padding = new Padding(10, 4, 10, 6)
            };
            ntfsSelectorGroup.Controls.Add(ntfsSelector);

            _ntfsSummary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.HeadingFont(),
                ForeColor = UiStyles.Navy,
                BackColor = UiStyles.PaleBlue,
                Padding = new Padding(16, 10, 16, 8),
                TextAlign = ContentAlignment.MiddleLeft,
                Text = "选择目录后，只读显示 Guard 分类和 Windows 原始 DACL。\r\nGuard 策略表不等于 Windows 最终有效权限。"
            };

            _ntfsPolicyList = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false };
            _ntfsPolicyList.Columns.Add("状态", 72);
            _ntfsPolicyList.Columns.Add("身份", 150);
            _ntfsPolicyList.Columns.Add("SID", 255);
            _ntfsPolicyList.Columns.Add("读取", 110);
            _ntfsPolicyList.Columns.Add("写入/新建", 125);
            _ntfsPolicyList.Columns.Add("删除/重命名", 135);
            _ntfsPolicyList.Columns.Add("改 ACL/所有者", 140);
            _ntfsPolicyList.Columns.Add("证据边界", 430);

            _ntfsAclList = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false };
            _ntfsAclList.Columns.Add("身份", 230);
            _ntfsAclList.Columns.Add("SID", 250);
            _ntfsAclList.Columns.Add("类型", 70);
            _ntfsAclList.Columns.Add("权限", 355);
            _ntfsAclList.Columns.Add("来源", 72);
            _ntfsAclList.Columns.Add("作用范围", 190);

            GroupBox ntfsPolicyGroup = new GroupBox
            {
                Text = "Guard 策略表征（Worker / Sandbox / admin）",
                Dock = DockStyle.Fill,
                Padding = new Padding(10),
                Font = UiStyles.HeadingFont()
            };
            ntfsPolicyGroup.Controls.Add(_ntfsPolicyList);
            GroupBox ntfsAclGroup = new GroupBox
            {
                Text = "Windows 原始 DACL（允许/拒绝、显式/继承）",
                Dock = DockStyle.Fill,
                Padding = new Padding(10),
                Font = UiStyles.HeadingFont()
            };
            ntfsAclGroup.Controls.Add(_ntfsAclList);
            TableLayoutPanel ntfsLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
            ntfsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));
            ntfsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 112));
            ntfsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 205));
            ntfsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            ntfsLayout.Controls.Add(ntfsSelectorGroup, 0, 0);
            ntfsLayout.Controls.Add(_ntfsSummary, 0, 1);
            ntfsLayout.Controls.Add(ntfsPolicyGroup, 0, 2);
            ntfsLayout.Controls.Add(ntfsAclGroup, 0, 3);
            ntfsTab.Controls.Add(ntfsLayout);

            _auditList = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, Font = UiStyles.BodyFont() };
            _auditList.Columns.Add("级别", 72);
            _auditList.Columns.Add("代码", 190);
            _auditList.Columns.Add("路径", 360);
            _auditList.Columns.Add("说明", 430);
            Button auditRefresh = UiStyles.SecondaryButton("重新审计");
            Button exportReview = UiStyles.SecondaryButton("导出人工核查包");
            _openReviewerButton = UiStyles.SecondaryButton("独立核查器");
            _openProbeButton = UiStyles.SecondaryButton("验收探针");
            _repairButton = UiStyles.PrimaryButton("UAC 绑定 / 修复全部权限");
            auditRefresh.Click += delegate { RefreshAudit(); };
            exportReview.Click += ExportReviewClick;
            _openReviewerButton.Click += delegate { OpenCompanion(AppPaths.InstalledReviewerExecutable, "独立只读核查器"); };
            _openProbeButton.Click += delegate { OpenCompanion(AppPaths.InstalledAcceptanceExecutable, "验收探针"); };
            _repairButton.Click += RepairClick;
            _auditSummary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.HeadingFont(),
                ForeColor = UiStyles.Navy,
                BackColor = UiStyles.PaleBlue,
                Padding = new Padding(16, 12, 16, 10),
                TextAlign = ContentAlignment.MiddleLeft,
                Text = "正在读取只读核查事实……"
            };
            TableLayoutPanel auditLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            auditLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 82));
            auditLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            auditLayout.Controls.Add(_auditSummary, 0, 0);
            auditLayout.Controls.Add(CreateGroup("只读安全检查（含 Worker/admin 本地记录路径隔离；不读取令牌或对话正文）", _auditList, new[] { auditRefresh, exportReview, _openReviewerButton, _openProbeButton, _repairButton }), 0, 1);
            auditTab.Controls.Add(auditLayout);

            _softwareList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                CheckBoxes = true,
                Font = UiStyles.BodyFont()
            };
            _softwareList.Columns.Add("分类", 125);
            _softwareList.Columns.Add("软件", 220);
            _softwareList.Columns.Add("版本", 105);
            _softwareList.Columns.Add("发布者", 170);
            _softwareList.Columns.Add("已核验位置", 340);
            _softwareList.Columns.Add("下一步", 390);
            _softwareList.ItemCheck += delegate(object sender, ItemCheckEventArgs e)
            {
                SoftwareInventoryItem candidate = _softwareList.Items[e.Index].Tag as SoftwareInventoryItem;
                if (e.NewValue == CheckState.Checked && (candidate == null || !candidate.CanCreateShortcut))
                    e.NewValue = CheckState.Unchecked;
                if (IsHandleCreated) BeginInvoke((MethodInvoker)delegate { UpdateButtonState(); });
            };
            Button refreshSoftware = UiStyles.SecondaryButton("重新扫描");
            Button selectAllSoftware = UiStyles.SecondaryButton("勾选全部可映射");
            Button clearSoftwareSelection = UiStyles.SecondaryButton("取消勾选");
            _createSoftwareShortcutsButton = UiStyles.PrimaryButton("UAC 创建勾选快捷方式");
            Button exportSoftware = UiStyles.SecondaryButton("导出 CSV 清单");
            Button openMappedSoftware = UiStyles.SecondaryButton("打开公共快捷方式目录");
            refreshSoftware.Click += delegate { RefreshSoftwareInventory(); UpdateButtonState(); };
            selectAllSoftware.Click += delegate
            {
                foreach (ListViewItem row in _softwareList.Items)
                {
                    SoftwareInventoryItem item = row.Tag as SoftwareInventoryItem;
                    row.Checked = item != null && item.CanCreateShortcut;
                }
                UpdateButtonState();
            };
            clearSoftwareSelection.Click += delegate
            {
                foreach (ListViewItem row in _softwareList.Items) row.Checked = false;
                UpdateButtonState();
            };
            _createSoftwareShortcutsButton.Click += CreateSoftwareShortcutsClick;
            exportSoftware.Click += ExportSoftwareInventoryClick;
            openMappedSoftware.Click += OpenMappedSoftwareDirectoryClick;
            _softwareSummary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.HeadingFont(),
                ForeColor = UiStyles.Navy,
                BackColor = UiStyles.PaleBlue,
                Padding = new Padding(16, 12, 16, 10),
                TextAlign = ContentAlignment.MiddleLeft,
                Text = "正在以只读方式扫描系统级安装、用户级注册和开始菜单快捷方式……"
            };
            Label softwareBoundary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Navy,
                BackColor = Color.FromArgb(248, 250, 253),
                Padding = new Padding(16, 10, 16, 8),
                Text = "安全边界\r\n\r\n"
                    + "• 扫描只读取卸载注册表与 .lnk 元数据，不启动软件、不读取软件数据。\r\n"
                    + "• 自动映射接受 Program Files，以及父路径直到盘根均通过 ACL 核验的本机固定 NTFS 共享 EXE。\r\n"
                    + "• 输出只是公共开始菜单 .lnk，不复制程序、不包含启动参数，也不开放 admin AppData。\r\n"
                    + "• Store/MSIX 需要复用现有包注册；admin AppData、未知 EXE 和不安全 ACL 会显示“技术阻断”。"
            };
            TableLayoutPanel softwareLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            softwareLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 82));
            softwareLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 132));
            softwareLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            softwareLayout.Controls.Add(_softwareSummary, 0, 0);
            softwareLayout.Controls.Add(softwareBoundary, 0, 1);
            softwareLayout.Controls.Add(CreateGroup("全部可直接映射的软件（技术阻断项不会被勾选）", _softwareList, new[] { selectAllSoftware, clearSoftwareSelection, _createSoftwareShortcutsButton, refreshSoftware, exportSoftware, openMappedSoftware }), 0, 2);
            softwareTab.Controls.Add(softwareLayout);

            _offlineReuseList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                CheckBoxes = true,
                Font = UiStyles.BodyFont()
            };
            _offlineReuseList.Columns.Add("无下载方式", 145);
            _offlineReuseList.Columns.Add("软件", 215);
            _offlineReuseList.Columns.Add("版本", 100);
            _offlineReuseList.Columns.Add("现有程序/介质", 410);
            _offlineReuseList.Columns.Add("下一步", 420);
            _offlineReuseList.ItemCheck += delegate(object sender, ItemCheckEventArgs e)
            {
                OfflineReuseItem candidate = _offlineReuseList.Items[e.Index].Tag as OfflineReuseItem;
                if (e.NewValue == CheckState.Checked && (candidate == null || !candidate.CanPrepareCopy))
                    e.NewValue = CheckState.Unchecked;
                if (IsHandleCreated) BeginInvoke((MethodInvoker)delegate { UpdateButtonState(); });
            };
            Button refreshOfflineReuse = UiStyles.SecondaryButton("重新盘点");
            Button selectOfflineCopies = UiStyles.SecondaryButton("勾选 AppData 可提取项");
            Button clearOfflineCopies = UiStyles.SecondaryButton("取消勾选");
            _prepareOfflineCopiesButton = UiStyles.PrimaryButton("UAC 准备 Worker 本地副本");
            Button exportOfflineReuse = UiStyles.SecondaryButton("导出模拟迁移 CSV");
            Button openOfflineHistory = UiStyles.SecondaryButton("打开离线复用审计目录");
            refreshOfflineReuse.Click += delegate { RefreshOfflineReuse(); UpdateButtonState(); };
            selectOfflineCopies.Click += delegate
            {
                foreach (ListViewItem row in _offlineReuseList.Items)
                {
                    OfflineReuseItem item = row.Tag as OfflineReuseItem;
                    row.Checked = item != null && item.CanPrepareCopy;
                }
                UpdateButtonState();
            };
            clearOfflineCopies.Click += delegate
            {
                foreach (ListViewItem row in _offlineReuseList.Items) row.Checked = false;
                UpdateButtonState();
            };
            _prepareOfflineCopiesButton.Click += PrepareOfflineCopiesClick;
            exportOfflineReuse.Click += ExportOfflineReuseClick;
            openOfflineHistory.Click += OpenOfflineReuseHistoryClick;
            _offlineReuseSummary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.HeadingFont(),
                ForeColor = UiStyles.Navy,
                BackColor = UiStyles.PaleBlue,
                Padding = new Padding(16, 12, 16, 10),
                TextAlign = ContentAlignment.MiddleLeft,
                Text = "正在盘点可直接复用、本地安装介质、admin AppData 程序与 Store 注册需求……"
            };
            Label offlineReuseBoundary = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = false,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Navy,
                BackColor = Color.FromArgb(248, 250, 253),
                Padding = new Padding(16, 9, 16, 7),
                Text = "离线复用边界\r\n\r\n"
                    + "• 机器级软件直接使用；本地 MSI/EXE 只列出路径，Codex Guard 不自动执行安装器。\r\n"
                    + "• 自动复制仅接受 admin\\AppData\\Local\\Programs 下的单一程序目录，目标固定为 CodexWorker\\AppData\\Local\\Programs。\r\n"
                    + "• 源文件只读，目标 CreateNew；不覆盖、不移动、不删除、不复制整个 AppData，不导入注册表或登录令牌。\r\n"
                    + "• 复制后必须由 Worker 首次运行；注册表、许可证、Store 包和特殊启动参数仍需逐项验证。"
            };
            TableLayoutPanel offlineReuseLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            offlineReuseLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 82));
            offlineReuseLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 136));
            offlineReuseLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            offlineReuseLayout.Controls.Add(_offlineReuseSummary, 0, 0);
            offlineReuseLayout.Controls.Add(offlineReuseBoundary, 0, 1);
            offlineReuseLayout.Controls.Add(CreateGroup("模拟迁移清单（只有 AppData 可提取项可以勾选复制）", _offlineReuseList,
                new[] { selectOfflineCopies, clearOfflineCopies, _prepareOfflineCopiesButton, refreshOfflineReuse, exportOfflineReuse, openOfflineHistory }), 0, 2);
            offlineReuseTab.Controls.Add(offlineReuseLayout);

            _exportButton = UiStyles.SecondaryButton("导出可移植策略");
            _importButton = UiStyles.PrimaryButton("导入策略并通过一次 UAC 应用");
            Button install = UiStyles.PrimaryButton("安装 / 修复 Codex Guard");
            _submitDeleteRequestButton = UiStyles.SecondaryButton("提交删除申请");
            Button openDeleteRequests = UiStyles.SecondaryButton("打开删除申请目录");
            _exportButton.Click += ExportClick;
            _importButton.Click += ImportClick;
            install.Click += InstallClick;
            _submitDeleteRequestButton.Click += delegate
            {
                using (DeletionRequestForm form = new DeletionRequestForm()) form.ShowDialog(this);
            };
            openDeleteRequests.Click += OpenDeleteRequestsClick;

            Label migrationText = new Label
            {
                Dock = DockStyle.Top,
                Height = 210,
                AutoSize = false,
                Font = UiStyles.BodyFont(),
                ForeColor = UiStyles.Navy,
                BackColor = UiStyles.PaleBlue,
                Padding = new Padding(18),
                Text = "迁移原则\r\n\r\n"
                    + "• 导出文件只保存已激活项目路径，不保存管理员资料保护、默认只读边界、密码、登录、机器 SID 或原始 ACL。\r\n"
                    + "• 在新电脑先安装固定管理员资料保护并应用本机默认只读，再通过路径映射恢复激活项目。\r\n"
                    + "• 导入是累加操作，不会把当前已经激活的目录恢复为只读。\r\n"
                    + "• Codex Guard 不包含删除功能；删除申请由 admin 人工处理。"
            };
            FlowLayoutPanel migrationButtons = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 62, Padding = new Padding(0, 12, 0, 8) };
            migrationButtons.Controls.Add(install);
            migrationButtons.Controls.Add(_exportButton);
            migrationButtons.Controls.Add(_importButton);
            migrationButtons.Controls.Add(_submitDeleteRequestButton);
            migrationButtons.Controls.Add(openDeleteRequests);
            migrationTab.Controls.Add(migrationButtons);
            migrationTab.Controls.Add(migrationText);

            StatusStrip statusStrip = new StatusStrip();
            statusStrip.Items.Add(new ToolStripStatusLabel("Codex Guard " + AppInfo.Version + " — 活跃目录采用累加模式"));
            Controls.Add(tabs);
            Controls.Add(statusStrip);
            Controls.Add(header);
            Shown += delegate { RefreshAll(); };
        }

        private void RefreshAll()
        {
            bool installedFilesPresent = File.Exists(AppPaths.InstalledExecutable) && StateStore.Exists;
            string installedVersion;
            bool installedVersionCurrent = ElevationService.InstalledExecutableMatchesCurrentVersion(out installedVersion);
            bool privilegedRuntimeReady = installedFilesPresent && installedVersionCurrent;
            _canManagePermissionRequests = false;
            _canSubmitDeletionRequests = false;
            bool currentIsRegisteredAdmin = false;
            bool currentIsElevatedAdministrator = IdentityService.IsAdministrator();
            _installationStatus.Text = !installedFilesPresent ? "● 尚未安装"
                : privilegedRuntimeReady ? "● 已安装 " + AppInfo.Version
                : "● 需安装/修复：受保护版 " + (string.IsNullOrWhiteSpace(installedVersion) ? "未知" : installedVersion) + "，当前 " + AppInfo.Version;
            _installationStatus.ForeColor = privilegedRuntimeReady ? Color.FromArgb(107, 224, 169) : Color.FromArgb(255, 193, 113);

            _activeList.Items.Clear();
            if (StateStore.Exists)
            {
                try
                {
                    GuardState state = StateStore.Load();
                    string currentSid = IdentityService.CurrentSid();
                    string adminSid = IdentityService.FindProfileSid(state.AdminProfilePath);
                    currentIsRegisteredAdmin = !string.IsNullOrWhiteSpace(adminSid)
                        && string.Equals(currentSid, adminSid, StringComparison.OrdinalIgnoreCase);
                    _canManagePermissionRequests = GuardOperationService.IsRequesterSidAllowed(
                        GuardOperation.Activate, currentSid, state.WorkerSid, adminSid)
                        && !currentIsElevatedAdministrator;
                    _canSubmitDeletionRequests = IdentityService.CurrentIdentityIsGuardActor(state);
                    foreach (GuardedDirectory item in state.ActivatedDirectories) AddPathItem(_activeList, item.CanonicalPath, item.ActivatedAtUtc);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "无法读取 Codex Guard 状态", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            string identityMode = _canManagePermissionRequests && !privilegedRuntimeReady ? "admin 控制面 / 请先安装或修复升级"
                : _canManagePermissionRequests ? "可管理 CodexWorker 权限 / 只读查看 / 安装"
                : currentIsRegisteredAdmin && currentIsElevatedAdministrator ? "已提升：请普通启动后管理权限 / 只读查看 / 安装"
                : _canSubmitDeletionRequests ? "只读查看 / 仅可提交删除申请"
                : "只读查看 / 安装";
            _identityStatus.Text = "当前身份：" + Environment.UserDomainName + "\\" + Environment.UserName + "（" + identityMode + "）";
            RefreshDefaultReadOnly();
            RefreshNtfsInspection();
            RefreshAudit();
            RefreshSoftwareInventory();
            RefreshOfflineReuse();
            UpdateButtonState();
        }

        private void RefreshDefaultReadOnly()
        {
            _defaultReadOnlyList.Items.Clear();
            _defaultReadOnlyReport = null;
            try
            {
                if (!StateStore.Exists)
                {
                    _defaultReadOnlySummary.Text = "Codex Guard 尚未安装，无法生成默认只读计划。";
                    _defaultReadOnlySummary.ForeColor = UiStyles.Amber;
                    return;
                }
                GuardState state = StateStore.Load();
                bool adminPreview = _canManagePermissionRequests;
                _defaultReadOnlyReport = DefaultReadOnlyPolicyService.CapturePreview(state, adminPreview);
                _defaultReadOnlySummary.Text = _defaultReadOnlyReport.Summary
                    + "\r\n允许写入并可清理：AppData、.codex、已存在的 .cache；admin SID 不受 Guard 限制。";
                _defaultReadOnlySummary.ForeColor = string.Equals(_defaultReadOnlyReport.Status, "BLOCK", StringComparison.OrdinalIgnoreCase) ? UiStyles.Red
                    : string.Equals(_defaultReadOnlyReport.Status, "PASS", StringComparison.OrdinalIgnoreCase) ? UiStyles.Green : UiStyles.Amber;
                foreach (DefaultReadOnlyItem fact in _defaultReadOnlyReport.Items)
                {
                    ListViewItem row = new ListViewItem(new[]
                    {
                        DefaultReadOnlyStatusText(fact.Status),
                        DefaultReadOnlyPolicyService.KindText(fact.Kind),
                        fact.Path ?? string.Empty,
                        fact.Effect ?? string.Empty,
                        fact.Reason ?? string.Empty
                    });
                    row.ForeColor = string.Equals(fact.Status, "BLOCK", StringComparison.OrdinalIgnoreCase) ? UiStyles.Red
                        : string.Equals(fact.Status, "ALLOW", StringComparison.OrdinalIgnoreCase) || string.Equals(fact.Status, "APPLIED", StringComparison.OrdinalIgnoreCase) || string.Equals(fact.Status, "ADMIN", StringComparison.OrdinalIgnoreCase) ? UiStyles.Green
                        : string.Equals(fact.Status, "SYSTEM", StringComparison.OrdinalIgnoreCase) || string.Equals(fact.Status, "ABSENT", StringComparison.OrdinalIgnoreCase) ? UiStyles.Muted
                        : UiStyles.Amber;
                    _defaultReadOnlyList.Items.Add(row);
                }
            }
            catch (Exception ex)
            {
                _defaultReadOnlySummary.Text = "默认只读预览失败：" + ex.Message;
                _defaultReadOnlySummary.ForeColor = UiStyles.Red;
            }
        }

        private void BrowseNtfsPathClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog())
            {
                dialog.Description = "选择要只读核查 Guard 分类和 Windows DACL 的目录";
                dialog.ShowNewFolderButton = false;
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                _ntfsPathText.Text = dialog.SelectedPath;
                RefreshNtfsInspection();
            }
        }

        private void RefreshNtfsInspection()
        {
            _ntfsPolicyList.Items.Clear();
            _ntfsAclList.Items.Clear();
            try
            {
                if (!StateStore.Exists)
                {
                    _ntfsSummary.Text = "Codex Guard 尚未安装，无法判定管理员资料、默认只读和激活边界。";
                    _ntfsSummary.ForeColor = UiStyles.Amber;
                    return;
                }
                GuardState state = StateStore.Load();
                if (string.IsNullOrWhiteSpace(_ntfsPathText.Text))
                {
                    string initial = !string.IsNullOrWhiteSpace(state.AdminProfilePath) ? state.AdminProfilePath : state.WorkerProfilePath;
                    if (string.IsNullOrWhiteSpace(initial))
                    {
                        _ntfsSummary.Text = "请选择要只读核查的目录。";
                        _ntfsSummary.ForeColor = UiStyles.Amber;
                        return;
                    }
                    _ntfsPathText.Text = initial;
                }

                NtfsPermissionInspection report = NtfsPermissionInspectionService.Capture(state, _ntfsPathText.Text);
                string boundary = string.IsNullOrWhiteSpace(report.BoundaryPath) ? "无（未受管理）" : report.BoundaryPath;
                _ntfsSummary.Text = report.ClassificationText + "\r\nGuard 边界：" + boundary + "\r\n" + report.Summary;
                _ntfsSummary.ForeColor = string.Equals(report.Status, "FAIL", StringComparison.OrdinalIgnoreCase) ? UiStyles.Red
                    : string.Equals(report.Status, "WARN", StringComparison.OrdinalIgnoreCase) ? UiStyles.Amber : UiStyles.Green;

                foreach (NtfsPermissionSubjectFact fact in report.Subjects)
                {
                    ListViewItem row = new ListViewItem(new[]
                    {
                        NtfsSubjectStatusText(fact.Status),
                        fact.Subject ?? string.Empty,
                        fact.Sid ?? string.Empty,
                        fact.Read ?? string.Empty,
                        fact.WriteCreate ?? string.Empty,
                        fact.DeleteRename ?? string.Empty,
                        fact.ChangeAclOwner ?? string.Empty,
                        fact.Evidence ?? string.Empty
                    });
                    row.ForeColor = string.Equals(fact.Status, "FAIL", StringComparison.OrdinalIgnoreCase) ? UiStyles.Red
                        : string.Equals(fact.Status, "WARN", StringComparison.OrdinalIgnoreCase) ? UiStyles.Amber
                        : string.Equals(fact.Status, "ADMIN", StringComparison.OrdinalIgnoreCase) ? UiStyles.Blue : UiStyles.Green;
                    _ntfsPolicyList.Items.Add(row);
                }

                foreach (string finding in report.Findings)
                {
                    ListViewItem findingRow = new ListViewItem(new[] { "核查发现", string.Empty, "警告", finding, string.Empty, string.Empty });
                    findingRow.ForeColor = UiStyles.Red;
                    _ntfsAclList.Items.Add(findingRow);
                }
                foreach (NtfsAclRuleFact fact in report.Rules)
                {
                    ListViewItem row = new ListViewItem(new[]
                    {
                        fact.Identity ?? string.Empty,
                        fact.Sid ?? string.Empty,
                        fact.AccessType ?? string.Empty,
                        fact.Rights ?? string.Empty,
                        fact.Source ?? string.Empty,
                        fact.Scope ?? string.Empty
                    });
                    row.ForeColor = string.Equals(fact.AccessType, "拒绝", StringComparison.Ordinal) ? UiStyles.Red
                        : string.Equals(fact.Source, "继承", StringComparison.Ordinal) ? UiStyles.Muted : UiStyles.Blue;
                    _ntfsAclList.Items.Add(row);
                }
            }
            catch (Exception ex)
            {
                _ntfsSummary.Text = "NTFS 只读核查失败：" + ex.Message;
                _ntfsSummary.ForeColor = UiStyles.Red;
            }
        }

        private void RefreshAudit()
        {
            _auditList.Items.Clear();
            try
            {
                _lastReviewReport = ReviewService.Capture();
                _auditSummary.Text = _lastReviewReport.OverallStatus + "\r\n"
                    + "已合并 Worker/admin 本地记录路径隔离检查；不会读取令牌或对话正文，也不会尝试删除。";
                _auditSummary.ForeColor = _lastReviewReport.FailureCount > 0 ? UiStyles.Red
                    : _lastReviewReport.WarningCount > 0 ? UiStyles.Amber : UiStyles.Green;
                foreach (ReviewEvidence control in _lastReviewReport.Controls) AddReviewItem(control);
                foreach (ReviewEvidence finding in _lastReviewReport.Findings)
                    if (!string.Equals(finding.Status, "PASS", StringComparison.OrdinalIgnoreCase)) AddReviewItem(finding);
            }
            catch (Exception ex)
            {
                _lastReviewReport = null;
                _auditSummary.Text = "核查器自身发生错误：" + ex.Message;
                _auditSummary.ForeColor = UiStyles.Red;
            }
        }

        private void AddReviewItem(ReviewEvidence evidence)
        {
            ListViewItem item = new ListViewItem(new[]
            {
                ReviewStatusText(evidence.Status),
                evidence.Control ?? string.Empty,
                evidence.Path ?? string.Empty,
                evidence.Actual ?? string.Empty
            });
            item.ForeColor = string.Equals(evidence.Status, "FAIL", StringComparison.OrdinalIgnoreCase) ? UiStyles.Red
                : string.Equals(evidence.Status, "WARN", StringComparison.OrdinalIgnoreCase) || string.Equals(evidence.Status, "MANUAL", StringComparison.OrdinalIgnoreCase) ? UiStyles.Amber
                : UiStyles.Green;
            _auditList.Items.Add(item);
        }

        private void RefreshSoftwareInventory()
        {
            _softwareList.Items.Clear();
            try
            {
                _softwareReport = SoftwareMappingService.Capture();
                int shared = _softwareReport.Count(SoftwareMappingCategory.SharedReady);
                int shortcut = _softwareReport.Count(SoftwareMappingCategory.ShortcutRequired);
                int register = _softwareReport.Count(SoftwareMappingCategory.WorkerRegistrationRequired);
                int separate = _softwareReport.Count(SoftwareMappingCategory.SeparateInstallRequired);
                _softwareSummary.Text = "扫描到 " + _softwareReport.Items.Count + " 项：直接共用 " + shared
                    + "，可批量映射 " + shortcut + "，现有包需注册 " + register + "，技术阻断 " + separate + "。"
                    + (_softwareReport.Warnings.Count == 0 ? string.Empty : "\r\n有 " + _softwareReport.Warnings.Count + " 条扫描警告；导出 CSV 后人工复核。 ");
                _softwareSummary.ForeColor = _softwareReport.Warnings.Count == 0 ? UiStyles.Green : UiStyles.Amber;
                foreach (SoftwareInventoryItem software in _softwareReport.Items)
                {
                    string location = !string.IsNullOrWhiteSpace(software.ExecutablePath) ? software.ExecutablePath
                        : !string.IsNullOrWhiteSpace(software.InstallLocation) ? software.InstallLocation : "（未解析到主 EXE）";
                    ListViewItem item = new ListViewItem(new[]
                    {
                        SoftwareMappingService.CategoryText(software.Category),
                        software.DisplayName ?? string.Empty,
                        software.Version ?? string.Empty,
                        software.Publisher ?? string.Empty,
                        location,
                        software.RecommendedAction ?? string.Empty
                    });
                    item.Tag = software;
                    item.ForeColor = software.Category == SoftwareMappingCategory.SharedReady ? UiStyles.Green
                        : software.Category == SoftwareMappingCategory.ShortcutRequired ? UiStyles.Blue
                        : software.Category == SoftwareMappingCategory.WorkerRegistrationRequired ? UiStyles.Amber
                        : UiStyles.Red;
                    _softwareList.Items.Add(item);
                }
            }
            catch (Exception ex)
            {
                _softwareReport = null;
                _softwareSummary.Text = "软件清单扫描失败：" + ex.Message;
                _softwareSummary.ForeColor = UiStyles.Red;
            }
        }

        private void RefreshOfflineReuse()
        {
            _offlineReuseList.Items.Clear();
            try
            {
                _offlineReuseReport = OfflineReuseService.Capture();
                int direct = _offlineReuseReport.Count(OfflineReuseCategory.DirectReuse);
                int copy = _offlineReuseReport.Count(OfflineReuseCategory.AdminProgramCopy);
                int media = _offlineReuseReport.Count(OfflineReuseCategory.LocalMedia);
                int package = _offlineReuseReport.Count(OfflineReuseCategory.ExistingPackageRegistration);
                int review = _offlineReuseReport.Count(OfflineReuseCategory.PermissionReview);
                int missing = _offlineReuseReport.Count(OfflineReuseCategory.LocalPayloadMissing);
                _offlineReuseSummary.Text = "扫描到 " + _offlineReuseReport.Items.Count + " 项：直接复用 " + direct
                    + "，AppData 可提取 " + copy + "，本地介质 " + media + "，现有包注册 " + package
                    + "，权限/路径核查 " + review + "，载荷待定位 " + missing + "。"
                    + (_offlineReuseReport.Warnings.Count == 0 ? string.Empty : "\r\n有 " + _offlineReuseReport.Warnings.Count + " 条扫描警告；管理员扫描通常更完整。 ");
                _offlineReuseSummary.ForeColor = missing > 0 || _offlineReuseReport.Warnings.Count > 0 ? UiStyles.Amber : UiStyles.Green;
                foreach (OfflineReuseItem reuse in _offlineReuseReport.Items)
                {
                    string location = reuse.Category == OfflineReuseCategory.AdminProgramCopy && !string.IsNullOrWhiteSpace(reuse.SourceDirectory)
                        ? reuse.SourceDirectory
                        : reuse.Category == OfflineReuseCategory.LocalMedia && !string.IsNullOrWhiteSpace(reuse.LocalInstallSource)
                            ? reuse.LocalInstallSource
                            : !string.IsNullOrWhiteSpace(reuse.ExistingExecutable) ? reuse.ExistingExecutable
                                : !string.IsNullOrWhiteSpace(reuse.LocalInstallSource) ? reuse.LocalInstallSource : "（未定位本地载荷）";
                    ListViewItem row = new ListViewItem(new[]
                    {
                        OfflineReuseService.CategoryText(reuse.Category),
                        reuse.DisplayName ?? string.Empty,
                        reuse.Version ?? string.Empty,
                        location,
                        reuse.RecommendedAction ?? string.Empty
                    });
                    row.Tag = reuse;
                    row.ForeColor = reuse.Category == OfflineReuseCategory.DirectReuse ? UiStyles.Green
                        : reuse.Category == OfflineReuseCategory.AdminProgramCopy ? UiStyles.Blue
                        : reuse.Category == OfflineReuseCategory.LocalMedia || reuse.Category == OfflineReuseCategory.ExistingPackageRegistration ? UiStyles.Amber
                        : UiStyles.Red;
                    _offlineReuseList.Items.Add(row);
                }
            }
            catch (Exception ex)
            {
                _offlineReuseReport = null;
                _offlineReuseSummary.Text = "离线复用盘点失败：" + ex.Message;
                _offlineReuseSummary.ForeColor = UiStyles.Red;
            }
        }

        private void PrepareOfflineCopiesClick(object sender, EventArgs e)
        {
            try
            {
                List<OfflineReuseItem> selected = new List<OfflineReuseItem>();
                foreach (ListViewItem row in _offlineReuseList.Items)
                {
                    if (!row.Checked) continue;
                    OfflineReuseItem item = row.Tag as OfflineReuseItem;
                    if (item != null && item.CanPrepareCopy) selected.Add(item);
                }
                EnsureRiskyProcessesClosed();
                string request = OfflineReuseRequestService.Create(selected);
                try { ElevationService.RunInstalledOfflineReuseRequest(request); }
                catch (OperationCanceledException) { return; }
                RefreshOfflineReuse();
                RefreshSoftwareInventory();
                UpdateButtonState();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "离线复用失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ExportOfflineReuseClick(object sender, EventArgs e)
        {
            try
            {
                OfflineReuseReport report = _offlineReuseReport ?? OfflineReuseService.Capture();
                using (SaveFileDialog dialog = new SaveFileDialog())
                {
                    dialog.Filter = "CSV 模拟迁移清单 (*.csv)|*.csv";
                    dialog.FileName = "CodexGuard-offline-reuse-" + Environment.MachineName + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".csv";
                    if (dialog.ShowDialog(this) != DialogResult.OK) return;
                    File.WriteAllText(dialog.FileName, OfflineReuseService.ToCsv(report), new UTF8Encoding(true));
                    MessageBox.Show("已导出只读模拟迁移清单：\r\n" + dialog.FileName, "导出完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "模拟迁移清单导出失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OpenOfflineReuseHistoryClick(object sender, EventArgs e)
        {
            try
            {
                if (!Directory.Exists(AppPaths.OfflineReuseHistoryDirectory))
                {
                    MessageBox.Show("还没有离线复用审计清单。", "尚无记录", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                Process.Start(new ProcessStartInfo { FileName = "explorer.exe", Arguments = "\"" + AppPaths.OfflineReuseHistoryDirectory + "\"", UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "无法打开离线复用审计目录", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void CreateSoftwareShortcutsClick(object sender, EventArgs e)
        {
            try
            {
                List<SoftwareInventoryItem> selected = new List<SoftwareInventoryItem>();
                foreach (ListViewItem row in _softwareList.Items)
                {
                    if (!row.Checked) continue;
                    SoftwareInventoryItem item = row.Tag as SoftwareInventoryItem;
                    if (item != null && item.CanCreateShortcut) selected.Add(item);
                }
                string request = SoftwareMappingRequestService.Create(selected);
                try { ElevationService.RunInstalledSoftwareMappingRequest(request); }
                catch (OperationCanceledException) { return; }
                RefreshSoftwareInventory();
                UpdateButtonState();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "软件映射失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ExportSoftwareInventoryClick(object sender, EventArgs e)
        {
            try
            {
                SoftwareInventoryReport report = _softwareReport ?? SoftwareMappingService.Capture();
                using (SaveFileDialog dialog = new SaveFileDialog())
                {
                    dialog.Filter = "CSV 软件清单 (*.csv)|*.csv";
                    dialog.FileName = "CodexGuard-software-map-" + Environment.MachineName + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".csv";
                    if (dialog.ShowDialog(this) != DialogResult.OK) return;
                    File.WriteAllText(dialog.FileName, SoftwareMappingService.ToCsv(report), new UTF8Encoding(true));
                    MessageBox.Show("已导出只读软件分类清单：\r\n" + dialog.FileName, "导出完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "软件清单导出失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OpenMappedSoftwareDirectoryClick(object sender, EventArgs e)
        {
            try
            {
                if (!Directory.Exists(AppPaths.MappedSoftwareProgramsDirectory))
                {
                    MessageBox.Show("公共映射目录尚未创建。先勾选“创建快捷方式”类软件并通过 UAC。", "尚无映射", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                Process.Start(new ProcessStartInfo { FileName = "explorer.exe", Arguments = "\"" + AppPaths.MappedSoftwareProgramsDirectory + "\"", UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "无法打开公共快捷方式目录", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ExportReviewClick(object sender, EventArgs e)
        {
            try
            {
                ReviewReport report = ReviewService.Capture();
                using (SaveFileDialog dialog = new SaveFileDialog())
                {
                    dialog.Filter = "Codex Guard 核查报告 (*.html)|*.html";
                    dialog.FileName = "CodexGuard-review-" + Environment.MachineName + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".html";
                    if (dialog.ShowDialog(this) != DialogResult.OK) return;
                    string json = ReviewService.ExportPackage(dialog.FileName, report);
                    MessageBox.Show(
                        "已生成两份核查证据：\r\n\r\nHTML：" + dialog.FileName + "\r\nJSON：" + json
                            + "\r\n\r\n请再双击发布包中的 " + ReviewService.IndependentReviewerName + "，比较 SID、UAC、哈希和原始 SDDL。",
                        "人工核查包已导出",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "核查包导出失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OpenCompanion(string path, string title)
        {
            try
            {
                if (!File.Exists(path))
                {
                    MessageBox.Show("工具尚未安装：\r\n" + path + "\r\n\r\n请从完整发布包重新运行安装 / 修复。", title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                AclService.AssertProtectedFile(path);
                Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, title + "无法启动", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AddPendingClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog())
            {
                dialog.Description = "选择要追加激活的项目目录；可重复点击添加多个目录";
                dialog.ShowNewFolderButton = false;
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                foreach (object value in _pendingList.Items)
                    if (AppPaths.PathsEqual(Convert.ToString(value), dialog.SelectedPath)) return;
                _pendingList.Items.Add(dialog.SelectedPath);
                UpdateButtonState();
            }
        }

        private void ActivateClick(object sender, EventArgs e)
        {
            List<string> paths = new List<string>();
            foreach (object item in _pendingList.Items) paths.Add(Convert.ToString(item));
            if (paths.Count == 0) return;
            if (RunRequest(GuardOperation.Activate, paths)) _pendingList.Items.Clear();
            RefreshAll();
        }

        private void RevokeClick(object sender, EventArgs e)
        {
            List<string> paths = SelectedTags(_activeList);
            if (paths.Count == 0) return;
            if (MessageBox.Show("撤销只会移除写入权限并保留删除禁令。继续前必须完全退出 Codex、终端、Git 和 WSL。", "人工撤销确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;
            RunRequest(GuardOperation.Revoke, paths);
            RefreshAll();
        }

        private void ApplyDefaultReadOnlyClick(object sender, EventArgs e)
        {
            if (_defaultReadOnlyReport == null || !_defaultReadOnlyReport.CanApply) return;
            string message = "这会立即把固定数据盘和 Worker 数据目录改为默认只读。\r\n\r\n"
                + "只有 AppData、.codex、已存在的 .cache 和已经激活的工作目录保留写入；缓存允许列表可以删除，激活目录仍禁止删除。\r\n\r\n"
                + "请确认：已有独立备份；所有 Codex/终端/Git/WSL 已退出；需要继续写入的项目已经先建立。是否提交 UAC？";
            if (MessageBox.Show(message, "应用默认只读基线", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;
            RunRequest(GuardOperation.ApplyDefaultReadOnly, new string[0]);
            RefreshAll();
        }

        private void RepairClick(object sender, EventArgs e)
        {
            RunRequest(GuardOperation.Repair, new string[0]);
            RefreshAll();
        }

        private void InstallClick(object sender, EventArgs e)
        {
            try
            {
                EnsureRiskyProcessesClosed();
                ElevationService.RunAdminInstall();
                RefreshAll();
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { MessageBox.Show(ex.Message, "安装启动失败", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void ExportClick(object sender, EventArgs e)
        {
            if (!StateStore.Exists) return;
            using (SaveFileDialog dialog = new SaveFileDialog())
            {
                dialog.Filter = "Codex Guard 策略 (*.codexguard.json)|*.codexguard.json|JSON (*.json)|*.json";
                dialog.FileName = "CodexGuard-policy-" + DateTime.Now.ToString("yyyyMMdd") + ".codexguard.json";
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                PortablePolicy policy = PortablePolicy.FromState(StateStore.Load());
                JsonFile.WriteAtomic(dialog.FileName, policy, null);
                MessageBox.Show("策略已导出。文件不包含密码、登录令牌、SID 或原始 ACL。", "导出完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void ImportClick(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog open = new OpenFileDialog())
                {
                    open.Filter = "Codex Guard 策略 (*.codexguard.json;*.json)|*.codexguard.json;*.json";
                    if (open.ShowDialog(this) != DialogResult.OK) return;
                    PortablePolicy policy = JsonFile.Read<PortablePolicy>(open.FileName, 4 * 1024 * 1024);
                    if (policy.SchemaVersion != AppInfo.PolicySchemaVersion) throw new InvalidDataException("不支持的策略格式版本。");
                    using (ImportPolicyForm mapping = new ImportPolicyForm(policy))
                    {
                        if (mapping.ShowDialog(this) != DialogResult.OK) return;
                        EnsureRiskyProcessesClosed();
                        string request = RequestService.CreateImportRequest(mapping.ActivePaths);
                        try { ElevationService.RunInstalledRequest(request); }
                        catch (OperationCanceledException) { }
                    }
                    RefreshAll();
                }
            }
            catch (Exception ex) { MessageBox.Show(ex.Message, "策略导入失败", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void OpenDeleteRequestsClick(object sender, EventArgs e)
        {
            if (!Directory.Exists(AppPaths.DeleteRequestsDirectory))
            {
                MessageBox.Show("请先安装 Codex Guard。", "删除申请目录尚未建立", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Process.Start(new ProcessStartInfo { FileName = "explorer.exe", Arguments = "\"" + AppPaths.DeleteRequestsDirectory + "\"", UseShellExecute = true });
        }

        private bool RunRequest(GuardOperation operation, IEnumerable<string> paths)
        {
            try
            {
                EnsureRiskyProcessesClosed();
                string request = RequestService.CreateRequest(operation, paths);
                int exitCode = ElevationService.RunInstalledRequest(request);
                if (exitCode == 0) return true;
                MessageBox.Show(
                    exitCode == 3
                        ? "管理员最终确认未被程序接受，因此没有修改任何 ACL。请重新提交；输入四位码后点击“确认执行”，并等待成功结果窗口。"
                        : "提升后的 Codex Guard 未完成操作（退出代码 " + exitCode + "）。没有成功结果窗口就不能视为权限已应用；请查看安全审计和日志。",
                    "Codex Guard 操作未完成",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return false;
            }
            catch (OperationCanceledException)
            {
                MessageBox.Show("Windows UAC 已取消；没有修改任何 ACL。", "Codex Guard 操作已取消", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Codex Guard 操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        private static void EnsureRiskyProcessesClosed()
        {
            List<string> running = ProcessSafety.FindRunningRiskyProcesses();
            if (running.Count > 0)
                throw new InvalidOperationException("请先关闭 Codex、所有终端、Git 和 WSL 进程，再进行权限变更：\r\n" + string.Join("\r\n", running.ToArray()));
        }

        private void UpdateButtonState()
        {
            string installedVersion;
            bool privilegedRuntimeReady = StateStore.Exists
                && ElevationService.InstalledExecutableMatchesCurrentVersion(out installedVersion);
            _addPendingButton.Enabled = privilegedRuntimeReady && _canManagePermissionRequests;
            _removePendingButton.Enabled = privilegedRuntimeReady && _canManagePermissionRequests && _pendingList.SelectedItems.Count > 0;
            _activateButton.Enabled = privilegedRuntimeReady && _canManagePermissionRequests && _pendingList.Items.Count > 0;
            _revokeButton.Enabled = privilegedRuntimeReady && _canManagePermissionRequests && _activeList.SelectedItems.Count > 0;
            _applyDefaultReadOnlyButton.Enabled = privilegedRuntimeReady && _canManagePermissionRequests
                && _defaultReadOnlyReport != null && _defaultReadOnlyReport.CanApply;
            _repairButton.Enabled = privilegedRuntimeReady && _canManagePermissionRequests;
            _exportButton.Enabled = StateStore.Exists;
            _importButton.Enabled = privilegedRuntimeReady && _canManagePermissionRequests;
            _submitDeleteRequestButton.Enabled = StateStore.Exists && _canSubmitDeletionRequests;
            _openReviewerButton.Enabled = File.Exists(AppPaths.InstalledReviewerExecutable);
            _openProbeButton.Enabled = File.Exists(AppPaths.InstalledAcceptanceExecutable);
            _createSoftwareShortcutsButton.Enabled = privilegedRuntimeReady && SoftwareMappingRequestService.CanCurrentUserSubmit() && CheckedSoftwareShortcutCount() > 0;
            _prepareOfflineCopiesButton.Enabled = privilegedRuntimeReady && OfflineReuseRequestService.CanCurrentUserSubmit() && CheckedOfflineCopyCount() > 0;
        }

        private int CheckedSoftwareShortcutCount()
        {
            int count = 0;
            foreach (ListViewItem row in _softwareList.Items)
            {
                if (!row.Checked) continue;
                SoftwareInventoryItem item = row.Tag as SoftwareInventoryItem;
                if (item != null && item.CanCreateShortcut) count++;
            }
            return count;
        }

        private int CheckedOfflineCopyCount()
        {
            int count = 0;
            foreach (ListViewItem row in _offlineReuseList.Items)
            {
                if (!row.Checked) continue;
                OfflineReuseItem item = row.Tag as OfflineReuseItem;
                if (item != null && item.CanPrepareCopy) count++;
            }
            return count;
        }

        private static GroupBox CreateGroup(string title, Control content, Button[] buttons)
        {
            GroupBox group = new GroupBox { Text = title, Dock = DockStyle.Fill, Padding = new Padding(10), Font = UiStyles.HeadingFont() };
            FlowLayoutPanel footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 48, Padding = new Padding(0, 7, 0, 3), Font = UiStyles.BodyFont(), WrapContents = true };
            foreach (Button button in buttons) footer.Controls.Add(button);
            content.Font = UiStyles.BodyFont();
            group.Controls.Add(content);
            group.Controls.Add(footer);
            return group;
        }

        private static ListView CreatePathList(string timeHeader)
        {
            ListView view = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = true };
            view.Columns.Add("路径", 650);
            view.Columns.Add(timeHeader, 185);
            return view;
        }

        private static void AddPathItem(ListView view, string path, string time)
        {
            DateTime parsed;
            string displayTime = DateTime.TryParse(time, out parsed) ? parsed.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : time;
            ListViewItem item = new ListViewItem(new[] { path, displayTime });
            item.Tag = path;
            view.Items.Add(item);
        }

        private static List<string> SelectedTags(ListView view)
        {
            List<string> values = new List<string>();
            foreach (ListViewItem item in view.SelectedItems) values.Add(Convert.ToString(item.Tag));
            return values;
        }

        private static string SeverityText(AuditSeverity severity)
        {
            return severity == AuditSeverity.Error ? "错误" : severity == AuditSeverity.Warning ? "警告" : "正常";
        }

        private static string ReviewStatusText(string status)
        {
            if (string.Equals(status, "FAIL", StringComparison.OrdinalIgnoreCase)) return "失败";
            if (string.Equals(status, "WARN", StringComparison.OrdinalIgnoreCase)) return "警告";
            if (string.Equals(status, "MANUAL", StringComparison.OrdinalIgnoreCase)) return "人工";
            return "通过";
        }

        private static string NtfsSubjectStatusText(string status)
        {
            if (string.Equals(status, "FAIL", StringComparison.OrdinalIgnoreCase)) return "异常";
            if (string.Equals(status, "WARN", StringComparison.OrdinalIgnoreCase)) return "未管理";
            if (string.Equals(status, "ADMIN", StringComparison.OrdinalIgnoreCase)) return "管理员";
            return "策略通过";
        }

        private static string DefaultReadOnlyStatusText(string status)
        {
            if (string.Equals(status, "BLOCK", StringComparison.OrdinalIgnoreCase)) return "阻断";
            if (string.Equals(status, "APPLIED", StringComparison.OrdinalIgnoreCase)) return "已应用";
            if (string.Equals(status, "ALLOW", StringComparison.OrdinalIgnoreCase)) return "允许写入";
            if (string.Equals(status, "ADMIN", StringComparison.OrdinalIgnoreCase)) return "不限制 admin";
            if (string.Equals(status, "VERIFY", StringComparison.OrdinalIgnoreCase)) return "UAC 核验";
            if (string.Equals(status, "SYSTEM", StringComparison.OrdinalIgnoreCase)) return "系统管理";
            if (string.Equals(status, "ABSENT", StringComparison.OrdinalIgnoreCase)) return "未建立";
            return "待应用";
        }
    }
}
