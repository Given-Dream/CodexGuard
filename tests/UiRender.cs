using CodexGuard.App;
using CodexGuard.Core;
using CodexGuard.AcceptanceProbe;
using CodexGuard.ReadOnlyVerifier;
using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Windows.Forms;

namespace CodexGuard.Tests
{
    internal static class UiRender
    {
        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            string output = args.Length > 0 ? Path.GetFullPath(args[0]) : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ui");
            Directory.CreateDirectory(output);

            using (MainForm main = new MainForm())
            {
                Render(main, Path.Combine(output, "01-main-workspaces.png"));
                TabControl tabs = FindControl<TabControl>(main);
                if (tabs != null)
                {
                    tabs.SelectedIndex = 1;
                    Application.DoEvents();
                    RenderVisible(main, Path.Combine(output, "02-main-default-readonly.png"));
                    tabs.SelectedIndex = 2;
                    Application.DoEvents();
                    RenderVisible(main, Path.Combine(output, "03-main-ntfs-permissions.png"));
                    TextBox ntfsPath = FindControl<TextBox>(main);
                    Button ntfsInspect = FindButton(main, "只读核查");
                    if (ntfsPath != null && ntfsInspect != null)
                    {
                        ntfsPath.Text = "D:\\codex";
                        ntfsInspect.PerformClick();
                        Application.DoEvents();
                        RenderVisible(main, Path.Combine(output, "03b-main-ntfs-unmanaged.png"));
                    }
                    tabs.SelectedIndex = 3;
                    Application.DoEvents();
                    RenderVisible(main, Path.Combine(output, "04-main-audit.png"));
                    tabs.SelectedIndex = 4;
                    Application.DoEvents();
                    RenderVisible(main, Path.Combine(output, "05-main-software-mapping.png"));
                    tabs.SelectedIndex = 5;
                    Application.DoEvents();
                    RenderVisible(main, Path.Combine(output, "06-main-offline-reuse.png"));
                    tabs.SelectedIndex = 6;
                    Application.DoEvents();
                    RenderVisible(main, Path.Combine(output, "07-main-migration.png"));
                    tabs.SelectedIndex = 0;
                    main.Size = main.MinimumSize;
                    Application.DoEvents();
                    RenderVisible(main, Path.Combine(output, "09-main-minimum.png"));
                    tabs.SelectedIndex = 3;
                    Application.DoEvents();
                    RenderVisible(main, Path.Combine(output, "12-main-audit-minimum.png"));
                }
            }

            using (InstallForm install = new InstallForm()) Render(install, Path.Combine(output, "05-install.png"));
            using (DeletionRequestForm deletion = new DeletionRequestForm()) Render(deletion, Path.Combine(output, "06-delete-request.png"));

            PortablePolicy policy = new PortablePolicy
            {
                SchemaVersion = AppInfo.PolicySchemaVersion,
                ActivatedPaths = new System.Collections.Generic.List<string> { "D:\\Projects\\MineruFlow" }
            };
            using (ImportPolicyForm import = new ImportPolicyForm(policy)) Render(import, Path.Combine(output, "07-import.png"));

            PreparedGuardOperation prepared = new PreparedGuardOperation
            {
                Request = GuardRequest.Create(GuardOperation.Activate, new[] { "D:\\Projects\\MineruFlow" }, "S-1-5-21-preview"),
                StateSnapshot = GuardState.CreateDefault()
            };
            prepared.Paths.Add(new PathValidationResult
            {
                FullPath = "D:\\Projects\\MineruFlow",
                Identity = new PathIdentity { CanonicalPath = "D:\\Projects\\MineruFlow" }
            });
            prepared.ActorSids.Add(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null));
            prepared.Warnings.Add("预览：激活允许覆盖写入，但仍拒绝删除、重命名和 ACL 更改。");
            using (AdminConfirmationForm confirmation = new AdminConfirmationForm(prepared))
            {
                Render(confirmation, Path.Combine(output, "08-admin-confirmation.png"));
                AssertAdminConfirmationClick(confirmation);
            }
            PreparedGuardOperation defaultReadOnly = new PreparedGuardOperation
            {
                Request = GuardRequest.Create(GuardOperation.ApplyDefaultReadOnly, new string[0], "S-1-5-21-preview"),
                StateSnapshot = GuardState.CreateDefault()
            };
            defaultReadOnly.Paths.Add(new PathValidationResult
            {
                FullPath = "D:\\",
                Identity = new PathIdentity { CanonicalPath = "D:\\" }
            });
            defaultReadOnly.RootLockPaths.Add(new PathValidationResult
            {
                FullPath = "C:\\",
                Identity = new PathIdentity { CanonicalPath = "C:\\" }
            });
            defaultReadOnly.WritableExceptionPaths.Add("C:\\Users\\CodexWorker\\AppData");
            defaultReadOnly.WritableExceptionPaths.Add("C:\\Users\\CodexWorker\\.codex");
            defaultReadOnly.ActorSids.Add(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null));
            defaultReadOnly.Warnings.Add("预览：只有固定运行时目录和激活项目保留写入；其余数据位置默认只读。");
            using (AdminConfirmationForm confirmation = new AdminConfirmationForm(defaultReadOnly))
                Render(confirmation, Path.Combine(output, "08b-default-readonly-confirmation.png"));
            using (OperationProgressForm progress = new OperationProgressForm(defaultReadOnly, false))
            {
                Render(progress, Path.Combine(output, "08c-operation-progress.png"));
                AssertOperationProgressWindow(progress);
            }
            PreparedSoftwareShortcutRequest softwarePrepared = new PreparedSoftwareShortcutRequest
            {
                Request = new SoftwareShortcutRequest
                {
                    RequesterMachine = Environment.MachineName,
                    RequesterSid = "S-1-5-21-preview"
                },
                StateSnapshot = GuardState.CreateDefault()
            };
            softwarePrepared.Items.Add(new SoftwareInventoryItem
            {
                DisplayName = "PFC3D 6.0",
                Publisher = "Itasca Consulting Group",
                ExecutablePath = "C:\\Program Files\\Itasca\\PFC600\\exe64\\pfc3d600.exe",
                Category = SoftwareMappingCategory.ShortcutRequired,
                CanCreateShortcut = true
            });
            using (SoftwareShortcutConfirmationForm software = new SoftwareShortcutConfirmationForm(softwarePrepared))
                Render(software, Path.Combine(output, "12-software-mapping-confirmation.png"));
            PreparedOfflineReuseRequest offlinePrepared = new PreparedOfflineReuseRequest
            {
                Request = new OfflineReuseRequest
                {
                    RequesterMachine = Environment.MachineName,
                    RequesterSid = "S-1-5-21-preview"
                },
                StateSnapshot = GuardState.CreateDefault()
            };
            offlinePrepared.Plans.Add(new OfflineReuseCopyPlan
            {
                Item = new OfflineReuseItem { DisplayName = "Example AppData Program", Publisher = "Example Publisher" },
                SourceDirectory = "C:\\Users\\admin\\AppData\\Local\\Programs\\Example",
                TargetDirectory = "C:\\Users\\CodexWorker\\AppData\\Local\\Programs\\Example",
                TargetExecutable = "C:\\Users\\CodexWorker\\AppData\\Local\\Programs\\Example\\Example.exe",
                FileCount = 128,
                TotalBytes = 73400320
            });
            using (OfflineReuseConfirmationForm offline = new OfflineReuseConfirmationForm(offlinePrepared))
                Render(offline, Path.Combine(output, "13-offline-reuse-confirmation.png"));
            using (ReviewerForm reviewer = new ReviewerForm()) Render(reviewer, Path.Combine(output, "09-independent-reviewer.png"));
            using (ProbeForm probe = new ProbeForm()) Render(probe, Path.Combine(output, "10-acceptance-probe.png"));
            return 0;
        }

        private static void Render(Form form, string path)
        {
            form.StartPosition = FormStartPosition.Manual;
            form.Location = new Point(30, 30);
            form.Show();
            Application.DoEvents();
            RenderVisible(form, path);
        }

        private static void RenderVisible(Form form, string path)
        {
            form.PerformLayout();
            using (Bitmap bitmap = new Bitmap(form.Width, form.Height))
            {
                form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
                bitmap.Save(path, System.Drawing.Imaging.ImageFormat.Png);
            }
        }

        private static T FindControl<T>(Control parent) where T : Control
        {
            foreach (Control child in parent.Controls)
            {
                T typed = child as T;
                if (typed != null) return typed;
                T nested = FindControl<T>(child);
                if (nested != null) return nested;
            }
            return null;
        }

        private static Button FindButton(Control parent, string text)
        {
            foreach (Control child in parent.Controls)
            {
                Button button = child as Button;
                if (button != null && string.Equals(button.Text, text, StringComparison.Ordinal)) return button;
                Button nested = FindButton(child, text);
                if (nested != null) return nested;
            }
            return null;
        }

        private static void AssertAdminConfirmationClick(AdminConfirmationForm form)
        {
            BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
            FieldInfo challengeField = typeof(AdminConfirmationForm).GetField("_challenge", flags);
            FieldInfo inputField = typeof(AdminConfirmationForm).GetField("_challengeInput", flags);
            if (challengeField == null || inputField == null) throw new InvalidOperationException("Admin confirmation test fields were not found.");
            string challenge = challengeField.GetValue(form) as string;
            TextBox input = inputField.GetValue(form) as TextBox;
            Button confirm = FindButton(form, "确认执行");
            if (string.IsNullOrEmpty(challenge) || input == null || confirm == null)
                throw new InvalidOperationException("Admin confirmation controls were not available for the click regression test.");
            input.Text = challenge;
            Application.DoEvents();
            if (!confirm.Enabled) throw new InvalidOperationException("Correct challenge did not enable the final confirmation button.");
            confirm.PerformClick();
            Application.DoEvents();
            if (!form.ConfirmationAccepted || form.DialogResult != DialogResult.OK)
                throw new InvalidOperationException("Clicking the enabled final confirmation button did not produce explicit acceptance.");
        }

        private static void AssertOperationProgressWindow(OperationProgressForm form)
        {
            ProgressBar progress = FindControl<ProgressBar>(form);
            if (progress == null || progress.Style != ProgressBarStyle.Marquee)
                throw new InvalidOperationException("The privileged operation window does not show an indeterminate progress bar.");
            if (form.ControlBox)
                throw new InvalidOperationException("The privileged operation window still exposes a close control during the ACL transaction.");
            TextBox path = FindControl<TextBox>(form);
            if (path == null || path.Text.IndexOf("D:\\", StringComparison.OrdinalIgnoreCase) < 0)
                throw new InvalidOperationException("The privileged operation window does not expose the current path.");
        }
    }
}
