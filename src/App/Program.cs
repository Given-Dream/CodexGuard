using CodexGuard.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object sender, System.Threading.ThreadExceptionEventArgs e)
            {
                ShowFatal(e.Exception);
            };

            try
            {
                if (args.Length == 1 && string.Equals(args[0], "--admin-install", StringComparison.OrdinalIgnoreCase))
                    return RunAdminInstall();
                if (args.Length == 2 && string.Equals(args[0], "--admin-request", StringComparison.OrdinalIgnoreCase))
                    return RunAdminRequest(args[1]);
                if (args.Length == 2 && string.Equals(args[0], "--admin-map-software", StringComparison.OrdinalIgnoreCase))
                    return RunAdminSoftwareMapping(args[1]);
                if (args.Length == 2 && string.Equals(args[0], "--admin-offline-reuse", StringComparison.OrdinalIgnoreCase))
                    return RunAdminOfflineReuse(args[1]);
                if (args.Length >= 2 && string.Equals(args[0], "--request-delete", StringComparison.OrdinalIgnoreCase))
                    return SubmitDeletionRequest(args);
                if (args.Length == 1 && string.Equals(args[0], ShortcutService.ObsoleteWorkerCodexArguments, StringComparison.Ordinal))
                    return ShowRetiredWorkerLauncherNotice();
                if (args.Length != 0)
                    throw new InvalidDataException("不支持的 Codex Guard 命令行参数。");

                Application.Run(new MainForm());
                return 0;
            }
            catch (Exception ex)
            {
                ShowFatal(ex);
                return 1;
            }
        }

        private static int RunAdminInstall()
        {
            if (!IdentityService.IsAdministrator())
                throw new UnauthorizedAccessException("安装必须通过 Windows UAC 以管理员身份启动。");
            using (InstallForm form = new InstallForm())
            {
                Application.Run(form);
                return form.OperationSucceeded ? 0 : 2;
            }
        }

        private static int RunAdminRequest(string requestPath)
        {
            if (!IdentityService.IsAdministrator())
                throw new UnauthorizedAccessException("权限操作必须通过 Windows UAC 以管理员身份启动。");
            if (!UacPolicy.Read().MeetsRequirements)
                throw new InvalidOperationException("UAC 安全桌面策略不符合 Codex Guard 要求。请先运行安装/修复。");

            GuardRequest request = RequestService.ValidateAndRead(requestPath);
            PreparedGuardOperation prepared = GuardOperationService.Prepare(request);
            using (AdminConfirmationForm confirm = new AdminConfirmationForm(prepared))
            {
                DialogResult decision = confirm.ShowDialog();
                if (decision != DialogResult.OK || !confirm.ConfirmationAccepted)
                {
                    GuardLog.Write(request.RequestId, request.Operation.ToString(), false,
                        "Final confirmation closed without explicit acceptance. DialogResult=" + decision + ".");
                    return 3;
                }
            }
            GuardLog.Write(request.RequestId, request.Operation + "_CONFIRMATION", true,
                "Final confirmation was explicitly accepted; starting the privileged ACL transaction.");

            OperationResult result;
            using (OperationProgressForm progress = new OperationProgressForm(prepared))
            {
                progress.ShowDialog();
                if (progress.OperationError != null) throw progress.OperationError;
                result = progress.OperationResult;
            }
            if (result == null) throw new InvalidOperationException("权限事务未返回结果；请运行安全审计后再重试。");
            using (ResultForm form = new ResultForm(result)) form.ShowDialog();
            return result.Success ? 0 : 4;
        }

        private static int SubmitDeletionRequest(string[] args)
        {
            List<string> paths = new List<string>();
            for (int i = 1; i < args.Length; i++) paths.Add(args[i]);
            string output = DeletionRequestService.Submit(paths, "Submitted from the Codex Guard command line.");
            MessageBox.Show("删除申请已保存：\r\n" + output + "\r\n\r\n没有移动或删除任何目标。", "Codex Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }

        private static int ShowRetiredWorkerLauncherNotice()
        {
            MessageBox.Show(
                "“Codex (CodexWorker)”跨用户启动功能已移除。\r\n\r\n"
                + "请登录 CodexWorker 自己的 Windows 桌面，再从官方 ChatGPT/Codex 图标启动。\r\n"
                + "此旧快捷方式不会自动删除，请由 admin 人工移到待删除目录或删除。",
                "Codex Guard — 旧功能已移除",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return 5;
        }

        private static int RunAdminSoftwareMapping(string requestPath)
        {
            if (!IdentityService.IsAdministrator())
                throw new UnauthorizedAccessException("软件映射必须通过 Windows UAC 以管理员身份启动。");
            PreparedSoftwareShortcutRequest prepared = SoftwareMappingRequestService.ValidateAndPrepare(requestPath);
            using (SoftwareShortcutConfirmationForm confirm = new SoftwareShortcutConfirmationForm(prepared))
            {
                if (confirm.ShowDialog() != DialogResult.OK)
                {
                    GuardLog.Write(prepared.Request.RequestId, "SOFTWARE_SHORTCUT_MAPPING", false, "User canceled final confirmation.");
                    return 3;
                }
            }
            OperationResult result = SoftwareMappingRequestService.Execute(prepared);
            using (ResultForm form = new ResultForm(result)) form.ShowDialog();
            return result.Success ? 0 : 4;
        }

        private static int RunAdminOfflineReuse(string requestPath)
        {
            if (!IdentityService.IsAdministrator())
                throw new UnauthorizedAccessException("离线复用必须通过 Windows UAC 以管理员身份启动。");
            PreparedOfflineReuseRequest prepared = OfflineReuseRequestService.ValidateAndPrepare(requestPath);
            using (OfflineReuseConfirmationForm confirm = new OfflineReuseConfirmationForm(prepared))
            {
                if (confirm.ShowDialog() != DialogResult.OK)
                {
                    GuardLog.Write(prepared.Request.RequestId, "OFFLINE_REUSE_COPY", false, "User canceled final confirmation.");
                    return 3;
                }
            }
            OperationResult result = OfflineReuseRequestService.Execute(prepared);
            using (ResultForm form = new ResultForm(result)) form.ShowDialog();
            return result.Success ? 0 : 4;
        }

        private static void ShowFatal(Exception exception)
        {
            string message = exception == null ? "未知错误" : exception.Message;
            GuardLog.Write(null, "UNHANDLED", false, message);
            MessageBox.Show(message, "Codex Guard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
