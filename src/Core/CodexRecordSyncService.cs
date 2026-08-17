using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Principal;
using System.Text;

namespace CodexGuard.Core
{
    internal static class CodexRecordSyncService
    {
        public const string SyncMode = "CodexWorker 是未来任务与记录的唯一写入身份；ChatGPT/Codex 只在 CodexWorker 自己的 Windows 交互式桌面运行";
        private const int MaximumEnumeratedSessionFiles = 100000;

        public static string VerificationChecklist
        {
            get
            {
                return "CodexWorker 单一本地记录源人工核查\r\n\r\n"
                    + "1. 登录 CodexWorker 自己的 Windows 桌面，再启动并登录官方 ChatGPT/Codex；不要从 admin 桌面跨用户启动。\r\n"
                    + "2. 在任务管理器“详细信息”页显示“用户名”列，确认 ChatGPT/Codex/codex 进程均为 " + Environment.MachineName + "\\CodexWorker。\r\n"
                    + "3. 做一个无敏感信息的测试任务，确认 C:\\Users\\CodexWorker\\.codex 时间更新，而 admin\\.codex 不更新。\r\n"
                    + "4. admin 的既有本地记录保持只读旧档；不要复制、联接、共享或双向同步任何 .codex 目录。\r\n"
                    + "5. 目录激活、删除等管理动作只在 UAC 安全桌面输入 admin 凭据，不需要切回 admin 桌面运行 Codex。\r\n"
                    + "6. 安装/修复后确认公共桌面不再存在 Codex Guard 创建的“Codex (CodexWorker)”旧入口。";
            }
        }

        public static RecordSyncReport Capture()
        {
            string adminProfile = null;
            string workerProfile = null;
            GuardState state = null;
            if (StateStore.Exists)
            {
                try { state = StateStore.Load(); }
                catch { state = null; }
            }

            if (state != null && !string.IsNullOrWhiteSpace(state.AdminProfilePath))
                adminProfile = state.AdminProfilePath;
            if (string.IsNullOrWhiteSpace(adminProfile)
                && !string.Equals(Environment.UserName, AppInfo.WorkerAccountName, StringComparison.OrdinalIgnoreCase))
                adminProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            SecurityIdentifier workerSid;
            if (LocalAccountService.AccountExists(AppInfo.WorkerAccountName, out workerSid))
                workerProfile = IdentityService.GetProfilePathForSid(workerSid.Value);
            if (string.IsNullOrWhiteSpace(workerProfile)
                && string.Equals(Environment.UserName, AppInfo.WorkerAccountName, StringComparison.OrdinalIgnoreCase))
                workerProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            return Capture(adminProfile, workerProfile);
        }

        internal static RecordSyncReport Capture(string adminProfile, string workerProfile)
        {
            RecordSyncReport report = new RecordSyncReport
            {
                SchemaVersion = AppInfo.RecordSyncReportSchemaVersion,
                GeneratedAtUtc = AppInfo.UtcNow(),
                ProductVersion = AppInfo.Version,
                MachineName = Environment.MachineName,
                SyncMode = SyncMode,
                OfficialDocumentation = null,
                PrivacyStatement = "本检查只读取路径、文件是否存在、数量、大小、时间和链接属性；不打开 auth.json，不读取对话正文，不复制或修改任何 Codex 数据。"
            };

            RecordSyncProfileSnapshot admin = InspectProfile("admin", adminProfile);
            RecordSyncProfileSnapshot worker = InspectProfile(AppInfo.WorkerAccountName, workerProfile);
            report.Profiles.Add(admin);
            report.Profiles.Add(worker);
            AddChecks(report, admin, worker);
            FinalizeStatus(report, worker);
            return report;
        }

        internal static RecordSyncProfileSnapshot InspectProfile(string role, string profilePath)
        {
            RecordSyncProfileSnapshot snapshot = new RecordSyncProfileSnapshot
            {
                Role = role,
                ProfilePath = NormalizeWithoutThrowing(profilePath)
            };
            if (string.IsNullOrWhiteSpace(snapshot.ProfilePath)) return snapshot;

            snapshot.CodexDataPath = Path.Combine(snapshot.ProfilePath, ".codex");
            try
            {
                snapshot.ProfileExists = Directory.Exists(snapshot.ProfilePath);
                if (!snapshot.ProfileExists) return snapshot;
                if (IsReparsePoint(snapshot.ProfilePath)) snapshot.LinkedCriticalEntryDetected = true;

                snapshot.CodexDataExists = Directory.Exists(snapshot.CodexDataPath);
                if (!snapshot.CodexDataExists) return snapshot;
                snapshot.CodexDataIsReparsePoint = IsReparsePoint(snapshot.CodexDataPath);
                if (snapshot.CodexDataIsReparsePoint)
                {
                    snapshot.LinkedCriticalEntryDetected = true;
                    return snapshot;
                }

                string auth = Path.Combine(snapshot.CodexDataPath, "auth.json");
                snapshot.AuthenticationMarkerExists = File.Exists(auth);
                if (snapshot.AuthenticationMarkerExists && IsLinkedFile(auth)) snapshot.LinkedCriticalEntryDetected = true;

                string sessionIndex = Path.Combine(snapshot.CodexDataPath, "session_index.jsonl");
                snapshot.SessionIndexExists = File.Exists(sessionIndex);
                if (snapshot.SessionIndexExists && IsLinkedFile(sessionIndex)) snapshot.LinkedCriticalEntryDetected = true;

                string[] otherCriticalEntries =
                {
                    Path.Combine(snapshot.CodexDataPath, ".codex-global-state.json"),
                    Path.Combine(snapshot.CodexDataPath, "config.toml"),
                    Path.Combine(snapshot.CodexDataPath, "state_5.sqlite")
                };
                foreach (string entry in otherCriticalEntries)
                    if (File.Exists(entry) && IsLinkedFile(entry)) snapshot.LinkedCriticalEntryDetected = true;

                CountDatabases(snapshot);
                CountSessions(snapshot);
            }
            catch (Exception ex)
            {
                snapshot.InspectionError = ex.GetType().Name + ": " + ex.Message;
            }
            return snapshot;
        }

        public static string ExportPackage(string htmlPath, RecordSyncReport report)
        {
            if (report == null) throw new ArgumentNullException("report");
            string full = Path.GetFullPath(htmlPath);
            if (string.IsNullOrWhiteSpace(Path.GetDirectoryName(full))) throw new InvalidDataException("报告目录无效。");
            foreach (RecordSyncProfileSnapshot profile in report.Profiles)
            {
                if (string.IsNullOrWhiteSpace(profile.CodexDataPath)) continue;
                if (AppPaths.PathsEqual(full, profile.CodexDataPath) || AppPaths.IsPathInside(full, profile.CodexDataPath))
                    throw new InvalidDataException("本地记录核查报告不得写入任何 .codex 数据目录。");
            }
            Directory.CreateDirectory(Path.GetDirectoryName(full));
            File.WriteAllText(full, ToHtml(report), new UTF8Encoding(false));
            string json = Path.ChangeExtension(full, ".json");
            JsonFile.WriteAtomic(json, report, null);
            return json;
        }

        internal static string ToHtml(RecordSyncReport report)
        {
            StringBuilder html = new StringBuilder();
            html.Append("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>Codex Guard 本地记录隔离核查</title>")
                .Append("<style>body{font-family:'Microsoft YaHei UI',sans-serif;margin:32px;color:#15253d;line-height:1.55}h1{margin-bottom:4px}.meta{color:#5c6878}.banner{padding:16px 20px;border-radius:8px;margin:22px 0;background:#fff5df;color:#8a5700;font-weight:700}table{border-collapse:collapse;width:100%;margin:14px 0 26px}th,td{border:1px solid #d7dde5;padding:9px;vertical-align:top;text-align:left}th{background:#edf4fb}.PASS{color:#1f845b;font-weight:700}.FAIL{color:#be3939;font-weight:700}.WARN,.MANUAL{color:#b06f17;font-weight:700}code{word-break:break-all}small{color:#5c6878}</style></head><body>");
            html.Append("<h1>Codex Guard 本地记录隔离核查</h1><div class=\"meta\">机器：")
                .Append(H(report.MachineName)).Append("　生成时间：").Append(H(report.GeneratedAtUtc))
                .Append("　版本：").Append(H(report.ProductVersion)).Append("</div>");
            html.Append("<div class=\"banner\">").Append(H(report.OverallStatus)).Append("<br><small>")
                .Append(H(report.PrivacyStatement)).Append("</small></div>");
            html.Append("<h2>身份与记录边界</h2><p>").Append(H(report.SyncMode)).Append("</p>");
            html.Append("<table><tr><th>Windows 身份</th><th>本地路径</th><th>登录标记</th><th>本地会话元数据</th><th>数据库元数据</th><th>链接 / 错误</th></tr>");
            foreach (RecordSyncProfileSnapshot profile in report.Profiles)
            {
                html.Append("<tr><td>").Append(H(profile.Role)).Append("</td><td><code>").Append(H(profile.CodexDataPath ?? profile.ProfilePath ?? "未发现"))
                    .Append("</code></td><td>").Append(profile.AuthenticationMarkerExists ? "存在（未读取）" : "未检测到或不可见")
                    .Append("</td><td>").Append(profile.SessionFileCount).Append(" 个 / ").Append(H(FormatBytes(profile.SessionBytes)))
                    .Append("</td><td>").Append(profile.SqliteDatabaseCount).Append(" 个；活动 sidecar ").Append(profile.LiveDatabaseSidecarCount)
                    .Append("</td><td>").Append(profile.LinkedCriticalEntryDetected ? "检测到重解析/硬链接" : "未检测到关键链接")
                    .Append(string.IsNullOrWhiteSpace(profile.InspectionError) ? string.Empty : "；" + H(profile.InspectionError)).Append("</td></tr>");
            }
            html.Append("</table><h2>核查项</h2><table><tr><th>状态</th><th>检查项</th><th>实际事实</th><th>人工动作</th></tr>");
            foreach (ReviewEvidence check in report.Checks)
            {
                html.Append("<tr><td class=\"").Append(H(check.Status)).Append("\">").Append(H(check.Status)).Append("</td><td>")
                    .Append(H(check.Control)).Append("</td><td>").Append(H(check.Actual)).Append("</td><td>")
                    .Append(H(check.ManualAction)).Append("</td></tr>");
            }
            html.Append("</table><h2>人工核查清单</h2><pre>").Append(H(VerificationChecklist))
                .Append("</pre><p><small>最终进程用户名与两个 .codex 时间戳仍须人工核对；本报告不尝试跨用户启动 ChatGPT/Codex。</small></p></body></html>");
            return html.ToString();
        }

        private static void AddChecks(RecordSyncReport report, RecordSyncProfileSnapshot admin, RecordSyncProfileSnapshot worker)
        {
            AddCheck(report, "PASS", "单一本地记录源",
                "未来任务只由 CodexWorker 进程写入 Worker 自己的 .codex；不依赖云端记录同步。",
                "不要建立 .codex 联接，不要复制 auth.json、SQLite 或会话 JSONL。",
                null);

            string separationStatus;
            string separationActual;
            if (admin.LinkedCriticalEntryDetected || worker.LinkedCriticalEntryDetected)
            {
                separationStatus = "FAIL";
                separationActual = "检测到资料目录或关键记录项使用重解析/硬链接；这可能跨越 Windows 用户权限边界。";
            }
            else if (string.IsNullOrWhiteSpace(admin.ProfilePath) || string.IsNullOrWhiteSpace(worker.ProfilePath))
            {
                separationStatus = "WARN";
                separationActual = "尚未同时发现 admin 与 CodexWorker 的 Windows 用户资料路径。";
            }
            else if (AppPaths.PathsEqual(admin.ProfilePath, worker.ProfilePath)
                || (!string.IsNullOrWhiteSpace(admin.CodexDataPath) && !string.IsNullOrWhiteSpace(worker.CodexDataPath)
                    && AppPaths.PathsEqual(admin.CodexDataPath, worker.CodexDataPath)))
            {
                separationStatus = "FAIL";
                separationActual = "两个 Windows 身份解析到了同一个用户资料或 .codex 路径。";
            }
            else
            {
                separationStatus = "PASS";
                separationActual = "admin 与 CodexWorker 使用不同的本地资料路径，未检测到关键重解析链接。";
            }
            AddCheck(report, separationStatus, "本地数据隔离", separationActual,
                "失败时停止使用 Codex；移除目录联接/符号链接，并保留两套独立用户资料。", null);

            AddCheck(report, "PASS", "跨用户桌面启动已移除",
                "Codex Guard 不再从 admin 交互式桌面尝试以备用身份激活打包版 ChatGPT/Codex。",
                "登录 CodexWorker 自己的 Windows 桌面运行 ChatGPT/Codex；NTFS 权限管理切到非提升 admin 控制面提交并经 UAC 确认。",
                null);

            string workerMarker = worker.AuthenticationMarkerExists ? "Worker 初始化标记存在（内容未读取）" : "Worker 初始化标记未检测到或当前身份不可见";
            AddCheck(report, worker.ProfileExists && worker.CodexDataExists ? "PASS" : "WARN", "Worker 本地资料",
                workerMarker + "；会话=" + worker.SessionFileCount + "（" + FormatBytes(worker.SessionBytes) + "）。",
                "若未就绪，登录 CodexWorker 自己的 Windows 桌面安装/启动并登录官方 ChatGPT/Codex。", worker.CodexDataPath);

            AddCheck(report, "PASS", "admin 旧记录不合并",
                "admin 本地会话=" + admin.SessionFileCount + "（" + FormatBytes(admin.SessionBytes) + "），CodexWorker 本地会话="
                    + worker.SessionFileCount + "（" + FormatBytes(worker.SessionBytes) + "）；两者不做单向或双向文件复制。",
                "保留 admin\\.codex 作为既有旧档；不要把其数据库或 JSONL 写进 Worker 资料。", admin.CodexDataPath);

            AddCheck(report, "MANUAL", "进程身份与时间戳抽查",
                "静态检查无法替代对 CodexWorker 桌面中实际 ChatGPT/Codex 进程的令牌核查。",
                "在 CodexWorker 桌面打开任务管理器，确认 ChatGPT/Codex/codex 为 " + Environment.MachineName + "\\CodexWorker；运行测试任务后仅 Worker\\.codex 时间应更新。", null);
        }

        private static void FinalizeStatus(RecordSyncReport report, RecordSyncProfileSnapshot worker)
        {
            bool failed = false;
            bool warning = false;
            foreach (ReviewEvidence check in report.Checks)
            {
                if (string.Equals(check.Status, "FAIL", StringComparison.OrdinalIgnoreCase)) failed = true;
                if (string.Equals(check.Status, "WARN", StringComparison.OrdinalIgnoreCase)) warning = true;
            }
            if (failed)
                report.OverallStatus = "Worker 本地记录边界失败：先修复红色项目，不要启动 Codex";
            else if (warning || !worker.ProfileExists || !worker.CodexDataExists)
                report.OverallStatus = "Worker 单一本地记录方案尚未就绪：按黄色项目完成安装或首次初始化";
            else
                report.OverallStatus = "Worker 本地资料边界就绪；仍须在 Worker 桌面按清单人工核对进程用户名";
        }

        private static void CountDatabases(RecordSyncProfileSnapshot snapshot)
        {
            foreach (string path in Directory.GetFiles(snapshot.CodexDataPath, "*.sqlite", SearchOption.TopDirectoryOnly))
            {
                snapshot.SqliteDatabaseCount++;
                if (IsLinkedFile(path)) snapshot.LinkedCriticalEntryDetected = true;
            }
            string[] sidecarPatterns = { "*.sqlite-wal", "*.sqlite-shm", "*.db-wal", "*.db-shm", "*.db-journal" };
            foreach (string pattern in sidecarPatterns)
            {
                foreach (string sidecar in Directory.GetFiles(snapshot.CodexDataPath, pattern, SearchOption.TopDirectoryOnly))
                {
                    snapshot.LiveDatabaseSidecarCount++;
                    if (IsLinkedFile(sidecar)) snapshot.LinkedCriticalEntryDetected = true;
                }
            }
        }

        private static void CountSessions(RecordSyncProfileSnapshot snapshot)
        {
            string root = Path.Combine(snapshot.CodexDataPath, "sessions");
            if (!Directory.Exists(root)) return;
            if (IsReparsePoint(root))
            {
                snapshot.LinkedCriticalEntryDetected = true;
                return;
            }

            Stack<string> pending = new Stack<string>();
            pending.Push(root);
            DateTime newest = DateTime.MinValue;
            while (pending.Count > 0)
            {
                string current = pending.Pop();
                foreach (string directory in Directory.GetDirectories(current))
                {
                    if (IsReparsePoint(directory))
                    {
                        snapshot.LinkedCriticalEntryDetected = true;
                        continue;
                    }
                    pending.Push(directory);
                }
                foreach (string file in Directory.GetFiles(current, "*.jsonl", SearchOption.TopDirectoryOnly))
                {
                    if (IsLinkedFile(file))
                    {
                        snapshot.LinkedCriticalEntryDetected = true;
                        continue;
                    }
                    FileInfo information = new FileInfo(file);
                    snapshot.SessionFileCount++;
                    snapshot.SessionBytes += information.Length;
                    if (information.LastWriteTimeUtc > newest) newest = information.LastWriteTimeUtc;
                    if (snapshot.SessionFileCount > MaximumEnumeratedSessionFiles)
                        throw new InvalidDataException("会话文件超过安全枚举上限。");
                }
            }
            if (newest != DateTime.MinValue) snapshot.NewestSessionUtc = newest.ToString("o");
        }

        private static void AddCheck(RecordSyncReport report, string status, string control, string actual, string manualAction, string path)
        {
            report.Checks.Add(new ReviewEvidence
            {
                Status = status,
                Control = control,
                Expected = "未来记录仅由受控 CodexWorker 进程写入 Worker 自己的本地资料",
                Actual = actual,
                EvidenceSource = "受保护状态 + Windows SID/组/资料路径 + 只读本地元数据",
                ManualAction = manualAction,
                Path = path
            });
        }

        private static string NormalizeWithoutThrowing(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            try { return AppPaths.NormalizeDirectoryPath(path); }
            catch { return path.Trim(); }
        }

        private static bool IsReparsePoint(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }

        private static bool IsLinkedFile(string path)
        {
            return IsReparsePoint(path) || NativePath.GetFileLinkCount(path) > 1;
        }

        private static string FormatBytes(long value)
        {
            if (value < 1024) return value + " B";
            if (value < 1024L * 1024L) return (value / 1024D).ToString("0.0") + " KiB";
            if (value < 1024L * 1024L * 1024L) return (value / (1024D * 1024D)).ToString("0.0") + " MiB";
            return (value / (1024D * 1024D * 1024D)).ToString("0.0") + " GiB";
        }

        private static string H(string value)
        {
            return WebUtility.HtmlEncode(value ?? string.Empty);
        }
    }
}
