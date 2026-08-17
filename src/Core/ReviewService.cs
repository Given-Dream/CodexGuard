using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace CodexGuard.Core
{
    internal static class ReviewService
    {
        public const string IndependentReviewerName = "CodexGuard.ReadOnlyVerifier.exe";

        public static ReviewReport Capture()
        {
            ReviewReport report = new ReviewReport
            {
                SchemaVersion = AppInfo.ReviewReportSchemaVersion,
                GeneratedAtUtc = AppInfo.UtcNow(),
                ProductVersion = AppInfo.Version,
                MachineName = Environment.MachineName,
                CurrentIdentity = Environment.UserDomainName + "\\" + Environment.UserName,
                CurrentSid = SafeCurrentSid(),
                ScopeStatement = "This is a read-only configuration inspection. It does not attempt a write, rename, delete, ACL change, account change, or UAC change. A static PASS is not a black-box proof of effective access."
            };

            List<AuditItem> audit = AuditService.Run();
            UacStatus uac = UacPolicy.Read();
            AddControl(report, uac.MeetsRequirements ? "PASS" : "FAIL", "UAC 人工授权边界",
                "EnableLUA=1；PromptOnSecureDesktop=1；ConsentPromptBehaviorUser=1",
                "EnableLUA=" + BoolValue(uac.Enabled) + "；PromptOnSecureDesktop=" + BoolValue(uac.SecureDesktop)
                    + "；ConsentPromptBehaviorUser=" + BoolValue(uac.StandardUsersPromptForCredentialsOnSecureDesktop),
                "只读注册表 HKLM\\...\\Policies\\System", null,
                uac.MeetsRequirements ? null : "停止使用权限变更功能，由管理员检查 UAC 策略并重启 Windows。");

            bool requirementsPresent = File.Exists(AppPaths.SystemRequirementsFile);
            bool requirementsPass = requirementsPresent && CodexConfigurationService.SystemRequirementsMeetPolicy();
            AddControl(report, requirementsPass ? "PASS" : "FAIL", "官方 elevated 沙箱约束",
                "禁用 login shell；仅允许 elevated；启用 private desktop",
                requirementsPresent ? (requirementsPass ? "三个受管键值均符合" : "文件存在但键值不完整或不可解析") : "requirements.toml 不存在",
                AppPaths.SystemRequirementsFile, AppPaths.SystemRequirementsFile,
                requirementsPass ? null : "对照官方 Windows sandbox 文档检查 requirements.toml；不要允许 unelevated 回退。");

            GuardState state = TryLoadState(report);
            AddIdentityControl(report, state);
            AddProtectedArtifactControl(report, audit);
            AddPathBoundaryControl(report, state, audit);
            AddAclControl(report, state, audit);
            AddDefaultReadOnlyControl(report, state, audit);
            AddLocalRecordControl(report, audit);
            AddFullAuditControl(report, audit);

            AddControl(report, "MANUAL", "真实身份黑盒验收",
                "CodexWorker/沙箱：激活目录可读、可覆盖、可新建；删除、重命名、改 ACL 均拒绝；admin 可人工处理",
                "本次只读核查没有执行任何破坏性或权限变更尝试",
                "无重要数据的验收副本", null,
                "按 MANUAL_REVIEW.md 在专用副本上完成一次六项实测并保留截图。");

            foreach (AuditItem item in audit)
            {
                report.Findings.Add(new ReviewEvidence
                {
                    Status = item.Severity == AuditSeverity.Error ? "FAIL" : item.Severity == AuditSeverity.Warning ? "WARN" : "PASS",
                    Control = item.Code,
                    Expected = "Codex Guard 审计不得报告此项异常",
                    Actual = item.Message,
                    EvidenceSource = "AuditService 只读检查",
                    Path = item.Path
                });
            }

            AddFacts(report, state);
            CountAndFinalize(report);
            return report;
        }

        public static string ExportPackage(string htmlPath, ReviewReport report)
        {
            if (report == null) throw new ArgumentNullException("report");
            if (string.IsNullOrWhiteSpace(htmlPath)) throw new ArgumentException("Report path is required.", "htmlPath");
            string full = Path.GetFullPath(htmlPath);
            string directory = Path.GetDirectoryName(full);
            if (string.IsNullOrWhiteSpace(directory)) throw new InvalidOperationException("Report directory is missing.");
            Directory.CreateDirectory(directory);
            File.WriteAllText(full, ToHtml(report), new UTF8Encoding(false));
            string json = Path.ChangeExtension(full, ".json");
            JsonFile.WriteAtomic(json, report, null);
            return json;
        }

        internal static string ToHtml(ReviewReport report)
        {
            StringBuilder html = new StringBuilder();
            html.Append("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>Codex Guard 人工核查报告</title>");
            html.Append("<style>body{font-family:'Microsoft YaHei UI',sans-serif;margin:32px;color:#15253d;line-height:1.55}h1{margin-bottom:4px}.meta{color:#5c6878}.banner{padding:16px 20px;border-radius:8px;margin:22px 0;font-weight:700}.pass{background:#e9f7f0;color:#16714d}.fail{background:#fdecec;color:#a32424}.review{background:#fff5df;color:#8a5700}table{border-collapse:collapse;width:100%;margin:14px 0 26px}th,td{border:1px solid #d7dde5;padding:9px;vertical-align:top;text-align:left}th{background:#edf4fb}.status{font-weight:700;white-space:nowrap}.PASS{color:#1f845b}.FAIL{color:#be3939}.WARN,.MANUAL{color:#b06f17}code{word-break:break-all}small{color:#5c6878}</style></head><body>");
            html.Append("<h1>Codex Guard 人工核查报告</h1>");
            html.Append("<div class=\"meta\">机器：").Append(H(report.MachineName)).Append("　当前身份：").Append(H(report.CurrentIdentity))
                .Append("　生成时间：").Append(H(report.GeneratedAtUtc)).Append("　版本：").Append(H(report.ProductVersion)).Append("</div>");
            string bannerClass = report.FailureCount > 0 ? "fail" : report.WarningCount > 0 ? "review" : "pass";
            html.Append("<div class=\"banner ").Append(bannerClass).Append("\">").Append(H(report.OverallStatus))
                .Append("<br><small>").Append(H(report.ScopeStatement)).Append("</small></div>");
            html.Append("<h2>先看这几项</h2>");
            AppendEvidenceTable(html, report.Controls);
            html.Append("<h2>完整审计发现</h2>");
            AppendEvidenceTable(html, report.Findings);
            html.Append("<h2>原始事实（便于与独立核查器交叉核对）</h2><table><tr><th>项目</th><th>实际值</th></tr>");
            foreach (ReviewFact fact in report.Facts)
                html.Append("<tr><td>").Append(H(fact.Name)).Append("</td><td><code>").Append(H(fact.Value)).Append("</code></td></tr>");
            html.Append("</table><h2>三分钟人工判定</h2><ol>")
                .Append("<li>任何 <b class=\"FAIL\">FAIL</b>：立即停止使用 Codex 处理真实数据。</li>")
                .Append("<li>将本报告中的 SID、UAC 数值、文件哈希和 SDDL 与 <code>CodexGuard.ReadOnlyVerifier.exe</code> 的原始事实逐项比较。</li>")
                .Append("<li>所有静态项通过后，仍只在无重要数据副本上完成读取、覆盖、新建、重命名、删除和改 ACL 六项黑盒测试。</li>")
                .Append("<li>只有预期成功项成功、预期拒绝项均显示“拒绝访问”，才可把该机器标记为验收完成。</li></ol>")
                .Append("<p><small>官方基线：<a href=\"https://learn.chatgpt.com/docs/windows/windows-sandbox\">OpenAI Windows sandbox documentation</a>。报告文件本身可能包含本机路径与 SID，请按本地安全资料保管。</small></p>")
                .Append("</body></html>");
            return html.ToString();
        }

        private static void AddIdentityControl(ReviewReport report, GuardState state)
        {
            SecurityIdentifier worker;
            SecurityIdentifier sandbox;
            bool workerExists = IdentityService.TryResolveSid(IdentityService.MachineAccount(AppInfo.WorkerAccountName), out worker);
            bool sandboxExists = IdentityService.TryResolveSid(IdentityService.MachineAccount(AppInfo.SandboxGroupName), out sandbox);
            List<string> memberships = new List<string>();
            List<string> privileged = new List<string>();
            string membershipError = null;
            if (workerExists)
            {
                try
                {
                    memberships = LocalAccountService.GetLocalGroupMemberships(AppInfo.WorkerAccountName);
                    privileged = LocalAccountService.FindPrivilegedMemberships(memberships);
                }
                catch (Exception ex) { membershipError = ex.Message; }
            }
            bool sidMatches = state != null && workerExists && string.Equals(state.WorkerSid, worker.Value, StringComparison.OrdinalIgnoreCase);
            bool pass = workerExists && sandboxExists && sidMatches && membershipError == null && privileged.Count == 0;
            string actual = "Worker=" + (workerExists ? worker.Value : "不存在")
                + "；SandboxGroup=" + (sandboxExists ? sandbox.Value : "不存在")
                + "；state SID=" + (state == null ? "不可用" : (state.WorkerSid ?? "空"))
                + "；本地组=" + (membershipError ?? (memberships.Count == 0 ? "无" : string.Join(", ", memberships.ToArray())))
                + (privileged.Count == 0 ? string.Empty : "；特权组=" + string.Join(", ", privileged.ToArray()));
            AddControl(report, pass ? "PASS" : "FAIL", "身份隔离",
                "CodexWorker 存在、SID 与受保护状态一致、不属于特权组；CodexSandboxUsers 可解析",
                actual, "Windows SID 翻译 + NetUserGetLocalGroups + state.json", null,
                pass ? null : "不要激活项目；由管理员核对账户是否被重建或加入了特权组，并重新绑定沙箱 SID。");
        }

        private static void AddProtectedArtifactControl(ReviewReport report, List<AuditItem> audit)
        {
            string[] codes = { "APP_NOT_INSTALLED", "APP_FILE_UNTRUSTED", "APP_FILE_WRITABLE", "REVIEWER_NOT_INSTALLED", "REVIEWER_FILE_UNTRUSTED", "REVIEWER_FILE_WRITABLE", "PROBE_NOT_INSTALLED", "PROBE_FILE_UNTRUSTED", "PROBE_FILE_WRITABLE", "STATE_MISSING", "STATE_INVALID", "STATE_FILE_WRITABLE", "STATE_MACHINE_MISMATCH", "CODEX_REQUIREMENTS_WRITABLE" };
            List<AuditItem> failures = Select(audit, codes, AuditSeverity.Error);
            AddControl(report, failures.Count == 0 ? "PASS" : "FAIL", "受信任程序与状态",
                "安装 EXE、state.json、requirements.toml 由 Administrators/SYSTEM 控制，Codex 身份和宽泛主体不可写",
                failures.Count == 0 ? "未发现所有者或写入 ACL 异常" : JoinAudit(failures),
                "文件 Owner、DACL 与状态机器标识", AppPaths.InstalledExecutable,
                failures.Count == 0 ? null : "停止接受 UAC 请求；从受信任发布包修复并比较 SHA-256。");
        }

        private static void AddPathBoundaryControl(ReviewReport report, GuardState state, List<AuditItem> audit)
        {
            string[] pathCodes = { "ACTIVE_PATH_MISSING", "PATH_IDENTITY_CHANGED", "PATH_IDENTITY_FAILED", "ADMIN_PROFILE_PATH_INVALID",
                "ADMIN_PROFILE_BOUNDARY_MISSING", "ADMIN_PROFILE_PATH_MISSING", "ADMIN_PROFILE_IDENTITY_CHANGED", "ADMIN_PROFILE_IDENTITY_FAILED", "LEGACY_PROTECTION_ROOT",
                "DEFAULT_READONLY_PATH_MISSING", "DEFAULT_READONLY_IDENTITY_CHANGED", "DEFAULT_READONLY_IDENTITY_FAILED", "ROOT_LOCK_PATH_MISSING",
                "DEFAULT_READONLY_NOT_ENABLED", "DEFAULT_READONLY_PLAN_BLOCKED", "DEFAULT_READONLY_NEW_TARGET", "DEFAULT_READONLY_PLAN_FAILED" };
            List<AuditItem> failures = Select(audit, pathCodes, AuditSeverity.Error);
            int outside = 0;
            int activeCount = 0;
            int rootCount = 0;
            if (state != null)
            {
                activeCount = state.ActivatedDirectories.Count;
                rootCount = state.DefaultReadOnlyDirectories.Count + (AdminProfileBoundaryService.Find(state) == null ? 0 : 1);
                foreach (GuardedDirectory active in state.ActivatedDirectories)
                {
                    bool inside = AdminProfileBoundaryService.IsStrictDescendant(active.CanonicalPath, state);
                    if (!inside)
                    {
                        foreach (GuardedDirectory root in state.DefaultReadOnlyDirectories)
                        {
                            if (!AppPaths.PathsEqual(active.CanonicalPath, root.CanonicalPath)
                                && AppPaths.IsPathInside(active.CanonicalPath, root.CanonicalPath))
                            {
                                inside = true;
                                break;
                            }
                        }
                    }
                    if (!inside) outside++;
                }
            }
            bool pass = state != null && failures.Count == 0 && outside == 0 && activeCount > 0 && rootCount > 0;
            string status = pass ? "PASS" : state != null && failures.Count == 0 && outside == 0 ? "WARN" : "FAIL";
            AddControl(report, status, "路径与对象身份边界",
                "每个激活目录都是固定管理员资料边界或默认只读边界的严格后代，且 NTFS 卷序列号/文件 ID 未变化",
                "可激活边界=" + rootCount + "；激活目录=" + activeCount + "；边界外激活=" + outside
                    + (failures.Count == 0 ? string.Empty : "；" + JoinAudit(failures)),
                "state.json + 规范路径 + NTFS 文件 ID", null,
                status == "PASS" ? null : "先应用默认只读基线并使用无重要数据测试项目；路径身份变化时先做取证，不要直接修复。");
        }

        private static void AddAclControl(ReviewReport report, GuardState state, List<AuditItem> audit)
        {
            string[] codes = { "ACL_READ_FAILED", "ACTIVE_ALLOW_MISSING", "DELETE_DENY_MISSING", "OWNER_RIGHTS_RULE_MISSING", "READONLY_ALLOW_MISSING", "READONLY_WRITE_ALLOW", "BROAD_WRITE_ALLOW", "SENSITIVE_ACL_READ_FAILED", "SENSITIVE_DENY_MISSING", "INTERNAL_RIGHTS_ERROR",
                "DEFAULT_READONLY_STATE_INCOMPLETE", "DEFAULT_READONLY_ACL_READ_FAILED", "DEFAULT_READONLY_ALLOW_MISSING", "DEFAULT_READONLY_DENY_MISSING",
                "ROOT_LOCK_ACL_READ_FAILED", "ROOT_LOCK_DENY_MISSING", "ROOT_LOCK_OWNER_RIGHTS_MISSING" };
            List<AuditItem> failures = Select(audit, codes, AuditSeverity.Error);
            bool configured = state != null && (state.ActivatedDirectories.Count > 0 || AdminProfileBoundaryService.Find(state) != null || state.DefaultReadOnlyDirectories.Count > 0);
            string status = failures.Count > 0 ? "FAIL" : configured ? "PASS" : "WARN";
            AddControl(report, status, "NTFS 不删除规则",
                "激活目录 Allow=ReadAndExecute|Write|Synchronize 且不含 Delete；路径均拒绝 Delete/Delete child/WRITE_DAC/WRITE_OWNER，并用 OWNER RIGHTS 关闭所有者隐式 WRITE_DAC",
                failures.Count == 0 ? (configured ? "管理员资料、默认只读和激活路径上的精确 Codex Guard ACE 均存在" : "尚无可核查的固定边界或激活目录") : JoinAudit(failures),
                "目标目录 DACL 的精确显式 ACE", null,
                status == "PASS" ? null : "不要用真实项目；关闭 Codex/终端后由管理员修复，再重新导出核查包。");
        }

        private static void AddFullAuditControl(ReviewReport report, List<AuditItem> audit)
        {
            int errors = 0;
            int warnings = 0;
            foreach (AuditItem item in audit)
            {
                if (item.Severity == AuditSeverity.Error) errors++;
                else if (item.Severity == AuditSeverity.Warning) warnings++;
            }
            string status = errors > 0 ? "FAIL" : warnings > 0 ? "WARN" : "PASS";
            AddControl(report, status, "完整只读审计",
                "所有已知安全不变量均无错误或警告",
                "错误=" + errors + "；警告=" + warnings + "；详细记录=" + audit.Count,
                "AuditService 全量结果", null,
                status == "PASS" ? null : "逐项处理下方完整审计发现；不要用黑盒测试掩盖静态失败。");
        }

        private static void AddDefaultReadOnlyControl(ReviewReport report, GuardState state, List<AuditItem> audit)
        {
            string[] codes = { "DEFAULT_READONLY_STATE_INCOMPLETE", "DEFAULT_READONLY_PATH_MISSING", "DEFAULT_READONLY_IDENTITY_CHANGED",
                "DEFAULT_READONLY_IDENTITY_FAILED", "DEFAULT_READONLY_ACL_READ_FAILED", "DEFAULT_READONLY_ALLOW_MISSING", "DEFAULT_READONLY_DENY_MISSING",
                "ROOT_LOCK_PATH_MISSING", "ROOT_LOCK_ACL_READ_FAILED", "ROOT_LOCK_DENY_MISSING", "ROOT_LOCK_OWNER_RIGHTS_MISSING",
                "DEFAULT_READONLY_NOT_ENABLED", "DEFAULT_READONLY_PLAN_BLOCKED", "DEFAULT_READONLY_NEW_TARGET", "DEFAULT_READONLY_PLAN_FAILED",
                "DEFAULT_READONLY_EXCEPTION_INVALID", "DEFAULT_READONLY_EXCEPTION_MISSING" };
            List<AuditItem> failures = Select(audit, codes, AuditSeverity.Error);
            string status = state == null || failures.Count > 0 || !state.DefaultReadOnlyEnabled ? "FAIL" : "PASS";
            string actual = state == null ? "受保护状态不可用"
                : "启用=" + BoolValue(state.DefaultReadOnlyEnabled) + "；默认只读边界=" + state.DefaultReadOnlyDirectories.Count
                    + "；根锁=" + state.DefaultReadOnlyRootLocks.Count + "；运行时允许列表=" + state.WritableExceptionPaths.Count
                    + (failures.Count == 0 ? string.Empty : "；" + JoinAudit(failures));
            AddControl(report, status, "CodexWorker 默认只读基线",
                "固定数据盘和 Worker 数据目录默认只读；仅 AppData/.codex/已存在 .cache 正常清理，激活目录可写但禁删",
                actual, "state.json + 各边界 DACL + 本机固定卷盘点", null,
                status == "PASS" ? null : "从非提升 admin 控制面预览默认只读计划；确认备份和激活目录后通过 UAC 应用，再在副本上验收。");
        }

        private static void AddLocalRecordControl(ReviewReport report, List<AuditItem> audit)
        {
            int failures = 0;
            int warnings = 0;
            int passed = 0;
            foreach (AuditItem item in audit)
            {
                if (string.IsNullOrWhiteSpace(item.Code) || !item.Code.StartsWith("LOCAL_RECORD", StringComparison.OrdinalIgnoreCase)) continue;
                if (item.Severity == AuditSeverity.Error) failures++;
                else if (item.Severity == AuditSeverity.Warning) warnings++;
                else passed++;
            }
            string status = failures > 0 ? "FAIL" : warnings > 0 ? "WARN" : passed > 0 ? "PASS" : "WARN";
            AddControl(report, status, "本地记录路径隔离",
                "CodexWorker 使用自己的 .codex；admin 旧记录不联接、不复制、不合并；检查不读取令牌或对话正文",
                "错误=" + failures + "；需人工核查=" + warnings + "；通过摘要=" + passed,
                "路径、链接属性、文件数量/大小/时间元数据", null,
                status == "PASS" ? null : CodexRecordSyncService.VerificationChecklist);
        }

        private static GuardState TryLoadState(ReviewReport report)
        {
            if (!StateStore.Exists) return null;
            try { return StateStore.Load(); }
            catch (Exception ex)
            {
                report.Findings.Add(new ReviewEvidence { Status = "FAIL", Control = "STATE_LOAD", Expected = "受保护状态可读取且格式有效", Actual = ex.Message, EvidenceSource = AppPaths.StateFile, Path = AppPaths.StateFile });
                return null;
            }
        }

        private static void AddFacts(ReviewReport report, GuardState state)
        {
            report.Facts.Add(new ReviewFact { Name = "官方基线", Value = "https://learn.chatgpt.com/docs/windows/windows-sandbox" });
            report.Facts.Add(new ReviewFact { Name = "当前进程 SID", Value = report.CurrentSid });
            report.Facts.Add(new ReviewFact { Name = "预期 Active Allow 数值", Value = ((long)AclService.ActiveAllowRights).ToString() + " = " + AclService.ActiveAllowRights });
            report.Facts.Add(new ReviewFact { Name = "预期 Guard Deny 数值", Value = ((long)AclService.GuardDenyRights).ToString() + " = " + AclService.GuardDenyRights });
            report.Facts.Add(new ReviewFact { Name = "预期 OWNER RIGHTS Allow 数值", Value = ((long)AclService.OwnerRightsAllowRights).ToString() + " = " + AclService.OwnerRightsAllowRights + " | SID=S-1-3-4" });
            AddFileFact(report, "安装 EXE", AppPaths.InstalledExecutable);
            AddFileFact(report, "独立只读核查器", AppPaths.InstalledReviewerExecutable);
            AddFileFact(report, "验收探针", AppPaths.InstalledAcceptanceExecutable);
            AddFileFact(report, "受保护状态", AppPaths.StateFile);
            AddFileFact(report, "OpenAI requirements", AppPaths.SystemRequirementsFile);
            if (state == null) return;
            report.Facts.Add(new ReviewFact { Name = "状态机器 / Worker SID / Sandbox SID", Value = (state.MachineName ?? "") + " | " + (state.WorkerSid ?? "") + " | " + (state.SandboxGroupSid ?? "") });
            GuardedDirectory adminBoundary = AdminProfileBoundaryService.Find(state);
            if (adminBoundary != null) AddDirectoryFact(report, "固定管理员资料保护", AdminProfileBoundaryService.ItemPath(adminBoundary));
            foreach (GuardedDirectory legacy in AdminProfileBoundaryService.LegacyEntries(state))
                report.Facts.Add(new ReviewFact { Name = "旧版手工保护根（已禁用）", Value = AdminProfileBoundaryService.ItemPath(legacy) ?? "无有效路径" });
            foreach (GuardedDirectory root in state.DefaultReadOnlyDirectories) AddDirectoryFact(report, "默认只读边界", root.CanonicalPath);
            foreach (GuardedDirectory root in state.DefaultReadOnlyRootLocks) AddDirectoryFact(report, "仅锁根目录", root.CanonicalPath);
            foreach (string path in state.WritableExceptionPaths) report.Facts.Add(new ReviewFact { Name = "运行时写入允许列表", Value = path });
            foreach (GuardedDirectory active in state.ActivatedDirectories) AddDirectoryFact(report, "激活目录", active.CanonicalPath);
        }

        private static void AddFileFact(ReviewReport report, string label, string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    report.Facts.Add(new ReviewFact { Name = label, Value = path + " | 不存在" });
                    return;
                }
                FileSecurity security = File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
                report.Facts.Add(new ReviewFact
                {
                    Name = label,
                    Value = path + " | SHA256=" + HashFile(path) + " | Owner=" + security.GetOwner(typeof(SecurityIdentifier)).Value
                        + " | SDDL=" + security.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access)
                });
            }
            catch (Exception ex) { report.Facts.Add(new ReviewFact { Name = label, Value = path + " | 读取失败：" + ex.Message }); }
        }

        private static void AddDirectoryFact(ReviewReport report, string label, string path)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    report.Facts.Add(new ReviewFact { Name = label, Value = path + " | 不存在" });
                    return;
                }
                DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
                report.Facts.Add(new ReviewFact
                {
                    Name = label,
                    Value = path + " | Owner=" + security.GetOwner(typeof(SecurityIdentifier)).Value
                        + " | SDDL=" + security.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access)
                });
            }
            catch (Exception ex) { report.Facts.Add(new ReviewFact { Name = label, Value = path + " | 读取失败：" + ex.Message }); }
        }

        private static string HashFile(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                byte[] hash = sha.ComputeHash(stream);
                StringBuilder value = new StringBuilder(hash.Length * 2);
                foreach (byte item in hash) value.Append(item.ToString("x2"));
                return value.ToString();
            }
        }

        private static void CountAndFinalize(ReviewReport report)
        {
            foreach (ReviewEvidence item in report.Controls)
            {
                if (item.Status == "FAIL") report.FailureCount++;
                else if (item.Status == "WARN") report.WarningCount++;
                else if (item.Status == "MANUAL") report.ManualCheckCount++;
            }
            report.OverallStatus = report.FailureCount > 0
                ? "静态核查失败：有 " + report.FailureCount + " 项失败，禁止处理真实数据"
                : report.WarningCount > 0
                    ? "静态核查需要处理警告：" + report.WarningCount + " 项警告；另有 " + report.ManualCheckCount + " 项人工验收"
                    : "静态配置通过；仍有 " + report.ManualCheckCount + " 项必须在副本上人工验收";
        }

        private static void AddControl(ReviewReport report, string status, string control, string expected, string actual, string source, string path, string manualAction)
        {
            report.Controls.Add(new ReviewEvidence
            {
                Status = status,
                Control = control,
                Expected = expected,
                Actual = actual,
                EvidenceSource = source,
                Path = path,
                ManualAction = manualAction
            });
        }

        private static List<AuditItem> Select(List<AuditItem> items, string[] codes, AuditSeverity severity)
        {
            List<AuditItem> result = new List<AuditItem>();
            foreach (AuditItem item in items)
            {
                if (item.Severity != severity) continue;
                foreach (string code in codes)
                    if (string.Equals(item.Code, code, StringComparison.OrdinalIgnoreCase)) { result.Add(item); break; }
            }
            return result;
        }

        private static string JoinAudit(List<AuditItem> items)
        {
            List<string> values = new List<string>();
            foreach (AuditItem item in items) values.Add(item.Code + (string.IsNullOrEmpty(item.Path) ? string.Empty : " [" + item.Path + "]"));
            return string.Join("；", values.ToArray());
        }

        private static void AppendEvidenceTable(StringBuilder html, IEnumerable<ReviewEvidence> items)
        {
            html.Append("<table><tr><th>状态</th><th>控制项</th><th>应当如此</th><th>实际事实</th><th>证据 / 人工动作</th></tr>");
            foreach (ReviewEvidence item in items)
            {
                html.Append("<tr><td class=\"status ").Append(H(item.Status)).Append("\">").Append(H(item.Status)).Append("</td><td>").Append(H(item.Control));
                if (!string.IsNullOrEmpty(item.Path)) html.Append("<br><small>").Append(H(item.Path)).Append("</small>");
                html.Append("</td><td>").Append(H(item.Expected)).Append("</td><td>").Append(H(item.Actual)).Append("</td><td>").Append(H(item.EvidenceSource));
                if (!string.IsNullOrEmpty(item.ManualAction)) html.Append("<br><b>下一步：</b>").Append(H(item.ManualAction));
                html.Append("</td></tr>");
            }
            html.Append("</table>");
        }

        private static string H(string value)
        {
            return WebUtility.HtmlEncode(value ?? string.Empty);
        }

        private static string BoolValue(bool value)
        {
            return value ? "1" : "0";
        }

        private static string SafeCurrentSid()
        {
            try { return IdentityService.CurrentSid(); }
            catch (Exception ex) { return "读取失败：" + ex.Message; }
        }
    }
}
