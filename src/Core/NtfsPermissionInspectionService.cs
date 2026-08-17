using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal enum NtfsPolicyClassification
    {
        Activated,
        ProtectedReadOnly,
        SensitiveNoAccess,
        DefaultReadOnly,
        RootOnlyLock,
        WritableRuntimeException,
        WorkerProfileUnmanaged,
        SystemManaged,
        Unmanaged
    }

    internal sealed class NtfsPolicyMatch
    {
        public NtfsPolicyClassification Classification { get; set; }
        public string BoundaryPath { get; set; }
    }

    internal sealed class NtfsPermissionSubjectFact
    {
        public string Status { get; set; }
        public string Subject { get; set; }
        public string Sid { get; set; }
        public string Read { get; set; }
        public string WriteCreate { get; set; }
        public string DeleteRename { get; set; }
        public string ChangeAclOwner { get; set; }
        public string Evidence { get; set; }
    }

    internal sealed class NtfsAclRuleFact
    {
        public string Identity { get; set; }
        public string Sid { get; set; }
        public string AccessType { get; set; }
        public string Rights { get; set; }
        public string Source { get; set; }
        public string Scope { get; set; }
    }

    internal sealed class NtfsPermissionInspection
    {
        public string Status { get; set; }
        public string RequestedPath { get; set; }
        public string FullPath { get; set; }
        public string ClassificationCode { get; set; }
        public string ClassificationText { get; set; }
        public string BoundaryPath { get; set; }
        public string Owner { get; set; }
        public string OwnerSid { get; set; }
        public bool AccessInheritanceDisabled { get; set; }
        public bool ReparsePointOnPath { get; set; }
        public string Summary { get; set; }
        public List<NtfsPermissionSubjectFact> Subjects { get; set; }
        public List<NtfsAclRuleFact> Rules { get; set; }
        public List<string> Findings { get; set; }

        public NtfsPermissionInspection()
        {
            Subjects = new List<NtfsPermissionSubjectFact>();
            Rules = new List<NtfsAclRuleFact>();
            Findings = new List<string>();
        }
    }

    internal static class NtfsPermissionInspectionService
    {
        private static readonly string[] SensitiveAdminSegments =
        {
            "AppData", ".ssh", ".gnupg", ".aws", ".azure", ".codex"
        };

        public static NtfsPermissionInspection Capture(string input)
        {
            if (!StateStore.Exists) throw new InvalidOperationException("Codex Guard 尚未安装，无法判定保护边界。");
            return Capture(StateStore.Load(), input);
        }

        internal static NtfsPermissionInspection Capture(GuardState state, string input)
        {
            if (state == null) throw new ArgumentNullException("state");
            state.Normalize();
            string full = NormalizeInspectionPath(input);
            NtfsPolicyMatch match = ClassifyPath(state, full);
            NtfsPermissionInspection report = new NtfsPermissionInspection
            {
                RequestedPath = input,
                FullPath = full,
                ClassificationCode = match.Classification.ToString(),
                ClassificationText = ClassificationText(match.Classification),
                BoundaryPath = match.BoundaryPath
            };

            if (!Directory.Exists(full))
            {
                report.Status = "FAIL";
                report.Summary = "路径不存在，无法读取 NTFS DACL：" + full;
                return report;
            }

            try
            {
                report.ReparsePointOnPath = HasReparsePointOnPath(full);
                if (report.ReparsePointOnPath)
                    report.Findings.Add("路径或其父级包含重解析点；字面路径分类不能作为可信边界。");

                DirectorySecurity security = Directory.GetAccessControl(full, AccessControlSections.Owner | AccessControlSections.Access);
                SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
                report.OwnerSid = owner == null ? string.Empty : owner.Value;
                report.Owner = owner == null ? "未知" : TranslateSid(owner);
                report.AccessInheritanceDisabled = security.AreAccessRulesProtected;
                AddRuleFacts(report, security);

                List<SecurityIdentifier> actors = IdentityService.ResolveActorSids(state, true);
                List<AuditItem> policyIssues = AuditPolicyPath(match, full, actors);
                foreach (AuditItem issue in policyIssues)
                    report.Findings.Add(issue.Code + " | " + issue.Message);

                bool potentialWrite = AddPotentialWriteFindings(report, state, security, match.Classification);
                bool policyOk = policyIssues.Count == 0 && !potentialWrite && !report.ReparsePointOnPath;
                AddSubjectFacts(report, state, match, policyOk, policyIssues);
                SetSummary(report, match, policyOk);
                return report;
            }
            catch (Exception ex)
            {
                report.Status = "FAIL";
                report.Summary = "无法只读检查该路径的 NTFS 所有者或 DACL：" + ex.Message;
                report.Findings.Add(ex.Message);
                return report;
            }
        }

        internal static NtfsPolicyMatch ClassifyPath(GuardState state, string input)
        {
            if (state == null) throw new ArgumentNullException("state");
            state.Normalize();
            string full = AppPaths.NormalizeDirectoryPath(input);

            string sensitive = FindSensitiveBoundary(state, full);
            if (!string.IsNullOrWhiteSpace(sensitive))
                return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.SensitiveNoAccess, BoundaryPath = sensitive };

            string active = FindLongestBoundary(state.ActivatedDirectories, full);
            if (!string.IsNullOrWhiteSpace(active))
                return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.Activated, BoundaryPath = active };

            string writable = FindLongestStringBoundary(state.WritableExceptionPaths, full);
            if (!string.IsNullOrWhiteSpace(writable))
                return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.WritableRuntimeException, BoundaryPath = writable };

            string defaultReadOnly = FindLongestBoundary(state.DefaultReadOnlyDirectories, full);
            if (!string.IsNullOrWhiteSpace(defaultReadOnly))
                return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.DefaultReadOnly, BoundaryPath = defaultReadOnly };

            string rootLock = FindExactBoundary(state.DefaultReadOnlyRootLocks, full);
            if (!string.IsNullOrWhiteSpace(rootLock))
                return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.RootOnlyLock, BoundaryPath = rootLock };

            GuardedDirectory adminBoundary = AdminProfileBoundaryService.Find(state);
            string adminRoot = AdminProfileBoundaryService.ItemPath(adminBoundary);
            if (!string.IsNullOrWhiteSpace(adminRoot) && AppPaths.IsPathInside(full, adminRoot))
                return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.ProtectedReadOnly, BoundaryPath = adminRoot };

            string workerProfile = RegisteredWorkerProfile(state);
            if (!string.IsNullOrWhiteSpace(workerProfile) && AppPaths.IsPathInside(full, workerProfile))
                return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.WorkerProfileUnmanaged, BoundaryPath = workerProfile };

            string system = FindSystemBoundary(full);
            if (!string.IsNullOrWhiteSpace(system))
                return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.SystemManaged, BoundaryPath = system };

            return new NtfsPolicyMatch { Classification = NtfsPolicyClassification.Unmanaged, BoundaryPath = null };
        }

        internal static string ClassificationText(NtfsPolicyClassification classification)
        {
            switch (classification)
            {
                case NtfsPolicyClassification.Activated: return "已激活：Guard 允许读/写/新建，拒绝删除/重命名/改权限";
                case NtfsPolicyClassification.ProtectedReadOnly: return "管理员资料保护：Codex 身份只读，拒绝删除/重命名/改权限";
                case NtfsPolicyClassification.SensitiveNoAccess: return "admin 敏感区：Guard 拒绝 Codex 身份全部访问";
                case NtfsPolicyClassification.DefaultReadOnly: return "默认只读：Guard 拒绝写入/新建/删除/重命名/改权限";
                case NtfsPolicyClassification.RootOnlyLock: return "根目录锁：仅当前目录拒绝新建/写入/删除子项/改权限";
                case NtfsPolicyClassification.WritableRuntimeException: return "运行时允许列表：保留 Windows/ChatGPT/应用缓存的正常写入与清理";
                case NtfsPolicyClassification.WorkerProfileUnmanaged: return "未受管理：Worker 用户资料区沿用 Windows ACL，通常可写可删";
                case NtfsPolicyClassification.SystemManaged: return "系统/应用管理区：不属于 Guard 工作目录策略";
                default: return "未受管理：Guard 未施加权限，完全沿用 Windows ACL";
            }
        }

        private static string NormalizeInspectionPath(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) throw new InvalidDataException("请选择要核查的本地目录。");
            string trimmed = input.Trim();
            if (!Path.IsPathRooted(trimmed) || trimmed.StartsWith(@"\\", StringComparison.Ordinal)
                || trimmed.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
                || trimmed.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("只允许检查普通本地驱动器路径。");
            int colon = trimmed.IndexOf(':');
            if (colon != 1 || trimmed.IndexOf(':', colon + 1) >= 0 || trimmed.Length < 3
                || (trimmed[2] != Path.DirectorySeparatorChar && trimmed[2] != Path.AltDirectorySeparatorChar))
                throw new InvalidDataException("路径必须使用 C:\\Folder 形式，不允许相对路径或备用数据流。");
            return AppPaths.NormalizeDirectoryPath(trimmed);
        }

        private static string FindSensitiveBoundary(GuardState state, string full)
        {
            if (string.IsNullOrWhiteSpace(state.AdminProfilePath)) return null;
            string admin;
            try { admin = AppPaths.NormalizeDirectoryPath(state.AdminProfilePath); }
            catch { return null; }
            foreach (string segment in SensitiveAdminSegments)
            {
                string candidate = Path.Combine(admin, segment);
                if (AppPaths.IsPathInside(full, candidate)) return candidate;
            }
            return null;
        }

        private static string FindLongestBoundary(IEnumerable<GuardedDirectory> values, string full)
        {
            string best = null;
            if (values == null) return null;
            foreach (GuardedDirectory value in values)
            {
                if (value == null) continue;
                string path = string.IsNullOrWhiteSpace(value.CanonicalPath) ? value.Path : value.CanonicalPath;
                if (string.IsNullOrWhiteSpace(path)) continue;
                string normalized;
                try { normalized = AppPaths.NormalizeDirectoryPath(path); }
                catch { continue; }
                if (!AppPaths.IsPathInside(full, normalized)) continue;
                if (best == null || normalized.Length > best.Length) best = normalized;
            }
            return best;
        }

        private static string FindLongestStringBoundary(IEnumerable<string> values, string full)
        {
            string best = null;
            if (values == null) return null;
            foreach (string value in values)
            {
                if (string.IsNullOrWhiteSpace(value)) continue;
                string normalized;
                try { normalized = AppPaths.NormalizeDirectoryPath(value); }
                catch { continue; }
                if (!AppPaths.IsPathInside(full, normalized)) continue;
                if (best == null || normalized.Length > best.Length) best = normalized;
            }
            return best;
        }

        private static string FindExactBoundary(IEnumerable<GuardedDirectory> values, string full)
        {
            if (values == null) return null;
            foreach (GuardedDirectory value in values)
            {
                if (value == null) continue;
                string path = string.IsNullOrWhiteSpace(value.CanonicalPath) ? value.Path : value.CanonicalPath;
                if (!string.IsNullOrWhiteSpace(path) && AppPaths.PathsEqual(full, path)) return AppPaths.NormalizeDirectoryPath(path);
            }
            return null;
        }

        private static string RegisteredWorkerProfile(GuardState state)
        {
            if (!string.IsNullOrWhiteSpace(state.WorkerProfilePath))
            {
                try { return AppPaths.NormalizeDirectoryPath(state.WorkerProfilePath); }
                catch { }
            }
            if (!string.IsNullOrWhiteSpace(state.WorkerSid))
            {
                string registered = IdentityService.GetProfilePathForSid(state.WorkerSid);
                if (!string.IsNullOrWhiteSpace(registered)) return AppPaths.NormalizeDirectoryPath(registered);
            }
            return null;
        }

        private static string FindSystemBoundary(string full)
        {
            string[] candidates =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                AppPaths.InstallDirectory,
                AppPaths.DataDirectory
            };
            string best = null;
            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate)) continue;
                string normalized;
                try { normalized = AppPaths.NormalizeDirectoryPath(candidate); }
                catch { continue; }
                if (!AppPaths.IsPathInside(full, normalized)) continue;
                if (best == null || normalized.Length > best.Length) best = normalized;
            }
            return best;
        }

        private static List<AuditItem> AuditPolicyPath(NtfsPolicyMatch match, string inspectionPath, IEnumerable<SecurityIdentifier> actors)
        {
            if (match == null || string.IsNullOrWhiteSpace(match.BoundaryPath)) return new List<AuditItem>();
            switch (match.Classification)
            {
                case NtfsPolicyClassification.Activated:
                    return AclService.AuditActivated(inspectionPath, actors);
                case NtfsPolicyClassification.ProtectedReadOnly:
                    return AclService.AuditReadOnly(inspectionPath, actors);
                case NtfsPolicyClassification.SensitiveNoAccess:
                    return AclService.AuditNoAccess(inspectionPath, actors);
                case NtfsPolicyClassification.DefaultReadOnly:
                    return AclService.AuditDefaultReadOnlyBoundary(match.BoundaryPath, actors);
                case NtfsPolicyClassification.RootOnlyLock:
                    return AclService.AuditRootOnlyLock(match.BoundaryPath, actors);
                default:
                    return new List<AuditItem>();
            }
        }

        private static void AddRuleFacts(NtfsPermissionInspection report, DirectorySecurity security)
        {
            AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                SecurityIdentifier sid = (SecurityIdentifier)rule.IdentityReference;
                report.Rules.Add(new NtfsAclRuleFact
                {
                    Identity = TranslateSid(sid),
                    Sid = sid.Value,
                    AccessType = rule.AccessControlType == AccessControlType.Deny ? "拒绝" : "允许",
                    Rights = RightsText(rule.FileSystemRights),
                    Source = rule.IsInherited ? "继承" : "显式",
                    Scope = ScopeText(rule.InheritanceFlags, rule.PropagationFlags)
                });
            }
        }

        private static bool AddPotentialWriteFindings(NtfsPermissionInspection report, GuardState state, DirectorySecurity security, NtfsPolicyClassification classification)
        {
            if (classification == NtfsPolicyClassification.Activated
                || classification == NtfsPolicyClassification.SensitiveNoAccess
                || classification == NtfsPolicyClassification.RootOnlyLock
                || classification == NtfsPolicyClassification.WritableRuntimeException
                || classification == NtfsPolicyClassification.SystemManaged) return false;

            List<SecurityIdentifier> relevant = new List<SecurityIdentifier>();
            AddSidIfValid(relevant, state.WorkerSid);
            AddSidIfValid(relevant, state.SandboxGroupSid);
            relevant.Add(new SecurityIdentifier(WellKnownSidType.WorldSid, null));
            relevant.Add(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null));
            relevant.Add(IdentityService.BuiltinUsersSid());

            bool found = false;
            AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow || !AclService.RightsContainWriteLike(rule.FileSystemRights)) continue;
                if (classification == NtfsPolicyClassification.DefaultReadOnly && rule.IsInherited) continue;
                SecurityIdentifier sid = (SecurityIdentifier)rule.IdentityReference;
                if (!IdentityService.ContainsSid(relevant, sid)) continue;
                found = true;
                report.Findings.Add("发现潜在写/删 Allow ACE：" + TranslateSid(sid) + " | " + RightsText(rule.FileSystemRights)
                    + " | " + (rule.IsInherited ? "继承" : "显式") + "。Guard 策略表不等于 Windows 最终有效权限，需要人工复核。");
            }
            return found && (classification == NtfsPolicyClassification.ProtectedReadOnly || classification == NtfsPolicyClassification.DefaultReadOnly);
        }

        private static void AddSubjectFacts(NtfsPermissionInspection report, GuardState state, NtfsPolicyMatch match, bool policyOk, List<AuditItem> issues)
        {
            string evidence = string.IsNullOrWhiteSpace(match.BoundaryPath) ? "无 Guard 边界；查看下方原始 DACL"
                : "边界=" + match.BoundaryPath + (policyOk ? "；Guard ACE 核验通过" : "；" + IssueSummary(issues));
            report.Subjects.Add(BuildCodexSubject("CodexWorker", state.WorkerSid, match.Classification, policyOk, evidence));
            report.Subjects.Add(BuildCodexSubject("CodexSandboxUsers", state.SandboxGroupSid, match.Classification, policyOk, evidence));

            string adminSid = IdentityService.FindProfileSid(state.AdminProfilePath);
            bool adminDenied = false;
            if (!string.IsNullOrWhiteSpace(adminSid))
            {
                foreach (NtfsAclRuleFact rule in report.Rules)
                {
                    if (string.Equals(rule.Sid, adminSid, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(rule.AccessType, "拒绝", StringComparison.OrdinalIgnoreCase))
                    {
                        adminDenied = true;
                        break;
                    }
                }
            }
            report.Subjects.Add(new NtfsPermissionSubjectFact
            {
                Status = adminDenied ? "FAIL" : "ADMIN",
                Subject = "admin（管理员）",
                Sid = adminSid ?? "未解析",
                Read = adminDenied ? "检查原始 DACL" : "Guard 不限制",
                WriteCreate = adminDenied ? "检查原始 DACL" : "Guard 不限制",
                DeleteRename = adminDenied ? "检查原始 DACL" : "Guard 不限制",
                ChangeAclOwner = adminDenied ? "检查原始 DACL" : "Guard 不限制",
                Evidence = adminDenied
                    ? "原始 DACL 直接拒绝了 admin SID；Codex Guard 不会自动修改该规则，请由 admin 人工核查"
                    : "Guard 限制集合已排除 admin SID；最终权限由 Windows 令牌、所有者和下方 DACL 决定"
            });
        }

        private static NtfsPermissionSubjectFact BuildCodexSubject(string name, string sid, NtfsPolicyClassification classification, bool policyOk, string evidence)
        {
            NtfsPermissionSubjectFact fact = new NtfsPermissionSubjectFact
            {
                Subject = name,
                Sid = string.IsNullOrWhiteSpace(sid) ? "未绑定" : sid,
                Evidence = evidence
            };
            bool managed = classification == NtfsPolicyClassification.Activated
                || classification == NtfsPolicyClassification.ProtectedReadOnly
                || classification == NtfsPolicyClassification.SensitiveNoAccess
                || classification == NtfsPolicyClassification.DefaultReadOnly
                || classification == NtfsPolicyClassification.RootOnlyLock;
            if (classification == NtfsPolicyClassification.WritableRuntimeException)
            {
                fact.Status = "ALLOW";
                fact.Read = "沿用 Windows";
                fact.WriteCreate = "允许列表保留";
                fact.DeleteRename = "缓存可清理";
                fact.ChangeAclOwner = "沿用 Windows";
                return fact;
            }
            if (!managed)
            {
                fact.Status = "WARN";
                fact.Read = "未管理";
                fact.WriteCreate = "未管理";
                fact.DeleteRename = "未管理";
                fact.ChangeAclOwner = "未管理";
                return fact;
            }
            if (!policyOk)
            {
                fact.Status = "FAIL";
                fact.Read = "规则异常";
                fact.WriteCreate = "规则异常";
                fact.DeleteRename = "规则异常";
                fact.ChangeAclOwner = "规则异常";
                return fact;
            }
            fact.Status = "PASS";
            if (classification == NtfsPolicyClassification.Activated)
            {
                fact.Read = "Guard 允许";
                fact.WriteCreate = "Guard 允许";
                fact.DeleteRename = "Guard 拒绝";
                fact.ChangeAclOwner = "Guard 拒绝";
            }
            else if (classification == NtfsPolicyClassification.ProtectedReadOnly)
            {
                fact.Read = "Guard 允许";
                fact.WriteCreate = "Guard 未授予";
                fact.DeleteRename = "Guard 拒绝";
                fact.ChangeAclOwner = "Guard 拒绝";
            }
            else if (classification == NtfsPolicyClassification.DefaultReadOnly)
            {
                fact.Read = "Guard 允许";
                fact.WriteCreate = "Guard 拒绝";
                fact.DeleteRename = "Guard 拒绝";
                fact.ChangeAclOwner = "Guard 拒绝";
            }
            else if (classification == NtfsPolicyClassification.RootOnlyLock)
            {
                fact.Read = "沿用 Windows";
                fact.WriteCreate = "仅当前根拒绝";
                fact.DeleteRename = "仅当前根拒绝";
                fact.ChangeAclOwner = "仅当前根拒绝";
            }
            else
            {
                fact.Read = "Guard 拒绝";
                fact.WriteCreate = "Guard 拒绝";
                fact.DeleteRename = "Guard 拒绝";
                fact.ChangeAclOwner = "Guard 拒绝";
            }
            return fact;
        }

        private static void SetSummary(NtfsPermissionInspection report, NtfsPolicyMatch match, bool policyOk)
        {
            string owner = "Owner=" + (report.Owner ?? "未知") + " (" + (report.OwnerSid ?? "") + ")";
            string inheritance = report.AccessInheritanceDisabled ? "DACL 继承已禁用" : "DACL 继承已启用";
            switch (match.Classification)
            {
                case NtfsPolicyClassification.Activated:
                    report.Status = policyOk ? "PASS" : "FAIL";
                    report.Summary = (policyOk ? "已激活，Guard ACE 核验通过。" : "已记录为激活，但真实 DACL 与策略不一致。")
                        + " 允许读/写/新建，拒绝删除/重命名/改 ACL。 " + owner + "；" + inheritance + "。";
                    break;
                case NtfsPolicyClassification.ProtectedReadOnly:
                    report.Status = policyOk ? "PASS" : "FAIL";
                    report.Summary = (policyOk ? "受保护且未激活，Guard ACE 核验通过。" : "已记录为保护范围，但真实 DACL 存在缺失或潜在写入 Allow。")
                        + " “Guard 未授予写入”不等于 Windows 最终有效权限；请同时核对下方 DACL。 " + owner + "；" + inheritance + "。";
                    break;
                case NtfsPolicyClassification.SensitiveNoAccess:
                    report.Status = policyOk ? "PASS" : "FAIL";
                    report.Summary = (policyOk ? "admin 敏感区的全访问拒绝 ACE 核验通过。 " : "admin 敏感区的拒绝规则异常。 ") + owner + "；" + inheritance + "。";
                    break;
                case NtfsPolicyClassification.DefaultReadOnly:
                    report.Status = policyOk ? "PASS" : "FAIL";
                    report.Summary = (policyOk ? "默认只读写入/删除拒绝 ACE 核验通过。 " : "默认只读边界与真实 DACL 不一致。 ")
                        + owner + "；" + inheritance + "。激活子目录应另有显式写入 Allow，但仍不得含 Delete。";
                    break;
                case NtfsPolicyClassification.RootOnlyLock:
                    report.Status = policyOk ? "PASS" : "FAIL";
                    report.Summary = (policyOk ? "根目录的顶层新建/写入/删除子项/改 ACL 拒绝已核验。 " : "根目录锁缺失或异常。 ")
                        + "此规则只作用于当前目录，不代表所有子目录均只读。 " + owner + "；" + inheritance + "。";
                    break;
                case NtfsPolicyClassification.WritableRuntimeException:
                    report.Status = "WARN";
                    report.Summary = "运行时允许列表：Guard 不追加默认只读拒绝，缓存和更新可依现有 Windows ACL 写入及清理。不要存放唯一原件。 "
                        + owner + "；" + inheritance + "。";
                    break;
                case NtfsPolicyClassification.WorkerProfileUnmanaged:
                    report.Status = "WARN";
                    report.Summary = "未受管理：该路径在 CodexWorker 自己的用户资料中，Guard 没有施加只读或禁删规则，通常可写可删。 " + owner + "；" + inheritance + "。";
                    break;
                case NtfsPolicyClassification.SystemManaged:
                    report.Status = "WARN";
                    report.Summary = "系统/应用管理路径：Guard 不把它当作工作目录，请勿激活。 " + owner + "；" + inheritance + "。";
                    break;
                default:
                    report.Status = "WARN";
                    report.Summary = "未受管理：Guard 未施加任何工作目录权限，是否可写/可删完全由现有 Windows DACL 决定。 " + owner + "；" + inheritance + "。";
                    break;
            }
            if (report.Findings.Count > 0)
                report.Summary += " 发现 " + report.Findings.Count + " 项需要复核的 ACL 事实。";
        }

        private static bool HasReparsePointOnPath(string full)
        {
            string current = full;
            string root = Path.GetPathRoot(full);
            while (!string.IsNullOrWhiteSpace(current) && current.Length >= root.Length)
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return true;
                if (AppPaths.PathsEqual(current, root)) break;
                current = Path.GetDirectoryName(current);
            }
            return false;
        }

        private static void AddSidIfValid(List<SecurityIdentifier> values, string sidValue)
        {
            if (string.IsNullOrWhiteSpace(sidValue)) return;
            try
            {
                SecurityIdentifier sid = new SecurityIdentifier(sidValue);
                if (!IdentityService.ContainsSid(values, sid)) values.Add(sid);
            }
            catch { }
        }

        private static string TranslateSid(SecurityIdentifier sid)
        {
            if (sid == null) return "未知";
            try { return sid.Translate(typeof(NTAccount)).Value; }
            catch { return sid.Value; }
        }

        private static string RightsText(FileSystemRights rights)
        {
            if ((rights & FileSystemRights.FullControl) == FileSystemRights.FullControl) return "完全控制 [" + rights + "]";
            List<string> values = new List<string>();
            if ((rights & FileSystemRights.ReadAndExecute) == FileSystemRights.ReadAndExecute) values.Add("读取/执行");
            if ((rights & FileSystemRights.Write) == FileSystemRights.Write) values.Add("写入/新建");
            if ((rights & FileSystemRights.DeleteSubdirectoriesAndFiles) != 0) values.Add("删除子项");
            if ((rights & FileSystemRights.Delete) != 0) values.Add("删除/重命名");
            if ((rights & FileSystemRights.ChangePermissions) != 0) values.Add("更改权限");
            if ((rights & FileSystemRights.TakeOwnership) != 0) values.Add("取得所有权");
            if (values.Count == 0) values.Add(rights.ToString());
            return string.Join("、", values.ToArray()) + " [" + rights + "]";
        }

        private static string ScopeText(InheritanceFlags inheritance, PropagationFlags propagation)
        {
            if (inheritance == InheritanceFlags.None) return "仅当前对象";
            return inheritance + (propagation == PropagationFlags.None ? string.Empty : " / " + propagation);
        }

        private static string IssueSummary(List<AuditItem> issues)
        {
            if (issues == null || issues.Count == 0) return "需核对原始 DACL";
            List<string> values = new List<string>();
            for (int index = 0; index < issues.Count && index < 3; index++) values.Add(issues[index].Code);
            if (issues.Count > values.Count) values.Add("共 " + issues.Count + " 项");
            return string.Join("、", values.ToArray());
        }
    }
}
