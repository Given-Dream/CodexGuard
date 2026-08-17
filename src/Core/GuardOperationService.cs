using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal sealed class PreparedGuardOperation
    {
        public GuardRequest Request { get; set; }
        public GuardState StateSnapshot { get; set; }
        public List<PathValidationResult> Paths { get; set; }
        public List<PathValidationResult> RootLockPaths { get; set; }
        public List<string> WritableExceptionPaths { get; set; }
        public DefaultReadOnlyReport DefaultReadOnlyReport { get; set; }
        public List<SecurityIdentifier> ActorSids { get; set; }
        public List<string> Warnings { get; set; }

        public PreparedGuardOperation()
        {
            Paths = new List<PathValidationResult>();
            RootLockPaths = new List<PathValidationResult>();
            WritableExceptionPaths = new List<string>();
            ActorSids = new List<SecurityIdentifier>();
            Warnings = new List<string>();
        }
    }

    internal sealed class GuardOperationProgress
    {
        public string Stage { get; set; }
        public string Path { get; set; }
        public string Detail { get; set; }
    }

    internal static class GuardOperationService
    {
        public static PreparedGuardOperation Prepare(GuardRequest request)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required.");
            if (!AppPaths.IsInstalledExecutable())
                throw new InvalidOperationException("Privileged operations must run from the protected Codex Guard installation directory.");
            if (request == null) throw new ArgumentNullException("request");
            if (!CodexConfigurationService.SystemRequirementsMeetPolicy())
                throw new InvalidOperationException("The system requirements.toml does not enforce the hardened elevated Windows sandbox policy. Repair it before changing project permissions.");
            List<string> running = ProcessSafety.FindRunningRiskyProcesses();
            if (running.Count > 0)
                throw new InvalidOperationException("Close Codex and all terminal/Git/WSL processes before changing filesystem permissions: " + string.Join(", ", running.ToArray()));

            GuardState state = StateStore.Load();
            if (UacPolicy.RestartStillRequired(state))
                throw new InvalidOperationException("Windows must be restarted before the newly enabled UAC boundary can be trusted.");
            if (!string.Equals(state.MachineName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The protected state belongs to another computer. Import a portable policy instead of copying state.json.");
            string adminSid = IdentityService.FindProfileSid(state.AdminProfilePath);
            if (!IsRequesterSidAllowed(request.Operation, request.RequesterSid, state.WorkerSid, adminSid))
                throw new UnauthorizedAccessException("Only the registered admin profile account may manage CodexWorker permissions.");
            if (state.ProcessedRequestIds.Contains(request.RequestId))
                throw new InvalidOperationException("This request has already been processed.");

            PreparedGuardOperation prepared = new PreparedGuardOperation
            {
                Request = request,
                StateSnapshot = state,
                ActorSids = IdentityService.ResolveActorSids(state, true)
            };
            if (string.Equals(request.RequesterSid, adminSid, StringComparison.OrdinalIgnoreCase))
                prepared.Warnings.Add("此权限请求由 admin 控制面提交；限制对象仍仅为 CodexWorker 与 CodexSandboxUsers，admin 不会写入 Guard 限制集合。");
            List<AuditItem> stateAcl = AclService.AuditProtectedFileForActors(AppPaths.StateFile, prepared.ActorSids, "STATE_FILE_WRITABLE");
            if (stateAcl.Count > 0)
                throw new InvalidOperationException("The protected state file is writable by a Codex or broad Windows identity: " + stateAcl[0].Message);
            List<AuditItem> requirementsAcl = AclService.AuditProtectedFileForActors(AppPaths.SystemRequirementsFile, prepared.ActorSids, "CODEX_REQUIREMENTS_WRITABLE");
            if (requirementsAcl.Count > 0)
                throw new InvalidOperationException("The system requirements.toml is writable by a Codex or broad Windows identity: " + requirementsAcl[0].Message);

            SecurityIdentifier sandbox;
            if (!IdentityService.TryResolveSid(IdentityService.MachineAccount(AppInfo.SandboxGroupName), out sandbox))
                prepared.Warnings.Add("CodexSandboxUsers is not available yet; this operation currently protects CodexWorker only. Run Bind/Repair after elevated sandbox setup.");

            switch (request.Operation)
            {
                case GuardOperation.Activate:
                    PrepareActivation(prepared);
                    break;
                case GuardOperation.Revoke:
                    PrepareRevocation(prepared);
                    break;
                case GuardOperation.ApplyDefaultReadOnly:
                    PrepareDefaultReadOnly(prepared);
                    break;
                case GuardOperation.Repair:
                case GuardOperation.BindSandbox:
                    PrepareRepair(prepared);
                    break;
                case GuardOperation.ImportPolicy:
                    PrepareImport(prepared);
                    break;
                default:
                    throw new InvalidOperationException("Unsupported guard operation: " + request.Operation);
            }
            return prepared;
        }

        public static OperationResult Execute(PreparedGuardOperation prepared)
        {
            return Execute(prepared, null);
        }

        public static OperationResult Execute(PreparedGuardOperation prepared, Action<GuardOperationProgress> progress)
        {
            if (prepared == null || prepared.Request == null) throw new ArgumentNullException("prepared");
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required.");

            try
            {
                Report(progress, "正在进行最终安全复核", null,
                    "重新核验 UAC、请求身份、运行中进程以及受保护状态文件；通过前不会修改 ACL。");
                OperationResult result = StateStore.WithExclusive(state => ExecuteLocked(prepared, state, progress), false);
                Report(progress, "正在写入审计日志", AppPaths.LogsDirectory,
                    "权限与受保护状态已经提交，正在记录最终结果。");
                GuardLog.Write(prepared.Request.RequestId, prepared.Request.Operation.ToString(), result.Success, result.Summary);
                Report(progress, "权限事务已完成", null, "所有计划内步骤均已完成并通过验证。");
                return result;
            }
            catch (Exception ex)
            {
                GuardLog.Write(prepared.Request.RequestId, prepared.Request.Operation.ToString(), false, ex.Message);
                Report(progress, "操作未完成", null, ex.Message);
                throw;
            }
        }

        private static OperationResult ExecuteLocked(PreparedGuardOperation prepared, GuardState state,
            Action<GuardOperationProgress> progress)
        {
            if (!UacPolicy.Read().MeetsRequirements || !CodexConfigurationService.SystemRequirementsMeetPolicy())
                throw new InvalidOperationException("The UAC or Codex managed sandbox policy changed after confirmation. No ACL changes were applied.");
            List<string> running = ProcessSafety.FindRunningRiskyProcesses();
            if (running.Count > 0)
                throw new InvalidOperationException("A Codex, terminal, Git, or WSL process started after confirmation. No ACL changes were applied: " + string.Join(", ", running.ToArray()));
            string adminSid = IdentityService.FindProfileSid(state.AdminProfilePath);
            if (!string.Equals(state.MachineName, Environment.MachineName, StringComparison.OrdinalIgnoreCase)
                || !IsRequesterSidAllowed(prepared.Request.Operation, prepared.Request.RequesterSid, state.WorkerSid, adminSid))
                throw new InvalidOperationException("Protected identity state changed after confirmation. No ACL changes were applied.");
            state.UacRestartRequired = false;
            state.UacPolicyAppliedBootTimeUtc = null;
            if (state.ProcessedRequestIds.Contains(prepared.Request.RequestId))
                throw new InvalidOperationException("This request has already been processed.");
            if (!string.Equals(state.UpdatedAtUtc, prepared.StateSnapshot.UpdatedAtUtc, StringComparison.Ordinal))
                throw new InvalidOperationException("Codex Guard state changed while the confirmation window was open. Review and submit the operation again.");

            List<SecurityIdentifier> actors = IdentityService.ResolveActorSids(state, true);
            List<AuditItem> stateAcl = AclService.AuditProtectedFileForActors(AppPaths.StateFile, actors, "STATE_FILE_WRITABLE");
            if (stateAcl.Count > 0)
                throw new InvalidOperationException("The protected state file ACL changed after confirmation. No ACL changes were applied: " + stateAcl[0].Message);
            List<AuditItem> requirementsAcl = AclService.AuditProtectedFileForActors(AppPaths.SystemRequirementsFile, actors, "CODEX_REQUIREMENTS_WRITABLE");
            if (requirementsAcl.Count > 0)
                throw new InvalidOperationException("The system requirements.toml ACL changed after confirmation. No ACL changes were applied: " + requirementsAcl[0].Message);
            List<AclSnapshot> rollback = new List<AclSnapshot>();
            OperationResult result = new OperationResult();
            try
            {
                switch (prepared.Request.Operation)
                {
                    case GuardOperation.Activate:
                        ExecuteActivation(prepared, state, actors, rollback, result);
                        break;
                    case GuardOperation.Revoke:
                        ExecuteRevocation(prepared, state, actors, rollback, result);
                        break;
                    case GuardOperation.ApplyDefaultReadOnly:
                        ExecuteDefaultReadOnly(prepared, state, actors, rollback, result, progress);
                        break;
                    case GuardOperation.Repair:
                    case GuardOperation.BindSandbox:
                        ExecuteRepair(state, actors, rollback, result);
                        break;
                    case GuardOperation.ImportPolicy:
                        ExecuteImport(prepared, state, actors, rollback, result);
                        break;
                    default:
                        throw new InvalidOperationException("Unsupported guard operation.");
                }

                Report(progress, "正在提交受保护状态", AppPaths.StateFile,
                    "ACL 已应用并验证；状态文件只在全部步骤成功后提交。");
                state.ProcessedRequestIds.Add(prepared.Request.RequestId);
                while (state.ProcessedRequestIds.Count > 1000) state.ProcessedRequestIds.RemoveAt(0);
                StateStore.Save(state);
                result.Success = true;
                if (string.IsNullOrEmpty(result.Summary)) result.Summary = prepared.Request.Operation + " completed.";
                return result;
            }
            catch (Exception original)
            {
                Report(progress, "操作出错，正在自动回滚", null,
                    "请保持窗口开启；Codex Guard 正在按相反顺序恢复已经修改的 ACL。");
                List<Exception> rollbackFailures = RollBack(rollback, progress);
                if (rollbackFailures.Count > 0)
                {
                    rollbackFailures.Insert(0, original);
                    throw new AggregateException("The operation failed and at least one ACL rollback also failed. Stop Codex and run a manual security audit before continuing.", rollbackFailures);
                }
                Report(progress, "自动回滚已完成", null, "已恢复本次事务捕获的 ACL 快照。");
                throw;
            }
        }

        private static void PrepareActivation(PreparedGuardOperation prepared)
        {
            RequirePaths(prepared.Request);
            if (!prepared.StateSnapshot.DefaultReadOnlyEnabled)
                throw new InvalidOperationException("Apply the default read-only baseline before activating project directories.");
            List<string> combined = new List<string>();
            foreach (GuardedDirectory active in prepared.StateSnapshot.ActivatedDirectories)
                combined.Add(active.CanonicalPath);

            foreach (string input in prepared.Request.Paths)
            {
                PathValidationResult validation = PathSafety.ValidateExistingDirectory(input, true, prepared.ActorSids);
                GuardedDirectory existing = FindByPath(prepared.StateSnapshot.ActivatedDirectories, validation.Identity.CanonicalPath);
                if (existing != null)
                {
                    EnsureIdentity(existing, validation.Identity);
                    prepared.Warnings.Add("Already activated; permissions will be verified and repaired: " + validation.Identity.CanonicalPath);
                }
                else
                {
                    combined.Add(validation.Identity.CanonicalPath);
                }
                if (!AdminProfileBoundaryService.IsStrictDescendant(validation.Identity.CanonicalPath, prepared.StateSnapshot)
                    && !StrictlyInsideAny(validation.Identity.CanonicalPath, prepared.StateSnapshot.DefaultReadOnlyDirectories))
                    throw new InvalidDataException("The project must be a strict descendant of the fixed administrator-profile boundary or an applied default read-only boundary: " + validation.Identity.CanonicalPath);
                prepared.Paths.Add(validation);
            }
            PathSafety.RejectOverlaps(combined);
        }

        private static void PrepareRevocation(PreparedGuardOperation prepared)
        {
            RequirePaths(prepared.Request);
            foreach (string input in prepared.Request.Paths)
            {
                string normalized = PathSafety.NormalizeLexical(input);
                GuardedDirectory existing = FindByPath(prepared.StateSnapshot.ActivatedDirectories, normalized);
                if (existing == null) throw new InvalidOperationException("Directory is not activated: " + normalized);
                PathIdentity identity = NativePath.GetDirectoryIdentity(existing.CanonicalPath);
                EnsureIdentity(existing, identity);
                prepared.Paths.Add(new PathValidationResult { InputPath = input, FullPath = normalized, Identity = identity });
            }
        }

        private static void PrepareRepair(PreparedGuardOperation prepared)
        {
            SecurityIdentifier sandbox;
            if (!IdentityService.TryResolveSid(IdentityService.MachineAccount(AppInfo.SandboxGroupName), out sandbox))
                throw new InvalidOperationException("CodexSandboxUsers does not exist. Complete the official elevated Windows sandbox setup first.");
            if (!IdentityService.ContainsSid(prepared.ActorSids, sandbox)) prepared.ActorSids.Add(sandbox);
            GuardedDirectory adminBoundary = AdminProfileBoundaryService.Find(prepared.StateSnapshot);
            if (adminBoundary != null)
            {
                string adminPath = AdminProfileBoundaryService.ItemPath(adminBoundary);
                prepared.Paths.Add(new PathValidationResult { FullPath = adminPath, Identity = NativePath.GetDirectoryIdentity(adminPath) });
            }
            foreach (GuardedDirectory legacy in AdminProfileBoundaryService.LegacyEntries(prepared.StateSnapshot))
                prepared.Warnings.Add("Legacy manual protection-root state is ignored and will not be repaired: " + (AdminProfileBoundaryService.ItemPath(legacy) ?? "(invalid path)"));
            foreach (GuardedDirectory active in prepared.StateSnapshot.ActivatedDirectories)
                prepared.Paths.Add(new PathValidationResult { FullPath = active.CanonicalPath, Identity = NativePath.GetDirectoryIdentity(active.CanonicalPath) });
            foreach (GuardedDirectory boundary in prepared.StateSnapshot.DefaultReadOnlyDirectories)
                prepared.Paths.Add(new PathValidationResult { FullPath = boundary.CanonicalPath, Identity = NativePath.GetDirectoryIdentity(boundary.CanonicalPath) });
            foreach (GuardedDirectory rootLock in prepared.StateSnapshot.DefaultReadOnlyRootLocks)
                prepared.RootLockPaths.Add(new PathValidationResult { FullPath = rootLock.CanonicalPath, Identity = NativePath.GetDirectoryIdentity(rootLock.CanonicalPath) });
        }

        private static void PrepareDefaultReadOnly(PreparedGuardOperation prepared)
        {
            if (prepared.Request.Paths != null && prepared.Request.Paths.Count > 0)
                throw new InvalidDataException("The default read-only request cannot supply paths; the elevated process derives the plan from this computer.");

            DefaultReadOnlyReport report = DefaultReadOnlyPolicyService.Capture(prepared.StateSnapshot);
            prepared.DefaultReadOnlyReport = report;
            if (!report.CanApply)
                throw new InvalidOperationException(report.Summary);
            foreach (DefaultReadOnlyItem item in report.Items)
            {
                if (item.Kind == DefaultReadOnlyItemKind.Boundary)
                    prepared.Paths.Add(PathSafety.ValidateDefaultReadOnlyDirectory(item.Path, AppPaths.PathsEqual(item.Path, Path.GetPathRoot(item.Path))));
                else if (item.Kind == DefaultReadOnlyItemKind.RootOnlyLock)
                    prepared.RootLockPaths.Add(PathSafety.ValidateDefaultReadOnlyDirectory(item.Path, true));
                else if (item.Kind == DefaultReadOnlyItemKind.WritableException && Directory.Exists(item.Path))
                    prepared.WritableExceptionPaths.Add(AppPaths.NormalizeDirectoryPath(item.Path));
            }
            foreach (string warning in report.Warnings) prepared.Warnings.Add(warning);
            prepared.Warnings.Add("默认只读会拒绝 CodexWorker/CodexSandboxUsers 在非允许目录写入、创建、删除、重命名或改 ACL；admin 和 SYSTEM 不受影响。");
            prepared.Warnings.Add("AppData、.codex 和已存在的 .cache 保留 Windows 原有写入/删除权限；系统级软件更新应继续通过 admin、SYSTEM 或安装服务完成。");
            prepared.Warnings.Add("应用前确认所有真实工作目录已存在于一个默认只读边界之下，并在应用后逐个激活；未激活目录会立即变为只读。");
        }

        private static void PrepareImport(PreparedGuardOperation prepared)
        {
            if (prepared.Request.Paths == null || prepared.Request.Paths.Count == 0)
                throw new InvalidOperationException("The imported policy contains no activated project directories.");
            if (!prepared.StateSnapshot.DefaultReadOnlyEnabled)
                throw new InvalidOperationException("Apply the default read-only baseline before importing activated project directories.");

            List<string> activeUnion = new List<string>();
            foreach (GuardedDirectory active in prepared.StateSnapshot.ActivatedDirectories) activeUnion.Add(active.CanonicalPath);
            if (prepared.Request.Paths != null)
            {
                foreach (string input in prepared.Request.Paths)
                {
                    PathValidationResult validation = PathSafety.ValidateExistingDirectory(input, true, prepared.ActorSids);
                    if (FindByPath(prepared.StateSnapshot.ActivatedDirectories, validation.Identity.CanonicalPath) == null)
                        activeUnion.Add(validation.Identity.CanonicalPath);
                    if (!AdminProfileBoundaryService.IsStrictDescendant(validation.Identity.CanonicalPath, prepared.StateSnapshot)
                        && !StrictlyInsideAny(validation.Identity.CanonicalPath, prepared.StateSnapshot.DefaultReadOnlyDirectories))
                        throw new InvalidDataException("Imported project is not a strict descendant of the administrator-profile boundary or an applied default read-only boundary: " + validation.Identity.CanonicalPath);
                    prepared.Paths.Add(validation);
                }
            }
            PathSafety.RejectOverlaps(activeUnion);
            prepared.Warnings.Add("Import is additive: existing activated directories remain activated.");
            prepared.Warnings.Add("Portable policies contain activated project paths only; administrator-profile protection and default read-only boundaries are always derived locally.");
        }

        private static void ExecuteActivation(PreparedGuardOperation prepared, GuardState state, List<SecurityIdentifier> actors, List<AclSnapshot> rollback, OperationResult result)
        {
            foreach (PathValidationResult path in prepared.Paths)
            {
                RevalidateActiveTree(path, actors);
                rollback.Add(Capture(path.Identity.CanonicalPath));
                GuardedDirectory existing = FindByPath(state.ActivatedDirectories, path.Identity.CanonicalPath);
                AclService.ApplyActivated(path.Identity.CanonicalPath, actors);
                RevalidateActiveTree(path, actors);
                Revalidate(path);
                if (existing == null)
                {
                    GuardedDirectory added = InstallerService.CreateGuardedDirectory(path.Identity.CanonicalPath, false);
                    added.OriginalSddl = rollback[rollback.Count - 1].Sddl;
                    state.ActivatedDirectories.Add(added);
                    result.Messages.Add("Activated permanently: " + added.CanonicalPath);
                }
                else
                {
                    existing.LastVerifiedAtUtc = AppInfo.UtcNow();
                    result.Messages.Add("Repaired active permissions: " + existing.CanonicalPath);
                }
            }
            result.Summary = "Activated " + prepared.Paths.Count + " director" + (prepared.Paths.Count == 1 ? "y." : "ies.");
        }

        private static void ExecuteRevocation(PreparedGuardOperation prepared, GuardState state, List<SecurityIdentifier> actors, List<AclSnapshot> rollback, OperationResult result)
        {
            foreach (PathValidationResult path in prepared.Paths)
            {
                Revalidate(path);
                rollback.Add(Capture(path.Identity.CanonicalPath));
                AclService.ApplyReadOnly(path.Identity.CanonicalPath, actors);
                RemoveByPath(state.ActivatedDirectories, path.Identity.CanonicalPath);
                result.Messages.Add("Revoked write access and kept delete denial: " + path.Identity.CanonicalPath);
            }
            result.Summary = "Revoked " + prepared.Paths.Count + " activated director" + (prepared.Paths.Count == 1 ? "y." : "ies.");
        }

        private static void ExecuteRepair(GuardState state, List<SecurityIdentifier> actors, List<AclSnapshot> rollback, OperationResult result)
        {
            SecurityIdentifier sandbox = IdentityService.ResolveSid(IdentityService.MachineAccount(AppInfo.SandboxGroupName));
            state.SandboxGroupSid = sandbox.Value;
            if (!IdentityService.ContainsSid(actors, sandbox)) actors.Add(sandbox);

            foreach (GuardedDirectory boundary in state.DefaultReadOnlyDirectories)
            {
                rollback.Add(Capture(boundary.CanonicalPath));
                AclService.ApplyDefaultReadOnlyBoundary(boundary.CanonicalPath, actors);
                boundary.LastVerifiedAtUtc = AppInfo.UtcNow();
            }
            foreach (GuardedDirectory rootLock in state.DefaultReadOnlyRootLocks)
            {
                rollback.Add(Capture(rootLock.CanonicalPath));
                AclService.ApplyRootOnlyLock(rootLock.CanonicalPath, actors);
                rootLock.LastVerifiedAtUtc = AppInfo.UtcNow();
            }

            GuardedDirectory adminBoundary = AdminProfileBoundaryService.Find(state);
            if (adminBoundary != null)
            {
                string adminPath = AdminProfileBoundaryService.ItemPath(adminBoundary);
                rollback.Add(Capture(adminPath));
                AclService.ApplyReadOnly(adminPath, actors);
                adminBoundary.LastVerifiedAtUtc = AppInfo.UtcNow();
                string[] sensitive = { "AppData", ".ssh", ".gnupg", ".aws", ".azure", ".codex" };
                foreach (string name in sensitive)
                {
                    string sensitivePath = Path.Combine(adminPath, name);
                    if (!Directory.Exists(sensitivePath)) continue;
                    rollback.Add(Capture(sensitivePath));
                    AclService.ApplyNoAccess(sensitivePath, actors);
                    result.Messages.Add("Repaired administrator sensitive-area no-access rule: " + sensitivePath);
                }
            }
            foreach (GuardedDirectory active in state.ActivatedDirectories)
            {
                rollback.Add(Capture(active.CanonicalPath));
                AclService.ApplyActivated(active.CanonicalPath, actors);
                PathValidationResult validation = new PathValidationResult { FullPath = active.CanonicalPath, Identity = NativePath.GetDirectoryIdentity(active.CanonicalPath) };
                RevalidateActiveTree(validation, actors);
                active.LastVerifiedAtUtc = AppInfo.UtcNow();
            }
            AclService.SecureDeleteRequestDirectory(AppPaths.DeleteRequestsDirectory, actors);
            result.Messages.Add("Bound sandbox group: " + sandbox.Value);
            result.Summary = "Repaired all persistent Codex Guard ACLs.";
        }

        private static void ExecuteDefaultReadOnly(PreparedGuardOperation prepared, GuardState state, List<SecurityIdentifier> actors,
            List<AclSnapshot> rollback, OperationResult result, Action<GuardOperationProgress> progress)
        {
            int snapshotIndex = 0;
            int snapshotCount = prepared.Paths.Count + prepared.RootLockPaths.Count + state.ActivatedDirectories.Count;
            foreach (PathValidationResult path in prepared.Paths)
            {
                snapshotIndex++;
                Report(progress, "正在建立 ACL 回滚快照", path.Identity.CanonicalPath,
                    "快照 " + snapshotIndex + "/" + snapshotCount + "；此阶段不会修改权限。");
                AddSnapshotIfMissing(rollback, path.Identity.CanonicalPath);
            }
            foreach (PathValidationResult path in prepared.RootLockPaths)
            {
                snapshotIndex++;
                Report(progress, "正在建立 ACL 回滚快照", path.Identity.CanonicalPath,
                    "快照 " + snapshotIndex + "/" + snapshotCount + "；此阶段不会修改权限。");
                AddSnapshotIfMissing(rollback, path.Identity.CanonicalPath);
            }
            foreach (GuardedDirectory active in state.ActivatedDirectories)
            {
                snapshotIndex++;
                Report(progress, "正在建立 ACL 回滚快照", active.CanonicalPath,
                    "快照 " + snapshotIndex + "/" + snapshotCount + "；此阶段不会修改权限。");
                AddSnapshotIfMissing(rollback, active.CanonicalPath);
            }

            for (int i = 0; i < prepared.Paths.Count; i++)
            {
                PathValidationResult path = prepared.Paths[i];
                Revalidate(path);
                Report(progress, "正在应用默认只读边界", path.Identity.CanonicalPath,
                    "边界 " + (i + 1) + "/" + prepared.Paths.Count
                    + "；Windows 正在向现有子项传播继承 ACL，文件较多时可能耗时较长。");
                AclService.ApplyDefaultReadOnlyBoundary(path.Identity.CanonicalPath, actors);
                Report(progress, "正在验证默认只读边界", path.Identity.CanonicalPath,
                    "检查 Worker/Sandbox 的读取、写入、删除、重命名和改 ACL 权限。");
                List<AuditItem> issues = AclService.AuditDefaultReadOnlyBoundary(path.Identity.CanonicalPath, actors);
                if (issues.Count > 0) throw new InvalidOperationException("Default read-only ACL verification failed: " + issues[0].Message);
                UpsertDefaultBoundary(state.DefaultReadOnlyDirectories, path.Identity.CanonicalPath, FindSnapshotSddl(rollback, path.Identity.CanonicalPath));
                result.Messages.Add("Default read-only boundary: " + path.Identity.CanonicalPath);
            }
            for (int i = 0; i < prepared.RootLockPaths.Count; i++)
            {
                PathValidationResult path = prepared.RootLockPaths[i];
                Revalidate(path);
                Report(progress, "正在应用根目录锁", path.Identity.CanonicalPath,
                    "根锁 " + (i + 1) + "/" + prepared.RootLockPaths.Count + "；规则只作用于当前根目录，不向子目录继承。");
                AclService.ApplyRootOnlyLock(path.Identity.CanonicalPath, actors);
                Report(progress, "正在验证根目录锁", path.Identity.CanonicalPath,
                    "确认 Worker/Sandbox 无法在该根目录直接新建、写入、删除子项或修改 ACL。");
                List<AuditItem> issues = AclService.AuditRootOnlyLock(path.Identity.CanonicalPath, actors);
                if (issues.Count > 0) throw new InvalidOperationException("Root-only lock verification failed: " + issues[0].Message);
                UpsertDefaultBoundary(state.DefaultReadOnlyRootLocks, path.Identity.CanonicalPath, FindSnapshotSddl(rollback, path.Identity.CanonicalPath));
                result.Messages.Add("Root-only create/write lock: " + path.Identity.CanonicalPath);
            }

            for (int i = 0; i < state.ActivatedDirectories.Count; i++)
            {
                GuardedDirectory active = state.ActivatedDirectories[i];
                Report(progress, "正在恢复已激活项目的写入例外", active.CanonicalPath,
                    "激活目录 " + (i + 1) + "/" + state.ActivatedDirectories.Count
                    + "；允许修改和新建，仍拒绝删除、重命名与改 ACL。");
                AclService.ApplyActivated(active.CanonicalPath, actors);
                PathValidationResult validation = new PathValidationResult { FullPath = active.CanonicalPath, Identity = NativePath.GetDirectoryIdentity(active.CanonicalPath) };
                Report(progress, "正在核验已激活项目树", active.CanonicalPath,
                    "扫描重解析点、硬链接和可能绕过边界的子项；大型项目可能需要一些时间。");
                RevalidateActiveTree(validation, actors);
                active.LastVerifiedAtUtc = AppInfo.UtcNow();
                result.Messages.Add("Reapplied active write/no-delete exception: " + active.CanonicalPath);
            }

            state.WritableExceptionPaths.Clear();
            foreach (string path in prepared.WritableExceptionPaths)
                if (!ContainsPath(state.WritableExceptionPaths, path)) state.WritableExceptionPaths.Add(path);
            state.DefaultReadOnlyEnabled = true;
            state.DefaultReadOnlyAppliedAtUtc = AppInfo.UtcNow();
            result.Summary = "Applied the CodexWorker default read-only baseline to " + prepared.Paths.Count
                + " inherited boundary/boundaries and " + prepared.RootLockPaths.Count + " root-only lock(s).";
        }

        private static void ExecuteImport(PreparedGuardOperation prepared, GuardState state, List<SecurityIdentifier> actors, List<AclSnapshot> rollback, OperationResult result)
        {
            PreparedGuardOperation activePart = new PreparedGuardOperation { Request = prepared.Request, StateSnapshot = state, ActorSids = actors };
            activePart.Paths.AddRange(prepared.Paths);
            if (activePart.Paths.Count > 0) ExecuteActivation(activePart, state, actors, rollback, result);
            result.Summary = "Imported policy: " + prepared.Paths.Count + " activated project directory/directories.";
        }

        private static void Revalidate(PathValidationResult path)
        {
            PathIdentity current = NativePath.GetDirectoryIdentity(path.Identity.CanonicalPath);
            if (!path.Identity.SameObject(current))
                throw new InvalidDataException("Filesystem object changed during the privileged operation: " + path.Identity.CanonicalPath);
        }

        private static void RevalidateActiveTree(PathValidationResult path, IEnumerable<SecurityIdentifier> actorSids)
        {
            PathValidationResult current = PathSafety.ValidateExistingDirectory(path.Identity.CanonicalPath, true, actorSids);
            if (!path.Identity.SameObject(current.Identity))
                throw new InvalidDataException("Filesystem object changed during the privileged operation: " + path.Identity.CanonicalPath);
        }

        private static bool StrictlyInsideAny(string path, IEnumerable<GuardedDirectory> roots)
        {
            foreach (GuardedDirectory root in roots)
            {
                if (!AppPaths.PathsEqual(path, root.CanonicalPath) && AppPaths.IsPathInside(path, root.CanonicalPath)) return true;
            }
            return false;
        }

        private static GuardedDirectory FindByPath(List<GuardedDirectory> values, string path)
        {
            foreach (GuardedDirectory value in values)
                if (AppPaths.PathsEqual(value.CanonicalPath, path)) return value;
            return null;
        }

        private static void UpsertDefaultBoundary(List<GuardedDirectory> values, string path, string originalSddl)
        {
            GuardedDirectory existing = FindByPath(values, path);
            if (existing == null)
            {
                GuardedDirectory added = InstallerService.CreateGuardedDirectory(path, false);
                added.OriginalSddl = originalSddl;
                values.Add(added);
            }
            else existing.LastVerifiedAtUtc = AppInfo.UtcNow();
        }

        private static bool ContainsPath(IEnumerable<string> values, string path)
        {
            foreach (string value in values)
                if (AppPaths.PathsEqual(value, path)) return true;
            return false;
        }

        private static void RemoveByPath(List<GuardedDirectory> values, string path)
        {
            for (int i = values.Count - 1; i >= 0; i--)
                if (AppPaths.PathsEqual(values[i].CanonicalPath, path)) values.RemoveAt(i);
        }

        private static void EnsureIdentity(GuardedDirectory recorded, PathIdentity current)
        {
            if (recorded.VolumeSerialNumber != current.VolumeSerialNumber || recorded.FileIndexHigh != current.FileIndexHigh || recorded.FileIndexLow != current.FileIndexLow)
                throw new InvalidDataException("Recorded path now points to a different filesystem object: " + recorded.CanonicalPath);
        }

        private static void RequirePaths(GuardRequest request)
        {
            if (request.Paths == null || request.Paths.Count == 0) throw new InvalidOperationException("Select at least one directory.");
        }

        internal static bool IsRequesterSidAllowed(GuardOperation operation, string requesterSid, string workerSid, string adminSid)
        {
            if (string.IsNullOrWhiteSpace(requesterSid) || string.IsNullOrWhiteSpace(adminSid)) return false;
            if (!string.IsNullOrWhiteSpace(workerSid)
                && string.Equals(requesterSid, workerSid, StringComparison.OrdinalIgnoreCase)) return false;
            return string.Equals(requesterSid, adminSid, StringComparison.OrdinalIgnoreCase);
        }

        private static AclSnapshot Capture(string path)
        {
            return new AclSnapshot { Path = path, Sddl = AclService.CaptureSddl(path) };
        }

        private static void AddSnapshotIfMissing(List<AclSnapshot> snapshots, string path)
        {
            foreach (AclSnapshot snapshot in snapshots)
                if (AppPaths.PathsEqual(snapshot.Path, path)) return;
            snapshots.Add(Capture(path));
        }

        private static string FindSnapshotSddl(List<AclSnapshot> snapshots, string path)
        {
            foreach (AclSnapshot snapshot in snapshots)
                if (AppPaths.PathsEqual(snapshot.Path, path)) return snapshot.Sddl;
            throw new InvalidOperationException("Missing ACL rollback snapshot for " + path);
        }

        private static List<Exception> RollBack(List<AclSnapshot> snapshots, Action<GuardOperationProgress> progress)
        {
            List<Exception> failures = new List<Exception>();
            for (int i = snapshots.Count - 1; i >= 0; i--)
            {
                Report(progress, "正在回滚 ACL", snapshots[i].Path,
                    "回滚 " + (snapshots.Count - i) + "/" + snapshots.Count + "；请勿结束进程。");
                try { AclService.RestoreSddl(snapshots[i].Path, snapshots[i].Sddl); }
                catch (Exception ex) { failures.Add(new InvalidOperationException("ACL rollback failed for " + snapshots[i].Path, ex)); }
            }
            return failures;
        }

        private static void Report(Action<GuardOperationProgress> progress, string stage, string path, string detail)
        {
            if (progress == null) return;
            try
            {
                progress(new GuardOperationProgress { Stage = stage, Path = path, Detail = detail });
            }
            catch
            {
                // Progress reporting is informational and must never change ACL transaction semantics.
            }
        }

        private sealed class AclSnapshot
        {
            public string Path { get; set; }
            public string Sddl { get; set; }
        }
    }
}
