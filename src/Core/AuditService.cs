using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal static class AuditService
    {
        public static List<AuditItem> Run()
        {
            List<AuditItem> items = new List<AuditItem>();
            items.AddRange(UacPolicy.Audit());

            if (!File.Exists(AppPaths.InstalledExecutable))
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "APP_NOT_INSTALLED", Path = AppPaths.InstalledExecutable, Message = "Codex Guard is not installed in the protected Program Files location." });
            else
            {
                try { AclService.AssertProtectedFile(AppPaths.InstalledExecutable); }
                catch (Exception ex) { items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "APP_FILE_UNTRUSTED", Path = AppPaths.InstalledExecutable, Message = ex.Message }); }
            }

            AuditCompanion(items, AppPaths.InstalledReviewerExecutable, "REVIEWER_NOT_INSTALLED", "REVIEWER_FILE_UNTRUSTED");
            AuditCompanion(items, AppPaths.InstalledAcceptanceExecutable, "PROBE_NOT_INSTALLED", "PROBE_FILE_UNTRUSTED");

            if (!File.Exists(AppPaths.SystemRequirementsFile))
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "CODEX_REQUIREMENTS_MISSING", Path = AppPaths.SystemRequirementsFile, Message = "The system requirements file does not enforce the elevated Windows sandbox." });
            else
            {
                try
                {
                    if (!CodexConfigurationService.SystemRequirementsMeetPolicy())
                        items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "CODEX_REQUIREMENTS_INCOMPLETE", Path = AppPaths.SystemRequirementsFile, Message = "Requirements must disable login shells, allow only elevated sandbox users, and enforce the private desktop." });
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "CODEX_REQUIREMENTS_READ_FAILED", Path = AppPaths.SystemRequirementsFile, Message = ex.Message });
                }
            }

            if (!StateStore.Exists)
            {
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "STATE_MISSING", Path = AppPaths.StateFile, Message = "The protected state file does not exist." });
                return items;
            }

            GuardState state;
            try
            {
                state = StateStore.Load();
            }
            catch (Exception ex)
            {
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "STATE_INVALID", Path = AppPaths.StateFile, Message = ex.Message });
                return items;
            }

            if (!string.Equals(state.MachineName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "STATE_MACHINE_MISMATCH", Message = "The state belongs to another computer and must not be reused directly." });
            if (UacPolicy.RestartStillRequired(state))
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "UAC_RESTART_REQUIRED", Message = "Windows must be restarted before privileged Codex Guard operations are safe." });

            List<SecurityIdentifier> actors;
            try
            {
                actors = IdentityService.ResolveActorSids(state, true);
            }
            catch (Exception ex)
            {
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "WORKER_MISSING", Message = ex.Message });
                return items;
            }

            SecurityIdentifier sandbox;
            if (!IdentityService.TryResolveSid(IdentityService.MachineAccount(AppInfo.SandboxGroupName), out sandbox))
                items.Add(new AuditItem { Severity = AuditSeverity.Warning, Code = "SANDBOX_GROUP_PENDING", Message = "CodexSandboxUsers does not exist yet. Run Codex elevated sandbox setup, then bind/repair Codex Guard." });
            else if (!string.IsNullOrWhiteSpace(state.SandboxGroupSid)
                && !string.Equals(state.SandboxGroupSid, sandbox.Value, StringComparison.OrdinalIgnoreCase))
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "SANDBOX_SID_CHANGED", Message = "CodexSandboxUsers was recreated. Run Bind/Repair before trusting existing ACLs." });

            if (File.Exists(AppPaths.InstalledExecutable))
                items.AddRange(AclService.AuditProtectedFileForActors(AppPaths.InstalledExecutable, actors, "APP_FILE_WRITABLE"));
            if (File.Exists(AppPaths.InstalledReviewerExecutable))
                items.AddRange(AclService.AuditProtectedFileForActors(AppPaths.InstalledReviewerExecutable, actors, "REVIEWER_FILE_WRITABLE"));
            if (File.Exists(AppPaths.InstalledAcceptanceExecutable))
                items.AddRange(AclService.AuditProtectedFileForActors(AppPaths.InstalledAcceptanceExecutable, actors, "PROBE_FILE_WRITABLE"));
            if (File.Exists(AppPaths.StateFile))
                items.AddRange(AclService.AuditProtectedFileForActors(AppPaths.StateFile, actors, "STATE_FILE_WRITABLE"));
            if (File.Exists(AppPaths.SystemRequirementsFile))
                items.AddRange(AclService.AuditProtectedFileForActors(AppPaths.SystemRequirementsFile, actors, "CODEX_REQUIREMENTS_WRITABLE"));

            foreach (GuardedDirectory directory in state.ActivatedDirectories)
            {
                if (!Directory.Exists(directory.CanonicalPath))
                {
                    items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ACTIVE_PATH_MISSING", Path = directory.CanonicalPath, Message = "An activated directory no longer exists at its recorded path." });
                    continue;
                }
                try
                {
                    PathIdentity current = NativePath.GetDirectoryIdentity(directory.CanonicalPath);
                    if (current.VolumeSerialNumber != directory.VolumeSerialNumber || current.FileIndexHigh != directory.FileIndexHigh || current.FileIndexLow != directory.FileIndexLow)
                        items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "PATH_IDENTITY_CHANGED", Path = directory.CanonicalPath, Message = "The path now points to a different filesystem object." });
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "PATH_IDENTITY_FAILED", Path = directory.CanonicalPath, Message = ex.Message });
                }
                items.AddRange(AclService.AuditActivated(directory.CanonicalPath, actors));
            }

            bool adminPathMatches = false;
            try
            {
                adminPathMatches = !string.IsNullOrWhiteSpace(state.AdminProfilePath)
                    && AppPaths.PathsEqual(state.AdminProfilePath, AppInfo.AdminProfilePath);
            }
            catch { adminPathMatches = false; }
            if (!adminPathMatches)
            {
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ADMIN_PROFILE_PATH_INVALID", Path = state.AdminProfilePath, Message = "Administrator-profile protection must be fixed to " + AppInfo.AdminProfilePath + "." });
            }
            GuardedDirectory adminBoundary = AdminProfileBoundaryService.Find(state);
            if (adminBoundary == null)
            {
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ADMIN_PROFILE_BOUNDARY_MISSING", Path = AppInfo.AdminProfilePath, Message = "The fixed administrator-profile protection boundary is not recorded." });
            }
            else
            {
                string adminPath = AdminProfileBoundaryService.ItemPath(adminBoundary);
                if (Directory.Exists(adminPath))
                {
                    try
                    {
                        PathIdentity current = NativePath.GetDirectoryIdentity(adminPath);
                        if (current.VolumeSerialNumber != adminBoundary.VolumeSerialNumber || current.FileIndexHigh != adminBoundary.FileIndexHigh || current.FileIndexLow != adminBoundary.FileIndexLow)
                            items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ADMIN_PROFILE_IDENTITY_CHANGED", Path = adminPath, Message = "The fixed administrator-profile path now points to another filesystem object." });
                    }
                    catch (Exception ex)
                    {
                        items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ADMIN_PROFILE_IDENTITY_FAILED", Path = adminPath, Message = ex.Message });
                    }
                    items.AddRange(AclService.AuditReadOnly(adminPath, actors));
                }
                else items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ADMIN_PROFILE_PATH_MISSING", Path = adminPath, Message = "The fixed administrator-profile directory no longer exists." });
            }
            foreach (GuardedDirectory legacy in AdminProfileBoundaryService.LegacyEntries(state))
            {
                items.Add(new AuditItem
                {
                    Severity = AuditSeverity.Error,
                    Code = "LEGACY_PROTECTION_ROOT",
                    Path = AdminProfileBoundaryService.ItemPath(legacy),
                    Message = "A legacy manual protection-root entry remains in protected state. It is ignored by activation and repair; review its ACL manually before removing the state entry."
                });
            }

            if (!state.DefaultReadOnlyEnabled)
            {
                items.Add(new AuditItem
                {
                    Severity = AuditSeverity.Error,
                    Code = "DEFAULT_READONLY_NOT_ENABLED",
                    Message = "The required default read-only baseline is not enabled. CodexWorker may still follow ordinary Windows write permissions outside registered roots. Preview and explicitly apply the baseline before using real data."
                });
            }
            else
            {
                if (state.DefaultReadOnlyDirectories.Count == 0 || state.DefaultReadOnlyRootLocks.Count == 0)
                    items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_STATE_INCOMPLETE", Message = "The default read-only baseline is enabled but its recorded boundaries are incomplete." });
                foreach (GuardedDirectory directory in state.DefaultReadOnlyDirectories)
                {
                    if (!Directory.Exists(directory.CanonicalPath))
                    {
                        items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_PATH_MISSING", Path = directory.CanonicalPath, Message = "A recorded default read-only boundary is missing." });
                        continue;
                    }
                    try
                    {
                        PathIdentity current = NativePath.GetDirectoryIdentity(directory.CanonicalPath);
                        if (current.VolumeSerialNumber != directory.VolumeSerialNumber || current.FileIndexHigh != directory.FileIndexHigh || current.FileIndexLow != directory.FileIndexLow)
                            items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_IDENTITY_CHANGED", Path = directory.CanonicalPath, Message = "The default read-only path now points to another filesystem object." });
                    }
                    catch (Exception ex)
                    {
                        items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_IDENTITY_FAILED", Path = directory.CanonicalPath, Message = ex.Message });
                    }
                    items.AddRange(AclService.AuditDefaultReadOnlyBoundary(directory.CanonicalPath, actors));
                }
                foreach (GuardedDirectory directory in state.DefaultReadOnlyRootLocks)
                {
                    if (!Directory.Exists(directory.CanonicalPath))
                    {
                        items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ROOT_LOCK_PATH_MISSING", Path = directory.CanonicalPath, Message = "A recorded root-only lock is missing." });
                        continue;
                    }
                    items.AddRange(AclService.AuditRootOnlyLock(directory.CanonicalPath, actors));
                }

                try
                {
                    DefaultReadOnlyReport baseline = DefaultReadOnlyPolicyService.Capture(state);
                    List<string> expectedExceptions = new List<string>();
                    foreach (DefaultReadOnlyItem target in baseline.Items)
                    {
                        if (string.Equals(target.Status, "BLOCK", StringComparison.OrdinalIgnoreCase))
                            items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_PLAN_BLOCKED", Path = target.Path, Message = target.Reason });
                        else if ((target.Kind == DefaultReadOnlyItemKind.Boundary || target.Kind == DefaultReadOnlyItemKind.RootOnlyLock)
                            && !string.Equals(target.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                            items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_NEW_TARGET", Path = target.Path, Message = "A new or unrecorded location is outside the applied default read-only baseline." });
                        if (target.Kind == DefaultReadOnlyItemKind.WritableException
                            && string.Equals(target.Status, "ALLOW", StringComparison.OrdinalIgnoreCase)
                            && !string.IsNullOrWhiteSpace(target.Path))
                            expectedExceptions.Add(target.Path);
                    }
                    foreach (string recorded in state.WritableExceptionPaths)
                        if (!ContainsPath(expectedExceptions, recorded))
                            items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_EXCEPTION_INVALID", Path = recorded, Message = "The recorded writable exception is not one of the fixed Worker runtime paths." });
                    foreach (string expected in expectedExceptions)
                        if (!ContainsPath(state.WritableExceptionPaths, expected))
                            items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_EXCEPTION_MISSING", Path = expected, Message = "A required Worker runtime writable exception is missing from protected state." });
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_PLAN_FAILED", Message = ex.Message });
                }
            }

            if (!string.IsNullOrWhiteSpace(state.AdminProfilePath))
            {
                bool currentIsGuardActor = false;
                try { currentIsGuardActor = IdentityService.CurrentIdentityIsGuardActor(state); }
                catch { currentIsGuardActor = false; }
                if (currentIsGuardActor)
                {
                    items.Add(new AuditItem
                    {
                        Severity = AuditSeverity.Warning,
                        Code = "ADMIN_SENSITIVE_ACL_ADMIN_REVIEW",
                        Path = state.AdminProfilePath,
                        Message = "The current guarded identity is intentionally denied access to administrator-sensitive subdirectories. Recheck their raw DACL from the independent administrator verifier."
                    });
                }
                else
                {
                    string[] sensitive = { "AppData", ".ssh", ".gnupg", ".aws", ".azure", ".codex" };
                    foreach (string name in sensitive)
                    {
                        string path = Path.Combine(state.AdminProfilePath, name);
                        if (Directory.Exists(path)) items.AddRange(AclService.AuditNoAccess(path, actors));
                    }
                }
            }

            AppendLocalRecordChecks(items, state);

            if (AclService.ActiveAllowContainsDelete())
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "INTERNAL_RIGHTS_ERROR", Message = "The active write rule unexpectedly contains delete rights." });

            if (items.Count == 0)
                items.Add(new AuditItem { Severity = AuditSeverity.Info, Code = "OK", Message = "No Codex Guard policy violations were detected." });
            return items;
        }

        private static void AppendLocalRecordChecks(List<AuditItem> items, GuardState state)
        {
            try
            {
                RecordSyncReport report = CodexRecordSyncService.Capture(state.AdminProfilePath, state.WorkerProfilePath);
                int pass = 0;
                int index = 0;
                foreach (ReviewEvidence check in report.Checks)
                {
                    index++;
                    if (string.Equals(check.Status, "PASS", StringComparison.OrdinalIgnoreCase))
                    {
                        pass++;
                        continue;
                    }
                    string message = (check.Control ?? "Local record-path check") + "：" + (check.Actual ?? string.Empty);
                    if (!string.IsNullOrWhiteSpace(check.ManualAction)) message += "；下一步：" + check.ManualAction;
                    items.Add(new AuditItem
                    {
                        Severity = string.Equals(check.Status, "FAIL", StringComparison.OrdinalIgnoreCase) ? AuditSeverity.Error : AuditSeverity.Warning,
                        Code = "LOCAL_RECORD_" + index,
                        Path = check.Path,
                        Message = message
                    });
                }
                if (pass > 0)
                    items.Add(new AuditItem { Severity = AuditSeverity.Info, Code = "LOCAL_RECORDS_OK", Message = "Worker/admin local record-path isolation passed " + pass + " metadata-only check(s); tokens and conversation bodies were not read." });
            }
            catch (Exception ex)
            {
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "LOCAL_RECORD_AUDIT_FAILED", Message = "Local record-path isolation inspection failed: " + ex.Message });
            }
        }

        private static void AuditCompanion(List<AuditItem> items, string path, string missingCode, string untrustedCode)
        {
            if (!File.Exists(path))
            {
                items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = missingCode, Path = path, Message = "A required human-verification companion is not installed." });
                return;
            }
            try { AclService.AssertProtectedFile(path); }
            catch (Exception ex) { items.Add(new AuditItem { Severity = AuditSeverity.Error, Code = untrustedCode, Path = path, Message = ex.Message }); }
        }

        private static bool ContainsPath(IEnumerable<string> values, string path)
        {
            if (values == null || string.IsNullOrWhiteSpace(path)) return false;
            foreach (string value in values)
            {
                if (string.IsNullOrWhiteSpace(value)) continue;
                try { if (AppPaths.PathsEqual(value, path)) return true; }
                catch { }
            }
            return false;
        }
    }
}
