using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal sealed class InstallOptions
    {
        public string WorkerPassword { get; set; }
        public bool RemoveExistingWorkerFromPrivilegedGroups { get; set; }
        public bool ApplyRecommendedUacPolicy { get; set; }
        public bool ConfigureCodexRequirements { get; set; }
        public string AdminProfilePath { get; set; }
    }

    internal static class InstallerService
    {
        public static OperationResult Install(InstallOptions options)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required.");
            if (options == null) throw new ArgumentNullException("options");
            List<string> runningProcesses = ProcessSafety.FindRunningRiskyProcesses();
            if (runningProcesses.Count > 0)
                throw new InvalidOperationException("Close Codex and all terminal/Git/WSL processes before installing or repairing filesystem protection: " + string.Join(", ", runningProcesses.ToArray()));
            OperationResult result = new OperationResult();
            AclService.SecureApplicationDirectory(AppPaths.DataDirectory, true);
            if (StateStore.Exists && !File.Exists(AppPaths.InstalledExecutable))
                throw new InvalidOperationException("An orphaned Codex Guard state file exists without the protected installed executable. Preserve it for forensic review, then remove it manually before a clean installation.");
            GuardState state = StateStore.LoadOrDefault();
            if (!string.Equals(state.MachineName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The existing protected state belongs to another computer. Preserve a portable policy and remove the foreign state before installation; do not reuse state.json across machines.");

            bool restartRequired = false;
            if (options.ApplyRecommendedUacPolicy)
            {
                restartRequired = UacPolicy.ApplyRecommended();
                result.Messages.Add("Applied the secure-desktop UAC policy for standard-user elevation.");
            }

            SecurityIdentifier existingWorker;
            bool workerAlreadyExists = LocalAccountService.AccountExists(AppInfo.WorkerAccountName, out existingWorker);
            bool created;
            SecurityIdentifier workerSid;
            try
            {
                workerSid = LocalAccountService.EnsureStandardWorker(
                    workerAlreadyExists ? null : options.WorkerPassword,
                    options.RemoveExistingWorkerFromPrivilegedGroups,
                    out created);
            }
            finally
            {
                options.WorkerPassword = null;
            }
            result.Messages.Add(created ? "Created the standard CodexWorker account." : "Reused the existing CodexWorker account.");

            string workerProfile = null;
            try
            {
                workerProfile = LocalAccountService.EnsureProfile(workerSid);
                result.Messages.Add("CodexWorker profile: " + workerProfile);
            }
            catch (Exception ex)
            {
                result.Messages.Add("Worker profile creation requires first sign-in or repair: " + ex.Message);
            }

            InstallProgramFiles(result);
            AclService.SecureApplicationDirectory(AppPaths.HistoryDirectory, false);
            AclService.SecureApplicationDirectory(AppPaths.LogsDirectory, true);

            state.WorkerAccountName = AppInfo.WorkerAccountName;
            state.WorkerSid = workerSid.Value;
            state.WorkerProfilePath = string.IsNullOrWhiteSpace(workerProfile) ? null : AppPaths.NormalizeDirectoryPath(workerProfile);
            if (!string.IsNullOrWhiteSpace(options.AdminProfilePath)
                && !AppPaths.PathsEqual(options.AdminProfilePath, AppInfo.AdminProfilePath))
                throw new InvalidDataException("Administrator-profile protection is fixed to " + AppInfo.AdminProfilePath + ".");
            state.AdminProfilePath = NormalizeAdminProfile(AppInfo.AdminProfilePath, workerProfile);
            if (restartRequired)
            {
                state.UacRestartRequired = true;
                state.UacPolicyAppliedBootTimeUtc = UacPolicy.CurrentBootTimeUtc();
            }
            else if (!UacPolicy.RestartStillRequired(state))
            {
                state.UacRestartRequired = false;
                state.UacPolicyAppliedBootTimeUtc = null;
            }

            SecurityIdentifier sandboxSid;
            if (IdentityService.TryResolveSid(IdentityService.MachineAccount(AppInfo.SandboxGroupName), out sandboxSid))
            {
                state.SandboxGroupSid = sandboxSid.Value;
                result.Messages.Add("Bound the existing CodexSandboxUsers group.");
            }
            else
            {
                state.SandboxGroupSid = null;
                result.Messages.Add("CodexSandboxUsers is not present yet; run elevated sandbox setup and then Repair/Bind.");
            }

            List<SecurityIdentifier> actors = IdentityService.ResolveActorSids(state, true);
            AclService.SecureDeleteRequestDirectory(AppPaths.DeleteRequestsDirectory, actors);

            if (options.ConfigureCodexRequirements)
            {
                string requirementsMessage;
                state.CodexRequirementsConfigured = CodexConfigurationService.EnsureSystemRequirements(out requirementsMessage);
                result.Messages.Add(requirementsMessage);
            }

            if (!string.IsNullOrEmpty(workerProfile))
            {
                string config = CodexConfigurationService.EnsureWorkerConfig(workerProfile, workerSid);
                result.Messages.Add("Configured the CodexWorker elevated sandbox preference: " + config);
            }

            List<InstallAclSnapshot> profileRollback = new List<InstallAclSnapshot>();
            try
            {
                if (!string.IsNullOrEmpty(state.AdminProfilePath))
                {
                    GuardedDirectory protectedProfile = CreateGuardedDirectory(state.AdminProfilePath, true);
                    profileRollback.Add(new InstallAclSnapshot { Path = protectedProfile.CanonicalPath, Sddl = protectedProfile.OriginalSddl });
                    List<string> sensitivePaths = new List<string>();
                    string[] sensitive = { "AppData", ".ssh", ".gnupg", ".aws", ".azure", ".codex" };
                    foreach (string name in sensitive)
                    {
                        string path = Path.Combine(protectedProfile.CanonicalPath, name);
                        if (Directory.Exists(path))
                        {
                            sensitivePaths.Add(path);
                            profileRollback.Add(new InstallAclSnapshot { Path = path, Sddl = AclService.CaptureSddl(path) });
                        }
                    }

                    AclService.ApplyReadOnly(protectedProfile.CanonicalPath, actors);
                    UpsertByPath(state.ProtectedRoots, protectedProfile);
                    result.Messages.Add("Applied the Codex Guard read-only/delete-deny baseline to: " + protectedProfile.CanonicalPath);
                    foreach (string path in sensitivePaths)
                    {
                        AclService.ApplyNoAccess(path, actors);
                        result.Messages.Add("Denied Codex identities access to sensitive area: " + path);
                    }
                }

                state.UacSecureDesktopVerified = UacPolicy.Read().MeetsRequirements;
                StateStore.Save(state);
            }
            catch (Exception original)
            {
                List<Exception> rollbackFailures = RestoreInstallAcls(profileRollback);
                if (rollbackFailures.Count > 0)
                {
                    rollbackFailures.Insert(0, original);
                    throw new AggregateException("Installation failed and administrator-profile ACL rollback was incomplete. Keep Codex closed and perform a manual audit.", rollbackFailures);
                }
                throw;
            }

            try { result.Messages.Add("Created Start menu shortcut: " + ShortcutService.CreateStartMenuShortcut()); }
            catch (Exception ex) { result.Messages.Add("Start menu shortcut warning: " + ex.Message); }
            try { result.Messages.Add("Created common desktop shortcut: " + ShortcutService.CreateCommonDesktopShortcut()); }
            catch (Exception ex) { result.Messages.Add("Desktop shortcut warning: " + ex.Message); }
            try
            {
                string obsolete = ShortcutService.FindObsoleteWorkerCodexCommonDesktopShortcut();
                result.Messages.Add(string.IsNullOrWhiteSpace(obsolete)
                    ? "The obsolete admin-desktop Worker launcher shortcut was not present."
                    : "The obsolete Worker launcher is disabled but remains on disk. Ask admin to move or delete it manually: " + obsolete);
            }
            catch (Exception ex) { result.Messages.Add("Obsolete Worker launcher inspection warning: " + ex.Message); }
            if (restartRequired) result.Messages.Add("Windows must be restarted before the UAC policy is fully effective.");
            result.Success = true;
            result.Summary = created ? "Codex Guard installed and CodexWorker created." : "Codex Guard installed/repaired.";
            return result;
        }

        private static List<Exception> RestoreInstallAcls(List<InstallAclSnapshot> snapshots)
        {
            List<Exception> failures = new List<Exception>();
            for (int index = snapshots.Count - 1; index >= 0; index--)
            {
                try { AclService.RestoreSddl(snapshots[index].Path, snapshots[index].Sddl); }
                catch (Exception ex) { failures.Add(new InvalidOperationException("ACL rollback failed for " + snapshots[index].Path, ex)); }
            }
            return failures;
        }

        private sealed class InstallAclSnapshot
        {
            public string Path { get; set; }
            public string Sddl { get; set; }
        }

        private static void InstallProgramFiles(OperationResult result)
        {
            AclService.SecureApplicationDirectory(AppPaths.InstallDirectory, true);
            InstallProtectedBinary(AppPaths.CurrentExecutable, AppPaths.InstalledExecutable, result, true);

            string sourceDirectory = Path.GetDirectoryName(AppPaths.CurrentExecutable);
            InstallProtectedBinary(
                Path.Combine(sourceDirectory, AppInfo.ReviewerExecutableName),
                AppPaths.InstalledReviewerExecutable,
                result,
                false);
            InstallProtectedBinary(
                Path.Combine(sourceDirectory, AppInfo.AcceptanceExecutableName),
                AppPaths.InstalledAcceptanceExecutable,
                result,
                false);
        }

        private static void InstallProtectedBinary(string source, string target, OperationResult result, bool required)
        {
            if (!File.Exists(source) && !File.Exists(target))
            {
                if (required) throw new FileNotFoundException("A required Codex Guard binary is missing.", source);
                result.Messages.Add("Verification companion was not found beside the installer and was not installed: " + source);
                return;
            }
            if (!AppPaths.PathsEqual(source, target))
            {
                if (!File.Exists(source))
                {
                    AclService.SecureApplicationFile(target, true);
                    result.Messages.Add("Kept the existing protected verification companion because no replacement was supplied: " + target);
                    return;
                }
                if ((File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("An installer binary cannot be a reparse point: " + source);
                if (File.Exists(target))
                {
                    Directory.CreateDirectory(AppPaths.HistoryDirectory);
                    string backup = Path.Combine(AppPaths.HistoryDirectory, Path.GetFileName(target) + "." + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + ".bak");
                    File.Copy(target, backup, false);
                }
                string temporary = Path.Combine(AppPaths.InstallDirectory, Path.GetFileName(target) + ".new-" + Guid.NewGuid().ToString("N"));
                using (FileStream input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (FileStream output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    input.CopyTo(output);
                    output.Flush(true);
                }
                if (File.Exists(target)) File.Replace(temporary, target, null, true);
                else File.Move(temporary, target);
            }
            AclService.SecureApplicationFile(target, true);
            result.Messages.Add("Installed protected binary: " + target);
        }

        private static string NormalizeAdminProfile(string path, string workerProfile)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            PathValidationResult validated = PathSafety.ValidateAdminProfileBoundary(path, workerProfile);
            string full = validated.Identity.CanonicalPath;
            string root = Path.GetPathRoot(full);
            if (AppPaths.PathsEqual(root, full))
                throw new InvalidDataException("A drive root cannot be used as an administrator profile.");
            return full;
        }

        internal static GuardedDirectory CreateGuardedDirectory(string path, bool captureAcl)
        {
            PathIdentity identity = NativePath.GetDirectoryIdentity(path);
            return new GuardedDirectory
            {
                Path = path,
                CanonicalPath = identity.CanonicalPath,
                VolumeSerialNumber = identity.VolumeSerialNumber,
                FileIndexHigh = identity.FileIndexHigh,
                FileIndexLow = identity.FileIndexLow,
                OriginalSddl = captureAcl ? AclService.CaptureSddl(path) : null,
                ActivatedAtUtc = AppInfo.UtcNow(),
                LastVerifiedAtUtc = AppInfo.UtcNow()
            };
        }

        internal static void UpsertByPath(List<GuardedDirectory> items, GuardedDirectory value)
        {
            for (int i = 0; i < items.Count; i++)
            {
                if (AppPaths.PathsEqual(items[i].CanonicalPath, value.CanonicalPath))
                {
                    if (items[i].VolumeSerialNumber != 0
                        && (items[i].VolumeSerialNumber != value.VolumeSerialNumber
                            || items[i].FileIndexHigh != value.FileIndexHigh
                            || items[i].FileIndexLow != value.FileIndexLow))
                        throw new InvalidDataException("A protected path now points to a different filesystem object: " + value.CanonicalPath);
                    if (!string.IsNullOrWhiteSpace(items[i].OriginalSddl)) value.OriginalSddl = items[i].OriginalSddl;
                    if (!string.IsNullOrWhiteSpace(items[i].ActivatedAtUtc)) value.ActivatedAtUtc = items[i].ActivatedAtUtc;
                    items[i] = value;
                    return;
                }
            }
            items.Add(value);
        }
    }
}
