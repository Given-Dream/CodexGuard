using CodexGuard.Core;
using CodexGuard.AcceptanceProbe;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

internal static class TestRunner
{
    private static int _passed;
    private static int _failed;

    private static int Main()
    {
        Run("reject drive root activation", delegate { ExpectFailure(delegate { PathSafety.NormalizeLexical("D:\\"); }); });
        Run("reject relative path", delegate { ExpectFailure(delegate { PathSafety.NormalizeLexical("project"); }); });
        Run("reject drive-relative path", delegate { ExpectFailure(delegate { PathSafety.NormalizeLexical("D:project"); }); });
        Run("reject UNC path", delegate { ExpectFailure(delegate { PathSafety.NormalizeLexical("\\\\server\\share\\project"); }); });
        Run("reject Windows directory", delegate { ExpectFailure(delegate { PathSafety.NormalizeLexical(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\Temp"); }); });
        Run("reject complete user profile", delegate { ExpectFailure(delegate { PathSafety.NormalizeLexical("C:\\Users\\admin"); }); });
        Run("reject credential subtree", delegate { ExpectFailure(delegate { PathSafety.NormalizeLexical("C:\\Users\\admin\\.ssh\\project"); }); });
        Run("allow normal project syntax", delegate
        {
            string value = PathSafety.NormalizeLexical("D:\\CodexGuardTests\\ProjectA");
            Assert(value.EndsWith("CodexGuardTests\\ProjectA", StringComparison.OrdinalIgnoreCase), "Unexpected normalized path: " + value);
        });
        Run("detect nested selections", delegate
        {
            ExpectFailure(delegate { PathSafety.RejectOverlaps(new[] { "D:\\Projects", "D:\\Projects\\Child" }); });
        });
        Run("allow distinct boundary candidates", delegate
        {
            PathSafety.RejectOverlaps(new[] { "D:\\", "E:\\" }, true);
        });
        Run("reject nested boundary candidates", delegate
        {
            ExpectFailure(delegate { PathSafety.RejectOverlaps(new[] { "D:\\", "D:\\Projects" }, true); });
        });
        Run("path boundary comparison", delegate
        {
            Assert(AppPaths.IsPathInside("D:\\Projects\\A", "D:\\Projects"), "A real child was not recognized.");
            Assert(!AppPaths.IsPathInside("D:\\Projects2", "D:\\Projects"), "A sibling prefix was treated as a child.");
        });
        Run("NTFS inspector classifies managed and unmanaged paths", delegate
        {
            GuardState state = GuardState.CreateDefault();
            state.AdminProfilePath = "C:\\Users\\admin";
            state.WorkerProfilePath = "C:\\Users\\CodexWorker";
            state.ProtectedRoots.Add(new GuardedDirectory { CanonicalPath = "C:\\Users\\admin" });
            state.ActivatedDirectories.Add(new GuardedDirectory { CanonicalPath = "D:\\Projects\\Active" });
            state.DefaultReadOnlyDirectories.Add(new GuardedDirectory { CanonicalPath = "E:\\" });
            state.DefaultReadOnlyRootLocks.Add(new GuardedDirectory { CanonicalPath = "C:\\" });
            state.WritableExceptionPaths.Add("C:\\Users\\CodexWorker\\AppData");

            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "D:\\Projects\\Active\\Child").Classification == NtfsPolicyClassification.Activated,
                "An activated descendant was not classified as active.");
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "C:\\Users\\admin\\Desktop\\Dormant").Classification == NtfsPolicyClassification.ProtectedReadOnly,
                "The fixed administrator-profile descendant was not classified as read-only.");
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "C:\\Users\\admin\\.ssh\\keys").Classification == NtfsPolicyClassification.SensitiveNoAccess,
                "An admin credential subtree was not classified as no-access.");
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "C:\\Users\\CodexWorker\\Desktop\\Loose").Classification == NtfsPolicyClassification.WorkerProfileUnmanaged,
                "An unmanaged Worker-profile path was not identified.");
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "E:\\Loose").Classification == NtfsPolicyClassification.DefaultReadOnly,
                "A default read-only data drive was not classified correctly.");
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "C:\\Users\\CodexWorker\\AppData\\Local\\Temp").Classification == NtfsPolicyClassification.WritableRuntimeException,
                "A runtime cache exception was not classified correctly.");
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "C:\\").Classification == NtfsPolicyClassification.RootOnlyLock,
                "The system root-only lock was not classified correctly.");
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "F:\\Loose").Classification == NtfsPolicyClassification.Unmanaged,
                "An outside path was not classified as unmanaged.");
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "D:\\Projects2").Classification == NtfsPolicyClassification.Unmanaged,
                "A sibling prefix escaped the classification boundary.");
            state.ProtectedRoots.Add(new GuardedDirectory { CanonicalPath = "D:\\LegacyManualRoot" });
            Assert(NtfsPermissionInspectionService.ClassifyPath(state, "D:\\LegacyManualRoot\\Child").Classification == NtfsPolicyClassification.Unmanaged,
                "A legacy manual protection root still affected the current policy classifier.");
            state.AdminProfilePath = "D:\\LegacyManualRoot";
            Assert(AdminProfileBoundaryService.Find(state) == null,
                "A tampered administrator-profile path was accepted as the fixed boundary.");
        });
        Run("NTFS inspector source is read-only", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string source = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "NtfsPermissionInspectionService.cs"));
            string[] forbidden = { "SetAccessControl(", "File.Delete(", "Directory.Delete(", "File.Move(", "Directory.Move(", "Directory.CreateDirectory(", "Process.Start(", ".SetValue(" };
            foreach (string token in forbidden) Assert(source.IndexOf(token, StringComparison.Ordinal) < 0, "NTFS inspector contains a mutation API: " + token);
        });
        Run("default read-only allowlist is narrow and path-boundary safe", delegate
        {
            string profile = "C:\\Users\\CodexWorker";
            Assert(DefaultReadOnlyPolicyService.IsWritableExceptionPath(profile, profile + "\\AppData\\Local\\Temp"), "AppData cache was not allowlisted.");
            Assert(DefaultReadOnlyPolicyService.IsWritableExceptionPath(profile, profile + "\\.codex\\sessions"), ".codex was not allowlisted.");
            Assert(DefaultReadOnlyPolicyService.IsWritableExceptionPath(profile, profile + "\\.cache\\tool"), ".cache was not allowlisted.");
            Assert(!DefaultReadOnlyPolicyService.IsWritableExceptionPath(profile, profile + "\\Desktop"), "Desktop was incorrectly allowlisted.");
            Assert(!DefaultReadOnlyPolicyService.IsWritableExceptionPath(profile, "C:\\Users\\CodexWorker2\\AppData"), "A sibling profile escaped the allowlist boundary.");
            Assert(DefaultReadOnlyPolicyService.IsSystemManagedTopLevelName("Windows"), "Windows was not recognized as system-managed.");
            Assert(!DefaultReadOnlyPolicyService.IsSystemManagedTopLevelName("ResearchData"), "A custom system-drive directory was skipped as system-managed.");
            Assert(DefaultReadOnlyPolicyService.IsLegacyProfileAliasName("\u300c\u5f00\u59cb\u300d\u83dc\u5355"), "The localized Windows Start Menu compatibility junction was not recognized.");
            Assert(!DefaultReadOnlyPolicyService.IsLegacyProfileAliasName("\u5f00\u59cb\u83dc\u5355\u9879\u76ee"), "An unrelated localized directory was accepted as a compatibility junction.");
        });
        Run("administrator SID is excluded from restriction actors", delegate
        {
            SecurityIdentifier worker = new SecurityIdentifier("S-1-5-21-111-222-333-1001");
            SecurityIdentifier admin = new SecurityIdentifier("S-1-5-21-111-222-333-1002");
            IdentityService.AssertAdministratorNotRestricted(new[] { worker }, admin.Value);
            ExpectFailure(delegate { IdentityService.AssertAdministratorNotRestricted(new[] { worker, admin }, admin.Value); });
            IdentityService.AssertAdministratorNotInSandboxGroup(new[] { "Users", "Administrators" });
            ExpectFailure(delegate { IdentityService.AssertAdministratorNotInSandboxGroup(new[] { "Users", AppInfo.SandboxGroupName }); });
        });
        Run("only admin may manage Worker permissions", delegate
        {
            const string worker = "S-1-5-21-111-222-333-1001";
            const string admin = "S-1-5-21-111-222-333-1002";
            const string stranger = "S-1-5-21-111-222-333-1003";
            GuardOperation[] operations =
            {
                GuardOperation.Activate,
                GuardOperation.Revoke,
                GuardOperation.ApplyDefaultReadOnly,
                GuardOperation.Repair,
                GuardOperation.BindSandbox,
                GuardOperation.ImportPolicy
            };
            foreach (GuardOperation operation in operations)
            {
                Assert(GuardOperationService.IsRequesterSidAllowed(operation, admin, worker, admin), "Admin request was rejected: " + operation);
                Assert(!GuardOperationService.IsRequesterSidAllowed(operation, worker, worker, admin), "Worker was allowed to manage permissions: " + operation);
                Assert(!GuardOperationService.IsRequesterSidAllowed(operation, stranger, worker, admin), "An unrelated SID was allowed to manage permissions: " + operation);
            }
            Assert(!GuardOperationService.IsRequesterSidAllowed(GuardOperation.Activate, admin, worker, null), "Admin was allowed without a registered admin SID.");
            Assert(!GuardOperationService.IsRequesterSidAllowed(GuardOperation.Activate, admin, admin, admin), "A Worker/admin SID collision was not rejected.");
        });
        Run("installed privileged helper version must match current UI", delegate
        {
            Assert(ElevationService.VersionMatches(AppInfo.Version + ".0", AppInfo.Version), "The matching installed helper version was rejected.");
            Assert(!ElevationService.VersionMatches("0.6.2.0", AppInfo.Version), "An older installed helper version was accepted.");
            Assert(!ElevationService.VersionMatches(AppInfo.Version + ".1", AppInfo.Version), "A different installed helper revision was accepted.");
            Assert(!ElevationService.VersionMatches("not-a-version", AppInfo.Version), "A malformed installed helper version was accepted.");
        });
        Run("privileged ACL transaction has a non-cancellable progress window", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string program = File.ReadAllText(Path.Combine(projectRoot, "src", "App", "Program.cs"));
            string form = File.ReadAllText(Path.Combine(projectRoot, "src", "App", "OperationProgressForm.cs"));
            string operation = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "GuardOperationService.cs"));
            Assert(program.IndexOf("new OperationProgressForm(prepared)", StringComparison.Ordinal) >= 0,
                "The elevated request still executes the ACL transaction directly on the UI thread.");
            Assert(form.IndexOf("ProgressBarStyle.Marquee", StringComparison.Ordinal) >= 0,
                "The progress window no longer uses an indeterminate progress bar.");
            Assert(form.IndexOf("ControlBox = false", StringComparison.Ordinal) >= 0
                && form.IndexOf("e.CloseReason == CloseReason.UserClosing", StringComparison.Ordinal) >= 0,
                "The progress window no longer blocks ordinary user closure while the ACL transaction is running.");
            Assert(operation.IndexOf("正在应用默认只读边界", StringComparison.Ordinal) >= 0
                && operation.IndexOf("Windows 正在向现有子项传播继承 ACL", StringComparison.Ordinal) >= 0,
                "The default read-only transaction no longer reports its current NTFS boundary.");
        });
        Run("direct-use release launcher is complete and non-destructive", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string launcher = File.ReadAllText(Path.Combine(projectRoot, "tools", "ReleaseLauncher.cs"));
            string package = File.ReadAllText(Path.Combine(projectRoot, "Package.ps1"));
            Assert(launcher.IndexOf("CodexGuard.Payload", StringComparison.Ordinal) >= 0
                && launcher.IndexOf("CodexGuard.ReadOnlyVerifier.exe", StringComparison.Ordinal) >= 0
                && launcher.IndexOf("CodexGuard.AcceptanceProbe.exe", StringComparison.Ordinal) >= 0,
                "The direct-use launcher no longer embeds and requires the complete package.");
            Assert(launcher.IndexOf("FileMode.CreateNew", StringComparison.Ordinal) >= 0
                && launcher.IndexOf("File.Delete(", StringComparison.Ordinal) < 0
                && launcher.IndexOf("Directory.Delete(", StringComparison.Ordinal) < 0
                && launcher.IndexOf("File.Move(", StringComparison.Ordinal) < 0
                && launcher.IndexOf("Directory.Move(", StringComparison.Ordinal) < 0,
                "The direct-use launcher can overwrite, move, or delete extracted files.");
            Assert(launcher.IndexOf("Path.IsPathRooted", StringComparison.Ordinal) >= 0
                && launcher.IndexOf("FileAttributes.ReparsePoint", StringComparison.Ordinal) >= 0
                && launcher.IndexOf("HashesEqual", StringComparison.Ordinal) >= 0,
                "The direct-use launcher no longer rejects unsafe paths or verifies extracted bytes.");
            Assert(package.IndexOf("--self-test", StringComparison.Ordinal) >= 0
                && package.IndexOf("CodexGuard-0.6.7-preview-portable.zip", StringComparison.Ordinal) < 0,
                "The release build no longer performs the launcher self-test or has become version-name hardcoded.");
        });
        Run("default read-only planner source is read-only", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string source = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "DefaultReadOnlyPolicyService.cs"));
            string[] forbidden = { "SetAccessControl(", "File.Delete(", "Directory.Delete(", "File.Move(", "Directory.Move(", "Directory.CreateDirectory(", "Process.Start(", ".SetValue(" };
            foreach (string token in forbidden) Assert(source.IndexOf(token, StringComparison.Ordinal) < 0, "Default read-only planner contains a mutation API: " + token);
        });
        Run("default read-only request cannot inject target paths", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string source = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "GuardOperationService.cs"));
            Assert(source.IndexOf("The default read-only request cannot supply paths", StringComparison.Ordinal) >= 0,
                "The elevated operation no longer rejects caller-supplied default-read-only paths.");
            Assert(source.IndexOf("DefaultReadOnlyPolicyService.Capture(prepared.StateSnapshot)", StringComparison.Ordinal) >= 0,
                "The elevated operation no longer rebuilds the default-read-only plan from protected state and machine facts.");
        });
        Run("missing default read-only baseline fails the security audit", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string source = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "AuditService.cs"));
            int code = source.IndexOf("DEFAULT_READONLY_NOT_ENABLED", StringComparison.Ordinal);
            Assert(code >= 0, "The audit no longer reports a missing default-read-only baseline.");
            int severity = source.LastIndexOf("Severity = AuditSeverity.Error", code, StringComparison.Ordinal);
            Assert(severity >= 0 && code - severity < 500, "A missing default-read-only baseline is not a failing audit item.");
        });
        Run("deletion request stays inside activated project", delegate
        {
            List<GuardedDirectory> active = new List<GuardedDirectory>
            {
                new GuardedDirectory { CanonicalPath = "D:\\Projects\\Active" }
            };
            Assert(DeletionRequestService.IsInsideActivatedPaths("D:\\Projects\\Active\\temp.bin", active), "Activated descendant was rejected.");
            Assert(!DeletionRequestService.IsInsideActivatedPaths("D:\\Projects\\Active2\\temp.bin", active), "Sibling prefix escaped the activated boundary.");
        });
        Run("active rights exclude delete", delegate
        {
            Assert(!AclService.ActiveAllowContainsDelete(), "Active allow rights include delete.");
        });
        Run("guard deny includes ACL takeover prevention", delegate
        {
            Assert((AclService.GuardDenyRights & System.Security.AccessControl.FileSystemRights.Delete) != 0, "Delete deny is missing.");
            Assert((AclService.GuardDenyRights & System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles) != 0, "Parent delete-child deny is missing.");
            Assert((AclService.GuardDenyRights & System.Security.AccessControl.FileSystemRights.ChangePermissions) != 0, "Change-permissions deny is missing.");
            Assert((AclService.GuardDenyRights & System.Security.AccessControl.FileSystemRights.TakeOwnership) != 0, "Take-ownership deny is missing.");
        });
        Run("read-only rights are not misclassified as writable", delegate
        {
            Assert(!AclService.RightsContainWriteLike(AclService.ReadOnlyAllowRights), "Read-only rights were classified as writable.");
            Assert(AclService.RightsContainWriteLike(System.Security.AccessControl.FileSystemRights.FullControl), "Full control was not classified as writable.");
            Assert(AclService.RightsContainWriteLike(AclService.ActiveAllowRights), "Active write rights were not classified as writable.");
        });
        Run("guard ACL rules roundtrip in memory", delegate
        {
            Assert(AclService.GuardRulesRoundTripInMemory(), "Windows normalized the intended guard rules unexpectedly.");
        });
        Run("default read-only ACL rules are actor-specific and roundtrip", delegate
        {
            Assert((AclService.DefaultReadOnlyDenyRights & FileSystemRights.Write) == FileSystemRights.Write, "Default read-only denial does not cover write/create rights.");
            Assert((AclService.DefaultReadOnlyDenyRights & FileSystemRights.Delete) != 0, "Default read-only denial does not cover delete.");
            Assert((AclService.DefaultReadOnlyDenyRights & FileSystemRights.ChangePermissions) != 0, "Default read-only denial does not cover ACL changes.");
            Assert((AclService.ActiveAllowRights & FileSystemRights.Write) == FileSystemRights.Write, "Active exception cannot grant write.");
            Assert((AclService.ActiveAllowRights & FileSystemRights.Delete) == 0, "Active exception unexpectedly grants delete.");
            Assert(AclService.DefaultReadOnlyRulesRoundTripInMemory(), "Windows normalized the default read-only rules unexpectedly.");
        });
        Run("owner rights rule suppresses implicit WRITE_DAC without denying administrators", delegate
        {
            Assert((AclService.OwnerRightsAllowRights & System.Security.AccessControl.FileSystemRights.ReadPermissions) != 0, "OWNER RIGHTS cannot read the DACL.");
            Assert((AclService.OwnerRightsAllowRights & System.Security.AccessControl.FileSystemRights.ChangePermissions) == 0, "OWNER RIGHTS unexpectedly grants WRITE_DAC.");
            Assert((AclService.OwnerRightsAllowRights & System.Security.AccessControl.FileSystemRights.Delete) == 0, "OWNER RIGHTS unexpectedly grants Delete.");
        });
        Run("activation descendant rejects ACL inheritance protection", delegate
        {
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            string issue = AclService.FindActivationDescendantAclIssue(security, new[] { IdentityService.BuiltinUsersSid() });
            Assert(!string.IsNullOrEmpty(issue), "A protected descendant DACL was accepted.");
        });
        Run("activation descendant rejects explicit dangerous broad allow", delegate
        {
            DirectorySecurity security = new DirectorySecurity();
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.BuiltinUsersSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            string issue = AclService.FindActivationDescendantAclIssue(security, new[] { IdentityService.BuiltinUsersSid() });
            Assert(!string.IsNullOrEmpty(issue), "An explicit broad FullControl descendant rule was accepted.");
        });
        Run("activation descendant permits explicit write without delete or ACL takeover", delegate
        {
            DirectorySecurity security = new DirectorySecurity();
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.BuiltinUsersSid(), FileSystemRights.Write, AccessControlType.Allow));
            string issue = AclService.FindActivationDescendantAclIssue(security, new[] { IdentityService.BuiltinUsersSid() });
            Assert(string.IsNullOrEmpty(issue), "A write-only descendant rule was treated as a delete/ACL override: " + issue);
        });
        Run("acceptance probe path boundary", delegate
        {
            string root = "D:\\Acceptance\\.codexguard-acceptance-0123456789abcdef";
            Assert(ProbeRunner.IsSafeProbePath(root + "\\delete-test.txt", root), "A strict probe child was rejected.");
            Assert(!ProbeRunner.IsSafeProbePath(root, root), "The probe root itself was treated as a child target.");
            Assert(!ProbeRunner.IsSafeProbePath(root + "2\\delete-test.txt", root), "A sibling-prefix escape was accepted.");
            Assert(!ProbeRunner.IsSafeProbePath("D:\\Acceptance\\ordinary\\file.txt", "D:\\Acceptance\\ordinary"), "A non-probe root was accepted.");
        });
        Run("review HTML encodes machine-controlled text", delegate
        {
            ReviewReport report = new ReviewReport { MachineName = "<machine>", CurrentIdentity = "user&name", GeneratedAtUtc = "now", ProductVersion = "test", OverallStatus = "pass", ScopeStatement = "scope" };
            report.Controls.Add(new ReviewEvidence { Status = "PASS", Control = "<control>", Actual = "a&b" });
            string html = ReviewService.ToHtml(report);
            Assert(html.Contains("&lt;machine&gt;"), "Machine name was not encoded.");
            Assert(html.Contains("user&amp;name"), "Identity was not encoded.");
            Assert(!html.Contains("<control>"), "Control text was emitted as markup.");
        });
        Run("independent verifier source excludes system mutation APIs", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string source = File.ReadAllText(Path.Combine(projectRoot, "reviewer", "Program.cs"));
            string[] forbidden = { "SetAccessControl(", "Directory.Delete(", "File.Delete(", "Directory.Move(", "File.Move(", "NetUserAdd", ".SetValue(", "Process.Start(" };
            foreach (string token in forbidden) Assert(source.IndexOf(token, StringComparison.Ordinal) < 0, "Independent verifier contains forbidden mutation API: " + token);
            Assert(source.IndexOf("DefaultReadOnlyEnabled", StringComparison.Ordinal) >= 0, "Independent verifier does not expose the default-read-only enable flag.");
            Assert(source.IndexOf("WRITABLE EXCEPTION FACTS", StringComparison.Ordinal) >= 0, "Independent verifier does not expose the fixed writable exception list.");
            Assert(source.IndexOf("DEFAULT READ-ONLY BOUNDARY ACL FACTS", StringComparison.Ordinal) >= 0, "Independent verifier does not expose raw default boundary ACLs.");
        });
        Run("quote ordinary Windows path without doubling separators", delegate
        {
            string quoted = ElevationService.QuoteArgument("C:\\Users\\Codex Worker\\request.cgr");
            Assert(quoted == "\"C:\\Users\\Codex Worker\\request.cgr\"", "Unexpected quoting: " + quoted);
        });
        Run("quote trailing backslash safely", delegate
        {
            string quoted = ElevationService.QuoteArgument("D:\\Folder\\");
            Assert(quoted == "\"D:\\Folder\\\\\"", "Trailing separator was not escaped for the closing quote: " + quoted);
        });
        Run("obsolete Worker launcher detection is exact and read-only", delegate
        {
            Assert(ShortcutService.IsObsoleteWorkerCodexShortcutFacts(
                AppPaths.InstalledExecutable,
                ShortcutService.ObsoleteWorkerCodexArguments), "The exact legacy shortcut facts were not recognized.");
            Assert(!ShortcutService.IsObsoleteWorkerCodexShortcutFacts(
                "D:\\Other\\CodexGuard.exe",
                ShortcutService.ObsoleteWorkerCodexArguments), "A shortcut to another executable was accepted as obsolete.");
            Assert(!ShortcutService.IsObsoleteWorkerCodexShortcutFacts(
                AppPaths.InstalledExecutable,
                "--admin-install"), "A shortcut with different arguments was accepted as obsolete.");
            Assert(!ShortcutService.IsObsoleteWorkerCodexShortcutFacts(
                AppPaths.InstalledExecutable,
                ShortcutService.ObsoleteWorkerCodexArguments + " extra"), "A legacy argument prefix was accepted as obsolete.");
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string shortcutSource = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "ShortcutService.cs"));
            Assert(shortcutSource.IndexOf("File.Delete(", StringComparison.Ordinal) < 0, "Shortcut inspection must not delete the old shortcut.");
        });
        Run("admin-desktop Worker launch implementation is absent", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string appSource = File.ReadAllText(Path.Combine(projectRoot, "src", "App", "Program.cs"));
            string mainFormSource = File.ReadAllText(Path.Combine(projectRoot, "src", "App", "MainForm.cs"));
            Assert(appSource.IndexOf("WorkerCodexLaunchService", StringComparison.Ordinal) < 0, "Program still references the removed Worker launch service.");
            Assert(mainFormSource.IndexOf("LaunchWorkerCodex", StringComparison.Ordinal) < 0, "The main form still exposes the Worker launch action.");
            Assert(!File.Exists(Path.Combine(projectRoot, "src", "Core", "WorkerCodexLaunchService.cs")), "The removed Worker launch service source still exists.");
            Assert(!File.Exists(Path.Combine(projectRoot, "src", "Core", "OpenAiDesktopPackageService.cs")), "The removed package activation source still exists.");
        });
        Run("Codex config creates elevated section", delegate
        {
            string output = CodexConfigurationService.EnsureWindowsElevatedSetting("model = \"example\"\r\n");
            Assert(output.Contains("[windows]"), "Missing windows section.");
            Assert(output.Contains("sandbox = \"elevated\""), "Missing elevated setting.");
        });
        Run("Codex config replaces sandbox setting", delegate
        {
            string output = CodexConfigurationService.EnsureWindowsElevatedSetting("[windows]\r\nsandbox = \"unelevated\"\r\n");
            Assert(output.Contains("sandbox = \"elevated\""), "Setting was not replaced.");
            Assert(!output.Contains("unelevated"), "Old setting remains.");
        });
        Run("Codex config ignores commented sandbox setting", delegate
        {
            string output = CodexConfigurationService.EnsureWindowsElevatedSetting("[windows]\r\n# sandbox = \"unelevated\"\r\n");
            Assert(output.Contains("sandbox = \"elevated\""), "An active elevated setting was not inserted.");
            Assert(output.Contains("# sandbox = \"unelevated\""), "The comment should be preserved.");
        });
        Run("Codex config rejects separated duplicate windows sections", delegate
        {
            ExpectFailure(delegate
            {
                CodexConfigurationService.EnsureWindowsElevatedSetting("[windows]\r\nsandbox = \"elevated\"\r\n[other]\r\nx = 1\r\n[windows]\r\n");
            });
        });
        Run("Worker config ACL preserves the existing owner", delegate
        {
            SecurityIdentifier worker = IdentityService.BuiltinUsersSid();
            FileSecurity fileSecurity = CodexConfigurationService.CreateWorkerFileSecurity(worker);
            DirectorySecurity directorySecurity = CodexConfigurationService.CreateWorkerDirectorySecurity(worker);
            Assert(fileSecurity.GetOwner(typeof(SecurityIdentifier)) == null, "Worker config descriptor attempts to replace the file owner.");
            Assert(directorySecurity.GetOwner(typeof(SecurityIdentifier)) == null, "Worker config descriptor attempts to replace the directory owner.");
            Assert(HasFullControl(fileSecurity.GetAccessRules(true, false, typeof(SecurityIdentifier)), worker), "Worker lacks explicit full control on config files.");
            Assert(HasFullControl(directorySecurity.GetAccessRules(true, false, typeof(SecurityIdentifier)), worker), "Worker lacks explicit full control on the .codex directory.");
        });
        Run("requirements accept exact hardened policy", delegate
        {
            string requirements = "allow_login_shell = false\r\n[windows]\r\nallowed_sandbox_implementations = [\"elevated\"]\r\nsandbox_private_desktop = true\r\n";
            Assert(CodexConfigurationService.RequirementsTextMeetsPolicy(requirements), "Hardened policy was not recognized.");
        });
        Run("requirements reject commented fake policy", delegate
        {
            string requirements = "# allow_login_shell = false\r\n[windows]\r\n# allowed_sandbox_implementations = [\"elevated\"]\r\n# sandbox_private_desktop = true\r\n";
            Assert(!CodexConfigurationService.RequirementsTextMeetsPolicy(requirements), "Commented settings were treated as active.");
        });
        Run("requirements reject unelevated fallback", delegate
        {
            string requirements = "allow_login_shell = false\r\n[windows]\r\nallowed_sandbox_implementations = [\"elevated\", \"unelevated\"]\r\nsandbox_private_desktop = true\r\n";
            Assert(!CodexConfigurationService.RequirementsTextMeetsPolicy(requirements), "Unelevated fallback should not satisfy the hardened policy.");
        });
        Run("UAC restart marker tracks the current boot", delegate
        {
            GuardState state = GuardState.CreateDefault();
            state.UacRestartRequired = true;
            state.UacPolicyAppliedBootTimeUtc = UacPolicy.CurrentBootTimeUtc();
            Assert(UacPolicy.RestartStillRequired(state), "Current-boot UAC change should require restart.");
            state.UacPolicyAppliedBootTimeUtc = DateTime.UtcNow.AddYears(-1).ToString("o");
            Assert(!UacPolicy.RestartStillRequired(state), "A different boot marker should clear the restart requirement.");
        });
        Run("missing UAC values fail closed", delegate
        {
            Assert(!UacPolicy.FromRawValues(-1, 1, 1).MeetsRequirements, "Missing EnableLUA was treated as secure.");
            Assert(!UacPolicy.FromRawValues(1, -1, 1).MeetsRequirements, "Missing secure-desktop policy was treated as secure.");
            Assert(!UacPolicy.FromRawValues(1, 1, -1).MeetsRequirements, "Missing standard-user prompt policy was treated as secure.");
            Assert(UacPolicy.FromRawValues(1, 1, 1).MeetsRequirements, "The exact hardened UAC values were rejected.");
        });
        Run("policy export excludes SIDs", delegate
        {
            GuardState state = GuardState.CreateDefault();
            state.WorkerSid = "S-1-5-21-secret";
            state.AdminProfilePath = AppInfo.AdminProfilePath;
            state.ProtectedRoots.Add(new GuardedDirectory { CanonicalPath = AppInfo.AdminProfilePath });
            state.ProtectedRoots.Add(new GuardedDirectory { CanonicalPath = "D:\\LegacyManualRoot" });
            state.ActivatedDirectories.Add(new GuardedDirectory { CanonicalPath = "D:\\Projects\\A" });
            PortablePolicy policy = PortablePolicy.FromState(state);
            Assert(policy.ActivatedPaths.Count == 1, "Activated path missing.");
            Assert(policy.Note.IndexOf("excludes", StringComparison.OrdinalIgnoreCase) >= 0, "Safety note missing.");
            string path = Path.Combine(Path.GetTempPath(), "CodexGuard-policy-" + Guid.NewGuid().ToString("N") + ".json");
            JsonFile.WriteAtomic(path, policy, null);
            string json = File.ReadAllText(path);
            File.Delete(path);
            Assert(json.IndexOf("S-1-5-21-secret", StringComparison.OrdinalIgnoreCase) < 0, "Worker SID leaked into the portable policy.");
            Assert(json.IndexOf("ProtectedRootPaths", StringComparison.OrdinalIgnoreCase) < 0, "Legacy protection roots leaked into the portable policy.");
            Assert(json.IndexOf("LegacyManualRoot", StringComparison.OrdinalIgnoreCase) < 0, "A legacy manual root path leaked into the portable policy.");
            Assert(json.IndexOf(AppInfo.AdminProfilePath, StringComparison.OrdinalIgnoreCase) < 0, "The fixed administrator-profile path leaked into the portable policy.");
        });
        Run("manual protection-root request and UI are removed", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string models = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "Models.cs"));
            string mainForm = File.ReadAllText(Path.Combine(projectRoot, "src", "App", "MainForm.cs"));
            Assert(models.IndexOf("EnumMember] ProtectRoot", StringComparison.Ordinal) < 0, "The privileged manual protection-root operation still exists.");
            Assert(models.IndexOf("ProtectedRootPaths", StringComparison.Ordinal) < 0, "Portable policy still contains manual protection roots.");
            Assert(mainForm.IndexOf("添加保护根", StringComparison.Ordinal) < 0, "The normal UI still exposes Add protection root.");
        });
        Run("record sync keeps local profiles separate and redacts contents", delegate
        {
            string root = Path.Combine(Path.GetTempPath(), "CodexGuardRecordSync-" + Guid.NewGuid().ToString("N"));
            string admin = Path.Combine(root, "admin");
            string worker = Path.Combine(root, "worker");
            string adminCodex = Path.Combine(admin, ".codex");
            string workerCodex = Path.Combine(worker, ".codex");
            string sessionDirectory = Path.Combine(adminCodex, "sessions", "2026", "08", "16");
            Directory.CreateDirectory(sessionDirectory);
            Directory.CreateDirectory(workerCodex);
            File.WriteAllText(Path.Combine(adminCodex, "auth.json"), "SUPER-SECRET-AUTH-CONTENT");
            File.WriteAllText(Path.Combine(sessionDirectory, "rollout-test.jsonl"), "PRIVATE-CONVERSATION-CONTENT");
            File.WriteAllText(Path.Combine(workerCodex, "auth.json"), "OTHER-SECRET-AUTH-CONTENT");
            try
            {
                RecordSyncReport report = CodexRecordSyncService.Capture(admin, worker);
                Assert(report.Profiles.Count == 2, "Both profile snapshots were not produced.");
                Assert(report.Profiles[0].SessionFileCount == 1, "Session metadata count is wrong.");
                string html = CodexRecordSyncService.ToHtml(report);
                Assert(html.IndexOf("SUPER-SECRET-AUTH-CONTENT", StringComparison.Ordinal) < 0, "Authentication content leaked into the report.");
                Assert(html.IndexOf("PRIVATE-CONVERSATION-CONTENT", StringComparison.Ordinal) < 0, "Conversation content leaked into the report.");
                Assert(html.IndexOf("OTHER-SECRET-AUTH-CONTENT", StringComparison.Ordinal) < 0, "Worker authentication content leaked into the report.");
            }
            finally
            {
                Directory.Delete(root, true);
            }
        });
        Run("record sync rejects a shared Windows profile", delegate
        {
            string profile = Path.Combine(Path.GetTempPath(), "CodexGuardSharedProfile-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(profile, ".codex"));
            try
            {
                RecordSyncReport report = CodexRecordSyncService.Capture(profile, profile);
                bool failed = false;
                foreach (ReviewEvidence check in report.Checks)
                    if (check.Status == "FAIL" && check.Control == "本地数据隔离") failed = true;
                Assert(failed, "A shared local profile was not rejected.");
            }
            finally
            {
                Directory.Delete(profile, true);
            }
        });
        Run("record sync report cannot be written into Codex data", delegate
        {
            string root = Path.Combine(Path.GetTempPath(), "CodexGuardReportBoundary-" + Guid.NewGuid().ToString("N"));
            string admin = Path.Combine(root, "admin");
            string worker = Path.Combine(root, "worker");
            Directory.CreateDirectory(Path.Combine(admin, ".codex"));
            Directory.CreateDirectory(Path.Combine(worker, ".codex"));
            try
            {
                RecordSyncReport report = CodexRecordSyncService.Capture(admin, worker);
                ExpectFailure(delegate
                {
                    CodexRecordSyncService.ExportPackage(Path.Combine(admin, ".codex", "report.html"), report);
                });
            }
            finally
            {
                Directory.Delete(root, true);
            }
        });
        Run("record sync implementation never reads auth or copies Codex data", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string source = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "CodexRecordSyncService.cs"));
            Assert(source.IndexOf("ReadAllText", StringComparison.Ordinal) < 0, "Record sync service reads file contents.");
            Assert(source.IndexOf("File.Copy", StringComparison.Ordinal) < 0, "Record sync service copies local Codex data.");
            Assert(source.IndexOf("Directory.Move", StringComparison.Ordinal) < 0, "Record sync service moves local Codex data.");
            Assert(source.IndexOf("CreateSymbolicLink", StringComparison.Ordinal) < 0, "Record sync service creates a symbolic link.");
        });
        Run("software display icon parser removes quotes and resource index", delegate
        {
            string parsed = SoftwareMappingService.ParseDisplayIconPath("\"C:\\Program Files\\Example\\example.exe\",0");
            Assert(parsed == "C:\\Program Files\\Example\\example.exe", "Unexpected DisplayIcon path: " + parsed);
        });
        Run("software mapper rejects installer and uninstaller launchers", delegate
        {
            Assert(SoftwareMappingService.IsUnsafeLauncher("卸载 ToDesk", "C:\\Program Files\\ToDesk\\uninst.exe"), "A Chinese uninstall shortcut was accepted.");
            Assert(SoftwareMappingService.IsUnsafeLauncher("Docker Desktop", "C:\\Program Files\\Docker\\Docker Desktop Installer.exe"), "An installer executable was accepted.");
            Assert(!SoftwareMappingService.IsUnsafeLauncher("PFC3D 6.0", "C:\\Program Files\\Itasca\\PFC600\\exe64\\pfc3d600.exe"), "A normal application launcher was rejected.");
        });
        Run("software classification exposes only verified shared EXE for mapping", delegate
        {
            SoftwareInventoryItem shortcut = new SoftwareInventoryItem { DisplayName = "Example", ExecutablePath = "C:\\Program Files\\Example\\example.exe" };
            SoftwareMappingService.ClassifyFacts(shortcut, "C:\\Users\\admin", true, true, false, false, false, false, null);
            Assert(shortcut.Category == SoftwareMappingCategory.ShortcutRequired && shortcut.CanCreateShortcut, "A safe shared EXE was not offered for shortcut creation.");

            SoftwareInventoryItem admin = new SoftwareInventoryItem { DisplayName = "Admin App", ExecutablePath = "C:\\Users\\admin\\AppData\\Local\\Programs\\App\\app.exe" };
            SoftwareMappingService.ClassifyFacts(admin, "C:\\Users\\admin", true, false, false, false, true, false, "outside boundary");
            Assert(admin.Category == SoftwareMappingCategory.SeparateInstallRequired && !admin.CanCreateShortcut, "An admin-profile executable was offered for mapping.");

            SoftwareInventoryItem store = new SoftwareInventoryItem { DisplayName = "Store App" };
            SoftwareMappingService.ClassifyFacts(store, "C:\\Users\\admin", false, false, false, true, false, false, null);
            Assert(store.Category == SoftwareMappingCategory.WorkerRegistrationRequired && !store.CanCreateShortcut, "A Store app was treated as a direct EXE mapping.");

            SoftwareInventoryItem arguments = new SoftwareInventoryItem { DisplayName = "Parameterized", ExecutablePath = "C:\\Program Files\\Example\\example.exe" };
            SoftwareMappingService.ClassifyFacts(arguments, "C:\\Users\\admin", true, true, false, false, false, true, null);
            Assert(arguments.Category == SoftwareMappingCategory.SeparateInstallRequired && !arguments.CanCreateShortcut, "A shortcut with arguments was offered for automatic mapping.");

            SoftwareInventoryItem vendorCommon = new SoftwareInventoryItem { DisplayName = "Vendor Common", ExecutablePath = "C:\\Program Files\\Example\\example.exe" };
            SoftwareMappingService.ClassifyFacts(vendorCommon, "C:\\Users\\admin", true, true, true, false, false, true, null);
            Assert(vendorCommon.Category == SoftwareMappingCategory.SharedReady && !vendorCommon.CanCreateShortcut, "An existing vendor public shortcut was needlessly copied.");
        });
        Run("software mapper keeps user profiles and WindowsApps as hard blocks", delegate
        {
            GuardState state = GuardState.CreateDefault();
            state.AdminProfilePath = "C:\\Users\\admin";
            state.WorkerProfilePath = "C:\\Users\\CodexWorker";
            string reason;
            Assert(SoftwareMappingService.IsForbiddenSharedLocation("C:\\Users\\admin\\AppData\\Local\\Programs\\App\\app.exe", state, out reason), "An admin AppData executable was not blocked.");
            Assert(SoftwareMappingService.IsForbiddenSharedLocation("C:\\Program Files\\WindowsApps\\Vendor.App_1.0_x64__id\\app.exe", state, out reason), "A WindowsApps executable was not blocked.");
            Assert(!SoftwareMappingService.IsForbiddenSharedLocation("D:\\SharedEngineeringApps\\App\\app.exe", state, out reason), "A normal non-system-drive shared path was blocked before ACL verification: " + reason);
        });
        Run("software UI no longer recommends a separate install", delegate
        {
            Assert(SoftwareMappingService.CategoryText(SoftwareMappingCategory.SeparateInstallRequired) == "技术阻断", "The blocked category still tells the user to install separately.");
            SoftwareInventoryItem admin = new SoftwareInventoryItem { DisplayName = "Admin App", ExecutablePath = "C:\\Users\\admin\\AppData\\Local\\Programs\\App\\app.exe" };
            SoftwareMappingService.ClassifyFacts(admin, "C:\\Users\\admin", true, false, false, false, true, false, "blocked");
            Assert(admin.RecommendedAction.IndexOf("单独安装", StringComparison.Ordinal) < 0, "The admin-profile recommendation still requests a separate install.");
        });
        Run("mapped shortcut names cannot escape the public folder", delegate
        {
            string safe = ShortcutService.SanitizeShortcutName("..\\CON.lnk");
            Assert(safe.IndexOf('\\') < 0 && safe.IndexOf('/') < 0, "A mapped shortcut name retained a path separator: " + safe);
            Assert(!safe.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase), "The supplied link extension was retained.");
        });
        Run("software CSV neutralizes spreadsheet formulas", delegate
        {
            SoftwareInventoryReport report = new SoftwareInventoryReport();
            report.Items.Add(new SoftwareInventoryItem { DisplayName = "=HYPERLINK(\"bad\")", Category = SoftwareMappingCategory.SeparateInstallRequired });
            string csv = SoftwareMappingService.ToCsv(report);
            Assert(csv.Contains("'=HYPERLINK"), "A spreadsheet formula prefix was not neutralized.");
        });
        Run("software mapping requester is exact Worker SID", delegate
        {
            GuardState state = GuardState.CreateDefault();
            state.WorkerSid = "S-1-5-21-1234";
            state.AdminProfilePath = "Z:\\profile-that-does-not-exist";
            Assert(SoftwareMappingRequestService.IsAllowedRequester(state, "S-1-5-21-1234"), "The recorded Worker SID was rejected.");
            Assert(!SoftwareMappingRequestService.IsAllowedRequester(state, "S-1-5-21-12345"), "A Worker SID prefix was accepted.");
        });
        Run("software inventory core never executes installers or mutates software", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string source = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "SoftwareMappingService.cs"));
            string[] forbidden = { "Process.Start(", "File.Copy(", "File.Delete(", "File.Move(", "Directory.Delete(", "Directory.Move(", ".SetValue(", "UninstallString" };
            foreach (string token in forbidden) Assert(source.IndexOf(token, StringComparison.Ordinal) < 0, "Software inventory contains forbidden execution/mutation token: " + token);
        });
        Run("offline reuse accepts only one admin Local Programs application", delegate
        {
            string source;
            string relative;
            Assert(OfflineReuseService.TryGetAdminLocalProgramsSource(
                "C:\\Users\\admin\\AppData\\Local\\Programs\\Example\\bin\\example.exe",
                "C:\\Users\\admin",
                out source,
                out relative), "A normal Local Programs application was rejected.");
            Assert(source == "C:\\Users\\admin\\AppData\\Local\\Programs\\Example", "Unexpected source root: " + source);
            Assert(relative == "bin\\example.exe", "Unexpected relative EXE: " + relative);
            Assert(!OfflineReuseService.TryGetAdminLocalProgramsSource(
                "C:\\Users\\admin\\AppData\\Roaming\\Example\\example.exe",
                "C:\\Users\\admin",
                out source,
                out relative), "A Roaming profile program was accepted for automatic copy.");
            Assert(!OfflineReuseService.TryGetAdminLocalProgramsSource(
                "C:\\Users\\admin2\\AppData\\Local\\Programs\\Example\\example.exe",
                "C:\\Users\\admin",
                out source,
                out relative), "A sibling profile prefix escaped the admin boundary.");
        });
        Run("offline reuse target stays in Worker Local Programs", delegate
        {
            string target = OfflineReuseService.BuildWorkerTargetDirectory(
                "C:\\Users\\CodexWorker",
                "C:\\Users\\admin\\AppData\\Local\\Programs\\Example");
            Assert(target == "C:\\Users\\CodexWorker\\AppData\\Local\\Programs\\Example", "Unexpected Worker target: " + target);
            Assert(AppPaths.IsPathInside(target, "C:\\Users\\CodexWorker\\AppData\\Local\\Programs"), "Worker target escaped Local Programs.");
        });
        Run("offline reuse classification prefers existing files and local media", delegate
        {
            SoftwareInventoryItem shared = new SoftwareInventoryItem
            {
                InventoryId = "shared",
                DisplayName = "Shared App",
                Category = SoftwareMappingCategory.ShortcutRequired,
                ExecutablePath = "C:\\Program Files\\Shared\\app.exe"
            };
            OfflineReuseItem direct = OfflineReuseService.Classify(shared, null);
            Assert(direct.Category == OfflineReuseCategory.DirectReuse, "A shared application was not classified for direct reuse.");

            SoftwareInventoryItem cached = new SoftwareInventoryItem
            {
                InventoryId = "cached",
                DisplayName = "Cached App",
                Category = SoftwareMappingCategory.SeparateInstallRequired,
                LocalInstallSource = "E:\\Installers\\Cached",
                LocalInstallSourceExists = true
            };
            OfflineReuseItem media = OfflineReuseService.Classify(cached, null);
            Assert(media.Category == OfflineReuseCategory.LocalMedia, "An existing local installer source was not preferred over download.");
        });
        Run("offline reuse does not grant container host control by mapping", delegate
        {
            SoftwareInventoryItem docker = new SoftwareInventoryItem
            {
                InventoryId = "docker",
                DisplayName = "Docker Desktop",
                Category = SoftwareMappingCategory.SharedReady,
                ExecutablePath = "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe"
            };
            OfflineReuseItem result = OfflineReuseService.Classify(docker, null);
            Assert(result.Category == OfflineReuseCategory.PermissionReview, "Docker host control was treated as ordinary direct reuse.");
            Assert(result.RecommendedAction.IndexOf("docker-users", StringComparison.OrdinalIgnoreCase) >= 0, "Docker privilege boundary warning is missing.");
        });
        Run("offline reuse CSV neutralizes spreadsheet formulas", delegate
        {
            OfflineReuseReport report = new OfflineReuseReport();
            report.Items.Add(new OfflineReuseItem { DisplayName = "=HYPERLINK(\"bad\")", Category = OfflineReuseCategory.LocalPayloadMissing });
            Assert(OfflineReuseService.ToCsv(report).Contains("'=HYPERLINK"), "Offline reuse CSV emitted a formula prefix.");
        });
        Run("offline reuse copy implementation cannot delete move execute or import registry", delegate
        {
            string projectRoot = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            string source = File.ReadAllText(Path.Combine(projectRoot, "src", "Core", "OfflineReuseRequestService.cs"));
            string[] forbidden = { "File.Delete(", "Directory.Delete(", "File.Move(", "Directory.Move(", "Process.Start(", ".SetValue(", "UninstallString", "powershell", "cmd.exe" };
            foreach (string token in forbidden) Assert(source.IndexOf(token, StringComparison.OrdinalIgnoreCase) < 0, "Offline reuse contains forbidden source mutation/execution token: " + token);
            Assert(source.IndexOf("FileMode.CreateNew", StringComparison.Ordinal) >= 0, "Offline reuse does not enforce CreateNew destination files.");
            Assert(source.IndexOf("FileShare.Read", StringComparison.Ordinal) >= 0, "Offline reuse does not lock source files against writes while copying.");
        });
        Run("offline reuse source inspection counts a bounded ordinary tree", delegate
        {
            string root = Path.Combine(Path.GetTempPath(), "CodexGuardOfflineReuse-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(root, "bin"));
            File.WriteAllText(Path.Combine(root, "bin", "app.exe"), "test executable bytes");
            File.WriteAllText(Path.Combine(root, "resource.dat"), "resource");
            try
            {
                long files;
                long bytes;
                OfflineReuseRequestService.InspectSourceTree(root, out files, out bytes);
                Assert(files == 2, "Unexpected source file count: " + files);
                Assert(bytes > 0, "Source byte count was empty.");
            }
            finally
            {
                Directory.Delete(root, true);
            }
        });
        Run("offline reuse copy preserves source and refuses overwrite", delegate
        {
            string root = Path.Combine(Path.GetTempPath(), "CodexGuardOfflineCopy-" + Guid.NewGuid().ToString("N"));
            string source = Path.Combine(root, "source");
            string target = Path.Combine(root, "target");
            Directory.CreateDirectory(Path.Combine(source, "bin"));
            string sourceExe = Path.Combine(source, "bin", "app.exe");
            File.WriteAllText(sourceExe, "immutable source bytes");
            string before = Convert.ToBase64String(File.ReadAllBytes(sourceExe));
            Directory.CreateDirectory(root);
            NativePath.CreateDirectoryNew(target);
            try
            {
                long files;
                long bytes;
                OfflineReuseRequestService.InspectSourceTree(source, out files, out bytes);
                OfflineReuseCopyPlan plan = new OfflineReuseCopyPlan
                {
                    Item = new OfflineReuseItem { DisplayName = "Test" },
                    SourceDirectory = source,
                    TargetDirectory = target,
                    TargetExecutable = Path.Combine(target, "bin", "app.exe"),
                    FileCount = files,
                    TotalBytes = bytes
                };
                string mainHash;
                string aggregate = OfflineReuseRequestService.CopyTreeCreateNew(plan, out mainHash);
                Assert(!string.IsNullOrWhiteSpace(aggregate) && !string.IsNullOrWhiteSpace(mainHash), "Copy hashes were not produced.");
                Assert(Convert.ToBase64String(File.ReadAllBytes(sourceExe)) == before, "Source content changed during copy.");
                Assert(File.ReadAllText(plan.TargetExecutable) == "immutable source bytes", "Target content differs from source.");
                ExpectFailure(delegate { OfflineReuseRequestService.CopyTreeCreateNew(plan, out mainHash); });
            }
            finally
            {
                Directory.Delete(root, true);
            }
        });
        Run("JSON request roundtrip", delegate
        {
            string directory = Path.Combine(Path.GetTempPath(), "CodexGuardTests");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".json");
            GuardRequest request = GuardRequest.Create(GuardOperation.Activate, new[] { "D:\\Projects\\A" }, "S-1-5-21-test");
            JsonFile.WriteNew(path, request);
            GuardRequest loaded = JsonFile.Read<GuardRequest>(path, 1024 * 1024);
            Assert(loaded.RequestId == request.RequestId, "Request ID changed during roundtrip.");
            File.Delete(path);
        });
        Run("protected state roundtrips the recorded Worker profile", delegate
        {
            string directory = Path.Combine(Path.GetTempPath(), "CodexGuardTests");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".json");
            try
            {
                GuardState state = GuardState.CreateDefault();
                state.WorkerProfilePath = "C:\\Users\\CodexWorker";
                state.DefaultReadOnlyEnabled = true;
                state.DefaultReadOnlyDirectories.Add(new GuardedDirectory { CanonicalPath = "D:\\" });
                state.DefaultReadOnlyRootLocks.Add(new GuardedDirectory { CanonicalPath = "C:\\" });
                state.WritableExceptionPaths.Add("C:\\Users\\CodexWorker\\AppData");
                JsonFile.WriteNew(path, state);
                GuardState loaded = JsonFile.Read<GuardState>(path, 1024 * 1024);
                Assert(loaded.WorkerProfilePath == state.WorkerProfilePath, "Worker profile path was not persisted in protected state.");
                loaded.Normalize();
                Assert(loaded.DefaultReadOnlyEnabled, "Default read-only state was not persisted.");
                Assert(loaded.DefaultReadOnlyDirectories.Count == 1 && loaded.DefaultReadOnlyRootLocks.Count == 1, "Default read-only boundaries were not persisted.");
                Assert(loaded.WritableExceptionPaths.Count == 1, "Writable exceptions were not persisted.");
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        });
        Run("atomic JSON preparation failure preserves original", delegate
        {
            string directory = Path.Combine(Path.GetTempPath(), "CodexGuardTests");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".json");
            PortablePolicy original = new PortablePolicy { SchemaVersion = AppInfo.PolicySchemaVersion, SourceMachine = "original" };
            JsonFile.WriteAtomic(path, original, null);
            ExpectFailure(delegate
            {
                JsonFile.WriteAtomic(path, new PortablePolicy { SchemaVersion = AppInfo.PolicySchemaVersion, SourceMachine = "replacement" }, null,
                    delegate(string temporary) { throw new InvalidOperationException("test preparation failure"); });
            });
            PortablePolicy loaded = JsonFile.Read<PortablePolicy>(path, 1024 * 1024);
            Assert(loaded.SourceMachine == "original", "The original file changed before atomic preparation completed.");
            File.Delete(path);
            foreach (string temporary in Directory.GetFiles(directory, Path.GetFileName(path) + ".new-*")) File.Delete(temporary);
        });

        Console.WriteLine("Passed: " + _passed + "; Failed: " + _failed);
        return _failed == 0 ? 0 : 1;
    }

    private static void Run(string name, Action test)
    {
        try
        {
            test();
            _passed++;
            Console.WriteLine("PASS " + name);
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine("FAIL " + name + ": " + ex.Message);
        }
    }

    private static void ExpectFailure(Action action)
    {
        try
        {
            action();
        }
        catch
        {
            return;
        }
        throw new Exception("Expected the operation to fail.");
    }

    private static bool HasFullControl(AuthorizationRuleCollection rules, SecurityIdentifier sid)
    {
        foreach (AuthorizationRule authorizationRule in rules)
        {
            FileSystemAccessRule rule = authorizationRule as FileSystemAccessRule;
            if (rule == null || rule.AccessControlType != AccessControlType.Allow) continue;
            SecurityIdentifier identity = rule.IdentityReference as SecurityIdentifier;
            if (identity != null && identity.Equals(sid)
                && (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl)
                return true;
        }
        return false;
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }
}
