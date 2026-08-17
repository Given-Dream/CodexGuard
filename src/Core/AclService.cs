using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal static class AclService
    {
        public const FileSystemRights ActiveAllowRights =
            FileSystemRights.ReadAndExecute |
            FileSystemRights.Write |
            FileSystemRights.Synchronize;

        public const FileSystemRights ReadOnlyAllowRights =
            FileSystemRights.ReadAndExecute |
            FileSystemRights.Synchronize;

        public const FileSystemRights GuardDenyRights =
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;

        public const FileSystemRights OwnerRightsAllowRights =
            FileSystemRights.ReadPermissions |
            FileSystemRights.Synchronize;

        public const FileSystemRights WriteLikeRights =
            FileSystemRights.Write |
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;

        public const FileSystemRights DefaultReadOnlyDenyRights =
            FileSystemRights.Write |
            GuardDenyRights;

        public const FileSystemRights RootOnlyLockDenyRights =
            FileSystemRights.Write |
            GuardDenyRights;

        private const InheritanceFlags GuardInheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        private const PropagationFlags GuardPropagation = PropagationFlags.None;

        public static string CaptureSddl(string path)
        {
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.All);
            return security.GetSecurityDescriptorSddlForm(AccessControlSections.All);
        }

        public static void RestoreSddl(string path, string sddl)
        {
            if (string.IsNullOrWhiteSpace(sddl)) throw new InvalidDataException("ACL backup is empty.");
            DirectorySecurity security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.All);
            Directory.SetAccessControl(path, security);
        }

        public static void ApplyActivated(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
            AddRuleIfMissing(security, CreateRule(IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow));
            foreach (SecurityIdentifier sid in actorSids)
            {
                RemoveGuardRule(security, sid, AccessControlType.Allow, ActiveAllowRights);
                AddRuleIfMissing(security, CreateRule(sid, ActiveAllowRights, AccessControlType.Allow));
                AddRuleIfMissing(security, CreateRule(sid, GuardDenyRights, AccessControlType.Deny));
            }
            Directory.SetAccessControl(path, security);
        }

        public static void ApplyReadOnly(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
            AddRuleIfMissing(security, CreateRule(IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow));
            foreach (SecurityIdentifier sid in actorSids)
            {
                RemoveExplicitWriteAllows(security, sid);
                AddRuleIfMissing(security, CreateRule(sid, ReadOnlyAllowRights, AccessControlType.Allow));
                AddRuleIfMissing(security, CreateRule(sid, GuardDenyRights, AccessControlType.Deny));
            }
            Directory.SetAccessControl(path, security);
        }

        public static List<string> ApplyProtectedRoot(string path, IEnumerable<SecurityIdentifier> actorSids, bool removeBroadWriteAllows)
        {
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
            List<string> changes = new List<string>();
            AddRuleIfMissing(security, CreateRule(IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow));
            if (removeBroadWriteAllows)
            {
                SecurityIdentifier[] broad =
                {
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                    IdentityService.BuiltinUsersSid()
                };
                foreach (SecurityIdentifier sid in broad)
                    StripBroadWriteAllows(security, sid, changes);
            }

            foreach (SecurityIdentifier sid in actorSids)
            {
                RemoveExplicitWriteAllows(security, sid);
                AddRuleIfMissing(security, CreateRule(sid, ReadOnlyAllowRights, AccessControlType.Allow));
                AddRuleIfMissing(security, CreateRule(sid, GuardDenyRights, AccessControlType.Deny));
            }
            Directory.SetAccessControl(path, security);
            return changes;
        }

        public static void ApplyNoAccess(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
            AddRuleIfMissing(security, CreateRule(IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow));
            foreach (SecurityIdentifier sid in actorSids)
                AddRuleIfMissing(security, CreateRule(sid, FileSystemRights.FullControl, AccessControlType.Deny));
            Directory.SetAccessControl(path, security);
        }

        public static void ApplyDefaultReadOnlyBoundary(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
            AddRuleIfMissing(security, CreateRule(IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow));
            foreach (SecurityIdentifier sid in actorSids)
            {
                AddRuleIfMissing(security, CreateRule(sid, ReadOnlyAllowRights, AccessControlType.Allow));
                AddRuleIfMissing(security, CreateRule(sid, DefaultReadOnlyDenyRights, AccessControlType.Deny));
            }
            Directory.SetAccessControl(path, security);
        }

        public static void ApplyRootOnlyLock(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
            AddRuleIfMissing(security, CreateThisFolderRule(IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow));
            foreach (SecurityIdentifier sid in actorSids)
                AddRuleIfMissing(security, CreateThisFolderRule(sid, RootOnlyLockDenyRights, AccessControlType.Deny));
            Directory.SetAccessControl(path, security);
        }

        public static void SecureApplicationDirectory(string path, bool usersMayRead)
        {
            Directory.CreateDirectory(path);
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(IdentityService.BuiltinAdministratorsSid());
            security.AddAccessRule(CreateRule(IdentityService.BuiltinAdministratorsSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(CreateRule(IdentityService.LocalSystemSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            if (usersMayRead)
                security.AddAccessRule(CreateRule(IdentityService.BuiltinUsersSid(), ReadOnlyAllowRights, AccessControlType.Allow));
            Directory.SetAccessControl(path, security);
        }

        public static void SecureApplicationFile(string path, bool usersMayRead)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("Application file does not exist.", path);
            FileSecurity security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(IdentityService.BuiltinAdministratorsSid());
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.BuiltinAdministratorsSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.LocalSystemSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            if (usersMayRead)
                security.AddAccessRule(new FileSystemAccessRule(IdentityService.BuiltinUsersSid(), FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, AccessControlType.Allow));
            File.SetAccessControl(path, security);
        }

        public static void SecureWorkerApplicationDirectory(string path, SecurityIdentifier workerSid, SecurityIdentifier sandboxSid)
        {
            if (workerSid == null) throw new ArgumentNullException("workerSid");
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(IdentityService.BuiltinAdministratorsSid());
            security.AddAccessRule(CreateRule(IdentityService.BuiltinAdministratorsSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(CreateRule(IdentityService.LocalSystemSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(CreateRule(workerSid, FileSystemRights.Modify | FileSystemRights.Synchronize, AccessControlType.Allow));
            if (sandboxSid != null)
            {
                security.AddAccessRule(CreateRule(sandboxSid, ReadOnlyAllowRights, AccessControlType.Allow));
                security.AddAccessRule(CreateRule(sandboxSid, GuardDenyRights, AccessControlType.Deny));
            }
            Directory.SetAccessControl(path, security);
        }

        public static void SecureWorkerApplicationFile(string path, SecurityIdentifier workerSid, SecurityIdentifier sandboxSid)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("Worker application file does not exist.", path);
            if (workerSid == null) throw new ArgumentNullException("workerSid");
            FileSecurity security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(IdentityService.BuiltinAdministratorsSid());
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.BuiltinAdministratorsSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.LocalSystemSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(workerSid, FileSystemRights.Modify | FileSystemRights.Synchronize, AccessControlType.Allow));
            if (sandboxSid != null)
            {
                security.AddAccessRule(new FileSystemAccessRule(sandboxSid, ReadOnlyAllowRights, AccessControlType.Allow));
                FileSystemRights fileDeny = GuardDenyRights & ~FileSystemRights.DeleteSubdirectoriesAndFiles;
                security.AddAccessRule(new FileSystemAccessRule(sandboxSid, fileDeny, AccessControlType.Deny));
            }
            File.SetAccessControl(path, security);
        }

        public static void AssertProtectedFile(string path)
        {
            FileSecurity security = File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
            SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
            if (!owner.Equals(IdentityService.BuiltinAdministratorsSid()) && !owner.Equals(IdentityService.LocalSystemSid()))
                throw new InvalidDataException("The protected file has an unexpected owner and will not be trusted: " + owner.Value);

            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow || (rule.FileSystemRights & WriteLikeRights) == 0) continue;
                SecurityIdentifier sid = (SecurityIdentifier)rule.IdentityReference;
                if (sid.Equals(new SecurityIdentifier(WellKnownSidType.WorldSid, null))
                    || sid.Equals(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null))
                    || sid.Equals(IdentityService.BuiltinUsersSid()))
                    throw new InvalidDataException("The protected file is writable by a broad Windows principal and will not be trusted: " + sid.Value);
            }
        }

        public static void SecureDeleteRequestDirectory(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            SecureApplicationDirectory(path, true);
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
            AddRuleIfMissing(security, CreateRule(IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow));
            foreach (SecurityIdentifier sid in actorSids)
            {
                AddRuleIfMissing(security, CreateRule(sid, ActiveAllowRights, AccessControlType.Allow));
                AddRuleIfMissing(security, CreateRule(sid, GuardDenyRights, AccessControlType.Deny));
            }
            Directory.SetAccessControl(path, security);
        }

        public static List<AuditItem> AuditActivated(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            List<AuditItem> issues = new List<AuditItem>();
            DirectorySecurity security;
            try
            {
                security = Directory.GetAccessControl(path, AccessControlSections.Access);
            }
            catch (Exception ex)
            {
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ACL_READ_FAILED", Path = path, Message = ex.Message });
                return issues;
            }

            foreach (SecurityIdentifier sid in actorSids)
            {
                if (!HasRule(security, sid, ActiveAllowRights, AccessControlType.Allow))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ACTIVE_ALLOW_MISSING", Path = path, Message = "Missing Codex Guard read/write/create rule for " + sid.Value });
                if (!HasRuleContaining(security, sid, GuardDenyRights, AccessControlType.Deny, GuardInheritance, GuardPropagation))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DELETE_DENY_MISSING", Path = path, Message = "Missing delete/rename/ACL-change deny rule for " + sid.Value });
            }
            if (!HasRule(security, IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow))
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "OWNER_RIGHTS_RULE_MISSING", Path = path, Message = "Missing the OWNER RIGHTS rule that suppresses an owner's implicit WRITE_DAC permission." });
            return issues;
        }

        public static List<AuditItem> AuditReadOnly(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            List<AuditItem> issues = new List<AuditItem>();
            DirectorySecurity security;
            try
            {
                security = Directory.GetAccessControl(path, AccessControlSections.Access);
            }
            catch (Exception ex)
            {
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ACL_READ_FAILED", Path = path, Message = ex.Message });
                return issues;
            }

            foreach (SecurityIdentifier sid in actorSids)
            {
                if (!HasRule(security, sid, ReadOnlyAllowRights, AccessControlType.Allow))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "READONLY_ALLOW_MISSING", Path = path, Message = "Missing Codex Guard read-only rule for " + sid.Value });
                if (!HasRuleContaining(security, sid, GuardDenyRights, AccessControlType.Deny, GuardInheritance, GuardPropagation))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DELETE_DENY_MISSING", Path = path, Message = "Missing delete/rename/ACL-change deny rule for " + sid.Value });
                if (HasExplicitWriteAllow(security, sid))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "READONLY_WRITE_ALLOW", Path = path, Message = "An explicit write-like allow rule remains for " + sid.Value });
            }
            if (!HasRule(security, IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow))
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "OWNER_RIGHTS_RULE_MISSING", Path = path, Message = "Missing the OWNER RIGHTS rule that suppresses an owner's implicit WRITE_DAC permission." });
            foreach (SecurityIdentifier sid in BroadWritePrincipals())
            {
                if (HasExplicitWriteAllow(security, sid))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "BROAD_WRITE_ALLOW", Path = path, Message = "A broad principal still has an explicit write-like allow rule: " + sid.Value });
            }
            return issues;
        }

        public static List<AuditItem> AuditNoAccess(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            List<AuditItem> issues = new List<AuditItem>();
            DirectorySecurity security;
            try
            {
                security = Directory.GetAccessControl(path, AccessControlSections.Access);
            }
            catch (Exception ex)
            {
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "SENSITIVE_ACL_READ_FAILED", Path = path, Message = ex.Message });
                return issues;
            }
            foreach (SecurityIdentifier sid in actorSids)
                if (!HasRule(security, sid, FileSystemRights.FullControl, AccessControlType.Deny))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "SENSITIVE_DENY_MISSING", Path = path, Message = "Missing full access denial for " + sid.Value });
            return issues;
        }

        public static List<AuditItem> AuditDefaultReadOnlyBoundary(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            List<AuditItem> issues = new List<AuditItem>();
            DirectorySecurity security;
            try { security = Directory.GetAccessControl(path, AccessControlSections.Access); }
            catch (Exception ex)
            {
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_ACL_READ_FAILED", Path = path, Message = ex.Message });
                return issues;
            }
            foreach (SecurityIdentifier sid in actorSids)
            {
                if (!HasRule(security, sid, ReadOnlyAllowRights, AccessControlType.Allow))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_ALLOW_MISSING", Path = path, Message = "Missing the default read-only grant for " + sid.Value });
                if (!HasRuleContaining(security, sid, DefaultReadOnlyDenyRights, AccessControlType.Deny, GuardInheritance, GuardPropagation))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "DEFAULT_READONLY_DENY_MISSING", Path = path, Message = "Missing the inherited write/delete/ACL denial for " + sid.Value });
            }
            if (!HasRule(security, IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow))
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "OWNER_RIGHTS_RULE_MISSING", Path = path, Message = "Missing the OWNER RIGHTS rule on a default read-only boundary." });
            return issues;
        }

        public static List<AuditItem> AuditRootOnlyLock(string path, IEnumerable<SecurityIdentifier> actorSids)
        {
            List<AuditItem> issues = new List<AuditItem>();
            DirectorySecurity security;
            try { security = Directory.GetAccessControl(path, AccessControlSections.Access); }
            catch (Exception ex)
            {
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ROOT_LOCK_ACL_READ_FAILED", Path = path, Message = ex.Message });
                return issues;
            }
            foreach (SecurityIdentifier sid in actorSids)
                if (!HasThisFolderRule(security, sid, RootOnlyLockDenyRights, AccessControlType.Deny))
                    issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ROOT_LOCK_DENY_MISSING", Path = path, Message = "Missing the root-only create/write/delete denial for " + sid.Value });
            if (!HasThisFolderRule(security, IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow))
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = "ROOT_LOCK_OWNER_RIGHTS_MISSING", Path = path, Message = "Missing the root-only OWNER RIGHTS rule." });
            return issues;
        }

        public static List<AuditItem> AuditProtectedFileForActors(string path, IEnumerable<SecurityIdentifier> actorSids, string code)
        {
            List<AuditItem> issues = new List<AuditItem>();
            try
            {
                FileSecurity security = File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
                SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
                List<SecurityIdentifier> checkedSids = new List<SecurityIdentifier>();
                if (actorSids != null) checkedSids.AddRange(actorSids);
                checkedSids.AddRange(BroadWritePrincipals());
                foreach (SecurityIdentifier sid in checkedSids)
                {
                    if (sid.Equals(owner))
                        issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = code, Path = path, Message = "A Codex or broad principal owns this protected file: " + sid.Value });
                }

                AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (FileSystemAccessRule rule in rules)
                {
                    if (rule.AccessControlType != AccessControlType.Allow || !RightsContainWriteLike(rule.FileSystemRights)) continue;
                    SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                    foreach (SecurityIdentifier sid in checkedSids)
                    {
                        if (ruleSid.Equals(sid))
                        {
                            issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = code, Path = path, Message = "A Codex or broad principal has a write-like Allow rule on this protected file: " + sid.Value });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                issues.Add(new AuditItem { Severity = AuditSeverity.Error, Code = code, Path = path, Message = ex.Message });
            }
            return issues;
        }

        public static bool ActiveAllowContainsDelete()
        {
            return (ActiveAllowRights & (FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles)) != 0;
        }

        public static bool RightsContainWriteLike(FileSystemRights rights)
        {
            return (rights & WriteLikeRights) != 0;
        }

        public static bool GuardRulesRoundTripInMemory()
        {
            DirectorySecurity security = new DirectorySecurity();
            SecurityIdentifier sid = IdentityService.BuiltinUsersSid();
            security.AddAccessRule(CreateRule(sid, ActiveAllowRights, AccessControlType.Allow));
            security.AddAccessRule(CreateRule(sid, GuardDenyRights, AccessControlType.Deny));
            security.AddAccessRule(CreateRule(IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow));
            return HasRule(security, sid, ActiveAllowRights, AccessControlType.Allow)
                && HasRule(security, sid, GuardDenyRights, AccessControlType.Deny)
                && HasRule(security, IdentityService.OwnerRightsSid(), OwnerRightsAllowRights, AccessControlType.Allow);
        }

        public static bool DefaultReadOnlyRulesRoundTripInMemory()
        {
            DirectorySecurity boundary = new DirectorySecurity();
            DirectorySecurity rootLock = new DirectorySecurity();
            SecurityIdentifier sid = IdentityService.BuiltinUsersSid();
            boundary.AddAccessRule(CreateRule(sid, ReadOnlyAllowRights, AccessControlType.Allow));
            boundary.AddAccessRule(CreateRule(sid, DefaultReadOnlyDenyRights, AccessControlType.Deny));
            rootLock.AddAccessRule(CreateThisFolderRule(sid, RootOnlyLockDenyRights, AccessControlType.Deny));
            return HasRule(boundary, sid, ReadOnlyAllowRights, AccessControlType.Allow)
                && HasRule(boundary, sid, DefaultReadOnlyDenyRights, AccessControlType.Deny)
                && HasThisFolderRule(rootLock, sid, RootOnlyLockDenyRights, AccessControlType.Deny);
        }

        public static void AssertActivationDescendantAclCompatible(string path, bool isDirectory, IEnumerable<SecurityIdentifier> actorSids)
        {
            FileSystemSecurity security = isDirectory
                ? (FileSystemSecurity)Directory.GetAccessControl(path, AccessControlSections.Access)
                : (FileSystemSecurity)File.GetAccessControl(path, AccessControlSections.Access);
            string issue = FindActivationDescendantAclIssue(security, actorSids);
            if (!string.IsNullOrEmpty(issue)) throw new InvalidDataException(issue + ": " + path);
        }

        internal static string FindActivationDescendantAclIssue(FileSystemSecurity security, IEnumerable<SecurityIdentifier> actorSids)
        {
            if (security == null) throw new ArgumentNullException("security");
            if (security.AreAccessRulesProtected)
                return "A descendant has ACL inheritance disabled and would not receive Codex Guard rules";

            List<SecurityIdentifier> dangerousPrincipals = new List<SecurityIdentifier>();
            if (actorSids != null)
            {
                foreach (SecurityIdentifier sid in actorSids)
                    if (sid != null && !IdentityService.ContainsSid(dangerousPrincipals, sid)) dangerousPrincipals.Add(sid);
            }
            foreach (SecurityIdentifier sid in BroadWritePrincipals())
                if (!IdentityService.ContainsSid(dangerousPrincipals, sid)) dangerousPrincipals.Add(sid);
            dangerousPrincipals.Add(IdentityService.OwnerRightsSid());

            AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow || (rule.FileSystemRights & GuardDenyRights) == 0) continue;
                SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                if (IdentityService.ContainsSid(dangerousPrincipals, ruleSid))
                    return "A descendant has an explicit allow that could override inherited delete/ACL protection | "
                        + ruleSid.Value + " | " + rule.FileSystemRights;
            }
            return null;
        }

        private static FileSystemAccessRule CreateRule(SecurityIdentifier sid, FileSystemRights rights, AccessControlType type)
        {
            return new FileSystemAccessRule(sid, rights, GuardInheritance, GuardPropagation, type);
        }

        private static FileSystemAccessRule CreateThisFolderRule(SecurityIdentifier sid, FileSystemRights rights, AccessControlType type)
        {
            return new FileSystemAccessRule(sid, rights, InheritanceFlags.None, PropagationFlags.None, type);
        }

        private static void AddRuleIfMissing(DirectorySecurity security, FileSystemAccessRule desired)
        {
            SecurityIdentifier sid = (SecurityIdentifier)desired.IdentityReference;
            if (!HasExactRule(security, sid, desired.FileSystemRights, desired.AccessControlType, desired.InheritanceFlags, desired.PropagationFlags))
                security.AddAccessRule(desired);
        }

        private static bool HasRule(DirectorySecurity security, SecurityIdentifier sid, FileSystemRights rights, AccessControlType type)
        {
            AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                if (ruleSid.Equals(sid)
                    && rule.AccessControlType == type
                    && rule.FileSystemRights == rights
                    && rule.InheritanceFlags == GuardInheritance
                    && rule.PropagationFlags == GuardPropagation)
                    return true;
            }
            return false;
        }

        private static bool HasThisFolderRule(DirectorySecurity security, SecurityIdentifier sid, FileSystemRights rights, AccessControlType type)
        {
            return HasExactRule(security, sid, rights, type, InheritanceFlags.None, PropagationFlags.None);
        }

        private static bool HasExactRule(DirectorySecurity security, SecurityIdentifier sid, FileSystemRights rights, AccessControlType type,
            InheritanceFlags inheritance, PropagationFlags propagation)
        {
            AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                if (ruleSid.Equals(sid)
                    && rule.AccessControlType == type
                    && rule.FileSystemRights == rights
                    && rule.InheritanceFlags == inheritance
                    && rule.PropagationFlags == propagation)
                    return true;
            }
            return false;
        }

        private static bool HasRuleContaining(DirectorySecurity security, SecurityIdentifier sid, FileSystemRights rights, AccessControlType type,
            InheritanceFlags inheritance, PropagationFlags propagation)
        {
            AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                if (ruleSid.Equals(sid)
                    && rule.AccessControlType == type
                    && (rule.FileSystemRights & rights) == rights
                    && rule.InheritanceFlags == inheritance
                    && rule.PropagationFlags == propagation)
                    return true;
            }
            return false;
        }

        private static bool HasExplicitWriteAllow(DirectorySecurity security, SecurityIdentifier sid)
        {
            AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                if (ruleSid.Equals(sid) && (rule.FileSystemRights & WriteLikeRights) != 0) return true;
            }
            return false;
        }

        private static void RemoveExplicitWriteAllows(DirectorySecurity security, SecurityIdentifier sid)
        {
            List<FileSystemAccessRule> removals = new List<FileSystemAccessRule>();
            AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                if (ruleSid.Equals(sid) && (rule.FileSystemRights & WriteLikeRights) != 0) removals.Add(rule);
            }
            foreach (FileSystemAccessRule rule in removals) security.RemoveAccessRuleSpecific(rule);
        }

        private static void RemoveGuardRule(DirectorySecurity security, SecurityIdentifier sid, AccessControlType type, FileSystemRights rights)
        {
            FileSystemAccessRule rule = CreateRule(sid, rights, type);
            security.RemoveAccessRuleSpecific(rule);
        }

        private static IEnumerable<SecurityIdentifier> BroadWritePrincipals()
        {
            yield return new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            yield return new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            yield return IdentityService.BuiltinUsersSid();
        }

        private static void StripBroadWriteAllows(DirectorySecurity security, SecurityIdentifier sid, List<string> changes)
        {
            List<FileSystemAccessRule> removals = new List<FileSystemAccessRule>();
            AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                if (ruleSid.Equals(sid) && (rule.FileSystemRights & WriteLikeRights) != 0)
                    removals.Add(rule);
            }

            foreach (FileSystemAccessRule rule in removals)
            {
                security.RemoveAccessRuleSpecific(rule);
                FileSystemRights retained = rule.FileSystemRights & ~WriteLikeRights;
                if ((retained & ReadOnlyAllowRights) != ReadOnlyAllowRights)
                    retained |= ReadOnlyAllowRights;
                FileSystemAccessRule replacement = new FileSystemAccessRule(
                    sid,
                    retained,
                    rule.InheritanceFlags,
                    rule.PropagationFlags,
                    AccessControlType.Allow);
                security.AddAccessRule(replacement);
                changes.Add("Replaced broad write allow with read-only for " + sid.Value + ": " + rule.FileSystemRights);
            }
        }
    }
}
