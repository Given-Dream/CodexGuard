using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal static class IdentityService
    {
        public static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        public static string CurrentSid()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                return identity.User == null ? string.Empty : identity.User.Value;
            }
        }

        public static string MachineAccount(string accountName)
        {
            return Environment.MachineName + "\\" + accountName;
        }

        public static SecurityIdentifier ResolveSid(string accountName)
        {
            if (string.IsNullOrWhiteSpace(accountName)) throw new ArgumentException("Account name is required.", "accountName");
            IdentityReference translated = new NTAccount(accountName).Translate(typeof(SecurityIdentifier));
            return (SecurityIdentifier)translated;
        }

        public static bool TryResolveSid(string accountName, out SecurityIdentifier sid)
        {
            try
            {
                sid = ResolveSid(accountName);
                return true;
            }
            catch (IdentityNotMappedException)
            {
                sid = null;
                return false;
            }
        }

        public static List<SecurityIdentifier> ResolveActorSids(GuardState state, bool requireWorker)
        {
            List<SecurityIdentifier> result = new List<SecurityIdentifier>();
            SecurityIdentifier worker;
            string workerName = IdentityService.MachineAccount(AppInfo.WorkerAccountName);
            if (TryResolveSid(workerName, out worker))
            {
                if (state != null && !string.IsNullOrWhiteSpace(state.WorkerSid)
                    && !string.Equals(state.WorkerSid, worker.Value, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("CodexWorker was recreated and its SID no longer matches protected state. Run the administrator installation/repair flow before changing permissions.");
                result.Add(worker);
            }
            else if (requireWorker)
                throw new InvalidOperationException("The local CodexWorker account does not exist.");

            SecurityIdentifier sandbox;
            string sandboxName = IdentityService.MachineAccount(AppInfo.SandboxGroupName);
            if (TryResolveSid(sandboxName, out sandbox) && !ContainsSid(result, sandbox))
                result.Add(sandbox);

            string adminSid = state == null ? null : FindProfileSid(state.AdminProfilePath);
            if (state != null && !string.IsNullOrWhiteSpace(state.AdminProfilePath) && string.IsNullOrWhiteSpace(adminSid))
                throw new InvalidOperationException("The admin profile SID could not be resolved. No Codex Guard ACL operation is allowed.");
            AssertAdministratorNotRestricted(result, adminSid);
            if (!string.IsNullOrWhiteSpace(adminSid))
                AssertAdministratorNotInSandboxGroup(LocalAccountService.GetLocalGroupMemberships(AppInfo.AdminAccountName));
            return result;
        }

        internal static void AssertAdministratorNotRestricted(IEnumerable<SecurityIdentifier> restrictedSids, string adminSidValue)
        {
            if (string.IsNullOrWhiteSpace(adminSidValue)) return;
            SecurityIdentifier adminSid;
            try { adminSid = new SecurityIdentifier(adminSidValue); }
            catch (ArgumentException ex) { throw new InvalidDataException("The administrator profile SID is invalid.", ex); }
            if (ContainsSid(restrictedSids, adminSid))
                throw new InvalidOperationException("The admin account SID appeared in the Codex Guard restriction set. No ACL changes are allowed.");
        }

        internal static void AssertAdministratorNotInSandboxGroup(IEnumerable<string> groupNames)
        {
            if (groupNames == null) return;
            foreach (string groupName in groupNames)
            {
                if (string.Equals(groupName, AppInfo.SandboxGroupName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("The admin account is a member of CodexSandboxUsers. No ACL changes are allowed until admin is removed from that group.");
            }
        }

        public static bool ContainsSid(IEnumerable<SecurityIdentifier> values, SecurityIdentifier target)
        {
            foreach (SecurityIdentifier value in values)
                if (value != null && value.Equals(target)) return true;
            return false;
        }

        public static bool CurrentIdentityIsGuardActor(GuardState state)
        {
            if (state == null) return false;
            string currentSid = CurrentSid();
            if (!string.IsNullOrWhiteSpace(state.WorkerSid)
                && string.Equals(currentSid, state.WorkerSid, StringComparison.OrdinalIgnoreCase))
                return true;

            SecurityIdentifier sandbox;
            if (!TryResolveSid(MachineAccount(AppInfo.SandboxGroupName), out sandbox)) return false;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(identity).IsInRole(sandbox);
            }
        }

        public static string GetProfilePathForSid(string sidValue)
        {
            if (string.IsNullOrWhiteSpace(sidValue)) return null;
            const string baseKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(baseKey + "\\" + sidValue, false))
            {
                if (key == null) return null;
                object raw = key.GetValue("ProfileImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (raw == null) return null;
                return Path.GetFullPath(Environment.ExpandEnvironmentVariables(Convert.ToString(raw)));
            }
        }

        public static string FindProfileSid(string profilePath)
        {
            if (string.IsNullOrWhiteSpace(profilePath)) return null;
            string expected;
            try { expected = AppPaths.NormalizeDirectoryPath(profilePath); }
            catch { return null; }
            const string profileList = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
            try
            {
                using (RegistryKey root = Registry.LocalMachine.OpenSubKey(profileList, false))
                {
                    if (root == null) return null;
                    foreach (string sid in root.GetSubKeyNames())
                    {
                        using (RegistryKey entry = root.OpenSubKey(sid, false))
                        {
                            if (entry == null) continue;
                            object raw = entry.GetValue("ProfileImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                            if (raw == null) continue;
                            string actual = Environment.ExpandEnvironmentVariables(Convert.ToString(raw));
                            if (AppPaths.PathsEqual(actual, expected)) return sid;
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        public static SecurityIdentifier BuiltinAdministratorsSid()
        {
            return new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        }

        public static SecurityIdentifier LocalSystemSid()
        {
            return new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        }

        public static SecurityIdentifier BuiltinUsersSid()
        {
            return new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        }

        public static SecurityIdentifier CreatorOwnerSid()
        {
            return new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null);
        }

        public static SecurityIdentifier OwnerRightsSid()
        {
            // S-1-3-4 disables the owner's implicit READ_CONTROL/WRITE_DAC grant when an ACE for it is present.
            return new SecurityIdentifier("S-1-3-4");
        }
    }
}
