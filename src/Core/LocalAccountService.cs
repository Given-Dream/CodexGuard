using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace CodexGuard.Core
{
    internal static class LocalAccountService
    {
        private const uint UserPrivilegeUser = 1;
        private const uint UserFlagScript = 0x0001;
        private const uint UserFlagNormalAccount = 0x0200;
        private const int NerrSuccess = 0;
        private const int NerrUserExists = 2224;
        private const int ErrorMemberInAlias = 1378;
        private const int ErrorNoSuchMember = 1387;
        private const int ErrorMemberNotInAlias = 1377;
        private const int ErrorNoSuchAlias = 1376;
        private const int MaxPreferredLength = -1;
        private const int IncludeIndirectGroups = 1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct UserInfo1
        {
            public string Name;
            public string Password;
            public uint PasswordAge;
            public uint Privilege;
            public string HomeDirectory;
            public string Comment;
            public uint Flags;
            public string ScriptPath;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LocalGroupMembersInfo3
        {
            public string DomainAndName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LocalGroupUsersInfo0
        {
            public IntPtr Name;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetUserAdd(string serverName, int level, ref UserInfo1 buffer, out uint parameterError);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetLocalGroupAddMembers(string serverName, string groupName, int level, ref LocalGroupMembersInfo3 buffer, int totalEntries);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetLocalGroupDelMembers(string serverName, string groupName, int level, ref LocalGroupMembersInfo3 buffer, int totalEntries);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetUserGetLocalGroups(
            string serverName,
            string userName,
            int level,
            int flags,
            out IntPtr buffer,
            int preferredMaximumLength,
            out int entriesRead,
            out int totalEntries);

        [DllImport("Netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int CreateProfile(string userSid, string userName, StringBuilder profilePath, uint profilePathLength);

        public static bool AccountExists(string accountName, out SecurityIdentifier sid)
        {
            return IdentityService.TryResolveSid(IdentityService.MachineAccount(accountName), out sid);
        }

        public static SecurityIdentifier EnsureStandardWorker(string password, bool removePrivilegedMemberships, out bool created)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required.");
            SecurityIdentifier existing;
            if (AccountExists(AppInfo.WorkerAccountName, out existing))
            {
                created = false;
                if (removePrivilegedMemberships) RemoveFromPrivilegedGroups();
                EnsureBuiltinUsersMembership();
                return existing;
            }

            if (string.IsNullOrEmpty(password) || password.Length < 12)
                throw new InvalidOperationException("CodexWorker password must contain at least 12 characters.");

            UserInfo1 info = new UserInfo1
            {
                Name = AppInfo.WorkerAccountName,
                Password = password,
                PasswordAge = 0,
                Privilege = UserPrivilegeUser,
                HomeDirectory = null,
                Comment = "Low-privilege interactive account managed by Codex Guard",
                Flags = UserFlagScript | UserFlagNormalAccount,
                ScriptPath = null
            };
            uint parameterError;
            int result = NetUserAdd(null, 1, ref info, out parameterError);
            info.Password = null;
            if (result != NerrSuccess && result != NerrUserExists)
                throw new Win32Exception(result, "Unable to create CodexWorker. Parameter index: " + parameterError);

            created = result == NerrSuccess;
            EnsureBuiltinUsersMembership();
            if (removePrivilegedMemberships) RemoveFromPrivilegedGroups();

            SecurityIdentifier sid;
            if (!AccountExists(AppInfo.WorkerAccountName, out sid))
                throw new InvalidOperationException("CodexWorker was created but its SID could not be resolved.");
            return sid;
        }

        public static List<string> GetLocalGroupMemberships(string accountName)
        {
            if (string.IsNullOrWhiteSpace(accountName)) throw new ArgumentException("Account name is required.", "accountName");
            IntPtr buffer = IntPtr.Zero;
            int entriesRead;
            int totalEntries;
            int result = NetUserGetLocalGroups(
                null,
                accountName,
                0,
                IncludeIndirectGroups,
                out buffer,
                MaxPreferredLength,
                out entriesRead,
                out totalEntries);
            if (result != NerrSuccess) throw new Win32Exception(result, "Unable to read local group memberships for " + accountName + ".");

            List<string> memberships = new List<string>();
            try
            {
                int size = Marshal.SizeOf(typeof(LocalGroupUsersInfo0));
                for (int index = 0; index < entriesRead; index++)
                {
                    IntPtr current = new IntPtr(buffer.ToInt64() + (long)(index * size));
                    LocalGroupUsersInfo0 value = (LocalGroupUsersInfo0)Marshal.PtrToStructure(current, typeof(LocalGroupUsersInfo0));
                    string name = Marshal.PtrToStringUni(value.Name);
                    if (!string.IsNullOrWhiteSpace(name)) memberships.Add(name);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
            memberships.Sort(StringComparer.OrdinalIgnoreCase);
            return memberships;
        }

        public static List<string> FindPrivilegedMemberships(IEnumerable<string> groupNames)
        {
            List<string> result = new List<string>();
            if (groupNames == null) return result;
            foreach (string groupName in groupNames)
            {
                SecurityIdentifier groupSid;
                if (!IdentityService.TryResolveSid(IdentityService.MachineAccount(groupName), out groupSid)) continue;
                if (IsPrivilegedGroupSid(groupSid)) result.Add(groupName + " (" + groupSid.Value + ")");
            }
            return result;
        }

        internal static bool IsPrivilegedGroupSid(SecurityIdentifier sid)
        {
            if (sid == null) return false;
            WellKnownSidType[] privileged =
            {
                WellKnownSidType.BuiltinAdministratorsSid,
                WellKnownSidType.BuiltinPowerUsersSid,
                WellKnownSidType.BuiltinBackupOperatorsSid,
                WellKnownSidType.BuiltinAccountOperatorsSid,
                WellKnownSidType.BuiltinSystemOperatorsSid,
                WellKnownSidType.BuiltinPrintOperatorsSid
            };
            foreach (WellKnownSidType type in privileged)
                if (sid.Equals(new SecurityIdentifier(type, null))) return true;
            return false;
        }

        public static string EnsureProfile(SecurityIdentifier workerSid)
        {
            string existing = IdentityService.GetProfilePathForSid(workerSid.Value);
            if (!string.IsNullOrEmpty(existing)) return existing;

            StringBuilder path = new StringBuilder(1024);
            int result = CreateProfile(workerSid.Value, AppInfo.WorkerAccountName, path, (uint)path.Capacity);
            if (result != 0)
                throw new InvalidOperationException("Unable to create the CodexWorker Windows profile.", Marshal.GetExceptionForHR(result));
            return path.ToString();
        }

        private static void EnsureBuiltinUsersMembership()
        {
            NTAccount translated = (NTAccount)IdentityService.BuiltinUsersSid().Translate(typeof(NTAccount));
            string group = AccountLeafName(translated.Value);
            LocalGroupMembersInfo3 member = new LocalGroupMembersInfo3 { DomainAndName = IdentityService.MachineAccount(AppInfo.WorkerAccountName) };
            int result = NetLocalGroupAddMembers(null, group, 3, ref member, 1);
            if (result != NerrSuccess && result != ErrorMemberInAlias)
                throw new Win32Exception(result, "Unable to add CodexWorker to the built-in Users group.");
        }

        private static void RemoveFromPrivilegedGroups()
        {
            WellKnownSidType[] groups =
            {
                WellKnownSidType.BuiltinAdministratorsSid,
                WellKnownSidType.BuiltinPowerUsersSid,
                WellKnownSidType.BuiltinBackupOperatorsSid,
                WellKnownSidType.BuiltinAccountOperatorsSid,
                WellKnownSidType.BuiltinSystemOperatorsSid,
                WellKnownSidType.BuiltinPrintOperatorsSid
            };
            foreach (WellKnownSidType group in groups) RemoveFromBuiltinGroup(group);
        }

        private static void RemoveFromBuiltinGroup(WellKnownSidType groupSidType)
        {
            string group;
            try
            {
                NTAccount translated = (NTAccount)new SecurityIdentifier(groupSidType, null).Translate(typeof(NTAccount));
                group = AccountLeafName(translated.Value);
            }
            catch (IdentityNotMappedException)
            {
                return;
            }
            LocalGroupMembersInfo3 member = new LocalGroupMembersInfo3 { DomainAndName = IdentityService.MachineAccount(AppInfo.WorkerAccountName) };
            int result = NetLocalGroupDelMembers(null, group, 3, ref member, 1);
            if (result != NerrSuccess && result != ErrorNoSuchMember && result != ErrorMemberNotInAlias && result != ErrorNoSuchAlias)
                throw new Win32Exception(result, "Unable to remove CodexWorker from the privileged local group " + group + ".");
        }

        private static string AccountLeafName(string value)
        {
            int slash = value.LastIndexOf('\\');
            return slash >= 0 ? value.Substring(slash + 1) : value;
        }
    }
}
