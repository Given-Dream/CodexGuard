using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CodexGuard.Core
{
    internal sealed class UacStatus
    {
        public bool Enabled { get; set; }
        public bool SecureDesktop { get; set; }
        public bool StandardUsersPromptForCredentialsOnSecureDesktop { get; set; }
        public bool MeetsRequirements
        {
            get { return Enabled && SecureDesktop && StandardUsersPromptForCredentialsOnSecureDesktop; }
        }
    }

    internal static class UacPolicy
    {
        private const string PolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

        [DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        public static UacStatus Read()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(PolicyKey, false))
            {
                int enableLua = ReadDword(key, "EnableLUA", -1);
                int secureDesktop = ReadDword(key, "PromptOnSecureDesktop", -1);
                int standardPrompt = ReadDword(key, "ConsentPromptBehaviorUser", -1);
                return FromRawValues(enableLua, secureDesktop, standardPrompt);
            }
        }

        internal static UacStatus FromRawValues(int enableLua, int secureDesktop, int standardPrompt)
        {
            return new UacStatus
            {
                Enabled = enableLua == 1,
                SecureDesktop = secureDesktop == 1,
                StandardUsersPromptForCredentialsOnSecureDesktop = standardPrompt == 1
            };
        }

        public static bool ApplyRecommended()
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required.");
            bool restartRequired;
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(PolicyKey, true))
            {
                if (key == null) throw new InvalidOperationException("Unable to open the Windows UAC policy key.");
                restartRequired = ReadDword(key, "EnableLUA", -1) != 1;
                key.SetValue("EnableLUA", 1, RegistryValueKind.DWord);
                key.SetValue("PromptOnSecureDesktop", 1, RegistryValueKind.DWord);
                key.SetValue("ConsentPromptBehaviorUser", 1, RegistryValueKind.DWord);
            }
            return restartRequired;
        }

        public static string CurrentBootTimeUtc()
        {
            return (DateTime.UtcNow - TimeSpan.FromMilliseconds(GetTickCount64())).ToString("o");
        }

        public static bool RestartStillRequired(GuardState state)
        {
            if (state == null || !state.UacRestartRequired) return false;
            DateTime recorded;
            DateTime current;
            if (!DateTime.TryParse(state.UacPolicyAppliedBootTimeUtc, null, System.Globalization.DateTimeStyles.RoundtripKind, out recorded)) return true;
            if (!DateTime.TryParse(CurrentBootTimeUtc(), null, System.Globalization.DateTimeStyles.RoundtripKind, out current)) return true;
            return Math.Abs((current.ToUniversalTime() - recorded.ToUniversalTime()).TotalMinutes) < 5;
        }

        public static IEnumerable<AuditItem> Audit()
        {
            UacStatus status = Read();
            if (!status.Enabled)
                yield return new AuditItem { Severity = AuditSeverity.Error, Code = "UAC_DISABLED", Message = "Windows UAC is disabled." };
            if (!status.SecureDesktop)
                yield return new AuditItem { Severity = AuditSeverity.Error, Code = "UAC_NO_SECURE_DESKTOP", Message = "Elevation prompts are not configured for the Windows secure desktop." };
            if (!status.StandardUsersPromptForCredentialsOnSecureDesktop)
                yield return new AuditItem { Severity = AuditSeverity.Error, Code = "UAC_STANDARD_USER_POLICY", Message = "Standard users are not required to enter administrator credentials on the secure desktop." };
        }

        private static int ReadDword(RegistryKey key, string name, int fallback)
        {
            if (key == null) return fallback;
            object value = key.GetValue(name, fallback);
            try { return Convert.ToInt32(value); }
            catch { return fallback; }
        }
    }
}
