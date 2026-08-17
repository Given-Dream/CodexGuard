using System;

namespace CodexGuard.Core
{
    internal static class AppInfo
    {
        public const string ProductName = "Codex Guard";
        public const string ExecutableName = "CodexGuard.exe";
        public const string ReviewerExecutableName = "CodexGuard.ReadOnlyVerifier.exe";
        public const string AcceptanceExecutableName = "CodexGuard.AcceptanceProbe.exe";
        public const string WorkerAccountName = "CodexWorker";
        public const string SandboxGroupName = "CodexSandboxUsers";
        public const string AdminAccountName = "admin";
        public const string AdminProfilePath = @"C:\Users\admin";
        public const int StateSchemaVersion = 1;
        public const int RequestSchemaVersion = 2;
        public const int PolicySchemaVersion = 2;
        public const int DeletionRequestSchemaVersion = 1;
        public const int ReviewReportSchemaVersion = 1;
        public const int MaxRequestBytes = 128 * 1024;
        public const int RequestLifetimeMinutes = 15;
        public const int RecordSyncReportSchemaVersion = 2;
        public const int SoftwareMappingRequestSchemaVersion = 1;
        public const int OfflineReuseRequestSchemaVersion = 1;
        public const int OfflineReuseManifestSchemaVersion = 1;
        public const string Version = "0.6.7";

        public static string UtcNow()
        {
            return DateTime.UtcNow.ToString("o");
        }
    }
}
