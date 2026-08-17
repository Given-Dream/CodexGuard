using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace CodexGuard.Core
{
    [DataContract]
    internal sealed class GuardState
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string ProductVersion { get; set; }
        [DataMember(Order = 3)] public string MachineName { get; set; }
        [DataMember(Order = 4)] public string WorkerAccountName { get; set; }
        [DataMember(Order = 5)] public string WorkerSid { get; set; }
        [DataMember(Order = 6)] public string SandboxGroupSid { get; set; }
        [DataMember(Order = 7)] public string AdminProfilePath { get; set; }
        [DataMember(Order = 8)] public string InstalledAtUtc { get; set; }
        [DataMember(Order = 9)] public string UpdatedAtUtc { get; set; }
        [DataMember(Order = 10)] public bool CodexRequirementsConfigured { get; set; }
        [DataMember(Order = 11)] public bool UacSecureDesktopVerified { get; set; }
        [DataMember(Order = 12)] public List<GuardedDirectory> ActivatedDirectories { get; set; }
        // Serialized name retained for state compatibility. Since 0.6.1 this slot may
        // contain only the fixed administrator-profile boundary.
        [DataMember(Order = 13)] public List<GuardedDirectory> ProtectedRoots { get; set; }
        [DataMember(Order = 14)] public List<string> ProcessedRequestIds { get; set; }
        [DataMember(Order = 15)] public bool UacRestartRequired { get; set; }
        [DataMember(Order = 16)] public string UacPolicyAppliedBootTimeUtc { get; set; }
        [DataMember(Order = 17)] public string WorkerProfilePath { get; set; }
        [DataMember(Order = 18)] public bool DefaultReadOnlyEnabled { get; set; }
        [DataMember(Order = 19)] public string DefaultReadOnlyAppliedAtUtc { get; set; }
        [DataMember(Order = 20)] public List<GuardedDirectory> DefaultReadOnlyDirectories { get; set; }
        [DataMember(Order = 21)] public List<GuardedDirectory> DefaultReadOnlyRootLocks { get; set; }
        [DataMember(Order = 22)] public List<string> WritableExceptionPaths { get; set; }

        public static GuardState CreateDefault()
        {
            string now = AppInfo.UtcNow();
            return new GuardState
            {
                SchemaVersion = AppInfo.StateSchemaVersion,
                ProductVersion = AppInfo.Version,
                MachineName = Environment.MachineName,
                WorkerAccountName = AppInfo.WorkerAccountName,
                InstalledAtUtc = now,
                UpdatedAtUtc = now,
                ActivatedDirectories = new List<GuardedDirectory>(),
                ProtectedRoots = new List<GuardedDirectory>(),
                ProcessedRequestIds = new List<string>(),
                DefaultReadOnlyDirectories = new List<GuardedDirectory>(),
                DefaultReadOnlyRootLocks = new List<GuardedDirectory>(),
                WritableExceptionPaths = new List<string>()
            };
        }

        public void Normalize()
        {
            if (ActivatedDirectories == null) ActivatedDirectories = new List<GuardedDirectory>();
            if (ProtectedRoots == null) ProtectedRoots = new List<GuardedDirectory>();
            if (ProcessedRequestIds == null) ProcessedRequestIds = new List<string>();
            if (DefaultReadOnlyDirectories == null) DefaultReadOnlyDirectories = new List<GuardedDirectory>();
            if (DefaultReadOnlyRootLocks == null) DefaultReadOnlyRootLocks = new List<GuardedDirectory>();
            if (WritableExceptionPaths == null) WritableExceptionPaths = new List<string>();
        }
    }

    [DataContract]
    internal sealed class GuardedDirectory
    {
        [DataMember(Order = 1)] public string Path { get; set; }
        [DataMember(Order = 2)] public string CanonicalPath { get; set; }
        [DataMember(Order = 3)] public uint VolumeSerialNumber { get; set; }
        [DataMember(Order = 4)] public uint FileIndexHigh { get; set; }
        [DataMember(Order = 5)] public uint FileIndexLow { get; set; }
        [DataMember(Order = 6)] public string OriginalSddl { get; set; }
        [DataMember(Order = 7)] public string ActivatedAtUtc { get; set; }
        [DataMember(Order = 8)] public string LastVerifiedAtUtc { get; set; }
        [DataMember(Order = 9)] public bool ContainsReparsePoint { get; set; }
    }

    [DataContract]
    internal enum GuardOperation
    {
        [EnumMember] Activate,
        [EnumMember] Revoke,
        [EnumMember] Repair,
        [EnumMember] BindSandbox,
        [EnumMember] ApplyDefaultReadOnly,
        [EnumMember] ImportPolicy
    }

    [DataContract]
    internal sealed class GuardRequest
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string RequestId { get; set; }
        [DataMember(Order = 3)] public string CreatedAtUtc { get; set; }
        [DataMember(Order = 4)] public string RequesterSid { get; set; }
        [DataMember(Order = 5)] public string RequesterMachine { get; set; }
        [DataMember(Order = 6)] public GuardOperation Operation { get; set; }
        [DataMember(Order = 7)] public List<string> Paths { get; set; }
        [DataMember(Order = 9)] public string Comment { get; set; }

        public static GuardRequest Create(GuardOperation operation, IEnumerable<string> paths, string requesterSid)
        {
            return new GuardRequest
            {
                SchemaVersion = AppInfo.RequestSchemaVersion,
                RequestId = Guid.NewGuid().ToString("D"),
                CreatedAtUtc = AppInfo.UtcNow(),
                RequesterSid = requesterSid,
                RequesterMachine = Environment.MachineName,
                Operation = operation,
                Paths = paths == null ? new List<string>() : new List<string>(paths)
            };
        }

        public static GuardRequest CreateImport(IEnumerable<string> activePaths, string requesterSid)
        {
            return Create(GuardOperation.ImportPolicy, activePaths, requesterSid);
        }
    }

    [DataContract]
    internal sealed class PortablePolicy
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string ProductVersion { get; set; }
        [DataMember(Order = 3)] public string ExportedAtUtc { get; set; }
        [DataMember(Order = 4)] public string SourceMachine { get; set; }
        [DataMember(Order = 5)] public string WorkerAccountName { get; set; }
        [DataMember(Order = 7)] public List<string> ActivatedPaths { get; set; }
        [DataMember(Order = 9)] public string Note { get; set; }

        public static PortablePolicy FromState(GuardState state)
        {
            PortablePolicy policy = new PortablePolicy
            {
                SchemaVersion = AppInfo.PolicySchemaVersion,
                ProductVersion = AppInfo.Version,
                ExportedAtUtc = AppInfo.UtcNow(),
                SourceMachine = Environment.MachineName,
                WorkerAccountName = AppInfo.WorkerAccountName,
                ActivatedPaths = new List<string>(),
                Note = "This file exports activated project paths only and intentionally excludes passwords, login tokens, local SIDs, administrator-profile protection, and raw ACL backups."
            };

            foreach (GuardedDirectory item in state.ActivatedDirectories)
                policy.ActivatedPaths.Add(item.CanonicalPath ?? item.Path);
            return policy;
        }
    }

    [DataContract]
    internal sealed class DeletionRequest
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string RequestId { get; set; }
        [DataMember(Order = 3)] public string CreatedAtUtc { get; set; }
        [DataMember(Order = 4)] public string RequesterMachine { get; set; }
        [DataMember(Order = 5)] public string RequesterAccount { get; set; }
        [DataMember(Order = 6)] public string RequesterSid { get; set; }
        [DataMember(Order = 7)] public List<string> Paths { get; set; }
        [DataMember(Order = 8)] public string Reason { get; set; }
        [DataMember(Order = 9)] public string Status { get; set; }
        [DataMember(Order = 10)] public string SafetyNote { get; set; }
    }

    internal enum AuditSeverity
    {
        Info,
        Warning,
        Error
    }

    internal sealed class AuditItem
    {
        public AuditSeverity Severity { get; set; }
        public string Code { get; set; }
        public string Path { get; set; }
        public string Message { get; set; }

        public override string ToString()
        {
            string location = string.IsNullOrEmpty(Path) ? string.Empty : " [" + Path + "]";
            return Severity + " " + Code + location + ": " + Message;
        }
    }

    [DataContract]
    internal sealed class ReviewReport
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string GeneratedAtUtc { get; set; }
        [DataMember(Order = 3)] public string ProductVersion { get; set; }
        [DataMember(Order = 4)] public string MachineName { get; set; }
        [DataMember(Order = 5)] public string CurrentIdentity { get; set; }
        [DataMember(Order = 6)] public string CurrentSid { get; set; }
        [DataMember(Order = 7)] public string OverallStatus { get; set; }
        [DataMember(Order = 8)] public string ScopeStatement { get; set; }
        [DataMember(Order = 9)] public int FailureCount { get; set; }
        [DataMember(Order = 10)] public int WarningCount { get; set; }
        [DataMember(Order = 11)] public int ManualCheckCount { get; set; }
        [DataMember(Order = 12)] public List<ReviewEvidence> Controls { get; set; }
        [DataMember(Order = 13)] public List<ReviewEvidence> Findings { get; set; }
        [DataMember(Order = 14)] public List<ReviewFact> Facts { get; set; }

        public ReviewReport()
        {
            Controls = new List<ReviewEvidence>();
            Findings = new List<ReviewEvidence>();
            Facts = new List<ReviewFact>();
        }
    }

    [DataContract]
    internal sealed class ReviewEvidence
    {
        [DataMember(Order = 1)] public string Status { get; set; }
        [DataMember(Order = 2)] public string Control { get; set; }
        [DataMember(Order = 3)] public string Expected { get; set; }
        [DataMember(Order = 4)] public string Actual { get; set; }
        [DataMember(Order = 5)] public string EvidenceSource { get; set; }
        [DataMember(Order = 6)] public string Path { get; set; }
        [DataMember(Order = 7)] public string ManualAction { get; set; }
    }

    [DataContract]
    internal sealed class ReviewFact
    {
        [DataMember(Order = 1)] public string Name { get; set; }
        [DataMember(Order = 2)] public string Value { get; set; }
    }

    [DataContract]
    internal sealed class RecordSyncProfileSnapshot
    {
        [DataMember(Order = 1)] public string Role { get; set; }
        [DataMember(Order = 2)] public string ProfilePath { get; set; }
        [DataMember(Order = 3)] public string CodexDataPath { get; set; }
        [DataMember(Order = 4)] public bool ProfileExists { get; set; }
        [DataMember(Order = 5)] public bool CodexDataExists { get; set; }
        [DataMember(Order = 6)] public bool CodexDataIsReparsePoint { get; set; }
        [DataMember(Order = 7)] public bool AuthenticationMarkerExists { get; set; }
        [DataMember(Order = 8)] public bool SessionIndexExists { get; set; }
        [DataMember(Order = 9)] public long SessionFileCount { get; set; }
        [DataMember(Order = 10)] public long SessionBytes { get; set; }
        [DataMember(Order = 11)] public string NewestSessionUtc { get; set; }
        [DataMember(Order = 12)] public int SqliteDatabaseCount { get; set; }
        [DataMember(Order = 13)] public int LiveDatabaseSidecarCount { get; set; }
        [DataMember(Order = 14)] public bool LinkedCriticalEntryDetected { get; set; }
        [DataMember(Order = 15)] public string InspectionError { get; set; }
    }

    [DataContract]
    internal sealed class RecordSyncReport
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string GeneratedAtUtc { get; set; }
        [DataMember(Order = 3)] public string ProductVersion { get; set; }
        [DataMember(Order = 4)] public string MachineName { get; set; }
        [DataMember(Order = 5)] public string SyncMode { get; set; }
        [DataMember(Order = 6)] public string OfficialDocumentation { get; set; }
        [DataMember(Order = 7)] public string OverallStatus { get; set; }
        [DataMember(Order = 8)] public string PrivacyStatement { get; set; }
        [DataMember(Order = 9)] public List<RecordSyncProfileSnapshot> Profiles { get; set; }
        [DataMember(Order = 10)] public List<ReviewEvidence> Checks { get; set; }

        public RecordSyncReport()
        {
            Profiles = new List<RecordSyncProfileSnapshot>();
            Checks = new List<ReviewEvidence>();
        }
    }

    internal sealed class OperationResult
    {
        public bool Success { get; set; }
        public string Summary { get; set; }
        public List<string> Messages { get; private set; }

        public OperationResult()
        {
            Messages = new List<string>();
        }
    }
}
