using System.Collections.Generic;
using System.Runtime.Serialization;

namespace CodexGuard.Core
{
    internal enum OfflineReuseCategory
    {
        DirectReuse,
        AdminProgramCopy,
        LocalMedia,
        ExistingPackageRegistration,
        PermissionReview,
        LocalPayloadMissing
    }

    internal sealed class OfflineReuseItem
    {
        public string InventoryId { get; set; }
        public string DisplayName { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public string ExistingExecutable { get; set; }
        public string SourceDirectory { get; set; }
        public string RelativeExecutablePath { get; set; }
        public string LocalInstallSource { get; set; }
        public string Scope { get; set; }
        public OfflineReuseCategory Category { get; set; }
        public string Reason { get; set; }
        public string RecommendedAction { get; set; }
        public bool CanPrepareCopy { get; set; }
        public bool RequiresWorkerFirstRun { get; set; }
    }

    internal sealed class OfflineReuseReport
    {
        public string GeneratedAtUtc { get; set; }
        public string AdminProfilePath { get; set; }
        public string WorkerProfilePath { get; set; }
        public List<OfflineReuseItem> Items { get; set; }
        public List<string> Warnings { get; set; }

        public OfflineReuseReport()
        {
            Items = new List<OfflineReuseItem>();
            Warnings = new List<string>();
        }

        public int Count(OfflineReuseCategory category)
        {
            int count = 0;
            foreach (OfflineReuseItem item in Items) if (item.Category == category) count++;
            return count;
        }
    }

    [DataContract]
    internal sealed class OfflineReuseRequest
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string RequestId { get; set; }
        [DataMember(Order = 3)] public string CreatedAtUtc { get; set; }
        [DataMember(Order = 4)] public string RequesterSid { get; set; }
        [DataMember(Order = 5)] public string RequesterMachine { get; set; }
        [DataMember(Order = 6)] public List<OfflineReuseSelection> Applications { get; set; }
    }

    [DataContract]
    internal sealed class OfflineReuseSelection
    {
        [DataMember(Order = 1)] public string InventoryId { get; set; }
        [DataMember(Order = 2)] public string DisplayName { get; set; }
        [DataMember(Order = 3)] public string Publisher { get; set; }
        [DataMember(Order = 4)] public string SourceDirectory { get; set; }
        [DataMember(Order = 5)] public string RelativeExecutablePath { get; set; }
    }

    internal sealed class OfflineReuseCopyPlan
    {
        public OfflineReuseItem Item { get; set; }
        public string SourceDirectory { get; set; }
        public string TargetDirectory { get; set; }
        public string TargetExecutable { get; set; }
        public long FileCount { get; set; }
        public long TotalBytes { get; set; }
    }

    internal sealed class PreparedOfflineReuseRequest
    {
        public OfflineReuseRequest Request { get; set; }
        public GuardState StateSnapshot { get; set; }
        public List<OfflineReuseCopyPlan> Plans { get; set; }

        public PreparedOfflineReuseRequest()
        {
            Plans = new List<OfflineReuseCopyPlan>();
        }
    }

    [DataContract]
    internal sealed class OfflineReuseManifest
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string RequestId { get; set; }
        [DataMember(Order = 3)] public string CreatedAtUtc { get; set; }
        [DataMember(Order = 4)] public string CompletedAtUtc { get; set; }
        [DataMember(Order = 5)] public string MachineName { get; set; }
        [DataMember(Order = 6)] public string WorkerSid { get; set; }
        [DataMember(Order = 7)] public string SafetyStatement { get; set; }
        [DataMember(Order = 8)] public List<OfflineReuseManifestEntry> Applications { get; set; }

        public OfflineReuseManifest()
        {
            Applications = new List<OfflineReuseManifestEntry>();
        }
    }

    [DataContract]
    internal sealed class OfflineReuseManifestEntry
    {
        [DataMember(Order = 1)] public string DisplayName { get; set; }
        [DataMember(Order = 2)] public string SourceDirectory { get; set; }
        [DataMember(Order = 3)] public string TargetDirectory { get; set; }
        [DataMember(Order = 4)] public string TargetExecutable { get; set; }
        [DataMember(Order = 5)] public long FileCount { get; set; }
        [DataMember(Order = 6)] public long TotalBytes { get; set; }
        [DataMember(Order = 7)] public string AggregateSha256 { get; set; }
        [DataMember(Order = 8)] public string MainExecutableSha256 { get; set; }
        [DataMember(Order = 9)] public string WorkerShortcut { get; set; }
        [DataMember(Order = 10)] public string Status { get; set; }
        [DataMember(Order = 11)] public string Error { get; set; }
    }
}
