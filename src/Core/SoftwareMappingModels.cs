using System.Collections.Generic;
using System.Runtime.Serialization;

namespace CodexGuard.Core
{
    internal enum SoftwareMappingCategory
    {
        SharedReady,
        ShortcutRequired,
        WorkerRegistrationRequired,
        SeparateInstallRequired
    }

    internal sealed class SoftwareInventoryItem
    {
        public string InventoryId { get; set; }
        public string DisplayName { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public string ExecutablePath { get; set; }
        public string InstallLocation { get; set; }
        public string LocalInstallSource { get; set; }
        public string Source { get; set; }
        public string Scope { get; set; }
        public bool LocalInstallSourceExists { get; set; }
        public bool IsWindowsInstaller { get; set; }
        public bool IsStoreLike { get; set; }
        public bool IsAdminScoped { get; set; }
        public bool RequiresArguments { get; set; }
        public SoftwareMappingCategory Category { get; set; }
        public string Reason { get; set; }
        public string RecommendedAction { get; set; }
        public bool CanCreateShortcut { get; set; }
        public bool HasCommonShortcut { get; set; }
    }

    internal sealed class SoftwareInventoryReport
    {
        public string GeneratedAtUtc { get; set; }
        public string AdminProfilePath { get; set; }
        public List<SoftwareInventoryItem> Items { get; set; }
        public List<string> Warnings { get; set; }

        public SoftwareInventoryReport()
        {
            Items = new List<SoftwareInventoryItem>();
            Warnings = new List<string>();
        }

        public int Count(SoftwareMappingCategory category)
        {
            int count = 0;
            foreach (SoftwareInventoryItem item in Items)
                if (item.Category == category) count++;
            return count;
        }
    }

    [DataContract]
    internal sealed class SoftwareShortcutRequest
    {
        [DataMember(Order = 1)] public int SchemaVersion { get; set; }
        [DataMember(Order = 2)] public string RequestId { get; set; }
        [DataMember(Order = 3)] public string CreatedAtUtc { get; set; }
        [DataMember(Order = 4)] public string RequesterSid { get; set; }
        [DataMember(Order = 5)] public string RequesterMachine { get; set; }
        [DataMember(Order = 6)] public List<SoftwareShortcutSelection> Shortcuts { get; set; }
    }

    [DataContract]
    internal sealed class SoftwareShortcutSelection
    {
        [DataMember(Order = 1)] public string InventoryId { get; set; }
        [DataMember(Order = 2)] public string DisplayName { get; set; }
        [DataMember(Order = 3)] public string Publisher { get; set; }
        [DataMember(Order = 4)] public string ExecutablePath { get; set; }
    }

    internal sealed class PreparedSoftwareShortcutRequest
    {
        public SoftwareShortcutRequest Request { get; set; }
        public GuardState StateSnapshot { get; set; }
        public List<SoftwareInventoryItem> Items { get; set; }

        public PreparedSoftwareShortcutRequest()
        {
            Items = new List<SoftwareInventoryItem>();
        }
    }
}
