using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal static class SoftwareMappingRequestService
    {
        private const int MaximumSelections = 128;

        public static string Create(IEnumerable<SoftwareInventoryItem> selected)
        {
            if (!StateStore.Exists) throw new InvalidOperationException("请先安装 Codex Guard。");
            GuardState state = StateStore.Load();
            string requesterSid = IdentityService.CurrentSid();
            if (!IsAllowedRequester(state, requesterSid))
                throw new UnauthorizedAccessException("只有安装时记录的 admin 或 CodexWorker 可以提交软件快捷方式申请。");

            SoftwareShortcutRequest request = new SoftwareShortcutRequest
            {
                SchemaVersion = AppInfo.SoftwareMappingRequestSchemaVersion,
                RequestId = Guid.NewGuid().ToString("D"),
                CreatedAtUtc = AppInfo.UtcNow(),
                RequesterSid = requesterSid,
                RequesterMachine = Environment.MachineName,
                Shortcuts = new List<SoftwareShortcutSelection>()
            };
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (selected != null)
            {
                foreach (SoftwareInventoryItem item in selected)
                {
                    if (item == null || !item.CanCreateShortcut) continue;
                    if (!unique.Add(item.InventoryId)) continue;
                    request.Shortcuts.Add(new SoftwareShortcutSelection
                    {
                        InventoryId = item.InventoryId,
                        DisplayName = item.DisplayName,
                        Publisher = item.Publisher,
                        ExecutablePath = item.ExecutablePath
                    });
                }
            }
            if (request.Shortcuts.Count == 0) throw new InvalidOperationException("没有选中可安全映射的软件。");
            if (request.Shortcuts.Count > MaximumSelections) throw new InvalidOperationException("一次最多映射 " + MaximumSelections + " 个软件。");

            Directory.CreateDirectory(AppPaths.CurrentRequestDirectory);
            string path = Path.Combine(AppPaths.CurrentRequestDirectory, request.RequestId + ".cgs");
            JsonFile.WriteNew(path, request);
            return path;
        }

        public static PreparedSoftwareShortcutRequest ValidateAndPrepare(string requestPath)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("软件映射必须通过 Windows UAC 以管理员身份启动。");
            if (!AppPaths.IsInstalledExecutable())
                throw new InvalidOperationException("软件映射只能由受保护的 Codex Guard 安装副本执行。");
            if (!UacPolicy.Read().MeetsRequirements)
                throw new InvalidOperationException("UAC 安全桌面策略不符合 Codex Guard 要求。");

            SoftwareShortcutRequest request = ValidateRequestFile(requestPath);
            GuardState state = StateStore.Load();
            if (!string.Equals(state.MachineName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("受保护状态属于另一台计算机。");
            if (!IsAllowedRequester(state, request.RequesterSid))
                throw new UnauthorizedAccessException("软件映射申请者不是安装时记录的 admin 或 CodexWorker。");

            PreparedSoftwareShortcutRequest prepared = new PreparedSoftwareShortcutRequest
            {
                Request = request,
                StateSnapshot = state
            };
            prepared.Items.AddRange(ResolveSelections(request, state));
            return prepared;
        }

        public static OperationResult Execute(PreparedSoftwareShortcutRequest prepared)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required.");
            if (prepared == null || prepared.Request == null || prepared.StateSnapshot == null) throw new ArgumentNullException("prepared");
            GuardState current = StateStore.Load();
            if (!string.Equals(current.UpdatedAtUtc, prepared.StateSnapshot.UpdatedAtUtc, StringComparison.Ordinal)
                || !string.Equals(current.WorkerSid, prepared.StateSnapshot.WorkerSid, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(current.AdminProfilePath, prepared.StateSnapshot.AdminProfilePath, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("确认窗口打开期间 Codex Guard 身份状态已变化；没有创建快捷方式。");
            if (!IsAllowedRequester(current, prepared.Request.RequesterSid))
                throw new UnauthorizedAccessException("软件映射申请者已不再符合受保护身份状态。");

            List<SoftwareInventoryItem> verified = ResolveSelections(prepared.Request, current);
            OperationResult result = new OperationResult();
            foreach (SoftwareInventoryItem item in verified)
            {
                string safetyReason;
                if (!SoftwareMappingService.IsSafeSharedExecutablePath(item.ExecutablePath, current, out safetyReason))
                    throw new InvalidOperationException("创建前的最终 EXE 核验失败：" + item.DisplayName + " — " + safetyReason);
                string shortcut = ShortcutService.CreateMappedSoftwareCommonStartMenuShortcut(item.DisplayName, item.ExecutablePath, item.Publisher);
                result.Messages.Add(item.DisplayName + " → " + shortcut);
            }
            result.Success = true;
            result.Summary = "已创建或确认 " + verified.Count + " 个公共开始菜单快捷方式；没有复制、安装、移动或删除软件文件。";
            GuardLog.Write(prepared.Request.RequestId, "SOFTWARE_SHORTCUT_MAPPING", true, result.Summary);
            return result;
        }

        private static SoftwareShortcutRequest ValidateRequestFile(string requestPath)
        {
            string full = Path.GetFullPath(requestPath);
            FileInfo info = new FileInfo(full);
            if (!info.Exists) throw new FileNotFoundException("软件映射申请文件不存在。", full);
            if (!string.Equals(info.Extension, ".cgs", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("软件映射申请文件扩展名无效。");
            if (info.Length <= 0 || info.Length > AppInfo.MaxRequestBytes)
                throw new InvalidDataException("软件映射申请文件大小无效。");
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("软件映射申请文件不能是重解析点。");

            SoftwareShortcutRequest request = JsonFile.Read<SoftwareShortcutRequest>(full, AppInfo.MaxRequestBytes);
            if (request == null || request.SchemaVersion != AppInfo.SoftwareMappingRequestSchemaVersion)
                throw new InvalidDataException("不支持的软件映射申请格式。");
            Guid requestId;
            if (!Guid.TryParse(request.RequestId, out requestId)
                || !string.Equals(Path.GetFileNameWithoutExtension(full), requestId.ToString("D"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("软件映射申请 ID 与文件名不一致。");
            if (!string.Equals(request.RequesterMachine, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("软件映射申请来自另一台计算机。");

            DateTime created;
            if (!DateTime.TryParse(request.CreatedAtUtc, null, System.Globalization.DateTimeStyles.RoundtripKind, out created))
                throw new InvalidDataException("软件映射申请时间无效。");
            TimeSpan age = DateTime.UtcNow - created.ToUniversalTime();
            if (age < TimeSpan.FromMinutes(-1) || age > TimeSpan.FromMinutes(AppInfo.RequestLifetimeMinutes))
                throw new InvalidDataException("软件映射申请已过期。");

            SecurityIdentifier requester = new SecurityIdentifier(request.RequesterSid);
            string profile = IdentityService.GetProfilePathForSid(requester.Value);
            if (string.IsNullOrWhiteSpace(profile)) throw new InvalidDataException("无法解析软件映射申请者资料路径。");
            string expected = Path.Combine(profile, "AppData", "Local", AppInfo.ProductName, "Requests");
            if (!AppPaths.PathsEqual(Path.GetDirectoryName(full), expected))
                throw new InvalidDataException("软件映射申请不在申请者的固定收件箱中。");

            FileSecurity security = File.GetAccessControl(full, AccessControlSections.Owner);
            SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
            if (!owner.Equals(requester)) throw new InvalidDataException("软件映射申请文件所有者与申请者不一致。");
            if (request.Shortcuts == null || request.Shortcuts.Count == 0 || request.Shortcuts.Count > MaximumSelections)
                throw new InvalidDataException("软件映射申请数量无效。");
            return request;
        }

        private static List<SoftwareInventoryItem> ResolveSelections(SoftwareShortcutRequest request, GuardState state)
        {
            SoftwareInventoryReport current = SoftwareMappingService.Capture(state);
            Dictionary<string, SoftwareInventoryItem> byId = new Dictionary<string, SoftwareInventoryItem>(StringComparer.OrdinalIgnoreCase);
            foreach (SoftwareInventoryItem item in current.Items)
                if (!string.IsNullOrWhiteSpace(item.InventoryId) && !byId.ContainsKey(item.InventoryId)) byId.Add(item.InventoryId, item);

            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<SoftwareInventoryItem> resolved = new List<SoftwareInventoryItem>();
            foreach (SoftwareShortcutSelection selection in request.Shortcuts)
            {
                if (selection == null || string.IsNullOrWhiteSpace(selection.InventoryId) || !unique.Add(selection.InventoryId))
                    throw new InvalidDataException("软件映射申请包含空白或重复项目。");
                SoftwareInventoryItem item;
                if (!byId.TryGetValue(selection.InventoryId, out item) || !item.CanCreateShortcut)
                    throw new InvalidDataException("软件清单已变化，或项目不再允许自动创建快捷方式：" + (selection.DisplayName ?? selection.InventoryId));
                if (!string.Equals(item.DisplayName, selection.DisplayName, StringComparison.Ordinal)
                    || !string.Equals(item.Publisher ?? string.Empty, selection.Publisher ?? string.Empty, StringComparison.Ordinal)
                    || !AppPaths.PathsEqual(item.ExecutablePath, selection.ExecutablePath))
                    throw new InvalidDataException("软件映射申请内容与管理员重新扫描结果不一致：" + item.DisplayName);
                resolved.Add(item);
            }
            return resolved;
        }

        internal static bool IsAllowedRequester(GuardState state, string sid)
        {
            if (state == null || string.IsNullOrWhiteSpace(sid)) return false;
            if (!string.IsNullOrWhiteSpace(state.WorkerSid)
                && string.Equals(state.WorkerSid, sid, StringComparison.OrdinalIgnoreCase)) return true;
            string adminSid = SoftwareMappingService.FindProfileSid(state.AdminProfilePath);
            return !string.IsNullOrWhiteSpace(adminSid) && string.Equals(adminSid, sid, StringComparison.OrdinalIgnoreCase);
        }

        public static bool CanCurrentUserSubmit()
        {
            try { return StateStore.Exists && IsAllowedRequester(StateStore.Load(), IdentityService.CurrentSid()); }
            catch { return false; }
        }
    }
}
