using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace CodexGuard.Core
{
    internal static class OfflineReuseRequestService
    {
        private const int MaximumApplications = 64;
        private const long MaximumFiles = 250000;
        private const long MaximumBytes = 200L * 1024L * 1024L * 1024L;

        public static string Create(IEnumerable<OfflineReuseItem> selected)
        {
            if (!StateStore.Exists) throw new InvalidOperationException("请先安装 Codex Guard。");
            GuardState state = StateStore.Load();
            string requesterSid = IdentityService.CurrentSid();
            if (!SoftwareMappingRequestService.IsAllowedRequester(state, requesterSid))
                throw new UnauthorizedAccessException("只有安装时记录的 admin 或 CodexWorker 可以提交离线复用申请。");

            OfflineReuseRequest request = new OfflineReuseRequest
            {
                SchemaVersion = AppInfo.OfflineReuseRequestSchemaVersion,
                RequestId = Guid.NewGuid().ToString("D"),
                CreatedAtUtc = AppInfo.UtcNow(),
                RequesterSid = requesterSid,
                RequesterMachine = Environment.MachineName,
                Applications = new List<OfflineReuseSelection>()
            };
            HashSet<string> roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (selected != null)
            {
                foreach (OfflineReuseItem item in selected)
                {
                    if (item == null || !item.CanPrepareCopy || string.IsNullOrWhiteSpace(item.SourceDirectory)) continue;
                    string source = AppPaths.NormalizeDirectoryPath(item.SourceDirectory);
                    if (!roots.Add(source)) continue;
                    request.Applications.Add(new OfflineReuseSelection
                    {
                        InventoryId = item.InventoryId,
                        DisplayName = item.DisplayName,
                        Publisher = item.Publisher,
                        SourceDirectory = source,
                        RelativeExecutablePath = item.RelativeExecutablePath
                    });
                }
            }
            if (request.Applications.Count == 0) throw new InvalidOperationException("没有选中可安全提取的 admin AppData 程序。");
            if (request.Applications.Count > MaximumApplications) throw new InvalidOperationException("一次最多准备 " + MaximumApplications + " 个本地程序副本。");

            Directory.CreateDirectory(AppPaths.CurrentRequestDirectory);
            string path = Path.Combine(AppPaths.CurrentRequestDirectory, request.RequestId + ".cgr");
            JsonFile.WriteNew(path, request);
            return path;
        }

        public static PreparedOfflineReuseRequest ValidateAndPrepare(string requestPath)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("离线复用必须通过 Windows UAC 以管理员身份启动。");
            if (!AppPaths.IsInstalledExecutable()) throw new InvalidOperationException("离线复用只能由受保护的 Codex Guard 安装副本执行。");
            if (!UacPolicy.Read().MeetsRequirements) throw new InvalidOperationException("UAC 安全桌面策略不符合 Codex Guard 要求。");

            OfflineReuseRequest request = ValidateRequestFile(requestPath);
            GuardState state = StateStore.Load();
            if (!string.Equals(state.MachineName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("受保护状态属于另一台计算机。");
            if (!SoftwareMappingRequestService.IsAllowedRequester(state, request.RequesterSid))
                throw new UnauthorizedAccessException("离线复用申请者不是安装时记录的 admin 或 CodexWorker。");

            PreparedOfflineReuseRequest prepared = new PreparedOfflineReuseRequest
            {
                Request = request,
                StateSnapshot = state
            };
            prepared.Plans.AddRange(ResolveSelections(request, state));
            ValidateFreeSpace(prepared.Plans);
            return prepared;
        }

        public static OperationResult Execute(PreparedOfflineReuseRequest prepared)
        {
            if (!IdentityService.IsAdministrator()) throw new UnauthorizedAccessException("Administrator elevation is required.");
            if (prepared == null || prepared.Request == null || prepared.StateSnapshot == null) throw new ArgumentNullException("prepared");
            GuardState state = StateStore.Load();
            if (!string.Equals(state.UpdatedAtUtc, prepared.StateSnapshot.UpdatedAtUtc, StringComparison.Ordinal)
                || !string.Equals(state.WorkerSid, prepared.StateSnapshot.WorkerSid, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(state.WorkerProfilePath, prepared.StateSnapshot.WorkerProfilePath, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(state.AdminProfilePath, prepared.StateSnapshot.AdminProfilePath, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("确认窗口打开期间 Codex Guard 身份状态已变化；没有开始复制。");
            if (!SoftwareMappingRequestService.IsAllowedRequester(state, prepared.Request.RequesterSid))
                throw new UnauthorizedAccessException("离线复用申请者已不再符合受保护身份状态。");

            List<OfflineReuseCopyPlan> plans = ResolveSelections(prepared.Request, state);
            ValidateFreeSpace(plans);
            EnsureSafeWorkerParent(state);
            SecurityIdentifier worker = new SecurityIdentifier(state.WorkerSid);
            SecurityIdentifier sandbox = string.IsNullOrWhiteSpace(state.SandboxGroupSid) ? null : new SecurityIdentifier(state.SandboxGroupSid);
            OfflineReuseManifest manifest = new OfflineReuseManifest
            {
                SchemaVersion = AppInfo.OfflineReuseManifestSchemaVersion,
                RequestId = prepared.Request.RequestId,
                CreatedAtUtc = prepared.Request.CreatedAtUtc,
                MachineName = Environment.MachineName,
                WorkerSid = state.WorkerSid,
                SafetyStatement = "Source application files were opened read-only. Codex Guard did not move, overwrite, delete, install, execute, or import registry data."
            };
            OperationResult result = new OperationResult();
            int completed = 0;
            foreach (OfflineReuseCopyPlan plan in plans)
            {
                OfflineReuseManifestEntry entry = new OfflineReuseManifestEntry
                {
                    DisplayName = plan.Item.DisplayName,
                    SourceDirectory = plan.SourceDirectory,
                    TargetDirectory = plan.TargetDirectory,
                    TargetExecutable = plan.TargetExecutable,
                    FileCount = plan.FileCount,
                    TotalBytes = plan.TotalBytes,
                    Status = "PREPARED"
                };
                manifest.Applications.Add(entry);
                try
                {
                    NativePath.CreateDirectoryNew(plan.TargetDirectory);
                    AclService.SecureApplicationDirectory(plan.TargetDirectory, false);
                    string mainHash;
                    entry.AggregateSha256 = CopyTreeCreateNew(plan, out mainHash);
                    entry.MainExecutableSha256 = mainHash;
                    AclService.SecureWorkerApplicationDirectory(plan.TargetDirectory, worker, sandbox);
                    entry.WorkerShortcut = ShortcutService.CreateWorkerOfflineReuseShortcut(state, plan.Item.DisplayName, plan.TargetExecutable, plan.Item.Publisher);
                    entry.Status = "COPIED_REQUIRES_WORKER_FIRST_RUN";
                    completed++;
                    result.Messages.Add(plan.Item.DisplayName + " → " + plan.TargetDirectory + "（只复制；等待 Worker 首次运行）");
                }
                catch (Exception ex)
                {
                    entry.Status = "PARTIAL_REVIEW_REQUIRED";
                    entry.Error = ex.Message;
                    result.Messages.Add(plan.Item.DisplayName + "：未完成；任何已创建内容均保留供 admin 人工核查。原因：" + ex.Message);
                }
            }

            manifest.CompletedAtUtc = AppInfo.UtcNow();
            AclService.SecureApplicationDirectory(AppPaths.OfflineReuseHistoryDirectory, false);
            string manifestPath = Path.Combine(AppPaths.OfflineReuseHistoryDirectory, prepared.Request.RequestId + ".json");
            JsonFile.WriteNew(manifestPath, manifest);
            AclService.SecureApplicationFile(manifestPath, false);
            result.Success = completed == plans.Count;
            result.Summary = "已完整准备 " + completed + "/" + plans.Count + " 个 Worker 本地程序副本。源文件未修改；没有执行安装器、导入注册表、覆盖或删除文件。审计清单：" + manifestPath;
            GuardLog.Write(prepared.Request.RequestId, "OFFLINE_REUSE_COPY", result.Success, result.Summary);
            return result;
        }

        public static bool CanCurrentUserSubmit()
        {
            try { return StateStore.Exists && SoftwareMappingRequestService.IsAllowedRequester(StateStore.Load(), IdentityService.CurrentSid()); }
            catch { return false; }
        }

        private static OfflineReuseRequest ValidateRequestFile(string requestPath)
        {
            string full = Path.GetFullPath(requestPath);
            FileInfo info = new FileInfo(full);
            if (!info.Exists) throw new FileNotFoundException("离线复用申请文件不存在。", full);
            if (!string.Equals(info.Extension, ".cgr", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("离线复用申请文件扩展名无效。");
            if (info.Length <= 0 || info.Length > AppInfo.MaxRequestBytes) throw new InvalidDataException("离线复用申请文件大小无效。");
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("离线复用申请文件不能是重解析点。");

            OfflineReuseRequest request = JsonFile.Read<OfflineReuseRequest>(full, AppInfo.MaxRequestBytes);
            if (request == null || request.SchemaVersion != AppInfo.OfflineReuseRequestSchemaVersion) throw new InvalidDataException("不支持的离线复用申请格式。");
            Guid id;
            if (!Guid.TryParse(request.RequestId, out id)
                || !string.Equals(Path.GetFileNameWithoutExtension(full), id.ToString("D"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("离线复用申请 ID 与文件名不一致。");
            if (!string.Equals(request.RequesterMachine, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("离线复用申请来自另一台计算机。");
            DateTime created;
            if (!DateTime.TryParse(request.CreatedAtUtc, null, DateTimeStyles.RoundtripKind, out created)) throw new InvalidDataException("离线复用申请时间无效。");
            TimeSpan age = DateTime.UtcNow - created.ToUniversalTime();
            if (age < TimeSpan.FromMinutes(-1) || age > TimeSpan.FromMinutes(AppInfo.RequestLifetimeMinutes)) throw new InvalidDataException("离线复用申请已过期。");

            SecurityIdentifier requester = new SecurityIdentifier(request.RequesterSid);
            string profile = IdentityService.GetProfilePathForSid(requester.Value);
            if (string.IsNullOrWhiteSpace(profile)) throw new InvalidDataException("无法解析离线复用申请者资料路径。");
            string expected = Path.Combine(profile, "AppData", "Local", AppInfo.ProductName, "Requests");
            if (!AppPaths.PathsEqual(Path.GetDirectoryName(full), expected)) throw new InvalidDataException("离线复用申请不在申请者的固定收件箱中。");
            FileSecurity security = File.GetAccessControl(full, AccessControlSections.Owner);
            SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
            if (!owner.Equals(requester)) throw new InvalidDataException("离线复用申请文件所有者与申请者不一致。");
            if (request.Applications == null || request.Applications.Count == 0 || request.Applications.Count > MaximumApplications)
                throw new InvalidDataException("离线复用申请数量无效。");
            return request;
        }

        private static List<OfflineReuseCopyPlan> ResolveSelections(OfflineReuseRequest request, GuardState state)
        {
            OfflineReuseReport current = OfflineReuseService.Capture(state);
            Dictionary<string, OfflineReuseItem> byId = new Dictionary<string, OfflineReuseItem>(StringComparer.OrdinalIgnoreCase);
            foreach (OfflineReuseItem item in current.Items)
                if (!string.IsNullOrWhiteSpace(item.InventoryId) && !byId.ContainsKey(item.InventoryId)) byId.Add(item.InventoryId, item);

            HashSet<string> roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<OfflineReuseCopyPlan> plans = new List<OfflineReuseCopyPlan>();
            long files = 0;
            long bytes = 0;
            foreach (OfflineReuseSelection selection in request.Applications)
            {
                if (selection == null || string.IsNullOrWhiteSpace(selection.InventoryId)) throw new InvalidDataException("离线复用申请包含空白项目。");
                OfflineReuseItem item;
                if (!byId.TryGetValue(selection.InventoryId, out item) || !item.CanPrepareCopy)
                    throw new InvalidDataException("软件清单已变化，或项目不再允许提取：" + (selection.DisplayName ?? selection.InventoryId));
                if (!string.Equals(item.DisplayName, selection.DisplayName, StringComparison.Ordinal)
                    || !string.Equals(item.Publisher ?? string.Empty, selection.Publisher ?? string.Empty, StringComparison.Ordinal)
                    || !AppPaths.PathsEqual(item.SourceDirectory, selection.SourceDirectory)
                    || !string.Equals(item.RelativeExecutablePath, selection.RelativeExecutablePath, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("离线复用申请与管理员重新扫描结果不一致：" + item.DisplayName);
                if (!roots.Add(item.SourceDirectory)) throw new InvalidDataException("离线复用申请包含重复源目录：" + item.SourceDirectory);

                OfflineReuseCopyPlan plan = BuildPlan(item, state);
                files += plan.FileCount;
                bytes += plan.TotalBytes;
                if (files > MaximumFiles || bytes > MaximumBytes)
                    throw new InvalidDataException("所选程序超过离线复用安全上限（" + MaximumFiles + " 个文件 / 200 GB）。请分批处理。");
                plans.Add(plan);
            }
            return plans;
        }

        private static OfflineReuseCopyPlan BuildPlan(OfflineReuseItem item, GuardState state)
        {
            string registeredWorkerProfile = IdentityService.GetProfilePathForSid(state.WorkerSid);
            if (string.IsNullOrWhiteSpace(registeredWorkerProfile) || string.IsNullOrWhiteSpace(state.WorkerProfilePath)
                || !AppPaths.PathsEqual(registeredWorkerProfile, state.WorkerProfilePath))
                throw new InvalidDataException("CodexWorker 用户资料路径尚未可靠记录；请先安装/修复 Codex Guard。");
            string source;
            string relative;
            if (!OfflineReuseService.TryGetAdminLocalProgramsSource(item.ExistingExecutable, state.AdminProfilePath, out source, out relative)
                || !AppPaths.PathsEqual(source, item.SourceDirectory)
                || !string.Equals(relative, item.RelativeExecutablePath, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("源程序不再位于 admin AppData\\Local\\Programs 的单一应用目录内。");
            EnsureSourceAncestorsAreNotReparsePoints(source, state.AdminProfilePath);
            long fileCount;
            long totalBytes;
            InspectSourceTree(source, out fileCount, out totalBytes);
            string target = OfflineReuseService.BuildWorkerTargetDirectory(state.WorkerProfilePath, source);
            if (Directory.Exists(target) || File.Exists(target))
                throw new IOException("Worker 目标已存在；Codex Guard 不会覆盖或合并：" + target);
            string targetExecutable = Path.GetFullPath(Path.Combine(target, relative));
            if (!AppPaths.IsPathInside(targetExecutable, target) || AppPaths.PathsEqual(targetExecutable, target))
                throw new InvalidDataException("目标主程序越过 Worker 应用目录边界。");
            return new OfflineReuseCopyPlan
            {
                Item = item,
                SourceDirectory = source,
                TargetDirectory = target,
                TargetExecutable = targetExecutable,
                FileCount = fileCount,
                TotalBytes = totalBytes
            };
        }

        internal static void InspectSourceTree(string sourceDirectory, out long fileCount, out long totalBytes)
        {
            string source = AppPaths.NormalizeDirectoryPath(sourceDirectory);
            if (!Directory.Exists(source)) throw new DirectoryNotFoundException("源程序目录不存在：" + source);
            fileCount = 0;
            totalBytes = 0;
            Queue<string> pending = new Queue<string>();
            pending.Enqueue(source);
            while (pending.Count > 0)
            {
                string directory = pending.Dequeue();
                if (!AppPaths.IsPathInside(directory, source)) throw new InvalidDataException("源目录枚举越过应用边界。");
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("源程序包含目录联接或其他重解析点：" + directory);
                foreach (string child in Directory.GetDirectories(directory)) pending.Enqueue(child);
                foreach (string file in Directory.GetFiles(directory))
                {
                    if (!AppPaths.IsPathInside(file, source)) throw new InvalidDataException("源文件枚举越过应用边界。");
                    if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidDataException("源程序包含文件重解析点：" + file);
                    if (NativePath.GetFileLinkCount(file) != 1)
                        throw new InvalidDataException("源程序包含多硬链接文件，拒绝自动复制：" + file);
                    FileInfo info = new FileInfo(file);
                    fileCount++;
                    totalBytes += info.Length;
                    if (fileCount > MaximumFiles || totalBytes > MaximumBytes)
                        throw new InvalidDataException("单个源程序超过离线复用安全上限。");
                }
            }
            if (fileCount == 0) throw new InvalidDataException("源程序目录为空。");
        }

        private static void EnsureSourceAncestorsAreNotReparsePoints(string sourceDirectory, string adminProfile)
        {
            string boundary = AppPaths.NormalizeDirectoryPath(Path.Combine(adminProfile, "AppData", "Local", "Programs"));
            string current = AppPaths.NormalizeDirectoryPath(sourceDirectory);
            while (AppPaths.IsPathInside(current, boundary))
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("源程序路径包含重解析点：" + current);
                if (AppPaths.PathsEqual(current, boundary)) break;
                current = Path.GetDirectoryName(current);
            }
        }

        private static void EnsureSafeWorkerParent(GuardState state)
        {
            string workerProfile = IdentityService.GetProfilePathForSid(state.WorkerSid);
            if (string.IsNullOrWhiteSpace(workerProfile) || !Directory.Exists(workerProfile)) throw new DirectoryNotFoundException("CodexWorker 用户资料尚未初始化。");
            if ((File.GetAttributes(workerProfile) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("CodexWorker 用户资料不能是重解析点。");
            string root = AppPaths.WorkerLocalProgramsDirectory(state);
            Directory.CreateDirectory(root);
            string current = root;
            while (AppPaths.IsPathInside(current, workerProfile))
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Worker Local\\Programs 路径包含重解析点：" + current);
                if (AppPaths.PathsEqual(current, workerProfile)) break;
                current = Path.GetDirectoryName(current);
            }
        }

        private static void ValidateFreeSpace(List<OfflineReuseCopyPlan> plans)
        {
            long total = 0;
            foreach (OfflineReuseCopyPlan plan in plans) total += plan.TotalBytes;
            if (plans.Count == 0) throw new InvalidDataException("离线复用计划为空。");
            string root = Path.GetPathRoot(plans[0].TargetDirectory);
            DriveInfo drive = new DriveInfo(root);
            long reserve = 512L * 1024L * 1024L;
            if (drive.AvailableFreeSpace < total + reserve)
                throw new IOException("Worker 用户资料所在磁盘空间不足；至少保留复制体积外加 512 MB 余量。");
        }

        internal static string CopyTreeCreateNew(OfflineReuseCopyPlan plan, out string mainExecutableHash)
        {
            List<string> directories;
            List<string> files;
            EnumerateSourceTreeSafely(plan.SourceDirectory, out directories, out files);
            directories.Sort(delegate(string left, string right)
            {
                int depth = left.Length.CompareTo(right.Length);
                return depth != 0 ? depth : string.Compare(left, right, StringComparison.OrdinalIgnoreCase);
            });
            foreach (string sourceDirectory in directories)
            {
                string relative = RelativePath(plan.SourceDirectory, sourceDirectory);
                string targetDirectory = Path.GetFullPath(Path.Combine(plan.TargetDirectory, relative));
                if (!AppPaths.IsPathInside(targetDirectory, plan.TargetDirectory)) throw new InvalidDataException("目标目录越过 Worker 应用边界。");
                NativePath.CreateDirectoryNew(targetDirectory);
            }

            files.Sort(StringComparer.OrdinalIgnoreCase);
            long copiedFiles = 0;
            long copiedBytes = 0;
            mainExecutableHash = null;
            using (SHA256 aggregate = SHA256.Create())
            {
                foreach (string sourceFile in files)
                {
                    if ((File.GetAttributes(sourceFile) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("复制期间检测到文件重解析点：" + sourceFile);
                    if (NativePath.GetFileLinkCount(sourceFile) != 1) throw new InvalidDataException("复制期间检测到多硬链接文件：" + sourceFile);
                    string relative = RelativePath(plan.SourceDirectory, sourceFile);
                    string targetFile = Path.GetFullPath(Path.Combine(plan.TargetDirectory, relative));
                    if (!AppPaths.IsPathInside(targetFile, plan.TargetDirectory)) throw new InvalidDataException("目标文件越过 Worker 应用边界。");
                    string hash = CopyFileCreateNew(sourceFile, targetFile);
                    long length = new FileInfo(targetFile).Length;
                    copiedFiles++;
                    copiedBytes += length;
                    AddAggregateFact(aggregate, relative.Replace('\\', '/') + "|" + length.ToString(CultureInfo.InvariantCulture) + "|" + hash + "\n");
                    if (AppPaths.PathsEqual(targetFile, plan.TargetExecutable)) mainExecutableHash = hash;
                }
                aggregate.TransformFinalBlock(new byte[0], 0, 0);
                if (copiedFiles != plan.FileCount || copiedBytes != plan.TotalBytes)
                    throw new IOException("复制期间源程序的文件数量或总大小发生变化；保留目标供 admin 核查。");
                if (string.IsNullOrWhiteSpace(mainExecutableHash) || !File.Exists(plan.TargetExecutable))
                    throw new FileNotFoundException("复制完成后没有找到计划中的主 EXE。", plan.TargetExecutable);
                return Hex(aggregate.Hash);
            }
        }

        private static void EnumerateSourceTreeSafely(string sourceDirectory, out List<string> directories, out List<string> files)
        {
            string source = AppPaths.NormalizeDirectoryPath(sourceDirectory);
            directories = new List<string>();
            files = new List<string>();
            Queue<string> pending = new Queue<string>();
            pending.Enqueue(source);
            while (pending.Count > 0)
            {
                string directory = pending.Dequeue();
                if (!AppPaths.IsPathInside(directory, source)) throw new InvalidDataException("复制期间源目录越过应用边界。");
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("复制期间检测到目录重解析点：" + directory);
                foreach (string child in Directory.GetDirectories(directory))
                {
                    if (!AppPaths.IsPathInside(child, source)) throw new InvalidDataException("复制期间子目录越过应用边界。");
                    if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidDataException("复制期间检测到目录重解析点：" + child);
                    directories.Add(child);
                    pending.Enqueue(child);
                }
                foreach (string file in Directory.GetFiles(directory))
                {
                    if (!AppPaths.IsPathInside(file, source)) throw new InvalidDataException("复制期间源文件越过应用边界。");
                    if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidDataException("复制期间检测到文件重解析点：" + file);
                    files.Add(file);
                }
            }
        }

        private static string CopyFileCreateNew(string sourcePath, string targetPath)
        {
            byte[] buffer = new byte[1024 * 1024];
            using (SHA256 hash = SHA256.Create())
            using (FileStream source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (FileStream target = new FileStream(targetPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    target.Write(buffer, 0, read);
                    hash.TransformBlock(buffer, 0, read, buffer, 0);
                }
                hash.TransformFinalBlock(new byte[0], 0, 0);
                target.Flush(true);
                return Hex(hash.Hash);
            }
        }

        private static void AddAggregateFact(HashAlgorithm hash, string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
        }

        private static string RelativePath(string root, string child)
        {
            string normalizedRoot = AppPaths.NormalizeDirectoryPath(root);
            string full = Path.GetFullPath(child);
            if (!AppPaths.IsPathInside(full, normalizedRoot) || AppPaths.PathsEqual(full, normalizedRoot))
                throw new InvalidDataException("路径不在计划源目录内。");
            return full.Substring(normalizedRoot.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        private static string Hex(byte[] bytes)
        {
            StringBuilder text = new StringBuilder(bytes.Length * 2);
            foreach (byte value in bytes) text.Append(value.ToString("x2"));
            return text.ToString();
        }
    }
}
