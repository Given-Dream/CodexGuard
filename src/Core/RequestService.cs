using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal static class RequestService
    {
        public static string CreateRequest(GuardOperation operation, IEnumerable<string> paths)
        {
            string requesterSid = IdentityService.CurrentSid();
            if (string.IsNullOrEmpty(requesterSid)) throw new InvalidOperationException("Unable to identify the requesting user.");
            Directory.CreateDirectory(AppPaths.CurrentRequestDirectory);
            GuardRequest request = GuardRequest.Create(operation, paths, requesterSid);
            string path = Path.Combine(AppPaths.CurrentRequestDirectory, request.RequestId + ".cgr");
            JsonFile.WriteNew(path, request);
            return path;
        }

        public static string CreateImportRequest(IEnumerable<string> activePaths)
        {
            string requesterSid = IdentityService.CurrentSid();
            if (string.IsNullOrEmpty(requesterSid)) throw new InvalidOperationException("Unable to identify the requesting user.");
            Directory.CreateDirectory(AppPaths.CurrentRequestDirectory);
            GuardRequest request = GuardRequest.CreateImport(activePaths, requesterSid);
            string path = Path.Combine(AppPaths.CurrentRequestDirectory, request.RequestId + ".cgr");
            JsonFile.WriteNew(path, request);
            return path;
        }

        public static GuardRequest ValidateAndRead(string requestPath)
        {
            string full = Path.GetFullPath(requestPath);
            FileInfo info = new FileInfo(full);
            if (!info.Exists) throw new FileNotFoundException("Request file does not exist.", full);
            if (!string.Equals(info.Extension, ".cgr", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Unexpected request file extension.");
            if (info.Length <= 0 || info.Length > AppInfo.MaxRequestBytes)
                throw new InvalidDataException("Request file size is invalid.");
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Request files cannot be reparse points.");

            GuardRequest request = JsonFile.Read<GuardRequest>(full, AppInfo.MaxRequestBytes);
            if (request == null || request.SchemaVersion != AppInfo.RequestSchemaVersion)
                throw new InvalidDataException("Unsupported request schema.");
            Guid parsedId;
            if (!Guid.TryParse(request.RequestId, out parsedId))
                throw new InvalidDataException("Request ID is invalid.");
            if (!string.Equals(Path.GetFileNameWithoutExtension(full), parsedId.ToString("D"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Request file name does not match its request ID.");
            if (!string.Equals(request.RequesterMachine, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The request came from a different computer.");

            DateTime created;
            if (!DateTime.TryParse(request.CreatedAtUtc, null, System.Globalization.DateTimeStyles.RoundtripKind, out created))
                throw new InvalidDataException("Request timestamp is invalid.");
            TimeSpan age = DateTime.UtcNow - created.ToUniversalTime();
            if (age < TimeSpan.FromMinutes(-1) || age > TimeSpan.FromMinutes(AppInfo.RequestLifetimeMinutes))
                throw new InvalidDataException("The request has expired.");

            SecurityIdentifier requester = new SecurityIdentifier(request.RequesterSid);
            string profile = IdentityService.GetProfilePathForSid(requester.Value);
            if (string.IsNullOrEmpty(profile)) throw new InvalidDataException("Unable to resolve the requester profile.");
            string expectedDirectory = Path.Combine(profile, "AppData", "Local", AppInfo.ProductName, "Requests");
            if (!AppPaths.PathsEqual(Path.GetDirectoryName(full), expectedDirectory))
                throw new InvalidDataException("Request file is outside the requester's fixed inbox.");

            FileSecurity security = File.GetAccessControl(full, AccessControlSections.Owner);
            SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
            if (!owner.Equals(requester)) throw new InvalidDataException("Request file owner does not match the requester.");

            if (request.Paths == null) request.Paths = new List<string>();
            if (request.Paths.Count > 128) throw new InvalidDataException("Too many directories in a single request.");
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string path in request.Paths)
            {
                string normalized = PathSafety.NormalizeLexical(path);
                if (!unique.Add(normalized)) throw new InvalidDataException("Duplicate directory in request: " + normalized);
            }
            return request;
        }
    }
}
