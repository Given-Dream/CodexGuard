using System;
using System.Collections.Generic;
using System.IO;

namespace CodexGuard.Core
{
    internal static class DeletionRequestService
    {
        public static string Submit(IEnumerable<string> requestedPaths, string reason)
        {
            if (!StateStore.Exists) throw new InvalidOperationException("Install Codex Guard before submitting a deletion request.");
            GuardState state = StateStore.Load();
            if (!string.Equals(state.MachineName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The Codex Guard state belongs to another computer.");
            if (!IdentityService.CurrentIdentityIsGuardActor(state))
                throw new UnauthorizedAccessException("Only CodexWorker or an account in CodexSandboxUsers may submit deletion requests.");
            if (!Directory.Exists(AppPaths.DeleteRequestsDirectory))
                throw new DirectoryNotFoundException("The protected deletion-request directory is missing. Run Install/Repair first.");

            List<string> paths = new List<string>();
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (requestedPaths != null)
            {
                foreach (string input in requestedPaths)
                {
                    string full = PathSafety.NormalizeDeletionCandidate(input);
                    if (!IsInsideActivatedPaths(full, state.ActivatedDirectories))
                        throw new InvalidDataException("Deletion requests are accepted only for an activated project or its descendants: " + full);
                    if (!unique.Add(full)) throw new InvalidDataException("Duplicate deletion target: " + full);
                    paths.Add(full);
                }
            }
            if (paths.Count == 0) throw new InvalidOperationException("Select at least one file or directory.");
            if (paths.Count > 128) throw new InvalidOperationException("A deletion request may contain at most 128 targets.");

            string normalizedReason = (reason ?? string.Empty).Trim();
            if (normalizedReason.Length > 2000) throw new InvalidOperationException("The deletion reason may contain at most 2000 characters.");
            DeletionRequest request = new DeletionRequest
            {
                SchemaVersion = AppInfo.DeletionRequestSchemaVersion,
                RequestId = Guid.NewGuid().ToString("D"),
                CreatedAtUtc = AppInfo.UtcNow(),
                RequesterMachine = Environment.MachineName,
                RequesterAccount = Environment.UserDomainName + "\\" + Environment.UserName,
                RequesterSid = IdentityService.CurrentSid(),
                Paths = paths,
                Reason = normalizedReason,
                Status = "Pending administrator review",
                SafetyNote = "Codex Guard did not move or delete these targets. An administrator must inspect and act manually."
            };
            string fileName = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + request.RequestId + ".delete-request.json";
            string requestPath = Path.Combine(AppPaths.DeleteRequestsDirectory, fileName);
            JsonFile.WriteNew(requestPath, request);
            GuardLog.Write(request.RequestId, "DELETE_REQUEST", true, "Submitted " + paths.Count + " target(s) for administrator review.");
            return requestPath;
        }

        internal static bool IsInsideActivatedPaths(string path, IEnumerable<GuardedDirectory> activeDirectories)
        {
            if (string.IsNullOrWhiteSpace(path) || activeDirectories == null) return false;
            foreach (GuardedDirectory active in activeDirectories)
            {
                if (active != null && !string.IsNullOrWhiteSpace(active.CanonicalPath)
                    && AppPaths.IsPathInside(path, active.CanonicalPath))
                    return true;
            }
            return false;
        }
    }
}
