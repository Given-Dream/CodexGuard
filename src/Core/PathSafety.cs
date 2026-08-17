using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;

namespace CodexGuard.Core
{
    internal sealed class PathValidationResult
    {
        public string InputPath { get; set; }
        public string FullPath { get; set; }
        public PathIdentity Identity { get; set; }
        public int ScannedEntries { get; set; }
    }

    internal static class PathSafety
    {
        private static readonly string[] ForbiddenProfileSegments =
        {
            "AppData", ".ssh", ".gnupg", ".aws", ".azure", ".codex"
        };

        public static string NormalizeLexical(string input)
        {
            string full = NormalizeLocalDrivePath(input, false);
            RejectSystemLocation(full);
            RejectUserProfileRootOrSensitiveArea(full);
            return full;
        }

        private static string NormalizeLocalDrivePath(string input, bool allowDriveRoot)
        {
            if (string.IsNullOrWhiteSpace(input)) throw new InvalidDataException("Directory path is empty.");
            string trimmed = input.Trim();
            if (!Path.IsPathRooted(trimmed)) throw new InvalidDataException("Relative paths are not allowed.");
            if (trimmed.StartsWith(@"\\", StringComparison.Ordinal)) throw new InvalidDataException("UNC and device paths are not allowed.");
            if (trimmed.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Device paths are not allowed.");

            int colon = trimmed.IndexOf(':');
            if (colon != 1 || trimmed.IndexOf(':', colon + 1) >= 0)
                throw new InvalidDataException("Only a normal drive-letter path is allowed; alternate data streams are rejected.");
            if (trimmed.Length < 3 || (trimmed[2] != Path.DirectorySeparatorChar && trimmed[2] != Path.AltDirectorySeparatorChar))
                throw new InvalidDataException("Drive-relative paths such as D:folder are not allowed.");

            string full = AppPaths.NormalizeDirectoryPath(trimmed);
            string root = Path.GetPathRoot(full);
            if (string.IsNullOrEmpty(root)) throw new InvalidDataException("The path has no local volume root.");
            if (!allowDriveRoot && AppPaths.PathsEqual(full, root))
                throw new InvalidDataException("A drive root can never be activated.");
            return full;
        }

        public static PathValidationResult ValidateExistingDirectory(string input, bool scanDescendants)
        {
            return ValidateExistingDirectory(input, scanDescendants, null);
        }

        public static PathValidationResult ValidateExistingDirectory(string input, bool scanDescendants, IEnumerable<SecurityIdentifier> actorSids)
        {
            string full = NormalizeLexical(input);
            if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Directory does not exist: " + full);

            DriveInfo drive = new DriveInfo(Path.GetPathRoot(full));
            if (!drive.IsReady) throw new InvalidDataException("The target volume is not ready.");
            if (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable)
                throw new InvalidDataException("Only local fixed or removable volumes are supported.");
            if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Codex Guard requires an NTFS target volume.");

            RejectReparsePointOnPathOrAncestors(full);
            int scanned = scanDescendants ? ScanForReparsePoints(full, 500000, actorSids) : 0;
            PathIdentity identity = NativePath.GetDirectoryIdentity(full);
            if (!AppPaths.PathsEqual(full, identity.CanonicalPath))
                throw new InvalidDataException("The final filesystem path differs from the selected path.");

            return new PathValidationResult
            {
                InputPath = input,
                FullPath = full,
                Identity = identity,
                ScannedEntries = scanned
            };
        }

        public static string NormalizeDeletionCandidate(string input)
        {
            string full = NormalizeLocalDrivePath(input, false);
            if (!File.Exists(full) && !Directory.Exists(full))
                throw new FileNotFoundException("The requested deletion target does not exist.", full);
            RejectReparsePointOnPathOrAncestors(full);
            return full;
        }

        public static PathValidationResult ValidateAdminProfileBoundary(string input, string workerProfile)
        {
            string full = NormalizeLocalDrivePath(input, true);
            if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Administrator profile does not exist: " + full);
            DriveInfo drive = new DriveInfo(Path.GetPathRoot(full));
            if (!drive.IsReady || !string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Administrator-profile protection requires a ready NTFS volume.");
            if (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable)
                throw new InvalidDataException("Only local fixed or removable volumes are supported.");

            if (!string.IsNullOrWhiteSpace(workerProfile) && AppPaths.IsPathInside(workerProfile, full))
                throw new InvalidDataException("Administrator-profile protection cannot contain the CodexWorker profile, because its application cache must remain writable and deletable.");

            string systemRoot = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            if (AppPaths.PathsEqual(full, systemRoot))
                throw new InvalidDataException("The Windows system drive root cannot be used as an administrator profile.");

            RejectReparsePointOnPathOrAncestors(full);
            PathIdentity identity = NativePath.GetDirectoryIdentity(full);
            if (!AppPaths.PathsEqual(full, identity.CanonicalPath))
                throw new InvalidDataException("The final filesystem path differs from the selected administrator profile.");
            return new PathValidationResult { InputPath = input, FullPath = full, Identity = identity, ScannedEntries = 0 };
        }

        public static PathValidationResult ValidateDefaultReadOnlyDirectory(string input, bool allowDriveRoot)
        {
            string full = NormalizeLocalDrivePath(input, allowDriveRoot);
            if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Default read-only target does not exist: " + full);
            DriveInfo drive = new DriveInfo(Path.GetPathRoot(full));
            if (!drive.IsReady || drive.DriveType != DriveType.Fixed)
                throw new InvalidDataException("Default read-only targets require a ready fixed local volume.");
            if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Default read-only targets require NTFS.");
            RejectReparsePointOnPathOrAncestors(full);
            PathIdentity identity = NativePath.GetDirectoryIdentity(full);
            if (!AppPaths.PathsEqual(full, identity.CanonicalPath))
                throw new InvalidDataException("The final default read-only path differs from the selected path.");
            return new PathValidationResult { InputPath = input, FullPath = full, Identity = identity, ScannedEntries = 0 };
        }

        public static void RejectOverlaps(IEnumerable<string> paths)
        {
            RejectOverlaps(paths, false);
        }

        public static void RejectOverlaps(IEnumerable<string> paths, bool allowDriveRoot)
        {
            List<string> values = new List<string>();
            foreach (string path in paths)
                values.Add(allowDriveRoot ? NormalizeLocalDrivePath(path, true) : NormalizeLexical(path));

            for (int i = 0; i < values.Count; i++)
            {
                for (int j = i + 1; j < values.Count; j++)
                {
                    if (AppPaths.IsPathInside(values[i], values[j]) || AppPaths.IsPathInside(values[j], values[i]))
                        throw new InvalidDataException("Nested or duplicate selections are not allowed: " + values[i] + " and " + values[j]);
                }
            }
        }

        private static void RejectSystemLocation(string full)
        {
            List<string> forbidden = new List<string>();
            AddIfPresent(forbidden, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            AddIfPresent(forbidden, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            AddIfPresent(forbidden, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            AddIfPresent(forbidden, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            AddIfPresent(forbidden, AppPaths.InstallDirectory);
            AddIfPresent(forbidden, AppPaths.DataDirectory);

            foreach (string location in forbidden)
            {
                if (AppPaths.IsPathInside(full, location))
                    throw new InvalidDataException("System or application-managed locations cannot be activated: " + location);
            }

            string[] segments = full.Split(Path.DirectorySeparatorChar);
            foreach (string segment in segments)
            {
                if (string.Equals(segment, "$Recycle.Bin", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(segment, "System Volume Information", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(segment, "Recovery", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(segment, "WindowsApps", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Recovery, recycle-bin, and system-managed paths are forbidden.");
            }
        }

        private static void RejectUserProfileRootOrSensitiveArea(string full)
        {
            string root = Path.GetPathRoot(full).TrimEnd('\\');
            string usersRoot = root + "\\Users";
            if (!AppPaths.IsPathInside(full, usersRoot)) return;

            string relative = full.Substring(usersRoot.Length).TrimStart('\\');
            string[] parts = relative.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 1)
                throw new InvalidDataException("A complete Windows user profile can never be activated.");
            if (parts.Length >= 2)
            {
                foreach (string forbidden in ForbiddenProfileSegments)
                {
                    if (string.Equals(parts[1], forbidden, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Credential and application-profile areas cannot be activated: " + forbidden);
                }
            }
        }

        private static void RejectReparsePointOnPathOrAncestors(string full)
        {
            string current = full;
            string root = Path.GetPathRoot(full);
            while (!string.IsNullOrEmpty(current) && current.Length >= root.Length)
            {
                FileAttributes attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("Reparse points, junctions, and symbolic links are not allowed: " + current);
                if (AppPaths.PathsEqual(current, root)) break;
                current = Path.GetDirectoryName(current);
            }
        }

        private static int ScanForReparsePoints(string root, int maximumEntries, IEnumerable<SecurityIdentifier> actorSids)
        {
            int count = 0;
            Stack<string> pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                string directory = pending.Pop();
                IEnumerable<string> entries;
                try
                {
                    entries = Directory.EnumerateFileSystemEntries(directory);
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException("Unable to inspect every descendant; activation fails closed at: " + directory, ex);
                }

                try
                {
                    foreach (string entry in entries)
                    {
                        count++;
                        if (count > maximumEntries)
                            throw new InvalidDataException("The directory exceeds the safety scan limit of " + maximumEntries + " entries.");
                        FileAttributes attributes = File.GetAttributes(entry);
                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                            throw new InvalidDataException("A reparse point, junction, or symbolic link was found: " + entry);
                        if (actorSids != null)
                            AclService.AssertActivationDescendantAclCompatible(entry, (attributes & FileAttributes.Directory) != 0, actorSids);
                        if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
                        else if (NativePath.GetFileLinkCount(entry) > 1)
                            throw new InvalidDataException("A hard-linked file was found. Copy it to a new file before activation: " + entry);
                    }
                }
                catch (InvalidDataException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException("Unable to complete the descendant safety scan at: " + directory, ex);
                }
            }
            return count;
        }

        private static void AddIfPresent(List<string> values, string path)
        {
            if (!string.IsNullOrWhiteSpace(path)) values.Add(Path.GetFullPath(path));
        }
    }
}
