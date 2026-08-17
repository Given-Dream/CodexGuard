using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace CodexGuard.Core
{
    internal static class CodexConfigurationService
    {
        private const long MaximumConfigurationBytes = 4 * 1024 * 1024;
        private const string RequirementsText =
            "# Created by Codex Guard. Review against current official OpenAI documentation before changing.\r\n" +
            "allow_login_shell = false\r\n" +
            "\r\n" +
            "[windows]\r\n" +
            "allowed_sandbox_implementations = [\"elevated\"]\r\n" +
            "sandbox_private_desktop = true\r\n";

        public static bool EnsureSystemRequirements(out string message)
        {
            string path = AppPaths.SystemRequirementsFile;
            string directory = Path.GetDirectoryName(path);
            Directory.CreateDirectory(directory);
            if (File.Exists(path))
            {
                string existing;
                try { existing = ReadTextLimited(path); }
                catch (Exception ex)
                {
                    string oversizedFragment = Path.Combine(AppPaths.DataDirectory, "requirements.codexguard.fragment.toml");
                    File.WriteAllText(oversizedFragment, RequirementsText, new UTF8Encoding(false));
                    message = "The existing requirements.toml could not be safely inspected and was preserved (" + ex.Message + "). Review and merge: " + oversizedFragment;
                    return false;
                }
                if (RequirementsTextMeetsPolicy(existing))
                {
                    message = "Existing system requirements already constrain the Windows sandbox.";
                    return true;
                }

                string fragment = Path.Combine(AppPaths.DataDirectory, "requirements.codexguard.fragment.toml");
                File.WriteAllText(fragment, RequirementsText, new UTF8Encoding(false));
                message = "An existing requirements.toml was preserved. Merge the reviewed Codex Guard fragment manually: " + fragment;
                return false;
            }

            File.WriteAllText(path, RequirementsText, new UTF8Encoding(false));
            AclService.SecureApplicationFile(path, true);
            message = "Created the system Codex requirements file: " + path;
            return true;
        }

        public static bool SystemRequirementsMeetPolicy()
        {
            if (!File.Exists(AppPaths.SystemRequirementsFile)) return false;
            try { return RequirementsTextMeetsPolicy(ReadTextLimited(AppPaths.SystemRequirementsFile)); }
            catch { return false; }
        }

        public static string EnsureWorkerConfig(string workerProfile, SecurityIdentifier workerSid)
        {
            if (string.IsNullOrWhiteSpace(workerProfile) || !Directory.Exists(workerProfile))
                throw new DirectoryNotFoundException("CodexWorker profile is not available.");
            string directory = Path.Combine(workerProfile, ".codex");
            Directory.CreateDirectory(directory);
            SecureWorkerDirectory(directory, workerSid);
            string config = Path.Combine(directory, "config.toml");
            string original = File.Exists(config) ? ReadTextLimited(config) : string.Empty;
            string updated = EnsureWindowsElevatedSetting(original);
            if (!string.Equals(original, updated, StringComparison.Ordinal))
            {
                if (File.Exists(config))
                    File.Copy(config, config + ".codexguard-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + ".bak", false);
                File.WriteAllText(config, updated, new UTF8Encoding(false));
            }
            FileSecurity fileSecurity = CreateWorkerFileSecurity(workerSid);
            File.SetAccessControl(config, fileSecurity);
            return config;
        }

        internal static string EnsureWindowsElevatedSetting(string text)
        {
            List<string> lines = new List<string>((text ?? string.Empty).Replace("\r\n", "\n").Split('\n'));
            int sectionStart = -1;
            int sectionEnd = lines.Count;
            int sectionCount = 0;
            for (int i = 0; i < lines.Count; i++)
            {
                string trimmed = StripTomlComment(lines[i]).Trim();
                if (string.Equals(trimmed, "[windows]", StringComparison.OrdinalIgnoreCase))
                {
                    sectionCount++;
                    if (sectionStart < 0) sectionStart = i;
                    continue;
                }
                if (sectionStart >= 0 && sectionEnd == lines.Count && i > sectionStart && IsSectionHeader(trimmed))
                {
                    sectionEnd = i;
                }
            }
            if (sectionCount > 1) throw new InvalidDataException("config.toml contains duplicate [windows] sections.");

            if (sectionStart < 0)
            {
                if (lines.Count > 0 && lines[lines.Count - 1].Length != 0) lines.Add(string.Empty);
                lines.Add("[windows]");
                lines.Add("sandbox = \"elevated\"");
            }
            else
            {
                int setting = -1;
                for (int i = sectionStart + 1; i < sectionEnd; i++)
                {
                    string key;
                    string value;
                    if (TrySplitKeyValue(StripTomlComment(lines[i]), out key, out value)
                        && string.Equals(key, "sandbox", StringComparison.OrdinalIgnoreCase))
                    {
                        if (setting >= 0) throw new InvalidDataException("config.toml contains duplicate windows.sandbox settings.");
                        setting = i;
                    }
                }
                if (setting >= 0) lines[setting] = "sandbox = \"elevated\"";
                else lines.Insert(sectionStart + 1, "sandbox = \"elevated\"");
            }
            return string.Join("\r\n", lines).TrimEnd('\r', '\n') + "\r\n";
        }

        internal static bool RequirementsTextMeetsPolicy(string text)
        {
            bool loginShellDisabled = false;
            bool elevatedOnly = false;
            bool privateDesktop = false;
            string section = string.Empty;
            int windowsSections = 0;

            foreach (string rawLine in (text ?? string.Empty).Replace("\r\n", "\n").Split('\n'))
            {
                string line = StripTomlComment(rawLine).Trim();
                if (line.Length == 0) continue;
                if (IsSectionHeader(line))
                {
                    section = line.Substring(1, line.Length - 2).Trim();
                    if (string.Equals(section, "windows", StringComparison.OrdinalIgnoreCase)) windowsSections++;
                    continue;
                }

                string key;
                string value;
                if (!TrySplitKeyValue(line, out key, out value)) continue;
                if (section.Length == 0 && string.Equals(key, "allow_login_shell", StringComparison.OrdinalIgnoreCase))
                    loginShellDisabled = string.Equals(value.Trim(), "false", StringComparison.OrdinalIgnoreCase);
                if (!string.Equals(section, "windows", StringComparison.OrdinalIgnoreCase)) continue;

                if (string.Equals(key, "allowed_sandbox_implementations", StringComparison.OrdinalIgnoreCase))
                {
                    string compact = RemoveWhitespace(value);
                    elevatedOnly = string.Equals(compact, "[\"elevated\"]", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(compact, "['elevated']", StringComparison.OrdinalIgnoreCase);
                }
                else if (string.Equals(key, "sandbox_private_desktop", StringComparison.OrdinalIgnoreCase))
                {
                    privateDesktop = string.Equals(value.Trim(), "true", StringComparison.OrdinalIgnoreCase);
                }
            }
            return windowsSections == 1 && loginShellDisabled && elevatedOnly && privateDesktop;
        }

        private static bool TrySplitKeyValue(string line, out string key, out string value)
        {
            int equals = line.IndexOf('=');
            if (equals <= 0)
            {
                key = null;
                value = null;
                return false;
            }
            key = line.Substring(0, equals).Trim();
            value = line.Substring(equals + 1).Trim();
            return key.Length > 0;
        }

        private static bool IsSectionHeader(string value)
        {
            return value.Length >= 3 && value[0] == '[' && value[value.Length - 1] == ']';
        }

        private static string StripTomlComment(string line)
        {
            if (line == null) return string.Empty;
            bool inSingle = false;
            bool inDouble = false;
            bool escaped = false;
            for (int i = 0; i < line.Length; i++)
            {
                char character = line[i];
                if (inDouble && character == '\\' && !escaped)
                {
                    escaped = true;
                    continue;
                }
                if (character == '"' && !inSingle && !escaped) inDouble = !inDouble;
                else if (character == '\'' && !inDouble) inSingle = !inSingle;
                else if (character == '#' && !inSingle && !inDouble) return line.Substring(0, i);
                escaped = false;
            }
            return line;
        }

        private static string RemoveWhitespace(string value)
        {
            StringBuilder result = new StringBuilder((value ?? string.Empty).Length);
            foreach (char character in value ?? string.Empty)
                if (!char.IsWhiteSpace(character)) result.Append(character);
            return result.ToString();
        }

        private static string ReadTextLimited(string path)
        {
            FileInfo information = new FileInfo(path);
            if (!information.Exists) throw new FileNotFoundException("Configuration file does not exist.", path);
            if (information.Length < 0 || information.Length > MaximumConfigurationBytes)
                throw new InvalidDataException("Configuration file exceeds the 4 MiB safety limit.");
            return File.ReadAllText(path, Encoding.UTF8);
        }

        internal static FileSecurity CreateWorkerFileSecurity(SecurityIdentifier workerSid)
        {
            if (workerSid == null) throw new ArgumentNullException("workerSid");
            FileSecurity security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            // Preserve the existing owner. Windows does not allow an elevated
            // administrator to assign an arbitrary user SID as owner unless a
            // restore privilege is explicitly enabled. Codex Guard deliberately
            // does not enable that privilege; the Worker receives explicit full
            // control instead.
            security.AddAccessRule(new FileSystemAccessRule(workerSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.BuiltinAdministratorsSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.LocalSystemSid(), FileSystemRights.FullControl, AccessControlType.Allow));
            return security;
        }

        internal static DirectorySecurity CreateWorkerDirectorySecurity(SecurityIdentifier workerSid)
        {
            if (workerSid == null) throw new ArgumentNullException("workerSid");
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            // Do not set an Owner section. Existing Worker-owned directories stay
            // Worker-owned, while admin-created directories remain recoverable.
            InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(workerSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.BuiltinAdministratorsSid(), FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(IdentityService.LocalSystemSid(), FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            return security;
        }

        private static void SecureWorkerDirectory(string directory, SecurityIdentifier workerSid)
        {
            DirectorySecurity security = CreateWorkerDirectorySecurity(workerSid);
            Directory.SetAccessControl(directory, security);
        }
    }
}
