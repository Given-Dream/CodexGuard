using System;
using System.IO;
using System.Text;

namespace CodexGuard.Core
{
    internal static class GuardLog
    {
        public static void Write(string requestId, string operation, bool success, string message)
        {
            try
            {
                Directory.CreateDirectory(AppPaths.LogsDirectory);
                string path = Path.Combine(AppPaths.LogsDirectory, DateTime.UtcNow.ToString("yyyy-MM") + ".log");
                string clean = (message ?? string.Empty).Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
                string line = DateTime.UtcNow.ToString("o") + "\t" + Environment.MachineName + "\t" + IdentityService.CurrentSid()
                    + "\t" + (requestId ?? "-") + "\t" + operation + "\t" + (success ? "SUCCESS" : "FAILURE") + "\t" + clean + Environment.NewLine;
                File.AppendAllText(path, line, new UTF8Encoding(false));
            }
            catch
            {
                // Logging must never replace the primary operation result.
            }
        }
    }
}
