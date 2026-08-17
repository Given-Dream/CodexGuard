using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace CodexGuard.Core
{
    internal static class ProcessSafety
    {
        private static readonly string[] RiskyProcessNames =
        {
            "ChatGPT", "Codex", "codex", "powershell", "pwsh", "cmd", "bash", "sh", "zsh",
            "wsl", "wslhost", "WindowsTerminal", "OpenConsole", "mintty", "git"
        };

        public static List<string> FindRunningRiskyProcesses()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in RiskyProcessNames)
            {
                try
                {
                    foreach (Process process in Process.GetProcessesByName(name))
                    {
                        using (process)
                        {
                            if (process.Id != Process.GetCurrentProcess().Id)
                                result.Add(process.ProcessName + " (PID " + process.Id + ")");
                        }
                    }
                }
                catch
                {
                    result.Add(name + " (unable to inspect)");
                }
            }
            return new List<string>(result);
        }
    }
}
