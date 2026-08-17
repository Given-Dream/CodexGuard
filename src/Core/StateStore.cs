using System;
using System.IO;
using System.Threading;

namespace CodexGuard.Core
{
    internal static class StateStore
    {
        private const long MaximumStateBytes = 16 * 1024 * 1024;

        public static bool Exists
        {
            get { return File.Exists(AppPaths.StateFile); }
        }

        public static GuardState Load()
        {
            AclService.AssertProtectedFile(AppPaths.StateFile);
            GuardState state = JsonFile.Read<GuardState>(AppPaths.StateFile, MaximumStateBytes);
            if (state == null || state.SchemaVersion != AppInfo.StateSchemaVersion)
                throw new InvalidDataException("Unsupported Codex Guard state schema.");
            state.Normalize();
            return state;
        }

        public static GuardState LoadOrDefault()
        {
            if (!Exists) return GuardState.CreateDefault();
            return Load();
        }

        public static void Save(GuardState state)
        {
            state.SchemaVersion = AppInfo.StateSchemaVersion;
            state.ProductVersion = AppInfo.Version;
            state.MachineName = Environment.MachineName;
            state.UpdatedAtUtc = AppInfo.UtcNow();
            state.Normalize();
            JsonFile.WriteAtomic(AppPaths.StateFile, state, AppPaths.HistoryDirectory,
                delegate(string temporary) { AclService.SecureApplicationFile(temporary, true); });
        }

        public static T WithExclusive<T>(Func<GuardState, T> action, bool createIfMissing)
        {
            using (Mutex mutex = new Mutex(false, @"Local\CodexGuard-State-v1"))
            {
                bool locked = false;
                try
                {
                    locked = mutex.WaitOne(TimeSpan.FromSeconds(30));
                    if (!locked) throw new TimeoutException("Timed out waiting for the Codex Guard state lock.");
                    GuardState state = createIfMissing ? LoadOrDefault() : Load();
                    return action(state);
                }
                finally
                {
                    if (locked) mutex.ReleaseMutex();
                }
            }
        }
    }
}
