using System;
using System.Collections.Generic;

namespace CodexGuard.Core
{
    internal static class AdminProfileBoundaryService
    {
        public static GuardedDirectory Find(GuardState state)
        {
            if (state == null) return null;
            state.Normalize();
            string expected = ExpectedPath(state);
            if (string.IsNullOrWhiteSpace(expected)) return null;
            foreach (GuardedDirectory item in state.ProtectedRoots)
            {
                string path = ItemPath(item);
                if (!string.IsNullOrWhiteSpace(path) && SafePathsEqual(path, expected)) return item;
            }
            return null;
        }

        public static List<GuardedDirectory> LegacyEntries(GuardState state)
        {
            List<GuardedDirectory> legacy = new List<GuardedDirectory>();
            if (state == null) return legacy;
            state.Normalize();
            string expected = ExpectedPath(state);
            foreach (GuardedDirectory item in state.ProtectedRoots)
            {
                string path = ItemPath(item);
                if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(expected) || !SafePathsEqual(path, expected)) legacy.Add(item);
            }
            return legacy;
        }

        public static bool IsStrictDescendant(string path, GuardState state)
        {
            GuardedDirectory boundary = Find(state);
            string root = ItemPath(boundary);
            return !string.IsNullOrWhiteSpace(root)
                && !SafePathsEqual(path, root)
                && AppPaths.IsPathInside(path, root);
        }

        public static string ExpectedPath(GuardState state)
        {
            if (state == null || string.IsNullOrWhiteSpace(state.AdminProfilePath)) return null;
            try
            {
                if (!AppPaths.PathsEqual(state.AdminProfilePath, AppInfo.AdminProfilePath)) return null;
                return AppPaths.NormalizeDirectoryPath(AppInfo.AdminProfilePath);
            }
            catch { return null; }
        }

        public static string ItemPath(GuardedDirectory item)
        {
            if (item == null) return null;
            return string.IsNullOrWhiteSpace(item.CanonicalPath) ? item.Path : item.CanonicalPath;
        }

        private static bool SafePathsEqual(string left, string right)
        {
            try { return AppPaths.PathsEqual(left, right); }
            catch { return false; }
        }
    }
}
