using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace CodexGuard.Core
{
    internal sealed class PathIdentity
    {
        public string CanonicalPath { get; set; }
        public uint VolumeSerialNumber { get; set; }
        public uint FileIndexHigh { get; set; }
        public uint FileIndexLow { get; set; }

        public bool SameObject(PathIdentity other)
        {
            return other != null
                && VolumeSerialNumber == other.VolumeSerialNumber
                && FileIndexHigh == other.FileIndexHigh
                && FileIndexLow == other.FileIndexLow;
        }
    }

    internal static class NativePath
    {
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint FileShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateDirectory(string path, IntPtr securityAttributes);

        public static PathIdentity GetDirectoryIdentity(string path)
        {
            using (SafeFileHandle handle = CreateFile(
                path,
                0,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero))
            {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open directory safely.");

                ByHandleFileInformation info;
                if (!GetFileInformationByHandle(handle, out info))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to identify directory.");

                StringBuilder buffer = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
                if (length == 0 || length >= buffer.Capacity)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to resolve final directory path.");

                string finalPath = NormalizeFinalPath(buffer.ToString());
                return new PathIdentity
                {
                    CanonicalPath = finalPath,
                    VolumeSerialNumber = info.VolumeSerialNumber,
                    FileIndexHigh = info.FileIndexHigh,
                    FileIndexLow = info.FileIndexLow
                };
            }
        }

        public static uint GetFileLinkCount(string path)
        {
            using (SafeFileHandle handle = CreateFile(
                path,
                0,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint,
                IntPtr.Zero))
            {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to inspect file link count.");
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to inspect file link count.");
                return information.NumberOfLinks;
            }
        }

        public static void CreateDirectoryNew(string path)
        {
            if (CreateDirectory(path, IntPtr.Zero)) return;
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error, error == 183
                ? "目标目录已经存在；Codex Guard 不会覆盖或合并现有程序目录。"
                : "无法以 CreateNew 方式创建目标目录。");
        }

        private static string NormalizeFinalPath(string value)
        {
            if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                return AppPaths.NormalizeDirectoryPath(@"\\" + value.Substring(8));
            if (value.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                return AppPaths.NormalizeDirectoryPath(value.Substring(4));
            return AppPaths.NormalizeDirectoryPath(value);
        }
    }
}
