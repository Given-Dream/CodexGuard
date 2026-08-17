using System;
using System.IO;
using System.Runtime.Serialization.Json;

namespace CodexGuard.Core
{
    internal static class JsonFile
    {
        public static T Read<T>(string path, long maxBytes)
        {
            FileInfo info = new FileInfo(path);
            if (!info.Exists) throw new FileNotFoundException("JSON file not found.", path);
            if (info.Length <= 0 || info.Length > maxBytes)
                throw new InvalidDataException("JSON file size is outside the allowed range.");

            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                return (T)serializer.ReadObject(stream);
            }
        }

        public static void WriteNew<T>(string path, T value)
        {
            string directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (FileStream stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                serializer.WriteObject(stream, value);
                stream.Flush(true);
            }
        }

        public static void WriteAtomic<T>(string path, T value, string historyDirectory)
        {
            WriteAtomic(path, value, historyDirectory, null);
        }

        public static void WriteAtomic<T>(string path, T value, string historyDirectory, Action<string> prepareTemporary)
        {
            string directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory)) throw new InvalidOperationException("Target directory is missing.");
            Directory.CreateDirectory(directory);
            if (!string.IsNullOrEmpty(historyDirectory)) Directory.CreateDirectory(historyDirectory);

            string temporary = Path.Combine(directory, Path.GetFileName(path) + ".new-" + Guid.NewGuid().ToString("N"));
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (FileStream stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                serializer.WriteObject(stream, value);
                stream.Flush(true);
            }
            if (prepareTemporary != null) prepareTemporary(temporary);

            if (File.Exists(path))
            {
                string backup = string.IsNullOrEmpty(historyDirectory)
                    ? path + ".bak"
                    : Path.Combine(historyDirectory, Path.GetFileName(path) + "." + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff") + ".bak");
                File.Replace(temporary, path, backup, true);
            }
            else
            {
                File.Move(temporary, path);
            }
        }
    }
}
