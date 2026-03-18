// CtxSignlib.Manifest/ManifestVerificationCore.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static CtxSignlib.Functions;

namespace CtxSignlib.Manifest
{
    internal static class ManifestVerificationCore
    {
        internal static ManifestPartialVerificationResult VerifyManifestCore(
            string rootDir,
            string manifestPath)
        {
            var result = new ManifestPartialVerificationResult();

            if (Null(rootDir)) throw new ArgumentException("rootDir is required.", nameof(rootDir));
            if (Null(manifestPath)) throw new ArgumentException("manifestPath is required.", nameof(manifestPath));

            rootDir = Path.GetFullPath(rootDir);

            if (!Directory.Exists(rootDir))
                throw new DirectoryNotFoundException(rootDir);

            manifestPath = Path.GetFullPath(
                Path.IsPathRooted(manifestPath) ? manifestPath : Path.Combine(rootDir, manifestPath));

            if (!IsSubPathOf(rootDir, manifestPath))
                throw new InvalidOperationException("manifestPath must be inside rootDir.");

            if (!File.Exists(manifestPath))
                throw new FileNotFoundException("manifest not found.", manifestPath);

            byte[] manifestBytes = ReadAllBytesSafe(manifestPath);

            using var doc = JsonDocument.Parse(manifestBytes);
            var root = doc.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
                throw new InvalidOperationException("Invalid manifest format.");

            var dirExcludes = new List<string>();
            var fileExcludes = new Dictionary<string, (string path, string? regex)>(StringComparer.Ordinal);

            if (root.TryGetProperty("excludes", out var exArr) && exArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var e in exArr.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.Object) continue;

                    string? p0 = GetStringOrNull(e, "path");
                    if (Null(p0)) continue;

                    string p = NormalizeManifestPath(p0!);
                    if (Null(p)) continue;

                    string? r = GetStringOrNull(e, "regex");
                    r = Null(r) ? null : r;

                    bool isDir = p.EndsWith("/", StringComparison.Ordinal);

                    if (isDir)
                    {
                        if (!Null(r))
                            throw new InvalidOperationException($"Directory excludes must not define regex. Entry: \"{p}\"");

                        dirExcludes.Add(p);
                        continue;
                    }

                    if (fileExcludes.TryGetValue(p, out var existing))
                    {
                        bool aNull = Null(existing.regex);
                        bool bNull = Null(r);

                        if (aNull && bNull) continue;
                        if (!aNull && !bNull && string.Equals(existing.regex, r, StringComparison.Ordinal)) continue;

                        throw new InvalidOperationException($"Conflicting exclude entries for path \"{p}\".");
                    }

                    fileExcludes[p] = (p, r);
                }
            }

            dirExcludes.Sort(StringComparer.Ordinal);

            if (!root.TryGetProperty("files", out var filesArr) || filesArr.ValueKind != JsonValueKind.Array)
                throw new InvalidOperationException("Manifest missing files[] array.");

            foreach (var f in filesArr.EnumerateArray())
            {
                if (f.ValueKind != JsonValueKind.Object) continue;

                string? rel0 = GetStringOrNull(f, "path");
                string? exp0 = GetStringOrNull(f, "sha256");

                if (Null(rel0) || Null(exp0))
                    continue;

                string rel = NormalizeManifestPath(rel0!);
                string expected = NormalizeHex(exp0!);

                if (Null(rel) || expected.Length == 0)
                    continue;

                // Preserve expected hash metadata so legacy wrappers can rebuild
                // grouped failure output keyed by expected SHA-256.
                if (IsExcludedByDirectory(rel, dirExcludes))
                    continue;

                if (fileExcludes.TryGetValue(rel, out var exRule))
                {
                    if (Null(exRule.regex))
                        continue;

                    result.ExpectedHashByPath[rel] = expected;
                    VerifyOneFiltered(rootDir, rel, expected, exRule.regex!, result);
                    continue;
                }

                result.ExpectedHashByPath[rel] = expected;
                VerifyOneRaw(rootDir, rel, expected, result);
            }

            return result;
        }

        private static void VerifyOneRaw(
            string rootDir,
            string relManifestPath,
            string expectedSha256,
            ManifestPartialVerificationResult result)
        {
            string full = Path.GetFullPath(Path.Combine(rootDir, relManifestPath));

            if (!IsSubPathOf(rootDir, full))
            {
                result.FailedFiles.Add(relManifestPath);
                return;
            }

            if (!File.Exists(full))
            {
                result.MissingFiles.Add(relManifestPath);
                return;
            }

            string actual;
            try
            {
                using var fs = OpenReadLocked(full);
                actual = NormalizeHex(Sha256Hex(fs, rewindIfSeekable: true));
            }
            catch (UnauthorizedAccessException)
            {
                result.UnreadableFiles.Add(relManifestPath);
                return;
            }
            catch (IOException)
            {
                result.UnreadableFiles.Add(relManifestPath);
                return;
            }

            if (!HexBytesEquals(actual, expectedSha256))
            {
                result.FailedFiles.Add(relManifestPath);
                return;
            }

            result.PassedFiles.Add(relManifestPath);
        }

        private static void VerifyOneFiltered(
            string rootDir,
            string relManifestPath,
            string expectedSha256,
            string regexPattern,
            ManifestPartialVerificationResult result)
        {
            string full = Path.GetFullPath(Path.Combine(rootDir, relManifestPath));

            if (!IsSubPathOf(rootDir, full))
            {
                result.FailedFiles.Add(relManifestPath);
                return;
            }

            if (!File.Exists(full))
            {
                result.MissingFiles.Add(relManifestPath);
                return;
            }

            byte[] raw;
            try
            {
                using var fs = OpenReadLocked(full);
                using var ms = new MemoryStream();
                fs.CopyTo(ms);
                raw = ms.ToArray();
            }
            catch (UnauthorizedAccessException)
            {
                result.UnreadableFiles.Add(relManifestPath);
                return;
            }
            catch (IOException)
            {
                result.UnreadableFiles.Add(relManifestPath);
                return;
            }

            string text;
            try
            {
                text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                    .GetString(raw);
            }
            catch (DecoderFallbackException)
            {
                result.InvalidSyntaxFiles.Add(relManifestPath);
                return;
            }

            string filtered;
            try
            {
                var rx = new Regex(regexPattern, RegexOptions.CultureInvariant | RegexOptions.Multiline);
                filtered = rx.Replace(text, "");
            }
            catch (ArgumentException)
            {
                result.InvalidSyntaxFiles.Add(relManifestPath);
                return;
            }

            byte[] filteredBytes = Encoding.UTF8.GetBytes(filtered);
            string actual = NormalizeHex(Sha256Hex(filteredBytes));

            if (!HexBytesEquals(actual, expectedSha256))
            {
                result.FailedFiles.Add(relManifestPath);
                return;
            }

            result.PassedFiles.Add(relManifestPath);
        }

        private static bool IsExcludedByDirectory(string relManifestPath, List<string> dirExcludes)
        {
            foreach (var d in dirExcludes)
            {
                if (relManifestPath.StartsWith(d, StringComparison.Ordinal))
                    return true;
            }

            return false;
        }
    }
}