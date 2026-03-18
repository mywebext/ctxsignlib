// CtxSignlib.Verify/ManifestEntryHashResolver.cs
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static CtxSignlib.Functions;

namespace CtxSignlib.Verify
{
    /// <summary>
    /// Resolves how a manifest entry should be verified for a single target file and computes
    /// both the expected and actual SHA-256 values using the same exclude semantics as ManifestBuilder.
    /// </summary>
    internal static class ManifestEntryHashResolver
    {
        internal static bool TryResolveExpectedAndActualSha256(
            string rootDir,
            string absFile,
            JsonElement manifestRoot,
            out string expectedSha256,
            out string actualSha256,
            out string failure)
        {
            expectedSha256 = string.Empty;
            actualSha256 = string.Empty;
            failure = string.Empty;

            if (Null(rootDir)) throw new ArgumentException("rootDir is required.", nameof(rootDir));
            if (Null(absFile)) throw new ArgumentException("absFile is required.", nameof(absFile));

            rootDir = Path.GetFullPath(rootDir);
            absFile = Path.GetFullPath(absFile);

            if (manifestRoot.ValueKind != JsonValueKind.Object)
            {
                failure = "InvalidManifest";
                return false;
            }

            if (!IsSubPathOf(rootDir, absFile))
            {
                failure = "FileOutsideRoot";
                return false;
            }

            if (!File.Exists(absFile))
            {
                failure = "FileMissing";
                return false;
            }

            if (!manifestRoot.TryGetProperty("files", out var filesArr) || filesArr.ValueKind != JsonValueKind.Array)
            {
                failure = "InvalidManifest";
                return false;
            }

            string relManifestPath = NormalizeManifestPath(Path.GetRelativePath(rootDir, absFile));
            if (Null(relManifestPath))
            {
                failure = "InvalidManifest";
                return false;
            }

            // files[] is authoritative for inclusion.
            // excludes[] is consulted only to discover an exact-path regex rule
            // that changes how file content is hashed.
            var fileExcludes = new Dictionary<string, string?>(StringComparer.Ordinal);

            if (manifestRoot.TryGetProperty("excludes", out var exArr))
            {
                if (exArr.ValueKind != JsonValueKind.Array)
                {
                    failure = "InvalidManifest";
                    return false;
                }

                foreach (var e in exArr.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.Object)
                        continue;

                    string? p0 = GetStringOrNull(e, "path");
                    if (Null(p0))
                        continue;

                    string p = NormalizeManifestPath(p0!);
                    if (Null(p))
                        continue;

                    string? r = GetStringOrNull(e, "regex");
                    r = Null(r) ? null : r;

                    if (fileExcludes.TryGetValue(p, out var existing))
                    {
                        bool aNull = Null(existing);
                        bool bNull = Null(r);

                        if (aNull && bNull)
                            continue;

                        if (!aNull && !bNull && string.Equals(existing, r, StringComparison.Ordinal))
                            continue;

                        failure = "InvalidManifest";
                        return false;
                    }

                    fileExcludes[p] = r;
                }
            }

            bool foundEntry = false;

            foreach (var f in filesArr.EnumerateArray())
            {
                if (f.ValueKind != JsonValueKind.Object)
                    continue;

                string? p0 = GetStringOrNull(f, "path");
                if (Null(p0))
                    continue;

                string p = NormalizeManifestPath(p0!);
                if (!string.Equals(p, relManifestPath, StringComparison.Ordinal))
                    continue;

                string? h0 = GetStringOrNull(f, "sha256");
                if (Null(h0))
                {
                    failure = "InvalidManifest";
                    return false;
                }

                expectedSha256 = NormalizeHex(h0!);
                if (expectedSha256.Length == 0)
                {
                    failure = "InvalidManifest";
                    return false;
                }

                foundEntry = true;
                break;
            }

            if (!foundEntry)
            {
                failure = "FileNotInManifest";
                return false;
            }

            string? regexPattern = null;
            if (fileExcludes.TryGetValue(relManifestPath, out var exRule) && !Null(exRule))
            {
                regexPattern = exRule;
            }

            try
            {
                actualSha256 = ComputeActualSha256(absFile, regexPattern);
            }
            catch (DecoderFallbackException)
            {
                // Regex-filtered hashing requires valid UTF-8 text.
                failure = "InvalidSyntax";
                actualSha256 = string.Empty;
                return false;
            }
            catch (ArgumentException)
            {
                // Malformed regex or other malformed syntax associated with hashing rules.
                failure = "InvalidSyntax";
                actualSha256 = string.Empty;
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                failure = "FileUnreadable";
                actualSha256 = string.Empty;
                return false;
            }
            catch (IOException)
            {
                failure = "FileUnreadable";
                actualSha256 = string.Empty;
                return false;
            }

            return true;
        }

        private static string ComputeActualSha256(string absFile, string? regexPattern)
        {
            if (Null(regexPattern))
            {
                using var fs = OpenReadLocked(absFile);
                return NormalizeHex(Sha256Hex(fs, rewindIfSeekable: true));
            }

            byte[] raw;

            // TOCTOU hardening:
            // For regex-filtered files, read through a locked handle first,
            // then decode/filter/hash in memory.
            using (var fs = OpenReadLocked(absFile))
            using (var ms = new MemoryStream())
            {
                fs.CopyTo(ms);
                raw = ms.ToArray();
            }

            string text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                .GetString(raw);

            var rx = new Regex(
                regexPattern!,
                RegexOptions.CultureInvariant | RegexOptions.Multiline);

            string filtered = rx.Replace(text, string.Empty);
            byte[] filteredBytes = Encoding.UTF8.GetBytes(filtered);

            return NormalizeHex(Sha256Hex(filteredBytes));
        }
    }
}