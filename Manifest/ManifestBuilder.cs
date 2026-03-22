//CtxSignlib.Manifest/ManifestBuilder.cs
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CtxSignlib.Diagnostics;
using static CtxSignlib.Functions;

namespace CtxSignlib.Manifest
{
    /// <summary>
    /// Represents a manifest exclusion rule for a directory or file path, with an optional content-filtering regular expression.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rules are interpreted by <see cref="ManifestBuilder"/> as follows:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// If <see cref="Path"/> ends with <c>/</c>, it is treated as a directory prefix exclusion (all files under that prefix are excluded).
    /// Directory excludes must not define <see cref="Regex"/>.
    /// </description></item>
    /// <item><description>
    /// Otherwise it is treated as an exact file rule keyed by normalized manifest path.
    /// </description></item>
    /// <item><description>
    /// If <see cref="Regex"/> is null/empty for a file rule, the file is fully excluded.
    /// </description></item>
    /// <item><description>
    /// If <see cref="Regex"/> is present for a file rule, the file remains included but its hash is computed after applying the regex
    /// removal to UTF-8 decoded text content (non-UTF-8 content causes an error).
    /// </description></item>
    /// </list>
    /// <para>
    /// Paths are expected to be manifest-relative and are normalized to forward slashes by <see cref="Functions.NormalizeManifestPath(string)"/>.
    /// </para>
    /// </remarks>
    public sealed class ManifestExclude
    {
        /// <summary>
        /// Gets or sets the manifest-relative path for the exclusion rule.
        /// </summary>
        /// <remarks>
        /// Directory exclusions are indicated by a trailing <c>/</c> (for example <c>bin/</c>).
        /// File exclusions should be an exact manifest path (for example <c>appsettings.json</c>).
        /// </remarks>
        public string Path { get; set; } = "";

        /// <summary>
        /// Gets or sets an optional regular expression pattern used for content filtering prior to hashing.
        /// </summary>
        /// <remarks>
        /// When set for a file rule, the file is still included in the manifest, but its SHA-256 hash is computed from
        /// the UTF-8 decoded text with all matches removed. Directory rules must not specify a regex.
        /// </remarks>
        public string? Regex { get; set; }
    }

    /// <summary>
    /// Provides methods for building or updating a manifest that records file hashes and supports exclusion rules.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The manifest output includes:
    /// </para>
    /// <list type="bullet">
    /// <item><description>A deterministic list of files with SHA-256 hashes and sizes (ordering is deterministic; contents may change if files change).</description></item>
    /// <item><description>An <c>excludes</c> array that may contain directory prefix exclusions and file exclusions (optionally with regex filtering).</description></item>
    /// </list>
    /// <para>
    /// Exclusion rules may be reused from an existing manifest (if present), and can be merged with an external, newline-delimited
    /// excludes file containing path-only entries.
    /// </para>
    /// <para>
    /// Output ordering is deterministic: directory excludes first (sorted), then file excludes (sorted), then files sorted by path.
    /// </para>
    /// <para>
    /// Note: the manifest includes <c>createdUtc</c>, which intentionally varies between runs.
    /// </para>
    /// <para>
    /// Validation and operational failures are reported as <see cref="CtxException"/>.
    /// </para>
    /// </remarks>
    public static class ManifestBuilder
    {
        /// <summary>
        /// Builds or updates a manifest at <paramref name="outManifestPath"/> by hashing all files beneath <paramref name="rootDir"/>,
        /// applying exclusion rules, and writing a JSON manifest.
        /// </summary>
        /// <param name="rootDir">Root directory to enumerate and hash.</param>
        /// <param name="outManifestPath">
        /// Destination path for the manifest JSON. If relative, it is resolved under <paramref name="rootDir"/>.
        /// If a manifest already exists here, its <c>excludes</c> array is reused (if present).
        /// </param>
        /// <param name="pathToExcludesFile">
        /// Optional path to a newline-delimited excludes file. Lines are treated as path-only exclude entries; blank lines and lines starting with <c>#</c> are ignored.
        /// </param>
        /// <returns>The number of file entries written to the manifest.</returns>
        /// <remarks>
        /// <para>
        /// Exclusion rules:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// Directory excludes are specified by paths ending in <c>/</c>. They exclude all files under that prefix and must not specify regex.
        /// </description></item>
        /// <item><description>
        /// File excludes are exact path rules. If the rule has no regex, the file is fully excluded.
        /// If the rule has a regex, the file remains included and its hash is computed after removing regex matches from UTF-8 text.
        /// </description></item>
        /// </list>
        /// <para>
        /// The manifest output file itself and its common signature companion name <c>{manifest}.sig</c> are excluded to prevent self-referential hashing.
        /// </para>
        /// <para>
        /// Hash filtering requires the file to be valid UTF-8; otherwise an exception is thrown.
        /// </para>
        /// </remarks>
        public static int BuildOrUpdate(string rootDir, string outManifestPath, string? pathToExcludesFile = null)
        {
            if (Null(rootDir))
            {
                throw new CtxException(
                    message: "rootDir is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (Null(outManifestPath))
            {
                throw new CtxException(
                    message: "outManifestPath is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            rootDir = Path.GetFullPath(rootDir);

            if (!Directory.Exists(rootDir))
            {
                throw new CtxException(
                    message: $"Root directory not found: {rootDir}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.DirectoryNotFound);
            }

            outManifestPath = Path.GetFullPath(
                Path.IsPathRooted(outManifestPath) ? outManifestPath : Path.Combine(rootDir, outManifestPath));

            if (!IsSubPathOf(rootDir, outManifestPath))
            {
                throw new CtxException(
                    message: "outManifestPath must be inside rootDir.",
                    target: ErrorTarget.Manifest,
                    detail: ErrorDetail.TrustBoundaryViolation);
            }

            string outSigPath = outManifestPath + ".sig";

            var excludes = LoadAndMergeExcludes(outManifestPath, pathToExcludesFile);

            var dirExcludes = new List<string>();
            var fileExcludes = new Dictionary<string, ManifestExclude>(StringComparer.Ordinal);

            foreach (var ex in excludes)
            {
                string p = NormalizeManifestPath(ex.Path);
                if (Null(p)) continue;

                bool isDir = p.EndsWith("/", StringComparison.Ordinal);

                if (isDir)
                {
                    if (!Null(ex.Regex))
                    {
                        throw new CtxException(
                            message: $"Directory excludes must not define regex. Entry: \"{p}\"",
                            target: ErrorTarget.Manifest,
                            detail: ErrorDetail.InvalidManifest);
                    }

                    dirExcludes.Add(p);
                    continue;
                }

                if (fileExcludes.TryGetValue(p, out var existing))
                {
                    string? a = existing.Regex;
                    string? b = ex.Regex;

                    bool aNull = Null(a);
                    bool bNull = Null(b);

                    if (aNull && bNull)
                        continue;

                    if (!aNull && !bNull && string.Equals(a, b, StringComparison.Ordinal))
                        continue;

                    throw new CtxException(
                        message: $"Conflicting exclude entries for path \"{p}\".",
                        target: ErrorTarget.Manifest,
                        detail: ErrorDetail.ConflictingConfiguration);
                }

                fileExcludes[p] = new ManifestExclude { Path = p, Regex = ex.Regex };
            }

            dirExcludes.Sort(StringComparer.Ordinal);

            var files = new List<(string relPath, string sha256, long size)>();
            var pathCompare = IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            foreach (var file in Directory.EnumerateFiles(rootDir, "*", SearchOption.AllDirectories))
            {
                if (string.Equals(file, outManifestPath, pathCompare) ||
                    string.Equals(file, outSigPath, pathCompare))
                    continue;

                string name = Path.GetFileName(file);

                if (name.EndsWith(":Zone.Identifier", StringComparison.OrdinalIgnoreCase))
                    continue;

                string rel = Path.GetRelativePath(rootDir, file);
                rel = NormalizeManifestPath(rel);

                if (IsExcludedByDirectory(rel, dirExcludes))
                    continue;

                if (fileExcludes.TryGetValue(rel, out var exRule))
                {
                    if (Null(exRule.Regex))
                        continue;

                    var fi = new FileInfo(file);
                    string shaFiltered = HashFilteredUtf8(file, exRule.Regex!);
                    files.Add((rel, shaFiltered, fi.Length));
                    continue;
                }

                {
                    var fi = new FileInfo(file);
                    string sha = FileSha256(file);
                    files.Add((rel, sha, fi.Length));
                }
            }

            files.Sort((a, b) => string.CompareOrdinal(a.relPath, b.relPath));

            var orderedExcludes = OrderExcludesForWrite(dirExcludes, fileExcludes);

            byte[] json = WriteManifestJson(orderedExcludes, files);
            WriteAllBytesAtomic(outManifestPath, json);

            return files.Count;
        }

        private static List<ManifestExclude> LoadAndMergeExcludes(string outManifestPath, string? pathToExcludesFile)
        {
            var result = new List<ManifestExclude>();

            if (File.Exists(outManifestPath))
            {
                try
                {
                    byte[] bytes = ReadAllBytesSafe(outManifestPath);
                    using var doc = JsonDocument.Parse(bytes);

                    if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                        doc.RootElement.TryGetProperty("excludes", out var exArr) &&
                        exArr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var e in exArr.EnumerateArray())
                        {
                            if (e.ValueKind != JsonValueKind.Object) continue;

                            string? p = GetStringOrNull(e, "path");
                            string? r = GetStringOrNull(e, "regex");

                            if (Null(p)) continue;

                            result.Add(new ManifestExclude
                            {
                                Path = p!,
                                Regex = Null(r) ? null : r
                            });
                        }
                    }
                }
                catch (CtxException ex)
                {
                    throw new CtxException(
                        message: "Existing manifest could not be parsed to reuse excludes.",
                        target: ErrorTarget.Manifest,
                        detail: ErrorDetail.InvalidManifest,
                        innerException: ex);
                }
                catch (JsonException ex)
                {
                    throw new CtxException(
                        message: "Existing manifest could not be parsed to reuse excludes.",
                        target: ErrorTarget.Manifest,
                        detail: ErrorDetail.InvalidManifest,
                        innerException: ex);
                }
            }

            if (!Null(pathToExcludesFile))
            {
                string p = Path.GetFullPath(pathToExcludesFile!);

                if (!File.Exists(p))
                {
                    throw new CtxException(
                        message: $"Excludes file not found: {p}",
                        target: ErrorTarget.FileSystem,
                        detail: ErrorDetail.FileNotFound);
                }

                string[] lines;
                try
                {
                    lines = File.ReadAllLines(p);
                }
                catch (UnauthorizedAccessException ex)
                {
                    throw new CtxException(
                        message: $"Access denied while reading excludes file: {p}",
                        target: ErrorTarget.FileSystem,
                        detail: ErrorDetail.AccessDenied,
                        innerException: ex);
                }
                catch (DirectoryNotFoundException ex)
                {
                    throw new CtxException(
                        message: $"Directory not found while reading excludes file: {p}",
                        target: ErrorTarget.FileSystem,
                        detail: ErrorDetail.DirectoryNotFound,
                        innerException: ex);
                }
                catch (IOException ex)
                {
                    throw new CtxException(
                        message: $"Failed to read excludes file: {p}",
                        target: ErrorTarget.FileSystem,
                        detail: ErrorDetail.FileUnreadable,
                        innerException: ex);
                }

                foreach (var line in lines)
                {
                    string s = (line ?? "").Trim();
                    if (s.Length == 0) continue;
                    if (s.StartsWith("#", StringComparison.Ordinal)) continue;

                    result.Add(new ManifestExclude
                    {
                        Path = s,
                        Regex = null
                    });
                }
            }

            return result;
        }

        private static bool IsExcludedByDirectory(string relManifestPath, List<string> dirExcludes)
        {
            if (dirExcludes.Count == 0) return false;

            foreach (var d in dirExcludes)
            {
                if (relManifestPath.StartsWith(d, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        private static string HashFilteredUtf8(string filePath, string regexPattern)
        {
            byte[] raw = ReadAllBytesSafe(filePath);

            string text;
            try
            {
                text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                    .GetString(raw);
            }
            catch (DecoderFallbackException ex)
            {
                throw new CtxException(
                    message: $"Regex filtering requires UTF-8 text. File is not valid UTF-8: {filePath}",
                    target: ErrorTarget.Manifest,
                    detail: ErrorDetail.InvalidFormat,
                    innerException: ex);
            }

            try
            {
                var rx = new Regex(regexPattern, RegexOptions.CultureInvariant | RegexOptions.Multiline);
                string filtered = rx.Replace(text, "");

                byte[] filteredBytes = Encoding.UTF8.GetBytes(filtered);
                return Sha256Hex(filteredBytes);
            }
            catch (ArgumentException ex)
            {
                throw new CtxException(
                    message: $"Invalid regex pattern for manifest filtering: {regexPattern}",
                    target: ErrorTarget.Manifest,
                    detail: ErrorDetail.InvalidRegex,
                    innerException: ex);
            }
        }

        private static List<ManifestExclude> OrderExcludesForWrite(List<string> dirExcludes, Dictionary<string, ManifestExclude> fileExcludes)
        {
            var list = new List<ManifestExclude>();

            foreach (var d in dirExcludes)
                list.Add(new ManifestExclude { Path = d, Regex = null });

            var keys = fileExcludes.Keys.ToList();
            keys.Sort(StringComparer.Ordinal);

            foreach (var k in keys)
            {
                var ex = fileExcludes[k];
                list.Add(new ManifestExclude { Path = k, Regex = ex.Regex });
            }

            return list;
        }

        private static byte[] WriteManifestJson(
            List<ManifestExclude> excludes,
            List<(string relPath, string sha256, long size)> files)
        {
            using var ms = new MemoryStream();
            using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions
            {
                Indented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            }))
            {
                w.WriteStartObject();
                w.WriteNumber("manifestVersion", 1);
                w.WriteString("createdUtc", DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"));
                w.WriteString("root", ".");

                w.WriteStartArray("excludes");
                foreach (var ex in excludes)
                {
                    string p = NormalizeManifestPath(ex.Path);
                    if (Null(p)) continue;

                    w.WriteStartObject();
                    w.WriteString("path", p);

                    if (!Null(ex.Regex))
                        w.WriteString("regex", ex.Regex);

                    w.WriteEndObject();
                }
                w.WriteEndArray();

                w.WriteStartArray("files");
                foreach (var f in files)
                {
                    w.WriteStartObject();
                    w.WriteString("path", f.relPath);
                    w.WriteString("sha256", f.sha256);
                    w.WriteNumber("size", f.size);
                    w.WriteEndObject();
                }
                w.WriteEndArray();

                w.WriteEndObject();
            }

            return ms.ToArray();
        }
    }
}