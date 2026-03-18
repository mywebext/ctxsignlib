// CtxSignlib.Verify/RepairPackageId.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CtxSignlib.Manifest;
using static CtxSignlib.Functions;

namespace CtxSignlib.Verify
{
    /// <summary>
    /// Generates deterministic repair package identifiers from manifest-governed file identity data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A repair package ID is derived only from the manifest-relative file path and the expected SHA-256 hash
    /// of each file that must be satisfied by a package.
    /// </para>
    /// <para>
    /// Failure reason is intentionally ignored. A missing file, unreadable file, or corrupt file produces the same
    /// repair package ID as long as the required file path and expected manifest hash are the same.
    /// </para>
    /// <para>
    /// Canonical entry format:
    /// </para>
    /// <code>
    /// normalized/path|EXPECTEDSHA256
    /// </code>
    /// <para>
    /// Entries are normalized, de-duplicated, sorted using <see cref="StringComparer.Ordinal"/>, joined with LF,
    /// encoded as UTF-8, and hashed with SHA-256.
    /// </para>
    /// </remarks>
    public static class RepairPackageId
    {
        /// <summary>
        /// Generates a deterministic repair package ID from the repair-relevant portions of a manifest verification result.
        /// </summary>
        /// <param name="result">
        /// A manifest verification result containing categorized file state and expected-hash metadata.
        /// </param>
        /// <returns>
        /// Uppercase hexadecimal SHA-256 of the canonical repair entry list.
        /// Returns the SHA-256 of an empty UTF-8 payload if no repair-relevant entries are present.
        /// </returns>
        /// <remarks>
        /// This method includes:
        /// <list type="bullet">
        /// <item><description><see cref="ManifestPartialVerificationResult.MissingFiles"/></description></item>
        /// <item><description><see cref="ManifestPartialVerificationResult.FailedFiles"/></description></item>
        /// <item><description><see cref="ManifestPartialVerificationResult.UnreadableFiles"/></description></item>
        /// </list>
        /// <para>
        /// <see cref="ManifestPartialVerificationResult.PassedFiles"/> are intentionally excluded.
        /// </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="result"/> is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if any repair-relevant path does not have an expected SHA-256 entry in the result metadata.
        /// </exception>
        public static string Generate(ManifestPartialVerificationResult result)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            var entries = new List<string>();

            AddEntries(entries, result, result.MissingFiles);
            AddEntries(entries, result, result.FailedFiles);
            AddEntries(entries, result, result.UnreadableFiles);

            return GenerateFromCanonicalEntries(entries);
        }

        /// <summary>
        /// Generates a deterministic repair package ID from only the missing-file portion of a manifest verification result.
        /// </summary>
        /// <param name="result">A manifest verification result containing expected-hash metadata.</param>
        /// <returns>Uppercase hexadecimal SHA-256 of the canonical missing-file entry list.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="result"/> is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if any missing path does not have an expected SHA-256 entry in the result metadata.
        /// </exception>
        public static string GenerateMissing(ManifestPartialVerificationResult result)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            var entries = new List<string>();
            AddEntries(entries, result, result.MissingFiles);
            return GenerateFromCanonicalEntries(entries);
        }

        /// <summary>
        /// Generates a deterministic repair package ID from only the failed-file portion of a manifest verification result.
        /// </summary>
        /// <param name="result">A manifest verification result containing expected-hash metadata.</param>
        /// <returns>Uppercase hexadecimal SHA-256 of the canonical failed-file entry list.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="result"/> is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if any failed path does not have an expected SHA-256 entry in the result metadata.
        /// </exception>
        public static string GenerateFailed(ManifestPartialVerificationResult result)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            var entries = new List<string>();
            AddEntries(entries, result, result.FailedFiles);
            return GenerateFromCanonicalEntries(entries);
        }

        /// <summary>
        /// Generates a deterministic repair package ID from only the unreadable-file portion of a manifest verification result.
        /// </summary>
        /// <param name="result">A manifest verification result containing expected-hash metadata.</param>
        /// <returns>Uppercase hexadecimal SHA-256 of the canonical unreadable-file entry list.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="result"/> is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if any unreadable path does not have an expected SHA-256 entry in the result metadata.
        /// </exception>
        public static string GenerateUnreadable(ManifestPartialVerificationResult result)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            var entries = new List<string>();
            AddEntries(entries, result, result.UnreadableFiles);
            return GenerateFromCanonicalEntries(entries);
        }

        /// <summary>
        /// Generates a deterministic repair package ID from a single relative file path and expected SHA-256.
        /// </summary>
        /// <param name="relativeFilePath">Relative file path.</param>
        /// <param name="expectedSha256">Expected SHA-256 (hex) for the file.</param>
        /// <returns>Uppercase hexadecimal SHA-256 of the canonical single-entry payload.</returns>
        public static string Generate(string relativeFilePath, string expectedSha256)
        {
            string entry = CanonicalEntry(relativeFilePath, expectedSha256);
            return GenerateFromCanonicalEntries(new[] { entry });
        }

        /// <summary>
        /// Generates a deterministic repair package ID from a sequence of relative file paths and expected SHA-256 values.
        /// </summary>
        /// <param name="entries">
        /// Sequence of tuples in the form (path, expectedSha256).
        /// </param>
        /// <returns>Uppercase hexadecimal SHA-256 of the canonical entry payload.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="entries"/> is null.</exception>
        public static string Generate(IEnumerable<(string path, string expectedSha256)> entries)
        {
            if (entries == null)
                throw new ArgumentNullException(nameof(entries));

            var canonical = new List<string>();

            foreach (var e in entries)
                canonical.Add(CanonicalEntry(e.path, e.expectedSha256));

            return GenerateFromCanonicalEntries(canonical);
        }

        private static void AddEntries(
            List<string> target,
            ManifestPartialVerificationResult result,
            IEnumerable<string> paths)
        {
            foreach (var path in paths)
            {
                if (!result.ExpectedHashByPath.TryGetValue(path, out var expected) || Null(expected))
                    throw new InvalidOperationException($"Expected hash metadata is missing for path \"{path}\".");

                target.Add(CanonicalEntry(path, expected));
            }
        }

        private static string CanonicalEntry(string relativeFilePath, string expectedSha256)
        {
            if (Null(relativeFilePath))
                throw new ArgumentException("relativeFilePath is required.", nameof(relativeFilePath));

            if (Null(expectedSha256))
                throw new ArgumentException("expectedSha256 is required.", nameof(expectedSha256));

            string path = NormalizeManifestPath(relativeFilePath);
            string hash = NormalizeHex(expectedSha256);

            if (Null(path))
                throw new ArgumentException("relativeFilePath is required.", nameof(relativeFilePath));

            if (hash.Length == 0)
                throw new ArgumentException("expectedSha256 is required.", nameof(expectedSha256));

            return path + "|" + hash;
        }

        private static string GenerateFromCanonicalEntries(IEnumerable<string> canonicalEntries)
        {
            string[] ordered = canonicalEntries
                .Where(s => !Null(s))
                .Distinct(StringComparer.Ordinal)
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToArray();

            string payload = string.Join("\n", ordered);
            byte[] bytes = Encoding.UTF8.GetBytes(payload);
            return Sha256Hex(bytes);
        }
    }
}