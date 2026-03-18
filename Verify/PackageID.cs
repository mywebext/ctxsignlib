// CtxSignlib.Verify/PackageId.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CtxSignlib.Manifest;
using static CtxSignlib.Functions;

namespace CtxSignlib.Verify
{
    /// <summary>
    /// Generates deterministic package identifiers from expected file identity data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A package ID represents the identity of the full expected package content,
    /// not the current state of an installation.
    /// </para>
    /// <para>
    /// Canonical entry format:
    /// </para>
    /// <code>
    /// normalized/path|EXPECTEDSHA256
    /// </code>
    /// <para>
    /// Entries are normalized, de-duplicated, sorted using <see cref="StringComparer.Ordinal"/>,
    /// joined with LF, encoded as UTF-8, and hashed with SHA-256.
    /// </para>
    /// <para>
    /// Two packages with the same included file paths and expected hashes will always produce
    /// the same package ID across platforms.
    /// </para>
    /// </remarks>
    public static class PackageId
    {
        /// <summary>
        /// Generates a deterministic package ID from the full expected package contents
        /// represented by a manifest verification result.
        /// </summary>
        /// <param name="result">
        /// A manifest verification result whose expected-hash metadata represents the effective included package contents.
        /// </param>
        /// <returns>
        /// Uppercase hexadecimal SHA-256 of the canonical package entry list.
        /// Returns the SHA-256 of an empty UTF-8 payload if no included entries are present.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="result"/> is null.</exception>
        public static string Generate(ManifestPartialVerificationResult result)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            return Generate(
                result.ExpectedHashByPath.Select(kvp => (kvp.Key, kvp.Value)));
        }

        /// <summary>
        /// Generates a deterministic package ID from a single relative file path and expected SHA-256.
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
        /// Generates a deterministic package ID from a sequence of relative file paths and expected SHA-256 values.
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