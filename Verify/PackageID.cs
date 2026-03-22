// CtxSignlib.Verify/PackageId.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CtxSignlib.Diagnostics;
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
        /// <remarks>
        /// Input validation failures are reported as <see cref="CtxException"/>.
        /// </remarks>
        public static string Generate(ManifestPartialVerificationResult result)
        {
            if (result == null)
            {
                throw new CtxException(
                    message: "result is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            return Generate(
                result.ExpectedHashByPath.Select(kvp => (kvp.Key, kvp.Value)));
        }

        /// <summary>
        /// Generates a deterministic package ID from a single relative file path and expected SHA-256.
        /// </summary>
        /// <param name="relativeFilePath">Relative file path.</param>
        /// <param name="expectedSha256">Expected SHA-256 (hex) for the file.</param>
        /// <returns>Uppercase hexadecimal SHA-256 of the canonical single-entry payload.</returns>
        /// <remarks>
        /// Input validation failures are reported as <see cref="CtxException"/>.
        /// </remarks>
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
        /// <remarks>
        /// Input validation failures are reported as <see cref="CtxException"/>.
        /// </remarks>
        public static string Generate(IEnumerable<(string path, string expectedSha256)> entries)
        {
            if (entries == null)
            {
                throw new CtxException(
                    message: "entries is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            var canonical = new List<string>();

            foreach (var e in entries)
                canonical.Add(CanonicalEntry(e.path, e.expectedSha256));

            return GenerateFromCanonicalEntries(canonical);
        }

        private static string CanonicalEntry(string relativeFilePath, string expectedSha256)
        {
            if (Null(relativeFilePath))
            {
                throw new CtxException(
                    message: "relativeFilePath is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (Null(expectedSha256))
            {
                throw new CtxException(
                    message: "expectedSha256 is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            string path = NormalizeManifestPath(relativeFilePath);
            string hash = NormalizeHex(expectedSha256);

            if (Null(path))
            {
                throw new CtxException(
                    message: "relativeFilePath is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (hash.Length == 0)
            {
                throw new CtxException(
                    message: "expectedSha256 is not in a valid hex format.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.InvalidFormat);
            }

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