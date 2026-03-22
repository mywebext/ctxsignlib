// CtxSignlib.Manifest/ManifestVerifier.cs
using CtxSignlib.Diagnostics;
using System.Collections.Generic;

namespace CtxSignlib.Manifest
{
    /// <summary>
    /// Performs strict manifest verification using the legacy API surface.
    /// </summary>
    /// <remarks>
    /// This class preserves the original ctxsignlib strict verification API:
    ///
    /// bool VerifyManifest(string rootDir, string manifestPath, out Dictionary&lt;string,List&lt;string&gt;&gt; failed)
    ///
    /// Internally it now uses the shared ManifestVerificationCore engine and
    /// reconstructs the legacy grouped failure dictionary.
    /// </remarks>
    public static class ManifestVerifier
    {
        /// <summary>
        /// Verifies a manifest in strict mode and returns legacy grouped failure results.
        /// </summary>
        /// <param name="rootDir">
        /// Root directory that all manifest paths must resolve under.
        /// </param>
        /// <param name="manifestPath">
        /// Path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.
        /// </param>
        /// <param name="failed">
        /// Legacy failure dictionary grouped by expected SHA-256 value.
        /// </param>
        /// <returns>
        /// True if strict manifest verification succeeds; otherwise false.
        /// </returns>
        public static bool VerifyManifest(
            string rootDir,
            string manifestPath,
            out Dictionary<string, List<string>> failed)
        {
            var result = ManifestVerificationCore.VerifyManifestCore(rootDir, manifestPath);

            failed = new Dictionary<string, List<string>>(System.StringComparer.Ordinal);

            foreach (var p in result.MissingFiles)
                AddFailure(failed, result, p);

            foreach (var p in result.FailedFiles)
                AddFailure(failed, result, p);

            foreach (var p in result.UnreadableFiles)
                AddFailure(failed, result, p);

            return result.IsStrictlyValid;
        }

        private static void AddFailure(
            Dictionary<string, List<string>> failed,
            ManifestPartialVerificationResult result,
            string path)
        {
            if (!result.ExpectedHashByPath.TryGetValue(path, out var expected) || Null(expected))
                expected = "UNKNOWN";

            if (!failed.TryGetValue(expected, out var list))
            {
                list = new List<string>();
                failed[expected] = list;
            }

            list.Add(path);
        }
    }
}