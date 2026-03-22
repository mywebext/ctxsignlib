// CtxSignlib.Manifest/DetailedManifestFileVerification.cs
using CtxSignlib.Diagnostics;

namespace CtxSignlib.Manifest
{
    /// <summary>
    /// Performs strict manifest verification and returns a detailed categorized result.
    /// </summary>
    /// <remarks>
    /// This class preserves strict verification semantics:
    /// listed files must be present,
    /// present files must hash-match,
    /// and unreadable existing files are fatal.
    ///
    /// It does not replace or weaken <see cref="ManifestVerifier"/>.
    /// It adds a richer reporting surface for callers that need categorized file lists.
    /// </remarks>
    public static class DetailedManifestFileVerification
    {
        /// <summary>
        /// Verifies all manifest-listed files in strict mode and returns only pass/fail.
        /// </summary>
        /// <param name="rootDir">The root directory that all manifest file paths must resolve under.</param>
        /// <param name="manifestPath">
        /// Full or relative path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the result satisfies strict manifest verification semantics;
        /// otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// Strict mode means:
        /// missing file = fail,
        /// bad hash = fail,
        /// unreadable present file = fail.
        /// </remarks>
        public static bool VerifyManifestDetailed(
            string rootDir,
            string manifestPath)
        {
            return VerifyManifestDetailedResult(rootDir, manifestPath).Success;
        }

        /// <summary>
        /// Verifies all manifest-listed files in strict mode and returns detailed categorized results.
        /// </summary>
        /// <param name="rootDir">The root directory that all manifest file paths must resolve under.</param>
        /// <param name="manifestPath">
        /// Full or relative path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <returns>
        /// A detailed result containing passed, missing, failed, and unreadable file lists.
        /// </returns>
        /// <remarks>
        /// This method applies strict verification semantics over the shared categorized manifest result model.
        ///
        /// The returned <see cref="ManifestPartialVerificationResult.Success"/> value is computed
        /// using strict verification semantics.
        ///
        /// Excluded files remain excluded exactly as they are in the existing manifest verification model.
        /// </remarks>
        public static ManifestPartialVerificationResult VerifyManifestDetailedResult(
            string rootDir,
            string manifestPath)
        {
            var result = ManifestVerificationCore.VerifyManifestCore(rootDir, manifestPath);

            // Strict semantics: missing files are fatal here.
            result.Success = result.IsStrictlyValid;

            return result;
        }
    }
}