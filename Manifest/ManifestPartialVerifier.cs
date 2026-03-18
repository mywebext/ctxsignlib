// CtxSignlib.Manifest/ManifestPartialVerifier.cs
namespace CtxSignlib.Manifest
{
    /// <summary>
    /// Verifies manifest-listed content in partial mode.
    /// </summary>
    /// <remarks>
    /// Partial mode preserves the current manifest parsing and path-trust rules,
    /// but changes file-presence semantics:
    /// missing files are reported and are non-fatal by themselves,
    /// while present files must still validate exactly.
    /// </remarks>
    public static class ManifestPartialVerifier
    {
        /// <summary>
        /// Verifies a manifest in partial mode.
        /// </summary>
        /// <param name="rootDir">Root directory that all manifest entries must resolve under.</param>
        /// <param name="manifestPath">
        /// Path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the result satisfies partial manifest verification semantics;
        /// otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// Missing files are reported but do not fail partial verification by themselves.
        /// Malformed manifests and trust-boundary violations still throw, matching the strict parser expectations.
        /// </remarks>
        public static bool VerifyManifestPartial(
            string rootDir,
            string manifestPath)
        {
            return VerifyManifestPartialDetailed(rootDir, manifestPath).Success;
        }

        /// <summary>
        /// Verifies a manifest in partial mode and returns categorized file results.
        /// </summary>
        /// <param name="rootDir">Root directory that all manifest entries must resolve under.</param>
        /// <param name="manifestPath">
        /// Path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <returns>
        /// A detailed partial verification result containing passed, missing, failed, and unreadable file lists.
        /// </returns>
        /// <remarks>
        /// Missing files are non-fatal in this mode.
        /// Present unreadable files and present hash-mismatched files are fatal.
        /// Malformed manifests and invalid trust-boundary inputs still throw.
        /// The returned <see cref="ManifestPartialVerificationResult.Success"/> value is computed
        /// using partial verification semantics.
        /// </remarks>
        public static ManifestPartialVerificationResult VerifyManifestPartialDetailed(
            string rootDir,
            string manifestPath)
        {
            var result = ManifestVerificationCore.VerifyManifestCore(rootDir, manifestPath);
            result.Success = result.IsPartiallyValid;
            return result;
        }
    }
}