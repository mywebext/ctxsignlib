// CtxSignlib.Manifest/SignedManifestPartialVerifier.cs
using System;
using System.IO;
using CtxSignlib.Verify;
using static CtxSignlib.Functions;

namespace CtxSignlib.Manifest
{
    /// <summary>
    /// Verifies a signed manifest in partial mode.
    /// </summary>
    /// <remarks>
    /// This preserves the existing signed-manifest authentication contract:
    /// the manifest signature is verified first using public-key pinning,
    /// then authenticated manifest content is evaluated in partial mode.
    /// </remarks>
    public static class SignedManifestPartialVerifier
    {
        /// <summary>
        /// Verifies a signed manifest in partial mode.
        /// </summary>
        /// <param name="rootDir">The root directory that the manifest and signature must reside under.</param>
        /// <param name="manifestPath">
        /// Path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <param name="sigPath">
        /// Path to the detached signature file. If null or whitespace, defaults to <c>{manifestPath}.sig</c>.
        /// If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <param name="pinnedPublicKeySha256">
        /// Expected SHA-256 of the signer public key SPKI bytes, expressed as hex.
        /// </param>
        /// <param name="signatureResult">
        /// Receives the result of the detached CMS signature verification step.
        /// </param>
        /// <returns>
        /// <c>true</c> if signature verification succeeds and the authenticated manifest result
        /// satisfies partial verification semantics; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// Missing files are non-fatal in partial mode.
        /// Signature failure is always fatal.
        /// </remarks>
        public static bool VerifySignedManifestPartial(
            string rootDir,
            string manifestPath,
            string? sigPath,
            string pinnedPublicKeySha256,
            out VerifyResult signatureResult)
        {
            return VerifySignedManifestPartialDetailed(
                rootDir,
                manifestPath,
                sigPath,
                pinnedPublicKeySha256,
                out signatureResult).Success;
        }

        /// <summary>
        /// Verifies a signed manifest in partial mode and returns detailed categorized results.
        /// </summary>
        /// <param name="rootDir">The root directory that the manifest and signature must reside under.</param>
        /// <param name="manifestPath">
        /// Path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <param name="sigPath">
        /// Path to the detached signature file. If null or whitespace, defaults to <c>{manifestPath}.sig</c>.
        /// If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <param name="pinnedPublicKeySha256">
        /// Expected SHA-256 of the signer public key SPKI bytes, expressed as hex.
        /// Non-hex characters are ignored during normalization.
        /// </param>
        /// <param name="signatureResult">
        /// Receives the result of the detached CMS signature verification step.
        /// </param>
        /// <returns>
        /// A detailed partial verification result.
        /// </returns>
        /// <remarks>
        /// If signature verification fails, the method returns a failed result immediately and does not evaluate manifest file entries.
        /// Missing files are reported but are non-fatal in partial mode.
        /// The returned <see cref="ManifestPartialVerificationResult.Success"/> value is computed
        /// using partial verification semantics after signed-manifest authentication succeeds.
        /// </remarks>
        /// <exception cref="ArgumentException">
        /// Thrown if <paramref name="rootDir"/>, <paramref name="manifestPath"/>, or <paramref name="pinnedPublicKeySha256"/> is null or whitespace,
        /// or if the normalized pin is empty.
        /// </exception>
        /// <exception cref="DirectoryNotFoundException">Thrown if <paramref name="rootDir"/> does not exist.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <paramref name="manifestPath"/> or the resolved <paramref name="sigPath"/> is outside <paramref name="rootDir"/>.
        /// </exception>
        public static ManifestPartialVerificationResult VerifySignedManifestPartialDetailed(
            string rootDir,
            string manifestPath,
            string? sigPath,
            string pinnedPublicKeySha256,
            out VerifyResult signatureResult)
        {
            if (Null(rootDir)) throw new ArgumentException("rootDir is required.", nameof(rootDir));
            if (Null(manifestPath)) throw new ArgumentException("manifestPath is required.", nameof(manifestPath));
            if (Null(pinnedPublicKeySha256)) throw new ArgumentException("pinnedPublicKeySha256 is required.", nameof(pinnedPublicKeySha256));

            rootDir = Path.GetFullPath(rootDir);

            if (!Directory.Exists(rootDir))
                throw new DirectoryNotFoundException(rootDir);

            manifestPath = Path.GetFullPath(
                Path.IsPathRooted(manifestPath) ? manifestPath : Path.Combine(rootDir, manifestPath));

            if (!IsSubPathOf(rootDir, manifestPath))
                throw new InvalidOperationException("manifestPath must be inside rootDir.");

            if (Null(sigPath))
                sigPath = manifestPath + ".sig";

            sigPath = Path.GetFullPath(
                Path.IsPathRooted(sigPath!) ? sigPath! : Path.Combine(rootDir, sigPath!));

            if (!IsSubPathOf(rootDir, sigPath))
                throw new InvalidOperationException("sigPath must be inside rootDir.");

            pinnedPublicKeySha256 = NormalizeHex(pinnedPublicKeySha256);
            if (pinnedPublicKeySha256.Length == 0)
                throw new ArgumentException("pinnedPublicKeySha256 is required.", nameof(pinnedPublicKeySha256));

            signatureResult = CMSVerifier.VerifyDetachmentByPublicKey(
                manifestPath,
                sigPath,
                pinnedPublicKeySha256);

            if (signatureResult != VerifyResult.Ok)
            {
                return new ManifestPartialVerificationResult
                {
                    Success = false,
                    ManifestAuthenticated = false
                };
            }

            var result = ManifestVerificationCore.VerifyManifestCore(rootDir, manifestPath);
            result.ManifestAuthenticated = true;
            result.Success = result.IsPartiallyValid;
            return result;
        }
    }
}