//CtxSignlib.Manifest/SignedManifestVerifier.cs
using CtxSignlib.Diagnostics;
using CtxSignlib.Verify;
using static CtxSignlib.Functions;

namespace CtxSignlib.Manifest
{
    /// <summary>
    /// Verifies a manifest using a detached CMS/PKCS#7 signature with public-key pinning, then verifies the manifest’s file hashes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class composes two verification steps:
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// Signature verification: validates a detached CMS signature over the manifest file and enforces a pinned public-key SHA-256 (<c>--pubpin</c>).
    /// </description></item>
    /// <item><description>
    /// Content verification: validates all file hashes listed in the manifest (honoring manifest exclude rules).
    /// </description></item>
    /// </list>
    /// <para>
    /// Trust boundary:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <c>manifestPath</c> and <c>sigPath</c> must resolve to locations inside <c>rootDir</c> (otherwise this API throws).
    /// </description></item>
    /// <item><description>
    /// Manifest file entries are treated as untrusted. The underlying manifest verifier enforces that each listed path resolves under <c>rootDir</c>;
    /// escaping paths are treated as failures (reported) rather than being accessed.
    /// </description></item>
    /// </list>
    /// <para>
    /// This API returns <c>false</c> if either step fails (signature invalid/missing/pin mismatch, or any manifest file verification failure).
    /// </para>
    /// <para>
    /// Input and trust-boundary validation failures are reported as <see cref="CtxException"/>.
    /// </para>
    /// </remarks>
    public static class SignedManifestVerifier
    {
        /// <summary>
        /// Verifies a signed manifest by validating its detached CMS signature (with public-key pinning) and then validating the manifest’s file hashes.
        /// </summary>
        /// <param name="rootDir">The root directory that the manifest and signature must reside under, and that all manifest file entries must resolve under.</param>
        /// <param name="manifestPath">
        /// Path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <param name="sigPath">
        /// Path to the detached signature file. If null/whitespace, defaults to <c>{manifestPath}.sig</c>.
        /// If relative, it is resolved under <paramref name="rootDir"/>.
        /// Must resolve to a location inside <paramref name="rootDir"/>.
        /// </param>
        /// <param name="pinnedPublicKeySha256">
        /// The pinned signer identity in <c>--pubpin</c> form: SHA-256 of the signer's public key SPKI DER bytes (hex).
        /// This corresponds to the Laws in <c>Functions.cs</c> where <c>--pubpin = SHA-256(--pin)</c> and <c>--pin</c> is SPKI DER
        /// (PEM <c>BEGIN PUBLIC KEY</c>).
        /// Non-hex characters are ignored during normalization.
        /// </param>
        /// <param name="signatureResult">
        /// Receives the result code from signature verification (for example: Ok, SignatureMissing, BadSignature, WrongSigner).
        /// </param>
        /// <param name="failedFiles">
        /// Receives a grouped set of manifest file verification failures, keyed by expected SHA-256, with values listing the failing manifest-relative paths.
        /// </param>
        /// <returns>
        /// <c>true</c> if the signature verifies successfully under the pinned public key and the manifest contents verify with zero file failures;
        /// otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// <para>
        /// Return behavior:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// If signature verification fails, the method returns <c>false</c> immediately and does not perform file verification.
        /// </description></item>
        /// <item><description>
        /// If signature verification succeeds, the manifest file list is verified. Any missing/mismatching/escaping paths cause <c>false</c>,
        /// and details are returned in <paramref name="failedFiles"/>.
        /// </description></item>
        /// </list>
        /// </remarks>
        public static bool VerifySignedManifest(
            string rootDir,
            string manifestPath,
            string? sigPath,
            string pinnedPublicKeySha256,
            out VerifyResult signatureResult,
            out Dictionary<string, List<string>> failedFiles)
        {
            failedFiles = new Dictionary<string, List<string>>(StringComparer.Ordinal);

            if (Null(rootDir))
            {
                throw new CtxException(
                    message: "rootDir is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (Null(manifestPath))
            {
                throw new CtxException(
                    message: "manifestPath is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (Null(pinnedPublicKeySha256))
            {
                throw new CtxException(
                    message: "pinnedPublicKeySha256 is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            rootDir = Path.GetFullPath(rootDir);

            if (!Directory.Exists(rootDir))
            {
                throw new CtxException(
                    message: $"Directory not found: {rootDir}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.DirectoryNotFound);
            }

            // Resolve manifestPath under rootDir if relative
            manifestPath = Path.GetFullPath(
                Path.IsPathRooted(manifestPath) ? manifestPath : Path.Combine(rootDir, manifestPath));

            // manifest must be inside rootDir
            if (!IsSubPathOf(rootDir, manifestPath))
            {
                throw new CtxException(
                    message: "manifestPath must be inside rootDir.",
                    target: ErrorTarget.Manifest,
                    detail: ErrorDetail.TrustBoundaryViolation);
            }

            // Resolve sigPath
            if (Null(sigPath))
                sigPath = manifestPath + ".sig";

            sigPath = Path.GetFullPath(
                Path.IsPathRooted(sigPath!) ? sigPath! : Path.Combine(rootDir, sigPath!));

            // sig must be inside rootDir
            if (!IsSubPathOf(rootDir, sigPath))
            {
                throw new CtxException(
                    message: "sigPath must be inside rootDir.",
                    target: ErrorTarget.Manifest,
                    detail: ErrorDetail.TrustBoundaryViolation);
            }

            // Normalize pin deterministically (strip non-hex, uppercase)
            pinnedPublicKeySha256 = NormalizeHex(pinnedPublicKeySha256);
            if (pinnedPublicKeySha256.Length == 0)
            {
                throw new CtxException(
                    message: "pinnedPublicKeySha256 is not in a valid hex format.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.InvalidFormat);
            }

            // 1) Verify signature (crypto-only; pins signer extracted from CMS)
            signatureResult = CMSVerifier.VerifyDetachmentByPublicKey(
                manifestPath,
                sigPath,
                pinnedPublicKeySha256);

            if (signatureResult != VerifyResult.Ok)
                return false;

            // 2) Verify manifest contents
            return ManifestVerifier.VerifyManifest(rootDir, manifestPath, out failedFiles);
        }

        /// <summary>
        /// Verifies a signed manifest and returns only the file verification failures, omitting the signature result code.
        /// </summary>
        /// <param name="rootDir">The root directory that the manifest and signature must reside under, and that all manifest file entries must resolve under.</param>
        /// <param name="manifestPath">Path to the manifest JSON file. If relative, it is resolved under <paramref name="rootDir"/>.</param>
        /// <param name="sigPath">
        /// Path to the detached signature file. If null/whitespace, defaults to <c>{manifestPath}.sig</c>.
        /// If relative, it is resolved under <paramref name="rootDir"/>.
        /// </param>
        /// <param name="pinnedPublicKeySha256">
        /// <c>--pubpin</c>: SHA-256 of the signer's public key SPKI DER bytes (hex). Non-hex characters are ignored during normalization.
        /// </param>
        /// <param name="failedFiles">
        /// Receives a grouped set of manifest file verification failures, keyed by expected SHA-256, with values listing the failing manifest-relative paths.
        /// </param>
        /// <returns>
        /// <c>true</c> if the signature verifies successfully under the pinned public key and the manifest contents verify with zero file failures;
        /// otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This overload is a convenience wrapper that discards the signature status code. Use the full overload when you need to distinguish
        /// signature failures from file-hash failures.
        /// </remarks>
        public static bool VerifySignedManifest(
            string rootDir,
            string manifestPath,
            string? sigPath,
            string pinnedPublicKeySha256,
            out Dictionary<string, List<string>> failedFiles)
        {
            return VerifySignedManifest(
                rootDir,
                manifestPath,
                sigPath,
                pinnedPublicKeySha256,
                out _,
                out failedFiles);
        }
    }
}