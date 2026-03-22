// CtxSignlib.Verify/ManifestFileVerification.cs
using System.Text.Json;
using CtxSignlib.Diagnostics;
using static CtxSignlib.Functions;

namespace CtxSignlib.Verify
{
    /// <summary>
    /// Verifies a single file against an authenticated (signed) manifest in a TOCTOU-hardened way.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Workflow:
    /// </para>
    /// <list type="number">
    ///   <item><description>Verify the manifest's detached CMS signature (crypto-only, pinned signer).</description></item>
    ///   <item><description>Locate the file entry inside the manifest.</description></item>
    ///   <item><description>Compute the file hash using the same exclude semantics used by manifest creation.</description></item>
    /// </list>
    /// <para>
    /// This is <b>not</b> detached signature verification of the file bytes.
    /// It is file integrity validation using a signed manifest as the trust anchor.
    /// </para>
    /// <para>
    /// Failure details are returned via the <c>signatureResult</c> out parameter and the <c>failure</c> out string:
    /// </para>
    /// <list type="bullet">
    ///   <item><description><c>signatureResult</c> reports signature/identity failures (e.g., BadSignature, WrongSigner, ContentMissing).</description></item>
    ///   <item><description><c>failure</c> reports manifest/path/hash failures (e.g., FileNotInManifest, HashMismatch).</description></item>
    /// </list>
    /// </remarks>
    public static class ManifestFileVerification
    {
        /// <summary>
        /// Verifies <paramref name="filePath"/> against a signed manifest using a pinned signer certificate thumbprint (<c>--thumb</c>).
        /// </summary>
        /// <param name="rootDir">Root directory that all verified files must reside under.</param>
        /// <param name="filePath">Path to the target file (absolute, or relative to <paramref name="rootDir"/>).</param>
        /// <param name="manifestPath">Path to the manifest JSON (absolute, or relative to <paramref name="rootDir"/>).</param>
        /// <param name="sigPath">
        /// Optional path to the manifest detached signature file. If null/empty, defaults to <c>{manifestPath}.sig</c>.
        /// </param>
        /// <param name="pinnedThumbprint">
        /// Expected signer certificate thumbprint (hex). Non-hex characters are ignored during normalization.
        /// </param>
        /// <param name="signatureResult">
        /// Receives the result of validating the manifest signature and signer identity pin.
        /// </param>
        /// <param name="expectedSha256">Receives the expected SHA-256 (hex) from the manifest for the target file.</param>
        /// <param name="actualSha256">Receives the actual SHA-256 (hex) computed from the target file.</param>
        /// <param name="failure">
        /// Receives a deterministic failure code when signature validation succeeds but file/manifest checks fail:
        /// <c>FileOutsideRoot</c>, <c>FileMissing</c>, <c>InvalidManifest</c>, <c>FileNotInManifest</c>, <c>HashMismatch</c>.
        /// Empty string means no non-signature failure occurred.
        /// </param>
        /// <returns>
        /// <c>true</c> if the manifest signature is valid (and pinned signer matches) and the file hash matches the manifest entry; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// Signature verification is crypto-only and pins the signer extracted from the CMS signature itself (never OS stores).
        /// File hashing is delegated to <see cref="ManifestEntryHashResolver"/>, which applies the same manifest exclude semantics
        /// used during manifest creation, including regex-filtered hashing for matching file-level exclude rules.
        /// Input validation failures are reported as <see cref="CtxException"/>.
        /// </remarks>
        public static bool VerifyFileAgainstSignedManifest(
            string rootDir,
            string filePath,
            string manifestPath,
            string? sigPath,
            string pinnedThumbprint,
            out VerifyResult signatureResult,
            out string expectedSha256,
            out string actualSha256,
            out string failure)
        {
            expectedSha256 = string.Empty;
            actualSha256 = string.Empty;
            failure = string.Empty;
            signatureResult = VerifyResult.BadSignature;

            if (Null(rootDir))
            {
                throw new CtxException(
                    message: "rootDir is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (Null(filePath))
            {
                throw new CtxException(
                    message: "filePath is required.",
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

            if (Null(pinnedThumbprint))
            {
                throw new CtxException(
                    message: "pinnedThumbprint is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            rootDir = Path.GetFullPath(rootDir);

            manifestPath = Path.GetFullPath(Path.IsPathRooted(manifestPath) ? manifestPath : Path.Combine(rootDir, manifestPath));
            sigPath = Null(sigPath)
                ? (manifestPath + ".sig")
                : Path.GetFullPath(Path.IsPathRooted(sigPath!) ? sigPath! : Path.Combine(rootDir, sigPath!));

            bool sigOk = SingleFileVerification.VerifyFile(
                contentPath: manifestPath,
                sigPath: sigPath,
                pinnedThumbprint: pinnedThumbprint,
                out signatureResult);

            if (!sigOk)
                return false;

            string absFile = Path.GetFullPath(Path.IsPathRooted(filePath) ? filePath : Path.Combine(rootDir, filePath));

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

            if (!File.Exists(manifestPath))
            {
                signatureResult = VerifyResult.ContentMissing;
                return false;
            }

            byte[] manifestBytes = ReadAllBytesSafe(manifestPath);

            using var doc = JsonDocument.Parse(manifestBytes);
            var root = doc.RootElement;

            if (!ManifestEntryHashResolver.TryResolveExpectedAndActualSha256(
                    rootDir,
                    absFile,
                    root,
                    out expectedSha256,
                    out actualSha256,
                    out failure))
            {
                return false;
            }

            if (!HexBytesEquals(expectedSha256, actualSha256))
            {
                failure = "HashMismatch";
                return false;
            }

            return true;
        }

        /// <summary>
        /// Verifies <paramref name="filePath"/> against a signed manifest using a pinned public-key SHA-256 (<c>--pubpin</c>).
        /// </summary>
        /// <param name="rootDir">Root directory that all verified files must reside under.</param>
        /// <param name="filePath">Path to the target file (absolute, or relative to <paramref name="rootDir"/>).</param>
        /// <param name="manifestPath">Path to the manifest JSON (absolute, or relative to <paramref name="rootDir"/>).</param>
        /// <param name="sigPath">
        /// Optional path to the manifest detached signature file. If null/empty, defaults to <c>{manifestPath}.sig</c>.
        /// </param>
        /// <param name="pinnedPublicKeySha256">
        /// Expected SHA-256 of the signer's public key SPKI bytes (hex).
        /// This corresponds to <c>--pubpin</c>, where <c>--pubpin = SHA-256(--pin)</c> and <c>--pin</c> is SPKI DER
        /// (PEM <c>BEGIN PUBLIC KEY</c>).
        /// </param>
        /// <param name="signatureResult">Receives the result of validating the manifest signature and signer pin.</param>
        /// <param name="expectedSha256">Receives the expected SHA-256 (hex) from the manifest for the target file.</param>
        /// <param name="actualSha256">Receives the actual SHA-256 (hex) computed from the target file.</param>
        /// <param name="failure">
        /// Receives a deterministic failure code when signature validation succeeds but file/manifest checks fail:
        /// <c>FileOutsideRoot</c>, <c>FileMissing</c>, <c>InvalidManifest</c>, <c>FileNotInManifest</c>, <c>HashMismatch</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the manifest signature is valid (and pinned signer matches) and the file hash matches the manifest entry; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// Signature verification is crypto-only and pins the signer extracted from the CMS signature itself (never OS stores).
        /// File hashing is delegated to <see cref="ManifestEntryHashResolver"/>, which applies the same manifest exclude semantics
        /// used during manifest creation, including regex-filtered hashing for matching file-level exclude rules.
        /// Input validation failures are reported as <see cref="CtxException"/>.
        /// </remarks>
        public static bool VerifyFileAgainstSignedManifestByPublicKey(
            string rootDir,
            string filePath,
            string manifestPath,
            string? sigPath,
            string pinnedPublicKeySha256,
            out VerifyResult signatureResult,
            out string expectedSha256,
            out string actualSha256,
            out string failure)
        {
            expectedSha256 = string.Empty;
            actualSha256 = string.Empty;
            failure = string.Empty;
            signatureResult = VerifyResult.BadSignature;

            if (Null(rootDir))
            {
                throw new CtxException(
                    message: "rootDir is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (Null(filePath))
            {
                throw new CtxException(
                    message: "filePath is required.",
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

            manifestPath = Path.GetFullPath(Path.IsPathRooted(manifestPath) ? manifestPath : Path.Combine(rootDir, manifestPath));
            sigPath = Null(sigPath)
                ? (manifestPath + ".sig")
                : Path.GetFullPath(Path.IsPathRooted(sigPath!) ? sigPath! : Path.Combine(rootDir, sigPath!));

            bool sigOk = SingleFileVerification.VerifyFileByPublicKey(
                contentPath: manifestPath,
                sigPath: sigPath,
                pinnedPublicKeySha256: pinnedPublicKeySha256,
                out signatureResult);

            if (!sigOk)
                return false;

            string absFile = Path.GetFullPath(Path.IsPathRooted(filePath) ? filePath : Path.Combine(rootDir, filePath));

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

            if (!File.Exists(manifestPath))
            {
                signatureResult = VerifyResult.ContentMissing;
                return false;
            }

            byte[] manifestBytes = ReadAllBytesSafe(manifestPath);

            using var doc = JsonDocument.Parse(manifestBytes);
            var root = doc.RootElement;

            if (!ManifestEntryHashResolver.TryResolveExpectedAndActualSha256(
                    rootDir,
                    absFile,
                    root,
                    out expectedSha256,
                    out actualSha256,
                    out failure))
            {
                return false;
            }

            if (!HexBytesEquals(expectedSha256, actualSha256))
            {
                failure = "HashMismatch";
                return false;
            }

            return true;
        }

        /// <summary>
        /// Convenience overload: defaults the signature path to <c>{manifestPath}.sig</c>.
        /// </summary>
        public static bool VerifyFileAgainstSignedManifest(
            string rootDir,
            string filePath,
            string manifestPath,
            string pinnedThumbprint,
            out VerifyResult signatureResult,
            out string expectedSha256,
            out string actualSha256,
            out string failure)
            => VerifyFileAgainstSignedManifest(
                rootDir, filePath, manifestPath,
                sigPath: null,
                pinnedThumbprint: pinnedThumbprint,
                out signatureResult,
                out expectedSha256,
                out actualSha256,
                out failure);

        /// <summary>
        /// Convenience overload: defaults the signature path to <c>{manifestPath}.sig</c>.
        /// </summary>
        public static bool VerifyFileAgainstSignedManifestByPublicKey(
            string rootDir,
            string filePath,
            string manifestPath,
            string pinnedPublicKeySha256,
            out VerifyResult signatureResult,
            out string expectedSha256,
            out string actualSha256,
            out string failure)
            => VerifyFileAgainstSignedManifestByPublicKey(
                rootDir, filePath, manifestPath,
                sigPath: null,
                pinnedPublicKeySha256: pinnedPublicKeySha256,
                out signatureResult,
                out expectedSha256,
                out actualSha256,
                out failure);
    }
}