//CtxSignlib.Verify/SingleFileVerification.cs
using static CtxSignlib.Functions;

namespace CtxSignlib.Verify
{
    /// <summary>
    /// Provides convenience helpers for verifying a single signed file using detached CMS signatures.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These helpers wrap <see cref="CMSVerifier"/> and provide simple pass/fail semantics
    /// while still returning the underlying <see cref="VerifyResult"/> for detailed inspection.
    /// </para>
    /// <para>
    /// If <c>sigPath</c> is null or empty, it defaults to <c>{contentPath}.sig</c>.
    /// </para>
    /// </remarks>
    public static class SingleFileVerification
    {
        /// <summary>
        /// Verifies a single signed file using thumbprint pinning (<c>--thumb</c>).
        /// </summary>
        /// <param name="contentPath">Path to the content file.</param>
        /// <param name="sigPath">
        /// Path to the detached signature file. If null/empty, defaults to <c>{contentPath}.sig</c>.
        /// </param>
        /// <param name="pinnedThumbprint">
        /// Expected signer certificate thumbprint (hex). Non-hex characters are ignored during normalization.
        /// </param>
        /// <param name="result">
        /// Receives the detailed <see cref="VerifyResult"/> describing the verification outcome.
        /// </param>
        /// <returns>
        /// <c>true</c> if verification succeeds and the signer matches the pinned thumbprint; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This method performs crypto-only verification and enforces explicit thumbprint pinning.
        /// </remarks>
        public static bool VerifyFile(
            string contentPath,
            string? sigPath,
            string pinnedThumbprint,
            out VerifyResult result)
        {
            if (Null(sigPath))
                sigPath = contentPath + ".sig";

            result = CMSVerifier.VerifyDetachmentByThumbprint(contentPath, sigPath!, pinnedThumbprint);
            return result == VerifyResult.Ok;
        }

        /// <summary>
        /// Verifies a single signed file using public-key SHA-256 pinning (<c>--pubpin</c>).
        /// </summary>
        /// <param name="contentPath">Path to the content file.</param>
        /// <param name="sigPath">
        /// Path to the detached signature file. If null/empty, defaults to <c>{contentPath}.sig</c>.
        /// </param>
        /// <param name="pinnedPublicKeySha256">
        /// Expected SHA-256 of the signer's public key SPKI bytes (hex).
        /// This value corresponds to <c>--pubpin</c> (where <c>--pubpin = SHA-256(--pin)</c> and <c>--pin</c> is SPKI DER).
        /// </param>
        /// <param name="result">
        /// Receives the detailed <see cref="VerifyResult"/> describing the verification outcome.
        /// </param>
        /// <returns>
        /// <c>true</c> if verification succeeds and the signer matches the pinned public-key identity; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// Public-key pinning is generally more stable than thumbprint pinning,
        /// as it remains valid across certificate renewals that reuse the same key pair.
        /// </remarks>
        public static bool VerifyFileByPublicKey(
            string contentPath,
            string? sigPath,
            string pinnedPublicKeySha256,
            out VerifyResult result)
        {
            if (Null(sigPath))
                sigPath = contentPath + ".sig";

            result = CMSVerifier.VerifyDetachmentByPublicKey(contentPath, sigPath!, pinnedPublicKeySha256);
            return result == VerifyResult.Ok;
        }

        /// <summary>
        /// Verifies a single signed file using thumbprint pinning and the default signature path.
        /// </summary>
        /// <param name="contentPath">Path to the content file.</param>
        /// <param name="pinnedThumbprint">
        /// Expected signer certificate thumbprint (hex).
        /// </param>
        /// <param name="result">
        /// Receives the detailed <see cref="VerifyResult"/> describing the verification outcome.
        /// </param>
        /// <returns>
        /// <c>true</c> if verification succeeds and the signer matches the pinned thumbprint; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// The signature file is assumed to be located at <c>{contentPath}.sig</c>.
        /// </remarks>
        public static bool VerifyFile(
            string contentPath,
            string pinnedThumbprint,
            out VerifyResult result)
        {
            return VerifyFile(contentPath, null, pinnedThumbprint, out result);
        }

        /// <summary>
        /// Verifies a single signed file using public-key SHA-256 pinning and the default signature path.
        /// </summary>
        /// <param name="contentPath">Path to the content file.</param>
        /// <param name="pinnedPublicKeySha256">
        /// Expected SHA-256 of the signer's public key SPKI bytes (hex). This corresponds to <c>--pubpin</c>.
        /// </param>
        /// <param name="result">
        /// Receives the detailed <see cref="VerifyResult"/> describing the verification outcome.
        /// </param>
        /// <returns>
        /// <c>true</c> if verification succeeds and the signer matches the pinned public-key identity; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// The signature file is assumed to be located at <c>{contentPath}.sig</c>.
        /// </remarks>
        public static bool VerifyFileByPublicKey(
            string contentPath,
            string pinnedPublicKeySha256,
            out VerifyResult result)
        {
            return VerifyFileByPublicKey(contentPath, null, pinnedPublicKeySha256, out result);
        }

        /// <summary>
        /// Verifies a single signed file using raw public-key pinning (<c>--pin</c>).
        /// </summary>
        /// <param name="contentPath">Path to the content file.</param>
        /// <param name="sigPath">
        /// Path to the detached signature file. If null/empty, defaults to <c>{contentPath}.sig</c>.
        /// </param>
        /// <param name="rawPublicKey">
        /// The signer's raw public key in SPKI form (DER SubjectPublicKeyInfo), supplied as PEM (<c>BEGIN PUBLIC KEY</c>),
        /// base64, or hex. This corresponds to <c>--pin</c> and is NOT a secret.
        /// </param>
        /// <param name="result">
        /// Receives the detailed <see cref="VerifyResult"/> describing the verification outcome.
        /// </param>
        /// <returns>
        /// <c>true</c> if verification succeeds and the signer matches the pinned raw public key; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This method derives <c>--pubpin</c> deterministically as SHA-256(SPKI) and verifies via public-key pinning.
        /// </remarks>
        public static bool VerifyFileByRawPublicKey(
            string contentPath,
            string? sigPath,
            string rawPublicKey,
            out VerifyResult result)
        {
            if (Null(sigPath))
                sigPath = contentPath + ".sig";

            result = CMSVerifier.VerifyDetachmentByRawPublicKey(contentPath, sigPath!, rawPublicKey);
            return result == VerifyResult.Ok;
        }

        /// <summary>
        /// Verifies a single signed file using raw public-key pinning and the default signature path.
        /// </summary>
        /// <param name="contentPath">Path to the content file.</param>
        /// <param name="rawPublicKey">The signer's raw public key SPKI bytes, supplied as PEM/base64/hex.</param>
        /// <param name="result">Receives the detailed <see cref="VerifyResult"/> describing the verification outcome.</param>
        /// <returns><c>true</c> if verification succeeds; otherwise <c>false</c>.</returns>
        /// <remarks>
        /// The signature file is assumed to be located at <c>{contentPath}.sig</c>.
        /// </remarks>
        public static bool VerifyFileByRawPublicKey(
            string contentPath,
            string rawPublicKey,
            out VerifyResult result)
        {
            return VerifyFileByRawPublicKey(contentPath, null, rawPublicKey, out result);
        }
    }
}