// CtxSignlib.Verify/CMSVerifier.cs
using System.Security.Cryptography.Pkcs;
using static CtxSignlib.Functions;

namespace CtxSignlib.Verify
{
    /// <summary>
    /// Represents the result of a CMS / PKCS#7 detached signature verification operation.
    /// </summary>
    /// <remarks>
    /// These values distinguish between missing inputs, cryptographic failures,
    /// and signer identity mismatches (pinning failures).
    /// </remarks>
    public enum VerifyResult
    {
        /// <summary>
        /// Verification succeeded and the signer matched the pinned identity.
        /// </summary>
        Ok = 0,

        /// <summary>
        /// The content to be verified was missing or not found.
        /// </summary>
        ContentMissing = 2,

        /// <summary>
        /// The detached signature file or bytes were missing.
        /// </summary>
        SignatureMissing = 3,

        /// <summary>
        /// The CMS structure was invalid or cryptographic verification failed.
        /// </summary>
        BadSignature = 10,

        /// <summary>
        /// No signer certificate was present in the CMS message.
        /// </summary>
        NoSigner = 11,

        /// <summary>
        /// The signature was cryptographically valid, but the signer identity did not match the pinned value.
        /// </summary>
        WrongSigner = 12
    }

    /// <summary>
    /// Provides detached CMS / PKCS#7 verification helpers with explicit signer pinning modes.
    /// </summary>
    /// <remarks>
    /// <para><b>Contract (mirrors the immutable CLI laws in Functions.cs):</b></para>
    /// <list type="bullet">
    /// <item>
    /// <description>
    /// <c>--thumb</c> pins by signer certificate thumbprint (compares against the signer certificate embedded in the CMS signature).
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <c>--pin</c> is the signer's raw public key bytes: DER SubjectPublicKeyInfo (SPKI), same bytes as PEM
    /// <c>-----BEGIN PUBLIC KEY-----</c>.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <c>--pubpin</c> is the SHA-256 of <c>--pin</c> (64 hex).
    /// </description>
    /// </item>
    /// </list>
    /// <para>
    /// Verification is crypto-only: <see cref="SignedCms.CheckSignature(bool)"/> is called with <c>verifySignatureOnly: true</c>.
    /// No OS trust store validation is performed, and all pin comparisons are made against the signer embedded in the CMS signature.
    /// </para>
    /// </remarks>
    public static class CMSVerifier
    {
        // =========================
        // Thumbprint pinning (--thumb)
        // =========================

        /// <summary>
        /// Verifies a detached CMS signature using a pinned signer certificate thumbprint.
        /// </summary>
        /// <param name="contentPath">Path to the original content file.</param>
        /// <param name="sigPath">Path to the detached CMS signature file.</param>
        /// <param name="pinnedThumbprint">
        /// Expected signer certificate thumbprint (hex). Non-hex characters are ignored during normalization.
        /// </param>
        /// <returns>A <see cref="VerifyResult"/> describing the outcome.</returns>
        /// <remarks>
        /// Thumbprint pinning ties verification to a specific certificate instance.
        /// For identity stability across certificate renewals that reuse the same key pair,
        /// prefer <see cref="VerifyDetachmentByPublicKey(string,string,string)"/>.
        /// </remarks>
        public static VerifyResult VerifyDetachmentByThumbprint(string contentPath, string sigPath, string pinnedThumbprint)
        {
            if (Null(contentPath) || !File.Exists(contentPath))
                return VerifyResult.ContentMissing;

            if (Null(sigPath) || !File.Exists(sigPath))
                return VerifyResult.SignatureMissing;

            pinnedThumbprint = NormalizeHex(pinnedThumbprint);
            if (pinnedThumbprint.Length == 0)
                return VerifyResult.WrongSigner;

            byte[] content = ReadAllBytesSafe(contentPath);
            byte[] sig = ReadAllBytesSafe(sigPath);

            return VerifyDetachmentByThumbprint(content, sig, pinnedThumbprint);
        }

        /// <summary>
        /// Verifies a detached CMS signature using a pinned signer certificate thumbprint.
        /// </summary>
        /// <param name="content">Original content bytes.</param>
        /// <param name="sig">Detached CMS signature bytes.</param>
        /// <param name="pinnedThumbprint">Expected signer certificate thumbprint (hex).</param>
        /// <returns>A <see cref="VerifyResult"/> describing the outcome.</returns>
        public static VerifyResult VerifyDetachmentByThumbprint(byte[] content, byte[] sig, string pinnedThumbprint)
        {
            if (content == null) return VerifyResult.ContentMissing;
            if (sig == null) return VerifyResult.SignatureMissing;

            pinnedThumbprint = NormalizeHex(pinnedThumbprint);
            if (pinnedThumbprint.Length == 0)
                return VerifyResult.WrongSigner;

            var signerCert = DecodeAndCryptoVerifyAndGetSignerCert(content, sig, out var cmsResult);
            if (cmsResult != VerifyResult.Ok) return cmsResult;

            // Fixed-time compare on normalized hex.
            string actual = NormalizeHex(signerCert!.Thumbprint);
            return HexBytesEquals(actual, pinnedThumbprint) ? VerifyResult.Ok : VerifyResult.WrongSigner;
        }

        // =========================
        // Public-key pinning (--pubpin)
        // =========================

        /// <summary>
        /// Verifies a detached CMS signature using a pinned SHA-256 of the signer public key (SPKI).
        /// </summary>
        /// <param name="contentPath">Path to the original content file.</param>
        /// <param name="sigPath">Path to the detached CMS signature file.</param>
        /// <param name="pinnedPublicKeySha256">
        /// Expected SHA-256 of the signer public key SPKI bytes (hex). Non-hex characters are ignored during normalization.
        /// This value corresponds to <c>--pubpin</c>.
        /// </param>
        /// <returns>A <see cref="VerifyResult"/> describing the outcome.</returns>
        /// <remarks>
        /// This is the preferred pinning mode for long-lived trust because it remains valid across certificate renewals
        /// that reuse the same key pair.
        /// </remarks>
        public static VerifyResult VerifyDetachmentByPublicKey(string contentPath, string sigPath, string pinnedPublicKeySha256)
        {
            if (Null(contentPath) || !File.Exists(contentPath))
                return VerifyResult.ContentMissing;

            if (Null(sigPath) || !File.Exists(sigPath))
                return VerifyResult.SignatureMissing;

            pinnedPublicKeySha256 = NormalizeHex(pinnedPublicKeySha256);
            if (pinnedPublicKeySha256.Length == 0)
                return VerifyResult.WrongSigner;

            byte[] content = ReadAllBytesSafe(contentPath);
            byte[] sig = ReadAllBytesSafe(sigPath);

            return VerifyDetachmentByPublicKey(content, sig, pinnedPublicKeySha256);
        }

        /// <summary>
        /// Verifies a detached CMS signature using a pinned SHA-256 of the signer public key (SPKI).
        /// </summary>
        /// <param name="content">Original content bytes.</param>
        /// <param name="sig">Detached CMS signature bytes.</param>
        /// <param name="pinnedPublicKeySha256">
        /// Expected SHA-256 of the signer public key SPKI bytes (hex). This value corresponds to <c>--pubpin</c>.
        /// </param>
        /// <returns>A <see cref="VerifyResult"/> describing the outcome.</returns>
        public static VerifyResult VerifyDetachmentByPublicKey(byte[] content, byte[] sig, string pinnedPublicKeySha256)
        {
            if (content == null) return VerifyResult.ContentMissing;
            if (sig == null) return VerifyResult.SignatureMissing;

            pinnedPublicKeySha256 = NormalizeHex(pinnedPublicKeySha256);
            if (pinnedPublicKeySha256.Length == 0)
                return VerifyResult.WrongSigner;

            var signerCert = DecodeAndCryptoVerifyAndGetSignerCert(content, sig, out var cmsResult);
            if (cmsResult != VerifyResult.Ok) return cmsResult;

            // PublicKeySha256() is defined (by law) as SHA-256(SPKI DER).
            string actual = PublicKeySha256(signerCert!);

            // Fixed-time compare on normalized hex.
            return HexBytesEquals(actual, pinnedPublicKeySha256) ? VerifyResult.Ok : VerifyResult.WrongSigner;
        }

        // =========================
        // Raw public-key pinning (--pin)
        // =========================

        /// <summary>
        /// Verifies a detached CMS/PKCS#7 signature and pins the signer by a raw public key (SPKI).
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method performs two checks:
        /// </para>
        /// <list type="number">
        /// <item><description>Cryptographically verifies the detached CMS signature over <paramref name="contentPath"/>.</description></item>
        /// <item><description>
        /// Pins the signer identity by hashing the provided <paramref name="rawPublicKey"/> (SPKI / PEM "BEGIN PUBLIC KEY")
        /// with SHA-256 (producing the <c>--pubpin</c> value) and comparing it to the signer embedded in the CMS signature.
        /// </description></item>
        /// </list>
        /// <para>
        /// <paramref name="rawPublicKey"/> is NOT a secret. It is public key material and may be supplied as PEM, base64, or hex.
        /// </para>
        /// </remarks>
        /// <param name="contentPath">Path to the content file whose detached signature will be verified.</param>
        /// <param name="sigPath">Path to the detached CMS signature file (e.g., *.sig) for <paramref name="contentPath"/>.</param>
        /// <param name="rawPublicKey">
        /// The signer's raw public key bytes (DER SubjectPublicKeyInfo / SPKI), supplied as PEM, base64, or hex.
        /// This value corresponds to <c>--pin</c>.
        /// </param>
        /// <returns>
        /// A <see cref="VerifyResult"/> indicating success (<see cref="VerifyResult.Ok"/>) or the reason verification failed.
        /// </returns>
        public static VerifyResult VerifyDetachmentByRawPublicKey(string contentPath, string sigPath, string rawPublicKey)
        {
            if (Null(contentPath) || !File.Exists(contentPath))
                return VerifyResult.ContentMissing;

            if (Null(sigPath) || !File.Exists(sigPath))
                return VerifyResult.SignatureMissing;

            if (Null(rawPublicKey))
                return VerifyResult.WrongSigner;

            try
            {
                // ParsePublicKeyBytes() accepts PEM/base64/hex and returns SPKI DER bytes.
                byte[] spki = ParsePublicKeyBytes(rawPublicKey);

                // --pubpin = SHA-256(--pin) where --pin == SPKI DER bytes.
                string pubpin = Sha256Hex(spki);

                return VerifyDetachmentByPublicKey(contentPath, sigPath, pubpin);
            }
            catch
            {
                // Deterministic failure classification for invalid raw key inputs.
                return VerifyResult.WrongSigner;
            }
        }

        // =========================
        // Crypto-only verification (no pinning)
        // =========================

        /// <summary>
        /// Performs cryptographic verification of a detached CMS signature without any signer pinning.
        /// </summary>
        /// <param name="content">Original content bytes.</param>
        /// <param name="sig">Detached CMS signature bytes.</param>
        /// <remarks>
        /// This method validates only the cryptographic integrity of the signature.
        /// It does not perform certificate chain validation or identity pinning.
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="content"/> or <paramref name="sig"/> is null.</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown if CMS decoding or signature verification fails.</exception>
        public static void VerifyDetachmentOrThrow(byte[] content, byte[] sig)
        {
            if (content == null) throw new ArgumentNullException(nameof(content));
            if (sig == null) throw new ArgumentNullException(nameof(sig));

            var cms = new SignedCms(new ContentInfo(content), detached: true);
            cms.Decode(sig);
            cms.CheckSignature(verifySignatureOnly: true);
        }

        // =========================
        // Internal shared core (pins signer inside the signature)
        // =========================

        private static System.Security.Cryptography.X509Certificates.X509Certificate2? DecodeAndCryptoVerifyAndGetSignerCert(
            byte[] content,
            byte[] sig,
            out VerifyResult result)
        {
            result = VerifyResult.Ok;

            try
            {
                var cms = new SignedCms(new ContentInfo(content), detached: true);
                cms.Decode(sig);

                if (cms.SignerInfos.Count == 0)
                {
                    result = VerifyResult.NoSigner;
                    return null;
                }

                // Crypto verify only (NO OS trust store checks).
                cms.CheckSignature(verifySignatureOnly: true);

                // Law: comparisons must use signer extracted from the CMS itself.
                var signerCert = cms.SignerInfos[0].Certificate;
                if (signerCert == null)
                {
                    result = VerifyResult.NoSigner;
                    return null;
                }

                return signerCert;
            }
            catch
            {
                result = VerifyResult.BadSignature;
                return null;
            }
        }
    }
}