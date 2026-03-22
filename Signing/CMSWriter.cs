// CtxSignlib.Signing/CMSWriter.cs
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using CtxSignlib.Diagnostics;
using static CtxSignlib.Functions;

namespace CtxSignlib.Signing
{
    /// <summary>
    /// Provides CMS / PKCS#7 detached signing helpers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class produces detached CMS (Cryptographic Message Syntax) signatures suitable for portable verification.
    /// The signer certificate is embedded (end-cert only) so verification can pin the signer using values extracted
    /// from the CMS itself (thumbprint / raw public key / public-key SHA-256) without consulting OS certificate stores.
    /// </para>
    /// <para>
    /// This implementation does not add optional signed attributes such as signing time.
    /// </para>
    /// <para>
    /// Note: CMS signature bytes are not guaranteed to be identical across runs for all key algorithms/providers
    /// (for example, ECDSA signatures are typically non-deterministic). The security contract of this library is
    /// based on deterministic verification and explicit signer pinning, not byte-for-byte signature reproducibility.
    /// </para>
    /// </remarks>
    public static class CMSWriter
    {
        /// <summary>
        /// Creates a detached CMS / PKCS#7 signature over the provided content bytes.
        /// </summary>
        /// <param name="content">The content to sign.</param>
        /// <param name="signingCert">
        /// The X.509 certificate containing an accessible private key used to generate the signature.
        /// </param>
        /// <returns>Encoded CMS / PKCS#7 signature bytes (detached).</returns>
        /// <remarks>
        /// <para>
        /// The signer certificate is embedded using <see cref="X509IncludeOption.EndCertOnly"/> (no chain).
        /// Verification is expected to enforce trust through explicit pinning against the signer contained in the CMS.
        /// </para>
        /// <para>
        /// This method does not timestamp the signature and does not add signing-time attributes.
        /// </para>
        /// <para>
        /// Failures are reported as <see cref="CtxException"/>.
        /// </para>
        /// </remarks>
        public static byte[] SignDetachment(byte[] content, X509Certificate2 signingCert)
        {
            if (content == null)
            {
                throw new CtxException(
                    message: "content is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (signingCert == null)
            {
                throw new CtxException(
                    message: "signingCert is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (!signingCert.HasPrivateKey)
            {
                throw new CtxException(
                    message: "Signing certificate does not have an accessible private key.",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.PrivateKeyMissing);
            }

            try
            {
                var cms = new SignedCms(new ContentInfo(content), detached: true);

                var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signingCert)
                {
                    // Portable: embed just the signer cert (no chain, no OS trust dependency).
                    IncludeOption = X509IncludeOption.EndCertOnly
                };

                // Important: do not add SigningTime or any other optional attributes here.
                cms.ComputeSignature(signer);
                return cms.Encode();
            }
            catch (CryptographicException ex)
            {
                throw new CtxException(
                    message: "Failed to create detached CMS signature.",
                    target: ErrorTarget.Signing,
                    detail: ErrorDetail.CryptographicFailure,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Creates a detached CMS / PKCS#7 signature for a file and writes it to disk.
        /// </summary>
        /// <param name="contentPath">Path to the file whose contents will be signed.</param>
        /// <param name="sigPath">Destination path for the generated signature file.</param>
        /// <param name="signingCert">
        /// The X.509 certificate containing an accessible private key used to generate the signature.
        /// </param>
        /// <remarks>
        /// The content file is fully read into memory before signing.
        /// The signature file is written using <see cref="Functions.WriteAllBytesAtomic(string, byte[])"/>
        /// to prevent partially-written outputs.
        /// Failures are reported as <see cref="CtxException"/>.
        /// </remarks>
        public static void SignDetachment(string contentPath, string sigPath, X509Certificate2 signingCert)
        {
            if (Null(contentPath))
            {
                throw new CtxException(
                    message: "contentPath is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (Null(sigPath))
            {
                throw new CtxException(
                    message: "sigPath is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (signingCert == null)
            {
                throw new CtxException(
                    message: "signingCert is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (!signingCert.HasPrivateKey)
            {
                throw new CtxException(
                    message: "Signing certificate does not have an accessible private key.",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.PrivateKeyMissing);
            }

            if (!File.Exists(contentPath))
            {
                throw new CtxException(
                    message: "Content file not found.",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.FileNotFound);
            }

            byte[] content = ReadAllBytesSafe(contentPath);
            byte[] sig = SignDetachment(content, signingCert);
            WriteAllBytesAtomic(sigPath, sig);
        }
    }
}