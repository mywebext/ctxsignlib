// CtxSignlib.Certificates/CertHelpers.cs
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CtxSignlib.Diagnostics;
using static CtxSignlib.Functions;

namespace CtxSignlib.Certificates
{
    /// <summary>
    /// Certificate helper utilities for generating, exporting, loading, and (optionally) installing certificates.
    /// </summary>
    /// <remarks>
    /// These helpers are designed to support deterministic signing/verification workflows and developer tooling.
    /// Any interaction with OS certificate stores is explicitly opt-in and clearly marked as platform-specific.
    /// </remarks>
    public static class CertHelpers
    {
        /// <summary>
        /// Creates an in-memory self-signed RSA X.509 certificate suitable for code-signing scenarios.
        /// </summary>
        public static X509Certificate2 CreateSelfSignedRsa(
            string subjectName,
            int yearsValid = 5,
            int rsaBits = 3072)
        {
            if (Null(subjectName))
            {
                throw new CtxException(
                    message: "subjectName is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (yearsValid <= 0)
            {
                throw new CtxException(
                    message: "yearsValid must be > 0.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.InvalidArguments);
            }

            if (rsaBits < 2048)
            {
                throw new CtxException(
                    message: "rsaBits must be >= 2048.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.InvalidArguments);
            }

            try
            {
                using RSA rsa = RSA.Create(rsaBits);

                var req = new CertificateRequest(
                    new X500DistinguishedName($"CN={subjectName}"),
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                req.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));

                req.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature,
                        critical: true));

                var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") };
                req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));

                DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
                DateTimeOffset notAfter = notBefore.AddYears(yearsValid);

                using var created = req.CreateSelfSigned(notBefore, notAfter);

                byte[] pfx = created.Export(X509ContentType.Pfx);
                var flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

                return new X509Certificate2(pfx, (string?)null, flags);
            }
            catch (CryptographicException ex)
            {
                throw new CtxException(
                    message: "Failed to create self-signed certificate.",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.CryptographicFailure,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Exports a certificate (including its private key, if present) as a PFX/PKCS#12 byte array.
        /// </summary>
        public static byte[] ExportPfx(X509Certificate2 cert, string? password)
        {
            if (cert == null)
            {
                throw new CtxException(
                    message: "cert is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            try
            {
                return password == null
                    ? cert.Export(X509ContentType.Pfx)
                    : cert.Export(X509ContentType.Pfx, password);
            }
            catch (CryptographicException ex)
            {
                throw new CtxException(
                    message: "Failed to export certificate as PFX.",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.CertificateLoadFailed,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Writes a certificate as a PFX/PKCS#12 file using an atomic write strategy.
        /// </summary>
        public static void WritePfxFile(X509Certificate2 cert, string path, string? password)
        {
            if (cert == null)
            {
                throw new CtxException(
                    message: "cert is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (Null(path))
            {
                throw new CtxException(
                    message: "path is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            byte[] pfx = ExportPfx(cert, password);

            try
            {
                WriteAllBytesAtomic(path, pfx);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new CtxException(
                    message: $"Access denied while writing PFX file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.AccessDenied,
                    innerException: ex);
            }
            catch (DirectoryNotFoundException ex)
            {
                throw new CtxException(
                    message: $"Directory not found while writing PFX file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.DirectoryNotFound,
                    innerException: ex);
            }
            catch (IOException ex)
            {
                throw new CtxException(
                    message: $"Failed to write PFX file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.OperationFailed,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Loads a PFX/PKCS#12 file using cross-platform-friendly key storage flags intended for signing workflows.
        /// </summary>
        public static X509Certificate2 LoadPfxFile(string path, string? password)
        {
            if (Null(path))
            {
                throw new CtxException(
                    message: "path is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (!File.Exists(path))
            {
                throw new CtxException(
                    message: "PFX file not found.",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.FileNotFound);
            }

            try
            {
                var flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;
                return new X509Certificate2(path, password, flags);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new CtxException(
                    message: $"Access denied while loading PFX file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.AccessDenied,
                    innerException: ex);
            }
            catch (CryptographicException ex)
            {
                throw new CtxException(
                    message: $"Failed to load PFX file: {path}",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.CertificateLoadFailed,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Installs a certificate into the current user's personal ("My") certificate store.
        /// </summary>
        public static void InstallToCurrentUserStore(X509Certificate2 cert)
        {
            if (cert == null)
            {
                throw new CtxException(
                    message: "cert is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (!IsWindows)
            {
                throw new CtxException(
                    message: "Certificate store installation is Windows-only.",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.PlatformNotSupported);
            }

            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
            }
            catch (CryptographicException ex)
            {
                throw new CtxException(
                    message: "Failed to install certificate into the current user store.",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.CryptographicFailure,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Removes certificates from the current user's personal ("My") certificate store that match a given thumbprint.
        /// </summary>
        public static void RemoveFromCurrentUserStore(string thumbprint)
        {
            if (!IsWindows)
            {
                throw new CtxException(
                    message: "Certificate store removal is Windows-only.",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.PlatformNotSupported);
            }

            thumbprint = NormalizeHex(thumbprint);
            if (thumbprint.Length == 0)
                return;

            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);

                var found = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    validOnly: false);

                foreach (var cert in found)
                    store.Remove(cert);
            }
            catch (CryptographicException ex)
            {
                throw new CtxException(
                    message: "Failed to remove certificate from the current user store.",
                    target: ErrorTarget.Certificate,
                    detail: ErrorDetail.CryptographicFailure,
                    innerException: ex);
            }
        }
    }
}