//CtxSignlib.Certificates/CertHelpers.cs
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        /// <param name="subjectName">
        /// Common Name (CN) portion of the subject. This value is inserted as <c>CN={subjectName}</c>.
        /// </param>
        /// <param name="yearsValid">Number of years the certificate is valid from its creation time. Must be greater than zero.</param>
        /// <param name="rsaBits">
        /// RSA key size in bits. Must be at least 2048. Recommended values are 2048, 3072, or 4096.
        /// </param>
        /// <returns>
        /// A new <see cref="X509Certificate2"/> instance containing a private key.
        /// The returned certificate is not installed in any OS store.
        /// </returns>
        /// <remarks>
        /// The generated certificate includes:
        /// <list type="bullet">
        /// <item><description>Basic Constraints: not a CA</description></item>
        /// <item><description>Key Usage: Digital Signature (critical)</description></item>
        /// <item><description>Enhanced Key Usage: Code Signing (OID 1.3.6.1.5.5.7.3.3)</description></item>
        /// </list>
        /// Validity starts slightly in the past (UTC minus 5 minutes) to reduce clock-skew issues.
        /// <para/>
        /// The certificate is exported and re-imported as PFX to ensure the returned instance carries a usable private key.
        /// The re-import uses <see cref="X509KeyStorageFlags.Exportable"/> and <see cref="X509KeyStorageFlags.EphemeralKeySet"/>
        /// to keep key material from being persisted to disk where supported.
        /// </remarks>
        /// <exception cref="ArgumentException">
        /// Thrown if <paramref name="subjectName"/> is null/whitespace, if <paramref name="yearsValid"/> is not greater than zero,
        /// or if <paramref name="rsaBits"/> is less than 2048.
        /// </exception>
        public static X509Certificate2 CreateSelfSignedRsa(
            string subjectName,
            int yearsValid = 5,
            int rsaBits = 3072)
        {
            if (Null(subjectName))
                throw new ArgumentException("subjectName is required.", nameof(subjectName));

            if (yearsValid <= 0)
                throw new ArgumentException("yearsValid must be > 0.", nameof(yearsValid));

            if (rsaBits < 2048)
                throw new ArgumentException("rsaBits must be >= 2048.", nameof(rsaBits));

            using RSA rsa = RSA.Create(rsaBits);

            var req = new CertificateRequest(
                new X500DistinguishedName($"CN={subjectName}"),
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            // Basic Constraints: not a CA
            req.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));

            // Key usage: digital signature (critical)
            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature,
                    critical: true));

            // Extended Key Usage: Code Signing (1.3.6.1.5.5.7.3.3)
            var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") };
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));

            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            DateTimeOffset notAfter = notBefore.AddYears(yearsValid);

            using var created = req.CreateSelfSigned(notBefore, notAfter);

            // Re-import with explicit flags for consistent cross-platform behavior.
            byte[] pfx = created.Export(X509ContentType.Pfx);
            var flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

            return new X509Certificate2(pfx, (string?)null, flags);
        }

        /// <summary>
        /// Exports a certificate (including its private key, if present) as a PFX/PKCS#12 byte array.
        /// </summary>
        /// <param name="cert">The certificate to export.</param>
        /// <param name="password">
        /// Optional password used to protect the exported PFX payload. May be null to export without a password.
        /// </param>
        /// <returns>Binary PFX (PKCS#12) content.</returns>
        /// <remarks>
        /// This is an explicit export action. Callers are responsible for handling the returned bytes securely
        /// (for example, avoiding logging and ensuring appropriate file permissions if written to disk).
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="cert"/> is null.</exception>
        /// <exception cref="CryptographicException">Thrown if export fails.</exception>
        public static byte[] ExportPfx(X509Certificate2 cert, string? password)
        {
            if (cert == null)
                throw new ArgumentNullException(nameof(cert));

            // If password is null, export unprotected (PKCS#12 with no password).
            return password == null
                ? cert.Export(X509ContentType.Pfx)
                : cert.Export(X509ContentType.Pfx, password);
        }

        /// <summary>
        /// Writes a certificate as a PFX/PKCS#12 file using an atomic write strategy.
        /// </summary>
        /// <param name="cert">The certificate to export and write.</param>
        /// <param name="path">Destination file path for the PFX output.</param>
        /// <param name="password">
        /// Optional password used to protect the exported PFX payload. May be null to write an unprotected PFX.
        /// </param>
        /// <remarks>
        /// This method exports the certificate via <see cref="ExportPfx(X509Certificate2, string?)"/> and then writes
        /// the result using <see cref="Functions.WriteAllBytesAtomic(string, byte[])"/> to avoid partially-written files.
        /// Callers are responsible for selecting a secure output location and applying appropriate access controls.
        /// </remarks>
        public static void WritePfxFile(X509Certificate2 cert, string path, string? password)
        {
            if (Null(path))
                throw new ArgumentException("path is required.", nameof(path));

            byte[] pfx = ExportPfx(cert, password);
            WriteAllBytesAtomic(path, pfx);
        }

        /// <summary>
        /// Loads a PFX/PKCS#12 file using cross-platform-friendly key storage flags intended for signing workflows.
        /// </summary>
        /// <param name="path">Path to the PFX file.</param>
        /// <param name="password">Password protecting the PFX file, or null if the PFX is unprotected.</param>
        /// <returns>A loaded <see cref="X509Certificate2"/> instance.</returns>
        /// <remarks>
        /// Uses <see cref="X509KeyStorageFlags.Exportable"/> to allow re-export/signing after load and
        /// <see cref="X509KeyStorageFlags.EphemeralKeySet"/> to avoid persisting private key material to disk where supported.
        /// </remarks>
        public static X509Certificate2 LoadPfxFile(string path, string? password)
        {
            if (Null(path))
                throw new ArgumentException("path is required.", nameof(path));

            if (!File.Exists(path))
                throw new FileNotFoundException("PFX file not found.", path);

            var flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;
            return new X509Certificate2(path, password, flags);
        }

        /// <summary>
        /// Installs a certificate into the current user's personal ("My") certificate store.
        /// </summary>
        /// <param name="cert">The certificate to install.</param>
        /// <remarks>
        /// This is an optional helper and is intentionally Windows-only because store semantics vary by platform.
        /// Installing certificates modifies user/system state and should be treated as an explicit action by the caller.
        /// </remarks>
        public static void InstallToCurrentUserStore(X509Certificate2 cert)
        {
            if (!IsWindows)
                throw new PlatformNotSupportedException("Certificate store installation is Windows-only.");

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
        }

        /// <summary>
        /// Removes certificates from the current user's personal ("My") certificate store that match a given thumbprint.
        /// </summary>
        /// <param name="thumbprint">Certificate thumbprint. Non-hex characters are ignored during normalization.</param>
        /// <remarks>
        /// This is an optional helper and is intentionally Windows-only.
        /// The input thumbprint is normalized via <see cref="Functions.NormalizeHex(string)"/> (removes separators and uppercases).
        /// If the normalized thumbprint is empty, this method returns without changes.
        /// </remarks>
        public static void RemoveFromCurrentUserStore(string thumbprint)
        {
            if (!IsWindows)
                throw new PlatformNotSupportedException("Certificate store removal is Windows-only.");

            thumbprint = NormalizeHex(thumbprint);
            if (thumbprint.Length == 0)
                return;

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            var found = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                thumbprint,
                validOnly: false);

            foreach (var cert in found)
                store.Remove(cert);
        }
    }
}