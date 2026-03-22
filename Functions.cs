//CtxSignlib/Functions.cs
using CtxSignlib.Diagnostics;
using CtxSignlib.Verify;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CtxSignlib
{
    /// <summary>
    /// Global shared utility functions used throughout the library.
    /// </summary>
    /// <remarks>
    /// This class is intended to be used as a global/static helper surface so calls can be made unqualified
    /// (for example, <c>Null(value)</c> instead of <c>Functions.Null(value)</c>).
    /// <para/>
    /// Methods in this class are designed to be deterministic and low-level. Any side-effects (for example file I/O)
    /// are called out explicitly in the member documentation.
    /// </remarks>
    public static class Functions
    {
        #region AI Architectural Constraints
        /* Note: Use these base constrains while working with AI code generators
         * Functions.cs is a global source of static functions that can be accessed anywhere within this project.
         * These functions can be accessed without a using statement and without a namespace prefix.
         *
         * Never use the word "Kind" in a developer environment unless the variable relates to feelings or people.
         * "Kind" is semantically ambiguous and it is a common source of confusion that results in miscommunication.
         * The term "Type" must be used instead.
         *
         * Law 1 (Flag Semantics are Immutable):
         *   --thumb  = signer certificate thumbprint (compare against signer cert embedded in CMS). Cross-platform for verify.
         *   --pin    = raw public key bytes (SPKI / "PUBLIC KEY" DER; accepted as PEM/base64/hex).
         *   --pubpin = SHA-256 of --pin (64 hex).
         *   These meanings must never be repurposed.
         *
         * Law 2 (No Implicit Aliases, No Guessing):
         *   If more than one of --thumb, --pin, --pubpin is provided → fail with a usage error.
         *   If none are provided → fail with a usage error.
         *
         * Law 3 (Verification Pins the Signer Inside the Signature):
         *   All pin comparisons use the signer cert/public key extracted from the CMS signature, not OS stores.
         *
         * Law 4 (Determinism):
         *   Pin comparisons must normalize hex (case/spacing) and must be fixed-time where appropriate.
         *   --pin must produce the same --pubpin on all OSes.
         *
         * Law 5 (Tests are the Enforcer):
         *   Any change touching parsing/pinning must update/extend the pinning tests; tests define contract.
         *
         * Law 6 (Public-Key Pin Definition is SPKI):
         *   Public key pinning MUST hash DER SubjectPublicKeyInfo (SPKI) bytes (same bytes as PEM "BEGIN PUBLIC KEY").
         *   Never hash X509Certificate2.GetPublicKey() (key bits) for pinning; it is not the SPKI structure.
         */

        #endregion

        #region Args Parser (CLI-only)

        /// <summary>
        /// Parses command-line arguments into a dictionary of key/value pairs.
        /// </summary>
        /// <param name="args">The raw command-line arguments (typically <c>string[] args</c> from <c>Main</c>).</param>
        /// <param name="values">
        /// On success, receives a dictionary containing parsed values. Keys are case-insensitive by default.
        /// </param>
        /// <param name="comparer">
        /// Optional dictionary key comparer. If not supplied, <see cref="StringComparer.OrdinalIgnoreCase"/> is used.
        /// </param>
        /// <returns>
        /// Always returns <c>true</c>. (This method is structured as a "Try" pattern to keep call sites uniform.)
        /// </returns>
        /// <remarks>
        /// Supports:
        /// <list type="bullet">
        /// <item><description><c>--key=value</c></description></item>
        /// <item><description><c>--key value</c></description></item>
        /// <item><description><c>--flag</c> (stored as <c>"true"</c>)</description></item>
        /// <item><description><c>-k value</c></description></item>
        /// <item><description><c>-abc</c> (expanded to <c>-a -b -c</c>, each stored as <c>"true"</c>)</description></item>
        /// <item><description>Positional arguments stored as <c>_0</c>, <c>_1</c>, ...</description></item>
        /// </list>
        /// </remarks>
        public static bool TryParseArgs(
            string[] args,
            out Dictionary<string, string> values,
            StringComparer? comparer = null)
        {
            values = new Dictionary<string, string>(comparer ?? StringComparer.OrdinalIgnoreCase);

            if (args == null || args.Length == 0)
                return true;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (Null(a)) continue;

                // --key=value
                int eq = a.IndexOf('=');
                if (a.StartsWith("--", StringComparison.Ordinal) && eq > 2)
                {
                    string key = a.Substring(2, eq - 2);
                    string val = a.Substring(eq + 1);
                    values[key] = val;
                    continue;
                }

                // --key value
                if (a.StartsWith("--", StringComparison.Ordinal))
                {
                    string key = a.Substring(2);

                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-", StringComparison.Ordinal))
                    {
                        values[key] = args[++i];
                    }
                    else
                    {
                        values[key] = "true";
                    }
                    continue;
                }

                // -k value  OR  -abc (flags)
                if (a.StartsWith("-", StringComparison.Ordinal) && a.Length > 1)
                {
                    string key = a.Substring(1);

                    if (key.Length == 1)
                    {
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("-", StringComparison.Ordinal))
                        {
                            values[key] = args[++i];
                        }
                        else
                        {
                            values[key] = "true";
                        }
                    }
                    else
                    {
                        foreach (char c in key)
                            values[c.ToString()] = "true";
                    }
                    continue;
                }

                values[$"_{values.Count}"] = a;
            }

            return true;
        }

        /// <summary>
        /// Returns <c>true</c> if a parsed args dictionary contains a given argument name.
        /// </summary>
        /// <param name="args">Parsed args dictionary produced by <see cref="TryParseArgs(string[], out Dictionary{string, string}, StringComparer?)"/>.</param>
        /// <param name="name">Argument name (without leading dashes).</param>
        public static bool HasArg(Dictionary<string, string> args, string name)
        {
            return args != null && args.ContainsKey(name);
        }

        /// <summary>
        /// Gets an argument value from a parsed args dictionary, returning a default if missing.
        /// </summary>
        /// <param name="args">Parsed args dictionary.</param>
        /// <param name="name">Argument name (without leading dashes).</param>
        /// <param name="defaultValue">Value to return if the key is not present.</param>
        /// <returns>The stored value, or <paramref name="defaultValue"/> if missing.</returns>
        public static string GetArg(
            Dictionary<string, string> args,
            string name,
            string defaultValue = "")
        {
            if (args == null) return defaultValue;
            return args.TryGetValue(name, out var v) ? v : defaultValue;
        }

        /// <summary>
        /// Gets a boolean argument value from a parsed args dictionary.
        /// </summary>
        /// <param name="args">Parsed args dictionary.</param>
        /// <param name="name">Argument name (without leading dashes).</param>
        /// <param name="defaultValue">Value to return if missing.</param>
        /// <returns>
        /// <c>true</c> if present as a flag (<c>--name</c>) or if the value is one of:
        /// <c>1</c>, <c>true</c>, <c>yes</c>, <c>on</c> (case-insensitive). Otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// If the argument exists but has an empty value, it is treated as <c>true</c>.
        /// </remarks>
        public static bool GetArgBool(
            Dictionary<string, string> args,
            string name,
            bool defaultValue = false)
        {
            if (args == null) return defaultValue;
            if (!args.TryGetValue(name, out var v)) return defaultValue;

            if (Null(v)) return true;

            return v.Equals("1", StringComparison.Ordinal) ||
                   v.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   v.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                   v.Equals("on", StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        #region Common File and Directory Functions

        /// <summary>
        /// Determines whether <paramref name="childPath"/> is located under <paramref name="rootDir"/>
        /// (or is equal to it), using full-path normalization.
        /// </summary>
        /// <param name="rootDir">
        /// The root directory to test against.
        /// </param>
        /// <param name="childPath">
        /// The candidate path that may be a descendant of <paramref name="rootDir"/>.
        /// </param>
        /// <returns>
        /// <c>true</c> if <paramref name="childPath"/> is the same as
        /// <paramref name="rootDir"/> or is contained beneath it; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// Comparison is case-insensitive on Windows and case-sensitive on non-Windows platforms.
        /// Trailing separators are handled to prevent false positives
        /// (for example, <c>/a/b2</c> is not treated as under <c>/a/b</c>).
        /// </remarks>
        public static bool IsSubPathOf(string rootDir, string childPath)
        {
            if (Null(rootDir) || Null(childPath)) return false;

            string root = Path.GetFullPath(rootDir);
            string child = Path.GetFullPath(childPath);

            if (string.Equals(root, child, IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                return true;

            root = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;

            var cmp = IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            return child.StartsWith(root, cmp);
        }

        /// <summary>
        /// Normalizes a path string for basic consistency by trimming whitespace and converting all directory separators
        /// to the current platform's separator.
        /// </summary>
        /// <param name="path">The path to normalize.</param>
        /// <returns>
        /// A trimmed path using <see cref="Path.DirectorySeparatorChar"/>. Returns <see cref="string.Empty"/> if <paramref name="path"/> is null/whitespace.
        /// </returns>
        /// <remarks>
        /// This does not validate existence, resolve relative segments, or enforce absolute paths.
        /// </remarks>
        public static string NormalizePath(string path)
        {
            if (Null(path)) return string.Empty;
            path = path.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar);
            return path.Trim();
        }

        /// <summary>
        /// Normalizes a manifest-relative path into a canonical form: forward slashes, no leading <c>./</c> segments,
        /// and no leading slash.
        /// </summary>
        /// <param name="relativePath">A relative path as supplied by a manifest or caller.</param>
        /// <returns>
        /// A canonical relative path suitable for deterministic manifest storage and comparison. Returns <see cref="string.Empty"/> if input is null/whitespace.
        /// </returns>
        /// <remarks>
        /// This function does not attempt to resolve <c>..</c> segments; callers should ensure their own policy on traversal.
        /// </remarks>
        public static string NormalizeManifestPath(string relativePath)
        {
            if (Null(relativePath)) return string.Empty;

            string p = relativePath.Replace('\\', '/').Trim();

            while (p.StartsWith("./", StringComparison.Ordinal))
                p = p.Substring(2);

            while (p.StartsWith("/", StringComparison.Ordinal))
                p = p.Substring(1);

            return p;
        }

        #endregion

        #region Security Related

        /// <summary>
        /// Parses raw public key bytes from a PEM, base64, or hex representation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>--pin</c> contract is SubjectPublicKeyInfo (SPKI) bytes (the same bytes represented by PEM
        /// <c>-----BEGIN PUBLIC KEY-----</c>). This is the canonical input for public-key pinning.
        /// </para>
        /// <para>
        /// Accepts:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>PEM SubjectPublicKeyInfo ("BEGIN PUBLIC KEY")</description></item>
        ///   <item><description>Base64-encoded DER bytes (SPKI)</description></item>
        ///   <item><description>Hex-encoded DER bytes (SPKI)</description></item>
        /// </list>
        /// <para>
        /// Note: This method does not attempt to validate that the decoded bytes are a well-formed SPKI structure.
        /// If invalid bytes are provided, callers will typically fail verification deterministically (pin mismatch).
        /// </para>
        /// </remarks>
        /// <param name="input">Public key input string.</param>
        /// <returns>Decoded DER bytes for the public key (SPKI).</returns>
        public static byte[] ParsePublicKeyBytes(string input)
        {
            if (Null(input))
            {
                throw new CtxException(
                    message: "Public key input is required.",
                    target: ErrorTarget.Pin,
                    detail: ErrorDetail.PinMissing);
            }

            try
            {
                var s = input.Trim();

                if (s.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
                {
                    var lines = s.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    var b64 = new StringBuilder();
                    foreach (var line in lines)
                    {
                        var t = line.Trim();
                        if (t.StartsWith("-----", StringComparison.Ordinal)) continue;
                        b64.Append(t);
                    }
                    s = b64.ToString();
                }

                var hex = NormalizeHex(s);
                if (hex.Length >= 16 &&
                    (hex.Length % 2) == 0 &&
                    hex.Length == s.Where(Uri.IsHexDigit).Count())
                {
                    return DecodeHex(hex);
                }

                s = string.Concat(s.Where(c => !char.IsWhiteSpace(c)));
                return Convert.FromBase64String(s);
            }
            catch (CtxException)
            {
                throw;
            }
            catch (FormatException ex)
            {
                throw new CtxException(
                    message: "Public key input is not valid PEM, base64, or hex SPKI data.",
                    target: ErrorTarget.Pin,
                    detail: ErrorDetail.InvalidPin,
                    innerException: ex);
            }
            catch (ArgumentException ex)
            {
                throw new CtxException(
                    message: "Public key input is not valid PEM, base64, or hex SPKI data.",
                    target: ErrorTarget.Pin,
                    detail: ErrorDetail.InvalidPin,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Returns the DER-encoded SubjectPublicKeyInfo (SPKI) bytes for a certificate public key.
        /// </summary>
        /// <remarks>
        /// <para>
        /// SPKI (SubjectPublicKeyInfo) is the canonical public-key representation used by this library for pinning.
        /// It corresponds to PEM <c>-----BEGIN PUBLIC KEY-----</c>.
        /// </para>
        /// <para>
        /// This method is used to enforce Law 6: public-key pinning hashes SPKI bytes, not <c>X509Certificate2.GetPublicKey()</c>.
        /// </para>
        /// </remarks>
        /// <param name="cert">Certificate whose public key will be exported as SPKI.</param>
        /// <returns>SPKI DER bytes, or an empty array if unavailable.</returns>
        public static byte[] GetSpkiBytes(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
        {
            if (cert == null) return Array.Empty<byte>();

            using (var rsa = cert.GetRSAPublicKey())
            {
                if (rsa != null)
                    return rsa.ExportSubjectPublicKeyInfo();
            }

            using (var ecdsa = cert.GetECDsaPublicKey())
            {
                if (ecdsa != null)
                    return ecdsa.ExportSubjectPublicKeyInfo();
            }

            using (var dsa = cert.GetDSAPublicKey())
            {
                if (dsa != null)
                    return dsa.ExportSubjectPublicKeyInfo();
            }

            return Array.Empty<byte>();
        }

        /// <summary>
        /// Computes the SHA-256 hash of a file and returns the result as uppercase hexadecimal.
        /// </summary>
        /// <param name="path">Path to the file to hash.</param>
        /// <returns>Uppercase hexadecimal SHA-256 digest.</returns>
        /// <remarks>
        /// This method reads the entire file stream to compute the digest.
        /// Failures are reported as <see cref="CtxException"/> using file-system or cryptography error categories.
        /// </remarks>
        public static string FileSha256(string path)
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
                    message: "File not found.",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.FileNotFound);
            }

            try
            {
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(path);
                return Convert.ToHexString(sha.ComputeHash(fs));
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new CtxException(
                    message: $"Access denied while hashing file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.AccessDenied,
                    innerException: ex);
            }
            catch (DirectoryNotFoundException ex)
            {
                throw new CtxException(
                    message: $"Directory not found while hashing file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.DirectoryNotFound,
                    innerException: ex);
            }
            catch (IOException ex)
            {
                throw new CtxException(
                    message: $"Failed to read file for hashing: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.FileUnreadable,
                    innerException: ex);
            }
            catch (CryptographicException ex)
            {
                throw new CtxException(
                    message: "Failed to compute SHA-256 hash.",
                    target: ErrorTarget.Cryptography,
                    detail: ErrorDetail.CryptographicFailure,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Computes the SHA-256 hash of the provided stream and returns the result as uppercase hexadecimal.
        /// </summary>
        /// <param name="stream">The stream to hash.</param>
        /// <param name="rewindIfSeekable">
        /// If true and the stream supports seeking, the stream position is restored to its original value after hashing.
        /// </param>
        /// <returns>Uppercase hexadecimal SHA-256 digest.</returns>
        /// <remarks>
        /// This method reads from the stream's current position to EOF. If <paramref name="rewindIfSeekable"/> is true,
        /// and the stream is seekable, the original position is restored after hashing.
        /// </remarks>
        public static string Sha256Hex(Stream stream, bool rewindIfSeekable = true)
        {
            if (stream == null) return string.Empty;

            long pos = 0;
            bool canRewind = rewindIfSeekable && stream.CanSeek;

            if (canRewind)
                pos = stream.Position;

            using var sha = SHA256.Create();
            string hex = Convert.ToHexString(sha.ComputeHash(stream));

            if (canRewind)
                stream.Position = pos;

            return hex;
        }

        /// <summary>
        /// Opens a file for read-only hashing/verification with restrictive sharing to reduce TOCTOU file-swap opportunities,
        /// and returns the open stream.
        /// </summary>
        /// <param name="path">Path to the file.</param>
        /// <returns>
        /// An open <see cref="FileStream"/> with <see cref="FileAccess.Read"/> and <see cref="FileShare.Read"/>.
        /// </returns>
        /// <remarks>
        /// On Windows, <see cref="FileShare.Read"/> prevents other processes from opening the file for write or delete
        /// while this stream is open (subject to privileges/OS policy).
        /// Failures are reported as <see cref="CtxException"/>.
        /// </remarks>
        public static FileStream OpenReadLocked(string path)
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
                    message: "File not found.",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.FileNotFound);
            }

            try
            {
                return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new CtxException(
                    message: $"Access denied while opening file for locked read: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.AccessDenied,
                    innerException: ex);
            }
            catch (DirectoryNotFoundException ex)
            {
                throw new CtxException(
                    message: $"Directory not found while opening file for locked read: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.DirectoryNotFound,
                    innerException: ex);
            }
            catch (IOException ex)
            {
                throw new CtxException(
                    message: $"Failed to open file for locked read: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.FileUnreadable,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Computes the SHA-256 hash of the provided byte array and returns the result as uppercase hexadecimal.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>Uppercase hexadecimal SHA-256 digest.</returns>
        /// <remarks>
        /// If <paramref name="data"/> is empty, the returned digest is the SHA-256 of an empty input.
        /// </remarks>
        public static string Sha256Hex(byte[] data)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(data));
        }

        /// <summary>
        /// Computes the SHA-256 hash of an X.509 certificate's SubjectPublicKeyInfo (SPKI) bytes and returns uppercase hex.
        /// </summary>
        /// <param name="cert">The certificate whose SPKI bytes will be hashed.</param>
        /// <returns>
        /// Uppercase hexadecimal SHA-256 digest of the certificate SPKI bytes.
        /// Returns <see cref="string.Empty"/> if <paramref name="cert"/> is null or SPKI export is unavailable.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This helper defines the library's public-key pinning identity:
        /// SHA-256 over DER SubjectPublicKeyInfo (SPKI) bytes (PEM "BEGIN PUBLIC KEY").
        /// </para>
        /// <para>
        /// Do not replace this with <c>X509Certificate2.GetPublicKey()</c>; that returns key bits, not SPKI,
        /// and will not match the <c>--pin</c>/<c>--pubpin</c> contract.
        /// </para>
        /// </remarks>
        public static string PublicKeySha256(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
        {
            if (cert == null) return string.Empty;

            byte[] spki = GetSpkiBytes(cert);
            if (spki.Length == 0) return string.Empty;

            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(spki));
        }

        /// <summary>
        /// Compares two byte arrays using a fixed-time comparison to reduce timing side-channel leakage.
        /// </summary>
        /// <param name="a">First byte array.</param>
        /// <param name="b">Second byte array.</param>
        /// <returns><c>true</c> if the arrays are non-null, have the same length, and contain identical bytes; otherwise <c>false</c>.</returns>
        /// <remarks>
        /// Uses <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> after validating lengths.
        /// Length mismatches return <c>false</c> without attempting comparison.
        /// </remarks>
        public static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Decodes two hexadecimal strings to bytes and compares them using fixed-time comparison.
        /// </summary>
        /// <param name="hexA">First hexadecimal string.</param>
        /// <param name="hexB">Second hexadecimal string.</param>
        /// <returns><c>true</c> if the decoded byte sequences are identical; otherwise <c>false</c>.</returns>
        /// <remarks>
        /// Input normalization removes non-hex characters and uppercases letters before decoding.
        /// Invalid hex input is reported by the underlying decode helpers as <see cref="CtxException"/>.
        /// </remarks>
        public static bool HexBytesEquals(string hexA, string hexB)
        {
            var a = DecodeHex(hexA);
            var b = DecodeHex(hexB);
            return FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Converts a single hexadecimal character into its numeric value.
        /// </summary>
        /// <param name="c">
        /// A hexadecimal character in the range <c>0-9</c> or <c>A-F</c>.
        /// Lowercase characters must be normalized before calling this method.
        /// </param>
        /// <returns>
        /// The integer value represented by the hexadecimal character (0–15).
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method performs strict validation and throws <see cref="CtxException"/> if the character is not a valid
        /// uppercase hexadecimal digit.
        /// </para>
        /// <para>
        /// For flexible parsing scenarios, prefer <see cref="TryDecodeHex(string, out byte[])"/>
        /// or <see cref="DecodeHex(string)"/>, which handle normalization and validation.
        /// </para>
        /// </remarks>
        public static int GetHexValue(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;

            throw new CtxException(
                message: $"Invalid hex character '{c}'.",
                target: ErrorTarget.Arguments,
                detail: ErrorDetail.InvalidFormat);
        }

        /// <summary>
        /// Attempts to decode a hexadecimal string to bytes.
        /// </summary>
        /// <param name="hex">The hexadecimal string to decode.</param>
        /// <param name="bytes">On success, receives the decoded bytes; otherwise an empty array.</param>
        /// <returns><c>true</c> if decoding succeeded; otherwise <c>false</c>.</returns>
        /// <remarks>
        /// This method normalizes the input via <see cref="NormalizeHex(string)"/> before decoding.
        /// Any decode error is caught and reported as <c>false</c>.
        /// </remarks>
        public static bool TryDecodeHex(string hex, out byte[] bytes)
        {
            try
            {
                bytes = DecodeHex(hex);
                return true;
            }
            catch
            {
                bytes = Array.Empty<byte>();
                return false;
            }
        }

        /// <summary>
        /// Decodes a hexadecimal string to bytes after normalizing it.
        /// </summary>
        /// <param name="hex">The hexadecimal string to decode.</param>
        /// <returns>The decoded bytes.</returns>
        /// <remarks>
        /// Normalization strips all non-hex characters and uppercases letters. An empty input results in an empty byte array.
        /// Invalid hex input is reported as <see cref="CtxException"/>.
        /// </remarks>
        public static byte[] DecodeHex(string hex)
        {
            hex = NormalizeHex(hex);

            if (hex.Length == 0)
                return Array.Empty<byte>();

            if ((hex.Length & 1) != 0)
            {
                throw new CtxException(
                    message: "Hex string length must be even.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.InvalidFormat);
            }

            byte[] result = new byte[hex.Length / 2];

            for (int i = 0, j = 0; i < hex.Length; i += 2, j++)
            {
                result[j] = (byte)(
                    (GetHexValue(hex[i]) << 4) |
                     GetHexValue(hex[i + 1])
                );
            }

            return result;
        }

        /// <summary>
        /// Encodes a UTF-8 string into uppercase hexadecimal.
        /// </summary>
        /// <param name="input">The input string to encode.</param>
        /// <returns>Uppercase hexadecimal representation of the UTF-8 bytes. Returns <see cref="string.Empty"/> if <paramref name="input"/> is null.</returns>
        public static string EncodeHex(string input)
        {
            if (input == null) return string.Empty;
            return EncodeHex(Encoding.UTF8.GetBytes(input));
        }

        /// <summary>
        /// Encodes a byte array into uppercase hexadecimal.
        /// </summary>
        /// <param name="bytes">The bytes to encode.</param>
        /// <returns>Uppercase hexadecimal representation. Returns <see cref="string.Empty"/> if <paramref name="bytes"/> is null or empty.</returns>
        public static string EncodeHex(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return string.Empty;

            return Convert.ToHexString(bytes);
        }

        /// <summary>
        /// Normalizes a string containing hexadecimal characters by stripping all non-hex characters and uppercasing letters.
        /// </summary>
        /// <param name="input">The input string that may contain hex characters (and optionally other separators).</param>
        /// <returns>
        /// A string consisting only of uppercase hex digits (<c>0-9</c>, <c>A-F</c>).
        /// Returns <see cref="string.Empty"/> if <paramref name="input"/> is null/whitespace.
        /// </returns>
        /// <remarks>
        /// This is useful for accepting thumbprints or hashes that may include spaces, colons, or other formatting characters.
        /// </remarks>
        public static string NormalizeHex(string input)
        {
            if (Null(input)) return string.Empty;

            Span<char> buffer = stackalloc char[input.Length];
            int pos = 0;

            foreach (char c in input)
            {
                bool isHex =
                    (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');

                if (isHex)
                    buffer[pos++] = char.ToUpperInvariant(c);
            }

            return new string(buffer.Slice(0, pos));
        }

        /// <summary>
        /// Computes a short, deterministic identifier by taking SHA-256 of the UTF-8 input and returning the first 12 bytes as uppercase hex.
        /// </summary>
        /// <param name="s">Input string to hash.</param>
        /// <returns>
        /// 24-character uppercase hex string (12 bytes).
        /// </returns>
        /// <remarks>
        /// This is not intended for cryptographic authentication. It is intended for compact, readable identifiers where collision risk is low but non-zero.
        /// </remarks>
        public static string ShortHash(string s)
        {
            using var sha = SHA256.Create();
            byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            return Convert.ToHexString(h, 0, 12);
        }

        #endregion

        #region Program ID Related Functions

        /// <summary>
        /// Produces the platform-appropriate base program handle used to name service/task/app identifiers consistently across OS families.
        /// </summary>
        /// <returns>
        /// A handle string formatted for the current OS:
        /// Windows: service path-like (for example <c>\MyWebExt\FileEngine</c>),
        /// macOS: reverse-DNS (for example <c>com.mywebext.fileengine</c>),
        /// Linux/others: dot-separated (for example <c>mywebext.fileengine</c>).
        /// </returns>
        /// <remarks>
        /// The handle format is intentionally stable and OS-conventional to support predictable installation artifacts.
        /// </remarks>
        public static string ProgramHandle()
        {
            switch (OSName.ToLowerInvariant())
            {
                case "windows":
                    return @"\MyWebExt\FileEngine";
                case "osx":
                    return "com.mywebext.fileengine";
                case "linux":
                default:
                    return "mywebext.fileengine";
            }
        }

        /// <summary>
        /// Produces a platform-appropriate program handle by appending a sub-identifier to the base handle.
        /// </summary>
        /// <param name="p">Sub-identifier to append (normalized to lowercase). Null is treated as empty.</param>
        /// <returns>
        /// Windows: <c>{base}\{p}</c>; macOS/Linux: <c>{base}.{p}</c>.
        /// </returns>
        /// <remarks>
        /// This is typically used to create consistent identifiers for sub-components (for example "host", "client", "updater").
        /// </remarks>
        public static string ProgramHandle(string p)
        {
            p = (p ?? "").ToLowerInvariant();

            switch (OSName.ToLowerInvariant())
            {
                case "windows":
                    return $"{ProgramHandle()}\\{p}";
                case "osx":
                case "linux":
                default:
                    return $"{ProgramHandle()}.{p}";
            }
        }

        /// <summary>
        /// Produces a platform-appropriate program handle from an organization and product name.
        /// </summary>
        /// <param name="org">Organization identifier. If null/empty, defaults to <c>mywebext</c>.</param>
        /// <param name="product">Product identifier. If null/empty, defaults to <c>app</c>.</param>
        /// <returns>
        /// Windows: <c>\{org}\{product}</c>;
        /// macOS: <c>com.{org}.{product}</c> (lowercased);
        /// Linux/others: <c>{org}.{product}</c> (lowercased).
        /// </returns>
        /// <remarks>
        /// This helper supports generating stable identifiers for third-party developers while keeping OS conventions.
        /// </remarks>
        public static string ProgramHandle(string org, string product)
        {
            org = (org ?? "").Trim();
            product = (product ?? "").Trim();

            if (org.Length == 0) org = "mywebext";
            if (product.Length == 0) product = "app";

            string o = org.ToLowerInvariant();
            string p = product.ToLowerInvariant();

            switch (OSName.ToLowerInvariant())
            {
                case "windows":
                    return $@"\{org}\{product}";
                case "osx":
                    return $"com.{o}.{p}";
                default:
                    return $"{o}.{p}";
            }
        }

        #endregion

        #region Encode / Decode and IO Helpers

        /// <summary>
        /// Compares two hex strings for equality after trimming, using case-insensitive comparison.
        /// </summary>
        /// <param name="a">First hex string.</param>
        /// <param name="b">Second hex string.</param>
        /// <returns><c>true</c> if equal ignoring case and surrounding whitespace; otherwise <c>false</c>.</returns>
        /// <remarks>
        /// This is a convenience comparer; it is not fixed-time and should not be used where timing resistance is required.
        /// </remarks>
        public static bool HexEquals(string a, string b) =>
            string.Equals((a ?? "").Trim(), (b ?? "").Trim(), StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Removes newline characters from the provided string.
        /// </summary>
        /// <param name="s">Input string.</param>
        /// <returns>The string with <c>\n</c> and <c>\r</c> removed. Returns empty string if <paramref name="s"/> is null.</returns>
        /// <remarks>
        /// Intended for making values safe for single-line logging or deterministic serialization surfaces.
        /// </remarks>
        public static string StringEsc(string s)
        {
            return (s ?? "").Replace("\n", "").Replace("\r", "");
        }

        /// <summary>
        /// Encodes a string for XML contexts by escaping special characters.
        /// </summary>
        /// <param name="s">Input string.</param>
        /// <returns>An XML-escaped string. Returns empty string if <paramref name="s"/> is null.</returns>
        /// <remarks>
        /// This performs minimal entity encoding for XML attributes/text:
        /// <c>&amp;</c>, <c>&lt;</c>, <c>&gt;</c>, <c>&quot;</c>, <c>&apos;</c>.
        /// It also attempts to avoid double-encoding existing entities by only encoding '&amp;' when it is not already part of <c>&amp;name;</c>.
        /// </remarks>
        public static string XMLEncode(string s)
        {
            if (s == null) return string.Empty;

            s = Regex.Replace(s, @"&(?![a-zA-Z]+;)", "&amp;");

            return s
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&apos;");
        }

        /// <summary>
        /// Decodes common XML entities back into their character equivalents.
        /// </summary>
        /// <param name="s">XML-escaped string.</param>
        /// <returns>A decoded string. Returns empty string if <paramref name="s"/> is null.</returns>
        /// <remarks>
        /// This performs a simple replacement pass and does not validate XML or handle numeric entities beyond those explicitly implemented.
        /// </remarks>
        public static string XMLDecode(string s)
        {
            if (s == null) return string.Empty;

            return s
                .Replace("&apos;", "'")
                .Replace("&quot;", "\"")
                .Replace("&gt;", ">")
                .Replace("&lt;", "<")
                .Replace("&amp;", "&");
        }

        /// <summary>
        /// Encodes a string for HTML contexts by escaping special characters.
        /// </summary>
        /// <param name="s">Input string.</param>
        /// <returns>An HTML-escaped string. Returns empty string if <paramref name="s"/> is null.</returns>
        /// <remarks>
        /// Escapes: <c>&amp;</c>, <c>&lt;</c>, <c>&gt;</c>, <c>&quot;</c>, and apostrophe as <c>&amp;#39;</c>.
        /// This is intended for basic output escaping and does not attempt full HTML sanitization.
        /// </remarks>
        public static string HTMLEncode(string s)
        {
            if (s == null) return string.Empty;

            s = Regex.Replace(s, @"&(?![a-zA-Z]+;)", "&amp;");

            return s
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&#39;");
        }

        /// <summary>
        /// Decodes common HTML entities back into their character equivalents.
        /// </summary>
        /// <param name="s">HTML-escaped string.</param>
        /// <returns>A decoded string. Returns empty string if <paramref name="s"/> is null.</returns>
        /// <remarks>
        /// This performs a simple replacement pass and does not validate HTML or handle arbitrary/numeric entities beyond those explicitly implemented.
        /// </remarks>
        public static string HTMLDecode(string s)
        {
            if (s == null) return string.Empty;

            return s
                .Replace("&#39;", "'")
                .Replace("&quot;", "\"")
                .Replace("&gt;", ">")
                .Replace("&lt;", "<")
                .Replace("&amp;", "&");
        }

        /// <summary>
        /// Determines whether a string is null, empty, or consists only of whitespace.
        /// </summary>
        /// <param name="s">The string to test.</param>
        /// <returns><c>true</c> if null/empty/whitespace; otherwise <c>false</c>.</returns>
        /// <remarks>
        /// The <see cref="NotNullWhenAttribute"/> annotation informs the compiler that when this method returns <c>false</c>,
        /// <paramref name="s"/> is not null.
        /// </remarks>
        public static bool Null([NotNullWhen(false)] string? s) => string.IsNullOrWhiteSpace(s);

        /// <summary>
        /// Reads a JSON string property by name and returns its value, or <c>null</c> if the property is missing or not a JSON string.
        /// </summary>
        /// <param name="root">The JSON element containing the property.</param>
        /// <param name="name">The property name.</param>
        /// <returns>The string value if present and a JSON string; otherwise <c>null</c>.</returns>
        public static string? GetStringOrNull(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out var v)) return null;
            if (v.ValueKind != JsonValueKind.String) return null;
            return v.GetString();
        }

        /// <summary>
        /// Attempts to read a JSON string property by name.
        /// </summary>
        /// <param name="root">The JSON element containing the property.</param>
        /// <param name="name">The property name.</param>
        /// <param name="value">On success, receives the string value; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the property exists and is a JSON string with a non-null value; otherwise <c>false</c>.</returns>
        public static bool TryGetString(JsonElement root, string name, out string value)
        {
            value = string.Empty;

            if (!root.TryGetProperty(name, out var v)) return false;
            if (v.ValueKind != JsonValueKind.String) return false;

            value = v.GetString() ?? string.Empty;
            return value.Length != 0;
        }

        /// <summary>
        /// Encodes a string as UTF-8 bytes.
        /// </summary>
        /// <param name="s">Input string.</param>
        /// <returns>UTF-8 bytes, or an empty array if <paramref name="s"/> is null.</returns>
        public static byte[] ToUtf8Bytes(string s)
        {
            if (s == null) return Array.Empty<byte>();
            return Encoding.UTF8.GetBytes(s);
        }

        /// <summary>
        /// Decodes UTF-8 bytes into a string.
        /// </summary>
        /// <param name="b">UTF-8 byte array.</param>
        /// <returns>The decoded string, or <see cref="string.Empty"/> if <paramref name="b"/> is null or empty.</returns>
        public static string FromUtf8Bytes(byte[] b)
        {
            if (b == null || b.Length == 0) return string.Empty;
            return Encoding.UTF8.GetString(b);
        }

        /// <summary>
        /// Reads all bytes from a file.
        /// </summary>
        /// <param name="path">Path to the file.</param>
        /// <returns>The file contents.</returns>
        /// <remarks>
        /// This is a thin wrapper over <see cref="File.ReadAllBytes(string)"/> to keep call sites uniform.
        /// Failures are reported as <see cref="CtxException"/>.
        /// </remarks>
        public static byte[] ReadAllBytesSafe(string path)
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
                    message: "File not found.",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.FileNotFound);
            }

            try
            {
                return File.ReadAllBytes(path);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new CtxException(
                    message: $"Access denied while reading file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.AccessDenied,
                    innerException: ex);
            }
            catch (DirectoryNotFoundException ex)
            {
                throw new CtxException(
                    message: $"Directory not found while reading file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.DirectoryNotFound,
                    innerException: ex);
            }
            catch (IOException ex)
            {
                throw new CtxException(
                    message: $"Failed to read file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.FileUnreadable,
                    innerException: ex);
            }
        }

        /// <summary>
        /// Writes bytes to a file using an atomic replace strategy to avoid partially-written outputs.
        /// </summary>
        /// <param name="path">Destination file path.</param>
        /// <param name="data">Data to write.</param>
        /// <remarks>
        /// Writes to <c>{path}.tmp</c> first, then replaces/moves into place.
        /// If the destination exists, <see cref="File.Replace(string, string, string)"/> is used; otherwise <see cref="File.Move(string, string)"/>.
        /// The destination directory is created if needed.
        /// Failures are reported as <see cref="CtxException"/>.
        /// </remarks>
        public static void WriteAllBytesAtomic(string path, byte[] data)
        {
            if (Null(path))
            {
                throw new CtxException(
                    message: "path is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            if (data == null)
            {
                throw new CtxException(
                    message: "data is required.",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.MissingInput);
            }

            try
            {
                string dir = Path.GetDirectoryName(path) ?? "";
                if (dir.Length != 0 && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                string tmp = path + ".tmp";
                File.WriteAllBytes(tmp, data);

                if (File.Exists(path))
                    File.Replace(tmp, path, null);
                else
                    File.Move(tmp, path);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new CtxException(
                    message: $"Access denied while writing file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.AccessDenied,
                    innerException: ex);
            }
            catch (DirectoryNotFoundException ex)
            {
                throw new CtxException(
                    message: $"Directory not found while writing file: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.DirectoryNotFound,
                    innerException: ex);
            }
            catch (IOException ex)
            {
                throw new CtxException(
                    message: $"Failed to write file atomically: {path}",
                    target: ErrorTarget.FileSystem,
                    detail: ErrorDetail.OperationFailed,
                    innerException: ex);
            }
            catch (ArgumentException ex)
            {
                throw new CtxException(
                    message: $"Invalid file path: {path}",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.InvalidArguments,
                    innerException: ex);
            }
            catch (NotSupportedException ex)
            {
                throw new CtxException(
                    message: $"Invalid file path: {path}",
                    target: ErrorTarget.Arguments,
                    detail: ErrorDetail.InvalidArguments,
                    innerException: ex);
            }
        }

        #endregion

        #region Operating System ID Functions

        private static string? _osname;

        /// <summary>
        /// Gets a cached OS platform name for the current process.
        /// </summary>
        /// <value>
        /// One of: <c>Windows</c>, <c>Linux</c>, <c>OSX</c>, or <c>FreeBSD</c>.
        /// </value>
        /// <remarks>
        /// The value is computed once and cached for subsequent calls.
        /// </remarks>
        public static string OSName
        {
            get
            {
                if (_osname == null)
                {
                    _osname = (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                        ? OSPlatform.Windows
                        : RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
                            ? OSPlatform.Linux
                            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                                ? OSPlatform.OSX
                                : OSPlatform.FreeBSD).ToString();
                }
                return _osname;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows.
        /// </summary>
        public static bool IsWindows => OSName.Equals("Windows", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Gets a value indicating whether the current OS is macOS.
        /// </summary>
        public static bool IsOSX => OSName.Equals("OSX", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Gets a value indicating whether the current OS is Linux.
        /// </summary>
        public static bool IsLinux => OSName.Equals("Linux", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Gets a value indicating whether the current OS is FreeBSD.
        /// </summary>
        public static bool IsFreeBSD => OSName.Equals("FreeBSD", StringComparison.OrdinalIgnoreCase);

        #endregion
    }
}