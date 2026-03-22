// CtxSignlib.Diagnostics/ErrorDetail.cs
namespace CtxSignlib.Diagnostics;

/// <summary>
/// Identifies the specific diagnostic detail associated with a library outcome or failure.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ErrorDetail"/> provides a stable, machine-readable reason that callers can use
/// alongside <see cref="ErrorTarget"/> and higher-level result values.
/// </para>
/// <para>
/// Host applications may translate these values into return codes, help topics,
/// remediation guidance, logs, or localized messages.
/// </para>
/// </remarks>
public enum ErrorDetail
{
    /// <summary>
    /// No diagnostic detail is associated with the current outcome.
    /// </summary>
    None = 0,

    /// <summary>
    /// The operation completed successfully.
    /// </summary>
    Ok = 1,

    /// <summary>
    /// A general or unspecified diagnostic condition occurred.
    /// </summary>
    Generic = 2,

    /// <summary>
    /// The supplied arguments, options, or parameters were invalid, incomplete, or inconsistent.
    /// </summary>
    InvalidArguments = 3,

    /// <summary>
    /// A required value, file, path, or input was not provided.
    /// </summary>
    MissingInput = 4,

    /// <summary>
    /// A required file or path was not found.
    /// </summary>
    FileNotFound = 5,

    /// <summary>
    /// A required directory was not found.
    /// </summary>
    DirectoryNotFound = 6,

    /// <summary>
    /// A file or path could not be read.
    /// </summary>
    FileUnreadable = 7,

    /// <summary>
    /// Access to a required file, path, or resource was denied.
    /// </summary>
    AccessDenied = 8,

    /// <summary>
    /// Input data was present but not in a valid or expected format.
    /// </summary>
    InvalidFormat = 9,

    /// <summary>
    /// The requested format, algorithm, or input type is not supported.
    /// </summary>
    UnsupportedFormat = 10,

    /// <summary>
    /// The current platform does not support the requested operation.
    /// </summary>
    PlatformNotSupported = 11,

    /// <summary>
    /// A regular expression or pattern value was invalid.
    /// </summary>
    InvalidRegex = 12,

    /// <summary>
    /// The operation failed because the current state, configuration, or object usage was invalid.
    /// </summary>
    InvalidOperation = 13,

    /// <summary>
    /// The operation failed for a reason not covered by a more specific diagnostic detail.
    /// </summary>
    OperationFailed = 14,

    /// <summary>
    /// A required embedded or internal resource was not found.
    /// </summary>
    ResourceMissing = 15,

    /// <summary>
    /// Required metadata was missing from an otherwise valid operation or result.
    /// </summary>
    MissingMetadata = 16,

    /// <summary>
    /// Required structured data was missing from the input or payload.
    /// </summary>
    MissingRequiredData = 17,

    /// <summary>
    /// A conflict was detected in the supplied configuration, input, or excludes.
    /// </summary>
    ConflictingConfiguration = 18,

    /// <summary>
    /// A required detached signature was not found.
    /// </summary>
    SignatureMissing = 19,

    /// <summary>
    /// Signature verification failed because the signature content was invalid.
    /// </summary>
    BadSignature = 20,

    /// <summary>
    /// No signer certificate was present in the signature material.
    /// </summary>
    NoSigner = 21,

    /// <summary>
    /// The signer did not match the expected identity material, such as a thumbprint, pin, or public-key pin.
    /// </summary>
    WrongSigner = 22,

    /// <summary>
    /// Required pin material was not provided.
    /// </summary>
    PinMissing = 23,

    /// <summary>
    /// Provided pin material was invalid or could not be parsed.
    /// </summary>
    InvalidPin = 24,

    /// <summary>
    /// A manifest file was not found.
    /// </summary>
    ManifestMissing = 25,

    /// <summary>
    /// Manifest content was invalid, malformed, or could not be parsed.
    /// </summary>
    InvalidManifest = 26,

    /// <summary>
    /// A file required by the manifest was missing.
    /// </summary>
    FileMissing = 27,

    /// <summary>
    /// A file referenced by the manifest resolved outside the allowed root.
    /// </summary>
    FileOutsideRoot = 28,

    /// <summary>
    /// A file was encountered that is not present in the manifest.
    /// </summary>
    FileNotInManifest = 29,

    /// <summary>
    /// File content did not match the expected hash value.
    /// </summary>
    HashMismatch = 30,

    /// <summary>
    /// A path or resource violated the library trust boundary rules.
    /// </summary>
    TrustBoundaryViolation = 31,

    /// <summary>
    /// Certificate material could not be loaded.
    /// </summary>
    CertificateLoadFailed = 32,

    /// <summary>
    /// Certificate material was invalid, malformed, or unusable.
    /// </summary>
    InvalidCertificate = 33,

    /// <summary>
    /// Required private key material was missing or inaccessible.
    /// </summary>
    PrivateKeyMissing = 34,

    /// <summary>
    /// Authentication or signer identity validation failed.
    /// </summary>
    AuthenticationFailed = 35,

    /// <summary>
    /// A cryptographic operation failed.
    /// </summary>
    CryptographicFailure = 36,

    /// <summary>
    /// A timeout occurred while waiting for a required operation or resource.
    /// </summary>
    Timeout = 37,

    /// <summary>
    /// A time-based validation condition failed, such as a missing, invalid, expired, or out-of-range time value.
    /// </summary>
    InvalidTime = 38
}