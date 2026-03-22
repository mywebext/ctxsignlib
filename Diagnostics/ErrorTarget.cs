// CtxSignlib.Diagnostics/ErrorTarget.cs
namespace CtxSignlib.Diagnostics;

/// <summary>
/// Identifies the diagnostic target associated with a library operation, input category, or failure domain.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ErrorTarget"/> provides a stable, machine-readable classification that callers can use
/// to determine the functional area associated with an outcome, error, or diagnostic condition.
/// </para>
/// <para>
/// Host applications may translate these values into user-facing help, remediation guidance,
/// logging categories, exit codes, or other presentation-specific behavior.
/// </para>
/// </remarks>
public enum ErrorTarget
{
    /// <summary>
    /// No diagnostic target is associated with the current outcome.
    /// </summary>
    None = 0,

    /// <summary>
    /// Indicates a general or uncategorized diagnostic condition.
    /// </summary>
    General = 1,

    /// <summary>
    /// Indicates a diagnostic condition related to the requested operation or feature entry point.
    /// </summary>
    Operation = 2,

    /// <summary>
    /// Indicates a diagnostic condition related to arguments, options, or parameter input.
    /// </summary>
    Arguments = 3,

    /// <summary>
    /// Indicates a diagnostic condition related to files, paths, directories, or resource access.
    /// </summary>
    FileSystem = 4,

    /// <summary>
    /// Indicates a diagnostic condition related to public key pins or pin material.
    /// </summary>
    Pin = 5,

    /// <summary>
    /// Indicates a diagnostic condition related to certificates or certificate material.
    /// </summary>
    Certificate = 6,

    /// <summary>
    /// Indicates a diagnostic condition related to manifest creation, parsing, validation, or trust-boundary enforcement.
    /// </summary>
    Manifest = 7,

    /// <summary>
    /// Indicates a diagnostic condition related to signing operations.
    /// </summary>
    Signing = 8,

    /// <summary>
    /// Indicates a diagnostic condition related to verification operations.
    /// </summary>
    Verification = 9,

    /// <summary>
    /// Indicates a diagnostic condition related to authentication, signer identity, or trust validation.
    /// </summary>
    Authentication = 10,

    /// <summary>
    /// Indicates a diagnostic condition related to cryptographic operations or cryptographic material.
    /// </summary>
    Cryptography = 11,

    /// <summary>
    /// Indicates a diagnostic condition related to time-based validation or timing constraints.
    /// </summary>
    Time = 12
}