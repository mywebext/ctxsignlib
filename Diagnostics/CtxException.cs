// CtxSignlib.Diagnostics/CtxException.cs
namespace CtxSignlib.Diagnostics;

/// <summary>
/// Represents a CtxSignlib-specific exception that carries stable diagnostic metadata
/// for tooling, logging, and host-level error translation.
/// </summary>
public class CtxException : Exception
{
    /// <summary>
    /// Gets the diagnostic target associated with the exception.
    /// </summary>
    public ErrorTarget Target { get; }

    /// <summary>
    /// Gets the specific diagnostic detail associated with the exception.
    /// </summary>
    public ErrorDetail Detail { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CtxException"/> class
    /// with a default diagnostic classification.
    /// </summary>
    public CtxException()
        : this(
            message: "A CtxSignlib error occurred.",
            target: ErrorTarget.General,
            detail: ErrorDetail.Generic)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CtxException"/> class
    /// with the specified message and a default diagnostic classification.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public CtxException(string message)
        : this(
            message: message,
            target: ErrorTarget.General,
            detail: ErrorDetail.Generic)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CtxException"/> class
    /// with the specified diagnostic classification.
    /// </summary>
    /// <param name="target">The diagnostic target associated with the exception.</param>
    /// <param name="detail">The specific diagnostic detail associated with the exception.</param>
    public CtxException(ErrorTarget target, ErrorDetail detail)
        : this(
            message: BuildDefaultMessage(target, detail),
            target: target,
            detail: detail)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CtxException"/> class
    /// with the specified diagnostic classification and inner exception.
    /// </summary>
    /// <param name="target">The diagnostic target associated with the exception.</param>
    /// <param name="detail">The specific diagnostic detail associated with the exception.</param>
    /// <param name="innerException">The exception that caused the current exception.</param>
    public CtxException(ErrorTarget target, ErrorDetail detail, Exception innerException)
        : this(
            message: BuildDefaultMessage(target, detail),
            target: target,
            detail: detail,
            innerException: innerException)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CtxException"/> class
    /// with the specified message and diagnostic classification.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="target">The diagnostic target associated with the exception.</param>
    /// <param name="detail">The specific diagnostic detail associated with the exception.</param>
    public CtxException(string message, ErrorTarget target, ErrorDetail detail)
        : base(message)
    {
        Target = target;
        Detail = detail;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CtxException"/> class
    /// with the specified message, diagnostic classification, and inner exception.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="target">The diagnostic target associated with the exception.</param>
    /// <param name="detail">The specific diagnostic detail associated with the exception.</param>
    /// <param name="innerException">The exception that caused the current exception.</param>
    public CtxException(
        string message,
        ErrorTarget target,
        ErrorDetail detail,
        Exception innerException)
        : base(message, innerException)
    {
        Target = target;
        Detail = detail;
    }

    /// <summary>
    /// Returns a string representation of the current exception, including diagnostic metadata.
    /// </summary>
    /// <returns>A string representation of the current exception.</returns>
    public override string ToString()
        => $"{base.ToString()}{Environment.NewLine}Target: {Target}{Environment.NewLine}Detail: {Detail}";

    /// <summary>
    /// Creates a fallback message when no explicit message is supplied.
    /// </summary>
    /// <param name="target">The diagnostic target associated with the exception.</param>
    /// <param name="detail">The specific diagnostic detail associated with the exception.</param>
    /// <returns>A simple default exception message.</returns>
    private static string BuildDefaultMessage(ErrorTarget target, ErrorDetail detail)
        => $"CtxSignlib error. Target={target}; Detail={detail}.";
}