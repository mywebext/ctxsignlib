// CtxSignlib.Manifest/ManifestPartialVerificationResult.cs
using System.Collections.Generic;

namespace CtxSignlib.Manifest
{
    /// <summary>
    /// Represents the categorized result of a manifest verification operation.
    /// </summary>
    /// <remarks>
    /// This object records the observed state of files listed in a manifest.
    /// The verification engine populates the file lists and wrappers determine
    /// the policy outcome (strict vs partial).
    /// </remarks>
    public sealed class ManifestPartialVerificationResult
    {
        /// <summary>
        /// Gets the list of files that were present and matched the expected hash.
        /// </summary>
        public List<string> PassedFiles { get; } = new();

        /// <summary>
        /// Gets the list of files that were listed in the manifest but were not present.
        /// </summary>
        public List<string> MissingFiles { get; } = new();

        /// <summary>
        /// Gets the list of files that were present but whose hash did not match the manifest.
        /// </summary>
        public List<string> FailedFiles { get; } = new();

        /// <summary>
        /// Gets the list of files that existed but could not be read.
        /// </summary>
        public List<string> UnreadableFiles { get; } = new();

        /// <summary>
        /// Gets the list of files whose verification could not be completed because
        /// the syntax of a rule or instruction associated with that file was invalid.
        /// </summary>
        /// <remarks>
        /// Examples include malformed regex patterns or other malformed per-file
        /// verification syntax that prevents a safe hash evaluation.
        /// These files are not considered matched or mismatched; they are unverifiable.
        /// </remarks>
        public List<string> InvalidSyntaxFiles { get; } = new();

        /// <summary>
        /// Gets or sets the overall success state determined by the calling verification mode.
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Gets or sets whether the manifest signature authentication step succeeded.
        /// </summary>
        /// <remarks>
        /// For unsigned manifest verification this will remain <c>false</c>.
        /// Signed-manifest verification paths set this to <c>true</c> after
        /// successful CMS signature validation.
        /// </remarks>
        public bool ManifestAuthenticated { get; set; }

        /// <summary>
        /// Indicates whether the result satisfies strict verification semantics.
        /// </summary>
        /// <remarks>
        /// Strict mode requires:
        /// - no missing files
        /// - no failed files
        /// - no unreadable files
        /// - no invalid syntax files
        /// </remarks>
        public bool IsStrictlyValid =>
            MissingFiles.Count == 0 &&
            FailedFiles.Count == 0 &&
            UnreadableFiles.Count == 0 &&
            InvalidSyntaxFiles.Count == 0;

        /// <summary>
        /// Indicates whether the result satisfies partial verification semantics.
        /// </summary>
        /// <remarks>
        /// Partial mode allows missing files but still requires:
        /// - no failed files
        /// - no unreadable files
        /// - no invalid syntax files
        /// </remarks>
        public bool IsPartiallyValid =>
            FailedFiles.Count == 0 &&
            UnreadableFiles.Count == 0 &&
            InvalidSyntaxFiles.Count == 0;

        // ---------------------------------------------------------------------
        // Internal metadata used by legacy wrappers (not part of the public API)
        // ---------------------------------------------------------------------

        /// <summary>
        /// Maps manifest-relative file paths to their expected SHA-256 value.
        /// </summary>
        /// <remarks>
        /// This is used internally so legacy APIs can rebuild the original
        /// failure dictionary structure grouped by expected hash.
        /// </remarks>
        internal Dictionary<string, string> ExpectedHashByPath { get; }
            = new Dictionary<string, string>(System.StringComparer.Ordinal);
    }
}