
# CtxSignlib

Portable CMS / PKCS#7 detached signing and verification library for .NET.

CtxSignlib is a deterministic manifest‑based trust model for verifying distributed software content.

CtxSignlib provides a deterministic, cross‑platform CMS (Cryptographic Message Syntax) signing and verification library built on .NET 8.

It is designed for portable verification workflows such as:

- Detached signature validation
- Signed manifest distribution
- Secure file integrity enforcement
- Deterministic public‑key pinning

CtxSignlib performs crypto‑only verification and does not rely on OS trust stores.
Signer identity is validated through explicit pinning.

--------------------------------------------------------------------------

## Installation

dotnet add package ctxsignlib

--------------------------------------------------------------------------

# Quick Start

Verify a file signed with a detached CMS signature using a pinned public key hash.

Example:

using CtxSignlib.Verify;

bool ok = SingleFileVerification.VerifyFileByPublicKey(
    contentPath: "MyApp.zip",
    sigPath: "MyApp.sig",
    pinnedPublicKeySha256: "YOUR_PUBPIN_HEX",
    out var result);

Console.WriteLine(ok ? "Verified" : $"Failed: {result}");

--------------------------------------------------------------------------

# Using Embedded Public Keys

--pin represents the signer public key in SPKI format.
This corresponds to the key contained in a PEM block.

Example PEM:

-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

Applications can embed this key as a resource and load it during verification.

Example:

using System.Reflection;
using System.Text;
using CtxSignlib.Verify;

static string ReadEmbeddedText(string resourceName)
{
    var asm = Assembly.GetExecutingAssembly();

    using var stream = asm.GetManifestResourceStream(resourceName)
        ?? throw new InvalidOperationException($"Resource not found: {resourceName}");

    using var reader = new StreamReader(stream, Encoding.ASCII);
    return reader.ReadToEnd();
}

string pem = ReadEmbeddedText("MyApp.security.pem");

bool ok = SingleFileVerification.VerifyFileByRawPublicKey(
    contentPath: "MyApp.zip",
    sigPath: "MyApp.sig",
    rawPublicKey: pem,
    out var result);

Console.WriteLine(ok ? "Verified" : $"Failed: {result}");

Notes:

- The PEM contains public key material only
- The private signing key must never be embedded in applications

--------------------------------------------------------------------------

# Signer Identity Model

CtxSignlib supports three explicit pinning modes.

--thumb   Pins the exact certificate instance  
--pin     Raw SPKI public key  
--pubpin  SHA‑256 hash of the SPKI public key (recommended)

Relationship:

SPKI Public Key (--pin)
        ↓
SHA256(SPKI)
        ↓
--pubpin

Public‑key pinning allows identity continuity across certificate renewals that reuse the same key pair.

--------------------------------------------------------------------------

# Architecture

Signing

CMSWriter  
Creates detached CMS / PKCS#7 signatures.

Core Verification

CMSVerifier  
Low‑level CMS verification engine.

SingleFileVerification  
Convenience helpers for verifying individual files.

--------------------------------------------------------------------------

# Manifest System

CtxSignlib includes a deterministic manifest verification system designed for software distribution and package integrity.

Core components:

- ManifestBuilder
- ManifestVerifier
- SignedManifestVerifier
- ManifestFileVerification
- ManifestPartialVerifier
- SignedManifestPartialVerifier
- DetailedManifestFileVerification

These enable workflows such as:

- verifying downloaded binaries
- verifying software packages before execution
- secure update distribution
- repairing corrupted installations
- verifying partial package states

--------------------------------------------------------------------------

# Verification Modes

CtxSignlib provides multiple verification policies built on the same manifest engine.

Strict Verification

All manifest files must exist and verify.

Failure conditions:

- Missing file
- Hash mismatch
- Unreadable file

Used for:

- full installs
- archive validation
- final package verification

Partial Verification

Allows missing files but verifies everything that exists.

Failure conditions:

- Hash mismatch
- Unreadable file

Used for:

- incremental downloads
- patch installs
- optional modules
- repair operations

Signed Manifest Verification

Signed manifest verification authenticates the manifest first using a pinned public key, then evaluates file integrity.

Workflow:

Verify CMS Signature
        ↓
Authenticate Manifest
        ↓
Evaluate File Integrity

--------------------------------------------------------------------------

# Detailed Verification Results

CtxSignlib includes a structured result type for manifest verification:

ManifestPartialVerificationResult

This type provides categorized file state information.

Fields:

- PassedFiles
- MissingFiles
- FailedFiles
- UnreadableFiles

Policy evaluation helpers:

- IsStrictlyValid
- IsPartiallyValid

This allows higher‑level systems to evaluate installation state and determine corrective actions such as repairing or requesting missing files.

--------------------------------------------------------------------------

# Package Identity

CtxSignlib provides a deterministic **PackageId** generator.

A PackageId represents the identity of the full expected package content defined by a manifest.

The ID is generated from the canonical representation of each expected file:

normalized/path|EXPECTED_SHA256

Algorithm:

1. Normalize manifest path
2. Normalize SHA‑256 hex
3. Build canonical entries
4. Remove duplicates
5. Sort using StringComparer.Ordinal
6. Join entries using LF
7. SHA‑256 hash the UTF‑8 payload

Example:

using CtxSignlib.Verify;

string id = PackageId.Generate(result);

Two packages with identical file paths and expected hashes will always produce the same PackageId across platforms.

--------------------------------------------------------------------------

# Deterministic Repair Package IDs

CtxSignlib also includes a deterministic repair identity generator:

RepairPackageId

This feature derives a stable identifier for the subset of files that must be repaired or downloaded.

The ID is generated from the canonical entries of files that failed verification:

normalized/path|EXPECTED_SHA256

Important properties:

- Failure reason does not affect the ID
- Missing / corrupted / unreadable files produce the same ID if the required content is identical
- Two machines with the same repair state will generate the same RepairPackageId

Example:

using CtxSignlib.Verify;

var result = ManifestPartialVerifier.VerifyManifestPartialDetailed(
    rootDir: "MyPackage",
    manifestPath: "package.manifest.json");

string repairId = RepairPackageId.Generate(result);

Console.WriteLine($"Repair package id: {repairId}");

This enables deterministic repair distribution systems and patch delivery.

--------------------------------------------------------------------------

# Security Model

CtxSignlib is designed for deterministic, portable verification of signed content.

Cryptographic Authentication

Signed content is verified using CMS / PKCS#7 detached signatures.

Signer identity is validated through explicit pinning:

- certificate thumbprint
- raw SPKI public key
- SHA‑256 hash of the public key

CtxSignlib does not rely on OS trust stores.

Deterministic File Integrity

File integrity is validated using SHA‑256 hashes stored in a signed manifest.

Path Boundary Enforcement

Manifest entries are validated to ensure they resolve only inside the specified root directory.

This prevents path traversal attacks such as:

../../escape/file.dll

Policy-Based Verification

Policy    Missing Files   Hash Mismatch   Unreadable
Strict    Fail            Fail            Fail
Partial   Allowed         Fail            Fail

This allows secure support for:

- full installs
- patch installs
- incremental downloads
- repair workflows

Portable Verification

CtxSignlib performs crypto‑only verification and does not depend on:

- platform certificate stores
- network services
- external trust authorities

--------------------------------------------------------------------------

# Determinism Model

Deterministic elements:

- File SHA‑256 hashing
- Manifest hashing
- SPKI public key hashing
- Thumbprint normalization
- Fixed‑time comparisons
- Canonical entry sorting

Non‑deterministic elements:

- CMS signature bytes

Although CMS signatures vary between signing operations, verification remains deterministic because content hashes and signer identity are validated.

--------------------------------------------------------------------------

# Target Framework

.NET 8.0

--------------------------------------------------------------------------

# License

Copyright © Kenneth Poston
Licensed under the Apache License 2.0
