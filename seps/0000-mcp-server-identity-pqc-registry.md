# SEP-0000: MCP Server Identity — Post-Quantum Cryptography and Trust Registry

- **Status**: Draft
- **Type**: Extensions Track
- **Created**: 2026-02-17
- **Author(s)**: Abdel Fane (@abdelsfane)
- **Sponsor**: None (seeking sponsor)
- **PR**: TBD (will be assigned on submission)
- **Depends on**: SEP-0000 (MCP Server Identity and Tool Attestation)

## Abstract

This SEP extends the MCP Server Identity extension (SEP-0000) with two capabilities: post-quantum cryptography (PQC) support via hybrid Ed25519 + ML-DSA signatures, and trust registry integration for third-party identity verification. These are optional additions to the base identity extension — servers can implement identity without PQC or registry support.

## Motivation

### Post-Quantum Cryptography

Current asymmetric cryptography (Ed25519, ECDSA, RSA) will be broken by sufficiently powerful quantum computers. While large-scale quantum computers do not yet exist, the threat is significant: a quantum computer running Shor's algorithm could derive private signing keys from public keys. Any MCP server whose public key is known today would be vulnerable to identity forgery — an attacker could create fraudulent attestations and tool signatures that appear authentic.

NIST finalized post-quantum signature standards in August 2024 (FIPS 204: ML-DSA) and released draft transition guidance (NIST IR 8547, Initial Public Draft, November 2024) recommending that organizations begin migration planning. MCP server identity should provide a PQC migration path from inception rather than requiring a disruptive upgrade later.

### Trust Registry

The base identity extension (SEP-0000) provides self-attestation, publisher attestation, and DNS attestation. These mechanisms work for direct trust relationships but do not scale to ecosystems with many servers and clients that have no prior relationship.

A trust registry provides a third-party verification layer: clients can query a registry to check whether a server's identity has been independently verified, without requiring direct trust between the client and server. This is analogous to Certificate Transparency logs for TLS certificates.

## Specification

### 1. Post-Quantum Cryptography Support

#### 1.1 Hybrid Signature Scheme

To prepare for quantum computing threats while maintaining compatibility, this extension defines a hybrid signature scheme that combines a classical algorithm with a post-quantum algorithm.

**Classical algorithm:** Ed25519 (from base identity extension)
**Post-quantum algorithm:** ML-DSA-65 (FIPS 204, NIST Security Level 3)

Servers that support PQC MUST include a `pqcPublicKey` in their identity metadata (returned by `identity/get`):

```json
{
  "publicKey": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<base64url-encoded Ed25519 public key>",
    "kid": "srv-a1b2c3d4e5f6g7h8"
  },
  "pqcPublicKey": {
    "kty": "ML-DSA",
    "alg": "ML-DSA-65",
    "pub": "<base64url-encoded ML-DSA-65 public key>",
    "kid": "srv-pqc-a1b2c3d4e5f6g7h8"
  },
  "attestations": [
    {
      "type": "self",
      "signedAt": "2026-02-17T00:00:00Z",
      "signature": "<Ed25519 signature>",
      "pqcSignature": "<ML-DSA-65 signature>"
    }
  ]
}
```

When PQC is active, attestations and tool signatures include both a classical `signature` and a `pqcSignature` field. The challenge-response protocol similarly returns both signatures.

**Canonical signing payload:** The PQC signature (`pqcSignature`) is computed over the same canonical payload as the classical signature. Specifically, for any signed object (attestation, tool metadata, or challenge-response), the canonical payload is constructed by:

1. Taking the object to be signed
2. Removing both the `signature` and `pqcSignature` fields (if present)
3. Canonicalizing the remaining object using RFC 8785 (JSON Canonicalization Scheme)
4. Signing the canonical bytes with the ML-DSA private key

Both the classical Ed25519 signature and the ML-DSA PQC signature MUST be computed over the identical canonical payload. This ensures that both signatures attest to the same data.

**Verification rule:** A hybrid signature is valid if and only if BOTH the classical and PQC signatures verify successfully against their respective public keys. This ensures security even if one algorithm is compromised.

**Backward compatibility:** Clients that do not support PQC verify the classical `signature` field and ignore `pqcSignature`. The base identity extension continues to work unchanged.

#### 1.2 Algorithm Agility

Servers declare their PQC capability via the `pqcPublicKey` field. The key type `"ML-DSA"` is provisional, aligned with the direction of the current IETF draft (draft-ietf-cose-dilithium). When IETF finalizes JWK registration for ML-DSA, implementations MUST migrate to the registered key type. The following algorithms are defined:

| Algorithm | NIST Standard | Security Level | Public Key Size | Signature Size |
|-----------|---------------|----------------|-----------------|----------------|
| ML-DSA-44 | FIPS 204 | 2 | 1,312 bytes | 2,420 bytes |
| ML-DSA-65 | FIPS 204 | 3 (recommended) | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | FIPS 204 | 5 | 2,592 bytes | 4,627 bytes |

Servers that support PQC SHOULD use ML-DSA-65 (Level 3). ML-DSA-87 (Level 5) is available for deployments requiring higher security margins.

#### 1.3 Migration Path

1. **Current state:** Servers implement the base identity extension with Ed25519 only.
2. **Recommended next step:** Servers add `pqcPublicKey` and include `pqcSignature` in attestations and tool signatures. Classical-only clients continue to work by verifying only the Ed25519 component.
3. **Future (not specified here):** When quantum computers threaten classical cryptography, a future SEP may define PQC-only signatures. This will require all clients to support PQC verification.

#### 1.4 Extended Response Formats

When PQC is active, the following extension methods return additional fields:

**`identity/challenge` response with PQC:**

```json
{
  "signature": "<base64url-encoded Ed25519 signature over (challenge || timestamp)>",
  "pqcSignature": "<base64url-encoded ML-DSA-65 signature over (challenge || timestamp)>",
  "kid": "srv-a1b2c3d4e5f6g7h8",
  "pqcKid": "srv-pqc-a1b2c3d4e5f6g7h8"
}
```

**Tool `_meta` with PQC:**

```json
{
  "io.modelcontextprotocol/server-identity": {
    "signature": "<base64url-encoded Ed25519 signature>",
    "pqcSignature": "<base64url-encoded ML-DSA-65 signature>",
    "kid": "srv-a1b2c3d4e5f6g7h8",
    "pqcKid": "srv-pqc-a1b2c3d4e5f6g7h8",
    "signedAt": "2026-02-17T00:00:00Z"
  }
}
```

Clients that do not support PQC ignore the `pqcSignature` and `pqcKid` fields.

### 2. Trust Registry Integration

#### 2.1 Registry Verification Endpoint

Registries that track MCP server identity metadata MAY implement a verification endpoint. This section defines the interface.

**Request:**

```
GET /api/v1/mcp-identity/{kid}
```

Where `{kid}` is the server's key identifier from its identity metadata.

**Response (200 OK):**

```json
{
  "kid": "srv-a1b2c3d4e5f6g7h8",
  "serverName": "example-server",
  "publicKey": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<base64url-encoded public key>"
  },
  "pqcPublicKey": {
    "kty": "ML-DSA",
    "alg": "ML-DSA-65",
    "pub": "<base64url-encoded ML-DSA-65 public key>",
    "kid": "srv-pqc-a1b2c3d4e5f6g7h8"
  },
  "verified": true,
  "verifiedAt": "2026-02-17T00:00:00Z",
  "attestations": [
    {
      "type": "registry",
      "issuer": {
        "name": "Example Registry",
        "kid": "reg-x1y2z3"
      },
      "signedAt": "2026-02-17T00:00:00Z",
      "expiresAt": "2026-08-17T00:00:00Z",
      "signature": "<base64url-encoded registry signature>"
    }
  ],
  "registeredAt": "2026-01-15T00:00:00Z"
}
```

The `pqcPublicKey` field is OPTIONAL in the registry response. It is present only if the server registered a PQC key.

**Response (404 Not Found):** Server key ID is not registered.

**Response (410 Gone):** Server key has been revoked.

The `verified` field indicates whether the registry has independently verified the server's identity (e.g., through domain verification, organizational vetting). The methodology is registry-specific.

#### 2.2 Registry Attestation

A registry attestation is a signed statement from a registry operator that it has verified a server's identity. The attestation structure follows the same format as other attestation types defined in the base identity extension:

```json
{
  "type": "registry",
  "issuer": {
    "name": "Example Registry",
    "publicKey": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<registry public key>",
      "kid": "reg-x1y2z3"
    },
    "url": "https://registry.example.com"
  },
  "signedAt": "2026-02-17T00:00:00Z",
  "expiresAt": "2026-08-17T00:00:00Z",
  "signature": "<base64url-encoded signature>"
}
```

**Canonical signing payload for registry attestations:** The registry signs the attestation object with the `signature` field excluded, canonicalized using RFC 8785. Specifically, the registry constructs the attestation object (including `type`, `issuer`, `signedAt`, `expiresAt`, and the server's `kid` and `publicKey`), canonicalizes it, and signs the result with the registry's Ed25519 private key.

Servers that have been verified by a registry MAY include the registry attestation in their attestation list (returned by `identity/get`).

#### 2.3 Client Verification Flow

Clients implementing registry verification SHOULD:

1. Extract the `kid` from the server's identity metadata
2. Query one or more registry verification endpoints
3. Compare the public key from the registry with the key presented by the server
4. Use the `verified` status and attestations to make an access decision

This flow is OPTIONAL. Clients may choose to trust servers based on self-attestation alone, publisher attestation, DNS attestation, or any combination.

### 3. Implementation Notes

Servers implementing PQC or registry features SHOULD log identity-related events (PQC key generation, hybrid signature creation/verification, registry lookups) using their existing logging infrastructure. The audit event format is an implementation concern and is intentionally not specified by this SEP.

## Rationale

### Why ML-DSA-65?

ML-DSA-65 (previously known as Dilithium3) is the NIST-selected post-quantum digital signature algorithm at Security Level 3 (FIPS 204, August 2024):

- **NIST standardization**: Finalized, peer-reviewed standard.
- **Security level**: Level 3 provides a balance between security and performance.
- **Implementation availability**: Libraries exist for C (liboqs/Open Quantum Safe), Go (cloudflare/circl), Rust (pqcrypto), Python (oqs-python), JavaScript (liboqs via WebAssembly), and Java (Bouncy Castle 1.79+).
- **Signature size**: ~3,309 bytes. Larger than Ed25519 (64 bytes) but acceptable for identity metadata exchanged once per session.

SLH-DSA (FIPS 205, SPHINCS+) was considered for its conservative hash-based security assumptions but rejected due to larger signature sizes (~16KB for Level 3 small variant, ~35KB for Level 3 fast variant).

### Why Inline `pqcSignature` Instead of Separate Signature Entries?

MCP identity attestations use a single `signature` field per attestation. The simplest hybrid extension is to add a parallel `pqcSignature` field — this keeps each attestation self-contained and avoids introducing a grouping mechanism. This differs from protocols like A2A, where the existing `signatures` array naturally supports multiple entries per AgentCard and a grouping convention (e.g., `hybridGroup`) is a better fit for that data model.

### Why Hybrid Instead of PQC-Only?

The hybrid approach (classical + PQC) follows NIST draft transition guidance (NIST IR 8547, Initial Public Draft, November 2024):

- **Defense in depth**: Security is maintained even if one algorithm is broken.
- **Gradual migration**: Organizations can adopt PQC incrementally.
- **Backward compatibility**: Classical-only clients verify the Ed25519 component and ignore PQC fields.
- **Implementation maturity**: ML-DSA implementations are newer and less battle-tested than Ed25519. The hybrid scheme ensures Ed25519 remains a security floor.

### Why a Separate SEP?

PQC and registry integration are independent, optional features that build on the base identity extension. Separating them:

- Allows the base identity extension to be reviewed and adopted independently
- Keeps each SEP focused and reviewable
- Allows PQC adoption to proceed at a different pace than basic identity

## Backward Compatibility

All changes are additive to the base identity extension:

- `pqcPublicKey` is a new optional field in identity metadata. Clients that don't understand it ignore it.
- `pqcSignature` is a new optional field in attestations. Clients verify the classical `signature` field.
- Registry verification is client-initiated and optional. Servers are not affected.
- Logging practices are server-local and do not affect the protocol.

Servers can implement the base identity extension without PQC or registry support.

## Security Implications

### PQC-Specific

- **PQC implementation bugs**: ML-DSA implementations are newer than Ed25519. The hybrid scheme mitigates this by requiring both signatures to verify.
- **Key size impact**: ML-DSA-65 public keys are 1,952 bytes. This increases the `identity/get` response size but does not affect latency significantly since it is a one-time exchange.
- **Side-channel attacks**: ML-DSA implementations should be constant-time. Implementations using WebAssembly may have weaker side-channel resistance than native code.

### Registry-Specific

- **Registry compromise**: If a registry's signing key is compromised, all its attestations become untrustworthy. Mitigation: clients should support multiple registries and require attestations from more than one source for high-security deployments.
- **Registry availability**: If a registry is unavailable, clients fall back to other attestation types (self, publisher, DNS). Registry verification MUST NOT be a hard requirement for connection establishment.
- **Privacy**: Registry lookups reveal which servers a client is connecting to. Clients concerned about privacy may skip registry verification or use anonymizing proxies.

## Reference Implementation

Reference implementations are in progress and will be linked once pull requests are submitted. The implementations target:

- **TypeScript SDK** — PQC key generation, hybrid signing, registry client
- **Python SDK** — PQC key generation, hybrid signing, registry client
- **Registry endpoint** — Trust verification API implementation

## Performance Implications

Key and signature sizes are defined by NIST FIPS 204. Timing values are approximate and vary by hardware and implementation; the figures below are representative of optimized implementations on modern hardware (source: Open Quantum Safe benchmarks).

| Operation | Ed25519 | ML-DSA-65 | Hybrid (both) |
|-----------|---------|-----------|----------------|
| Public key size | 32 bytes | 1,952 bytes | +1,952 bytes |
| Signature size | 64 bytes | 3,309 bytes | +3,309 bytes |
| Key generation | sub-ms | sub-ms | sub-ms |
| Signing | sub-ms | low single-digit ms | low single-digit ms |
| Verification | sub-ms | sub-ms | sub-ms |

All operations complete in the low millisecond range or below. Identity exchange occurs once per session. The primary impact is increased payload size, which is acceptable for a one-time metadata exchange.

## Testing Plan

Conformance tests MUST cover:

1. **PQC key generation**: ML-DSA-65 key pairs are well-formed
2. **Hybrid self-attestation**: Both Ed25519 and ML-DSA signatures verify
3. **Hybrid tool signing**: Both signature components verify against their respective keys
4. **Hybrid challenge-response**: Both signature components in the response verify
5. **Classical fallback**: Client that only understands Ed25519 verifies the classical component and ignores PQC fields
6. **Registry lookup**: Verification endpoint returns correct identity data
7. **Registry revocation**: Endpoint returns 410 for revoked keys
8. **Registry unavailability**: Client gracefully falls back to other attestation types

## Open Questions

1. **PQC key type identifier**: This SEP uses `"kty": "ML-DSA"` as a provisional key type. Should we wait for IETF to finalize ML-DSA JWK registration (draft-ietf-cose-dilithium) before specifying a key type?
2. **Registry discovery**: How do clients discover which registries to query? Should servers declare their registry URL in identity metadata?
3. **Multiple registries**: Should clients require attestations from N-of-M registries for high-security deployments, or is that a client policy decision outside the scope of this SEP?

## References

- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST IR 8547: Transition to Post-Quantum Cryptography Standards (November 2024)](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [IETF draft-ietf-cose-dilithium: ML-DSA for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)
- [RFC 7517: JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 8785: JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
- SEP-0000: MCP Server Identity and Tool Attestation (this SEP's prerequisite)
- [SEP-2133: Extensions Framework for MCP](https://github.com/modelcontextprotocol/specification/blob/main/seps/2133-extensions.md)

