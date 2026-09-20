# Post-Quantum Backend: liboqs

The selected backend for post-quantum algorithms is [`suissa/liboqs.rs`](https://github.com/suissa/liboqs.rs), which follows the Open Quantum Safe `liboqs` C API. Despite the repository name, it is not a Rust crate and it is not an MCP server. It provides native KEM and signature implementations.

## AllasCode boundary

The TypeScript runtime exposes a `PqcProvider` contract and delegates cryptographic operations to a native provider. The first supported profile is:

- KEM: `ML-KEM-768` (NIST FIPS 203)
- signature: `ML-DSA-65` (NIST FIPS 204)
- backend: `liboqs.rs` / `liboqs`
- transport: sidecar, native addon, or FFI

The TS layer must never implement a fake PQC algorithm, silently downgrade to classical cryptography, or accept an unavailable provider when the secure profile requires PQC. `requirePqcProvider()` fails closed.

## Hybrid profile

PQC complements, rather than replaces, the existing primitives:

```text
TLS 1.3 / mTLS
  + X25519 or X25519ML-KEM-768 key agreement
  + ML-KEM-768 application envelope
  + Ed25519 or ML-DSA-65 signatures
  + DPoP per-request proof
```

The exact composition is selected by the security profile. Algorithm names are configurable, but the cryptographic categories and DPoP remain mandatory.

## Why a native boundary

`liboqs` is a C library with build-time algorithm selection and platform-specific native code. Calling it through a sidecar/native addon keeps secret material out of ad-hoc shell commands and allows the same provider contract to be implemented later in Zig, Rust, Go, or a Node-API addon.
