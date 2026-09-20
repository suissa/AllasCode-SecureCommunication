export type PqcKemAlgorithm = "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024";
export type PqcSignatureAlgorithm = "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" | "SLH-DSA";

export interface PqcCiphertext { algorithm: PqcKemAlgorithm; ciphertext: Uint8Array; sharedSecret: Uint8Array; }
export interface PqcSignature { algorithm: PqcSignatureAlgorithm; signature: Uint8Array; }

/**
 * Native PQC boundary. The TypeScript runtime never implements or silently
 * downgrades post-quantum primitives; a native provider such as liboqs.rs
 * must satisfy this contract.
 */
export interface PqcProvider {
  readonly name: string;
  readonly kem: PqcKemAlgorithm;
  readonly signature: PqcSignatureAlgorithm;
  isAvailable(): Promise<boolean>;
  encapsulate(publicKey: Uint8Array): Promise<PqcCiphertext>;
  decapsulate(privateKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
  sign(privateKey: Uint8Array, message: Uint8Array): Promise<PqcSignature>;
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface LibOqsBackendDescriptor {
  provider: "liboqs.rs";
  library: "liboqs";
  kem: PqcKemAlgorithm;
  signature: PqcSignatureAlgorithm;
  transport: "native-addon" | "sidecar" | "ffi";
}

export function libOqsBackend(options: Partial<Pick<LibOqsBackendDescriptor, "kem" | "signature" | "transport">> = {}): LibOqsBackendDescriptor {
  return {
    provider: "liboqs.rs",
    library: "liboqs",
    kem: options.kem ?? "ML-KEM-768",
    signature: options.signature ?? "ML-DSA-65",
    transport: options.transport ?? "sidecar",
  };
}

export async function requirePqcProvider(provider: PqcProvider): Promise<PqcProvider> {
  if (!(await provider.isAvailable())) throw new Error(`PQC provider unavailable: ${provider.name}`);
  return provider;
}
