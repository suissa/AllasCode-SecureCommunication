import { createHash, randomUUID } from "node:crypto";

export type CryptoCategory = "transport" | "identity" | "proof" | "payload" | "keyDerivation";
export type AlgorithmRegistry = Record<CryptoCategory, string>;

export interface CapabilityDescriptor {
  intent: string;
  description: string;
  examples: string[];
  inputSchema?: Record<string, unknown>;
}

export interface ProvisionedIdentity {
  agentId: string;
  certificatePem: string;
  privateKeyPem: string;
  dpopPrivateKeyJwk: JsonWebKey;
  capabilities: CapabilityDescriptor[];
  expiresAt: string;
}

export interface IdentityProvider {
  provision(agentId: string): Promise<ProvisionedIdentity>;
}

export interface SecureServerConfig {
  host?: string;
  restPort?: number;
  wsPort?: number;
  grpcPort?: number;
  mtls: { key: string; cert: string; ca: string; minVersion?: "TLSv1.3" };
  algorithms?: Partial<AlgorithmRegistry>;
  channels?: { linearAutodestroy?: boolean };
  jwt?: { enabled: boolean; issuer?: string; audience?: string };
  capabilities: CapabilityDescriptor[];
  identityProvider: IdentityProvider;
  eventStore?: EventStore;
}

export interface SecurityPolicy {
  readonly mtlsRequired: true;
  readonly dpopRequired: true;
  readonly jwtEnabled: boolean;
  readonly algorithms: AlgorithmRegistry;
  readonly channels: { linearAutodestroy: boolean };
}

export interface EventStore {
  append(event: { type: string; aggregateId: string; payload: Record<string, unknown> }): Promise<void>;
}

const defaults: AlgorithmRegistry = {
  transport: "TLS_AES_256_GCM_SHA384",
  identity: "X25519MLKEM768",
  proof: "Ed25519",
  payload: "XChaCha20-Poly1305",
  keyDerivation: "HKDF-SHA256",
};

export function resolveSecurityPolicy(config: SecureServerConfig): SecurityPolicy {
  const algorithms = { ...defaults, ...config.algorithms };
  for (const [category, algorithm] of Object.entries(algorithms)) {
    if (!algorithm?.trim()) throw new Error(`Algorithm is required for category ${category}`);
  }
  return {
    mtlsRequired: true,
    dpopRequired: true,
    jwtEnabled: config.jwt?.enabled === true,
    algorithms,
    channels: { linearAutodestroy: config.channels?.linearAutodestroy !== false },
  };
}

export function certificateHashFromRaw(certificate: Buffer): string {
  return createHash("sha256").update(certificate).digest("hex");
}

export function certificateHashFromPem(pem: string): string {
  const der = Buffer.from(pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\\s/g, ""), "base64");
  return certificateHashFromRaw(der);
}

export function newEventId(): string { return randomUUID(); }
