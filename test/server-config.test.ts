import { describe, expect, it } from "vitest";
import { certificateHashFromRaw, resolveSecurityPolicy } from "../src/server-config.js";

describe("secure server policy", () => {
  it("keeps mTLS and DPoP mandatory while allowing JWT as an addition", () => {
    const policy = resolveSecurityPolicy({
      mtls: { key: "key", cert: "cert", ca: "ca" },
      jwt: { enabled: true },
      capabilities: [],
      identityProvider: {} as never,
    });
    expect(policy.mtlsRequired).toBe(true);
    expect(policy.dpopRequired).toBe(true);
    expect(policy.jwtEnabled).toBe(true);
    expect(policy.channels.linearAutodestroy).toBe(true);
  });

  it("derives a stable SHA-256 certificate hash", () => {
    expect(certificateHashFromRaw(Buffer.from("certificate"))).toBe(
      "03d66dd08835c1ca3f128cceacd1f31ac94163096b20f445ae84285bc0832d72",
    );
  });
});
