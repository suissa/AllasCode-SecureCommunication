import { describe, expect, it } from "vitest";
import { createDpopProof, generateDpopKeyPair, verifyDpopProof } from "../src/dpop.js";
import { generateHybridRecipient, open, seal } from "../src/hybrid.js";

describe("secure communication", () => {
  it("creates and verifies a DPoP proof", async () => {
    const keyPair = await generateDpopKeyPair();
    const { proof } = await createDpopProof({ method: "GET", url: "https://api.example.test/a?b=1", accessToken: "token", keyPair });
    await expect(verifyDpopProof(proof, { method: "GET", url: "https://api.example.test/a?b=2", accessToken: "token" })).resolves.toBe(true);
    await expect(verifyDpopProof(proof, { method: "POST", url: "https://api.example.test/a", accessToken: "token" })).resolves.toBe(false);
  });
  it("seals and opens an authenticated hybrid envelope", async () => {
    const recipient = await generateHybridRecipient();
    const envelope = await seal("sensitive payload", recipient, "entity_id.address");
    await expect(new TextDecoder().decode(await open(envelope, recipient.privateKey))).toBe("sensitive payload");
    await expect(open({...envelope, aad: "tampered"}, recipient.privateKey)).rejects.toThrow();
  });
});
