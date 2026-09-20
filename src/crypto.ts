export const cryptoApi: Crypto = (() => {
  const value = globalThis.crypto;
  if (!value?.subtle) throw new Error("WebCrypto is required");
  return value;
})();

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
}
export function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  return Uint8Array.from(atob(normalized), c => c.charCodeAt(0));
}
export function utf8(value: string): Uint8Array { return new TextEncoder().encode(value); }
export function randomBytes(length = 32): Uint8Array {
  if (!Number.isInteger(length) || length < 16) throw new Error("random length must be >= 16");
  return cryptoApi.getRandomValues(new Uint8Array(length));
}
export async function sha256(value: string | BufferSource): Promise<Uint8Array> {
  return new Uint8Array(await cryptoApi.subtle.digest("SHA-256", value));
}
export async function hkdf(ikm: BufferSource, salt: BufferSource, info: BufferSource, length = 32): Promise<Uint8Array> {
  const key = await cryptoApi.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await cryptoApi.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt,info}, key, length * 8));
}
export function jsonBase64Url(value: unknown): string { return bytesToBase64Url(utf8(JSON.stringify(value))); }
export function canonicalUrl(input: string | URL): string {
  const url = new URL(input.toString()); url.search = ""; url.hash = ""; return url.toString();
}
