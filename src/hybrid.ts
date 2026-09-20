import {base64UrlToBytes,bytesToBase64Url,cryptoApi,hkdf,randomBytes,utf8} from "./crypto.js";

export interface HybridEnvelope { version:1; kem:"ECDH-P256"; aead:"AES-256-GCM"; enc:string; iv:string; ciphertext:string; tagLength:128; aad?:string; }
export interface HybridRecipient { publicKey:CryptoKey; publicJwk?:JsonWebKey; }

export async function generateHybridRecipient():Promise<{publicKey:CryptoKey;privateKey:CryptoKey;publicJwk:JsonWebKey}> {
  const pair=await cryptoApi.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]) as CryptoKeyPair;
  return {...pair,publicJwk:await cryptoApi.subtle.exportKey("jwk",pair.publicKey)};
}
export async function seal(plaintext:string|BufferSource,recipient:HybridRecipient,aad?:string):Promise<HybridEnvelope>{
  const eph=await cryptoApi.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]) as CryptoKeyPair;
  const shared=new Uint8Array(await cryptoApi.subtle.deriveBits({name:"ECDH",public:recipient.publicKey},eph.privateKey,256));
  const keyBytes=await hkdf(shared,new Uint8Array(32),utf8("allascode/secure-communication/v1"),32);
  const aes=await cryptoApi.subtle.importKey("raw",keyBytes,"AES-GCM",false,["encrypt"]);
  const iv=randomBytes(12);
  const ciphertext=new Uint8Array(await cryptoApi.subtle.encrypt({name:"AES-GCM",iv,additionalData:aad?utf8(aad):undefined,tagLength:128},aes,plaintext));
  return {version:1,kem:"ECDH-P256",aead:"AES-256-GCM",enc:JSON.stringify(await cryptoApi.subtle.exportKey("jwk",eph.publicKey)),iv:bytesToBase64Url(iv),ciphertext:bytesToBase64Url(ciphertext),tagLength:128,...(aad?{aad}:{})};
}
export async function open(envelope:HybridEnvelope,privateKey:CryptoKey):Promise<Uint8Array>{
  const eph=await cryptoApi.subtle.importKey("jwk",JSON.parse(envelope.enc),{name:"ECDH",namedCurve:"P-256"},false,[]);
  const shared=new Uint8Array(await cryptoApi.subtle.deriveBits({name:"ECDH",public:eph},privateKey,256));
  const keyBytes=await hkdf(shared,new Uint8Array(32),utf8("allascode/secure-communication/v1"),32);
  const aes=await cryptoApi.subtle.importKey("raw",keyBytes,"AES-GCM",false,["decrypt"]);
  return new Uint8Array(await cryptoApi.subtle.decrypt({name:"AES-GCM",iv:base64UrlToBytes(envelope.iv),additionalData:envelope.aad?utf8(envelope.aad):undefined,tagLength:128},aes,base64UrlToBytes(envelope.ciphertext)));
}
