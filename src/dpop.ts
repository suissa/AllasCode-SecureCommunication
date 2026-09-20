import {base64UrlToBytes,bytesToBase64Url,canonicalUrl,cryptoApi,jsonBase64Url,randomBytes,sha256,utf8} from "./crypto.js";

export interface DpopKeyPair { publicKey: CryptoKey; privateKey: CryptoKey; publicJwk: JsonWebKey; }
export interface DpopProofInput { method:string; url:string|URL; accessToken?:string; nonce?:string; keyPair?:DpopKeyPair; now?:number; }

export async function generateDpopKeyPair(): Promise<DpopKeyPair> {
  const pair = await cryptoApi.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},false,["sign","verify"]) as CryptoKeyPair;
  const publicJwk = await cryptoApi.subtle.exportKey("jwk", pair.publicKey); delete publicJwk.d;
  return {...pair, publicJwk};
}
export async function createDpopProof(input:DpopProofInput):Promise<{proof:string;keyPair:DpopKeyPair}> {
  const keyPair=input.keyPair ?? await generateDpopKeyPair();
  const header={typ:"dpop+jwt",alg:"ES256",jwk:keyPair.publicJwk};
  const payload:Record<string,string|number>={htu:canonicalUrl(input.url),htm:input.method.toUpperCase(),iat:input.now ?? Math.floor(Date.now()/1000),jti:bytesToBase64Url(randomBytes(24))};
  if(input.accessToken) payload.ath=bytesToBase64Url(await sha256(utf8(input.accessToken)));
  if(input.nonce) payload.nonce=input.nonce;
  const encoded=jsonBase64Url(header)+"."+jsonBase64Url(payload);
  const signature=new Uint8Array(await cryptoApi.subtle.sign({name:"ECDSA",hash:"SHA-256"},keyPair.privateKey,utf8(encoded)));
  return {proof:encoded+"."+bytesToBase64Url(signature),keyPair};
}
export async function verifyDpopProof(proof:string, expected:{method:string;url:string|URL;accessToken?:string;nonce?:string;maxAgeSeconds?:number}):Promise<boolean>{
  const [h,p,s]=proof.split("."); if(!h||!p||!s) return false;
  try {
    const header=JSON.parse(new TextDecoder().decode(base64UrlToBytes(h))) as Record<string,unknown>;
    const payload=JSON.parse(new TextDecoder().decode(base64UrlToBytes(p))) as Record<string,unknown>;
    if(header.typ!=="dpop+jwt"||header.alg!=="ES256"||payload.htm!==expected.method.toUpperCase()||payload.htu!==canonicalUrl(expected.url)) return false;
    if(typeof payload.iat!=="number"||Math.abs(Date.now()/1000-payload.iat)>(expected.maxAgeSeconds??300)) return false;
    if(expected.nonce!==undefined&&payload.nonce!==expected.nonce) return false;
    if(expected.accessToken&&payload.ath!==bytesToBase64Url(await sha256(utf8(expected.accessToken)))) return false;
    const key=await cryptoApi.subtle.importKey("jwk",header.jwk as JsonWebKey,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
    return cryptoApi.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,base64UrlToBytes(s),utf8(h+"."+p));
  } catch { return false; }
}
