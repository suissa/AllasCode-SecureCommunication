export interface MtlsIdentity { certificate:string; privateKey:string; certificateAuthority?:string; passphrase?:string; }
export interface MtlsPolicy { rejectUnauthorized?:boolean; minVersion?:"TLSv1.3"; serverName?:string; }
export interface NodeMtlsOptions extends MtlsIdentity,MtlsPolicy {}
export function createNodeMtlsOptions(identity:MtlsIdentity,policy:MtlsPolicy={}):NodeMtlsOptions {
  if(!identity.certificate||!identity.privateKey) throw new Error("mTLS certificate and private key are required");
  return {...identity,...policy,rejectUnauthorized:policy.rejectUnauthorized??true,minVersion:policy.minVersion??"TLSv1.3"};
}
export interface ProtocolSecurityContext { authorization?:string; dpop?:string; nonce?:string; mtls?:MtlsPolicy; }
export function applySecurityHeaders(headers:HeadersInit|undefined,context:ProtocolSecurityContext):Headers {
  const result=new Headers(headers); if(context.authorization) result.set("Authorization",context.authorization); if(context.dpop) result.set("DPoP",context.dpop); return result;
}
