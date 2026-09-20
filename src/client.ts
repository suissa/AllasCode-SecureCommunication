import {createDpopProof,DpopKeyPair} from "./dpop.js";
import {applySecurityHeaders,MtlsIdentity,MtlsPolicy,ProtocolSecurityContext} from "./mtls.js";
export interface AccessTokenProvider { getAccessToken():Promise<string>; }
export interface SecureCommunicationOptions { tokenProvider?:AccessTokenProvider; dpopKeyPair?:DpopKeyPair; mtls?:MtlsIdentity; mtlsPolicy?:MtlsPolicy; fetch?:typeof globalThis.fetch; }
export class SecureCommunicationClient {
  private readonly fetchImpl:typeof globalThis.fetch; private dpopKeyPair?:DpopKeyPair; private nonce?:string;
  constructor(private readonly options:SecureCommunicationOptions={}) { this.fetchImpl=options.fetch??globalThis.fetch.bind(globalThis); if(!this.fetchImpl) throw new Error("fetch is required"); this.dpopKeyPair=options.dpopKeyPair; }
  async headers(method:string,url:string|URL,accessToken?:string):Promise<Headers>{
    const {proof,keyPair}=await createDpopProof({method,url,accessToken,nonce:this.nonce,keyPair:this.dpopKeyPair}); this.dpopKeyPair=keyPair;
    return applySecurityHeaders(undefined,{authorization:accessToken?"DPoP "+accessToken:undefined,dpop:proof,nonce:this.nonce,mtls:this.options.mtlsPolicy});
  }
  async request(input:string|URL|Request,init:RequestInit={}):Promise<Response>{
    const url=typeof input==="string"||input instanceof URL?input.toString():input.url;
    const method=init.method??(input instanceof Request?input.method:"GET"); const token=await this.options.tokenProvider?.getAccessToken();
    const headers=await this.headers(method,url,token);
    const response=await this.fetchImpl(input,{...init,headers:new Headers(init.headers??headers)});
    const nonce=response.headers.get("DPoP-Nonce");
    if(nonce&&response.status===401&&this.nonce!==nonce){this.nonce=nonce;return this.fetchImpl(input,{...init,headers:await this.headers(method,url,token)});}
    return response;
  }
  async securityContext(method:string,url:string,accessToken?:string):Promise<ProtocolSecurityContext>{
    const {proof,keyPair}=await createDpopProof({method,url,accessToken,nonce:this.nonce,keyPair:this.dpopKeyPair}); this.dpopKeyPair=keyPair;
    return {authorization:accessToken?"DPoP "+accessToken:undefined,dpop:proof,nonce:this.nonce,mtls:this.options.mtlsPolicy};
  }
}
