# AllasCode SecureCommunication

Biblioteca TypeScript agnóstica de transporte para proteger REST, WebSocket, SSE, QUIC e protocolos próprios com:

- mTLS/TLS 1.3 como identidade e segurança do canal;
- DPoP (RFC 9449) como prova de posse por requisição/mensagem;
- cifragem híbrida no nível da aplicação: ECDH P-256 para encapsular a chave e AES-256-GCM para o payload;
- um contexto de segurança que pode ser convertido em headers, metadados de frame ou envelope de qualquer protocolo.

## REST

`ts
import { SecureCommunicationClient } from "@allascode.institute/secure-communication";

const client = new SecureCommunicationClient({
  tokenProvider: { getAccessToken: async () => accessToken },
  mtls: { certificate: process.env.CLIENT_CERT!, privateKey: process.env.CLIENT_KEY!, certificateAuthority: process.env.CA_CERT! },
  mtlsPolicy: { minVersion: "TLSv1.3", rejectUnauthorized: true },
});

const response = await client.request("https://api.example.com/orders", { method: "POST", body: JSON.stringify(order) });
`

Em Node, o agente HTTP/HTTPS ou adaptador do framework deve consumir createNodeMtlsOptions(). A API Fetch do navegador não permite injetar certificado cliente; isso é uma limitação da plataforma.

## WebSocket e protocolos customizados

`ts
const context = await client.securityContext("SEND", "wss://api.example.com/events", accessToken);
const frame = {
  type: "order.created",
  headers: { Authorization: context.authorization, DPoP: context.dpop },
  payload: await seal(JSON.stringify(order), recipient),
};
`

O mesmo contexto serve para ws, uWebSockets.js, QUIC, gRPC metadata e qualquer protocolo que carregue metadados.

## Envelope híbrido

`ts
const recipient = await generateHybridRecipient();
const envelope = await seal(JSON.stringify({ cpf: "process-on-client" }), recipient);
const plaintext = new TextDecoder().decode(await open(envelope, recipient.privateKey));
`

O envelope usa AES-GCM autenticado e vincula AAD opcional ao contexto externo. Nunca coloque PII em logs, eventos, traces ou headers.

## Limites e evolução

- DPoP não substitui mTLS: DPoP prova posse por requisição; mTLS autentica o canal e o certificado do cliente.
- Certificado cliente e chave privada são provisionados por uma CA/keystore; a biblioteca não inventa uma CA.
- A construção padrão é ECDH-P256 + AES-GCM. A interface do envelope está preparada para uma próxima implementação com ML-KEM-768, derivando HKDF sobre os segredos clássico e pós-quântico.
- Use uma chave DPoP persistente por sessão/token; chaves efêmeras podem invalidar tokens sender-constrained.

## Invariantes

1. TLS exige verificação de certificado por padrão e mínimo TLS 1.3 no adaptador Node.
2. DPoP usa typ=dpop+jwt, alg=ES256, htu sem query/hash, htm, iat, jti e ath quando há access token.
3. O retry de nonce é limitado a uma tentativa.
4. A chave privada DPoP não é exportável.
5. AES-GCM autentica o payload; AAD ou ciphertext adulterado falha.
6. O envelope é independente do transporte e não expõe plaintext.

## Desenvolvimento

`bash
npm install
npm run verify
`