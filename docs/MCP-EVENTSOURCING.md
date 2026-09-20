# MCP + Event Sourcing

Não existe hoje um padrão normativo único que combine MCP e Event Sourcing. São camadas diferentes:

- MCP padroniza como um host descobre e chama ferramentas, recursos e prompts.
- Event Sourcing define como fatos imutáveis são registrados e como o estado é reconstruído.

Este projeto usa a composição abaixo:

1. `/auth` ou `/intent` autentica o agente com `X-eXtreme-ZT-auth` e entrega a identidade provisionada, a chave DPoP e o catálogo de capabilities/intents.
2. `POST /prompt/:certificateHash` é a única operação externa. O hash precisa ser SHA-256 do certificado mTLS apresentado no canal.
3. REST, WebSocket e gRPC convertem suas mensagens para o mesmo `PromptEnvelope`.
4. O handler interno resolve a intenção em módulos MCP e grava `SecureCommunication.PromptAccepted` no Event Store.
5. O agente não recebe ferramentas executáveis arbitrárias: ele só submete uma intenção autorizada. A execução permanece dentro do servidor.

## Segurança não desligável

`mtlsRequired` e `dpopRequired` são invariantes do runtime. JWT pode ser adicionado como camada complementar, mas nunca substitui mTLS ou DPoP. O desenvolvedor pode trocar o algoritmo de cada categoria, mas não pode remover uma categoria criptográfica.

`LinearAutodestroy` é habilitado por padrão. No WebSocket, ele fecha o canal depois da entrega do resultado. Pode ser desligado em `channels.linearAutodestroy=false` quando a aplicação precisa de uma sessão durável.

## Rota e cabeçalho

Cada resposta operacional devolve `X-eXtreme-Zero-Trust: <sha256-do-certificado-mtls>`. O cliente usa esse valor para formar a rota seguinte. O hash não é segredo; ele é um vínculo de integridade entre a URL e o certificado apresentado.

## Event Store e MCP

O `EventStore` é uma porta mínima (`append`) para EventStoreDB, PostgreSQL append-only, BadgerDB ou outro backend. O módulo MCP deve ser chamado depois da validação de transporte, identidade, DPoP e capability. O evento de aceitação deve ser persistido antes de confirmar a operação ao agente.

Esse contrato é uma convenção AllasCode, não uma extensão oficial do MCP.
