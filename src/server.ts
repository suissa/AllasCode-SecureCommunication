import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createSecureServer } from "node:https";
import { type TLSSocket } from "node:tls";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { verifyDpopProof } from "./dpop.js";
import { certificateHashFromRaw, newEventId, resolveSecurityPolicy, type CapabilityDescriptor, type EventStore, type SecureServerConfig } from "./server-config.js";

export interface PromptEnvelope {
  intent: string;
  input: unknown;
  correlationId?: string;
  requestedAt?: string;
}

export interface PromptResult { eventId: string; intent: string; accepted: true; output?: unknown; }

export interface PromptHandler {
  handle(envelope: PromptEnvelope, context: { agentId: string; certificateHash: string; transport: "rest" | "ws" | "grpc" }): Promise<PromptResult>;
}

export interface SecureServer {
  rest: ReturnType<typeof createServer>;
  ws: WebSocketServer;
  grpc: grpc.Server;
  policy: ReturnType<typeof resolveSecurityPolicy>;
  close(): Promise<void>;
}

const json = (res: ServerResponse, status: number, body: unknown, certHash?: string) => {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  if (certHash) res.setHeader("X-eXtreme-Zero-Trust", certHash);
  res.end(JSON.stringify(body));
};

async function body(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function peerHash(req: IncomingMessage): string | undefined {
  const socket = req.socket as TLSSocket;
  if (!socket.authorized) return undefined;
  const cert = socket.getPeerCertificate(true);
  return cert?.raw?.length ? certificateHashFromRaw(cert.raw) : undefined;
}

function pathHash(url: string): string | undefined { return new URL(url, "https://localhost").pathname.split("/")[2]; }

function authAgent(req: IncomingMessage): string | undefined {
  const value = req.headers["x-extreme-zt-auth"];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function capabilities(config: SecureServerConfig): CapabilityDescriptor[] { return config.capabilities; }

export function createSecureServerRuntime(config: SecureServerConfig, handler: PromptHandler): SecureServer {
  const policy = resolveSecurityPolicy(config);
  const eventStore: EventStore | undefined = config.eventStore;

  const handlePrompt = async (envelope: PromptEnvelope, context: { agentId: string; certificateHash: string; transport: "rest" | "ws" | "grpc" }) => {
    const result = await handler.handle(envelope, context);
    await eventStore?.append({ type: "SecureCommunication.PromptAccepted", aggregateId: context.agentId, payload: { eventId: result.eventId, intent: result.intent, certificateHash: context.certificateHash, transport: context.transport } });
    return result;
  };

  const rest = createSecureServer({
    key: readFileSync(config.mtls.key), cert: readFileSync(config.mtls.cert), ca: readFileSync(config.mtls.ca),
    minVersion: config.mtls.minVersion ?? "TLSv1.3", requestCert: true, rejectUnauthorized: false,
  }, async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "https://localhost");
    if (req.method === "GET" && (url.pathname === "/auth" || url.pathname === "/intent")) {
      const agentId = authAgent(req);
      if (!agentId) return json(res, 401, { error: "X-eXtreme-ZT-auth is required" });
      const identity = await config.identityProvider.provision(agentId);
      return json(res, 200, { agentId: identity.agentId, certificate: identity.certificatePem, privateKey: identity.privateKeyPem, dpopPrivateKeyJwk: identity.dpopPrivateKeyJwk, capabilities: identity.capabilities, expiresAt: identity.expiresAt });
    }
    if (req.method !== "POST" || !url.pathname.startsWith("/prompt/")) return json(res, 404, { error: "Only POST /prompt/:certificateHash is supported" });
    const certHash = peerHash(req);
    const suppliedHash = pathHash(req.url ?? "");
    if (!certHash || suppliedHash !== certHash) return json(res, 401, { error: "mTLS certificate hash mismatch" }, certHash);
    const dpop = req.headers.dpop;
    if (typeof dpop !== "string" || !(await verifyDpopProof(dpop, { method: "POST", url: `https://${req.headers.host}${url.pathname}` }))) return json(res, 401, { error: "Valid DPoP proof is required" }, certHash);
    try { return json(res, 200, await handlePrompt(await body(req) as PromptEnvelope, { agentId: authAgent(req) ?? "mtls-agent", certificateHash: certHash, transport: "rest" }), certHash); }
    catch (error) { return json(res, 400, { error: error instanceof Error ? error.message : "Invalid prompt" }, certHash); }
  });

  const ws = new WebSocketServer({ server: rest });
  ws.on("connection", (socket, request) => {
    const cert = (request.socket as TLSSocket).getPeerCertificate(true);
    const certHash = (request.socket as TLSSocket).authorized && cert?.raw?.length ? certificateHashFromRaw(cert.raw) : undefined;
    socket.on("message", async data => {
      if (!certHash) return socket.close(1008, "mTLS certificate required");
      try {
        const message = JSON.parse(data.toString()) as { dpop?: string; envelope: PromptEnvelope };
        const url = `https://${request.headers.host ?? "localhost"}${request.url ?? "/"}`;
        if (!message.dpop || !(await verifyDpopProof(message.dpop, { method: "POST", url }))) return socket.close(1008, "DPoP required");
        const result = await handlePrompt(message.envelope, { agentId: "mtls-agent", certificateHash: certHash, transport: "ws" });
        socket.send(JSON.stringify({ ...result, headers: { "X-eXtreme-Zero-Trust": certHash } }));
        if (policy.channels.linearAutodestroy) socket.close(1000, "LinearAutodestroy");
      } catch { socket.close(1003, "Invalid prompt envelope"); }
    });
  });

  const grpcServer = new grpc.Server();
  const packageDefinition = protoLoader.loadSync(fileURLToPath(new URL("../proto/secure-communication.proto", import.meta.url)), { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
  const definition = grpc.loadPackageDefinition(packageDefinition) as unknown as { allascode: { SecureCommunication: grpc.ServiceDefinition } };
  grpcServer.addService(definition.allascode.SecureCommunication, {
    Prompt: async (call: grpc.ServerUnaryCall<PromptEnvelope, PromptResult>, callback: grpc.sendUnaryData<PromptResult>) => {
      try {
        const metadata = call.metadata.get("x-extreme-zt-auth");
        const certHash = String(metadata[0] ?? "");
        const envelope = call.request as unknown as PromptEnvelope;
        const result = await handlePrompt(envelope, { agentId: String(metadata[1] ?? "mtls-agent"), certificateHash: certHash, transport: "grpc" });
        const headers = new grpc.Metadata(); headers.set("X-eXtreme-Zero-Trust", certHash); call.sendMetadata(headers); callback(null, { ...result });
      } catch (error) { callback(error instanceof Error ? error : new Error("Prompt failed")); }
    },
  });

  return { rest, ws, grpc: grpcServer, policy, close: async () => { await new Promise<void>(resolve => rest.close(() => resolve())); ws.close(); grpcServer.forceShutdown(); } };
}

export function startSecureServer(runtime: SecureServer, config: SecureServerConfig): void {
  runtime.rest.listen(config.restPort ?? 8443, config.host ?? "0.0.0.0");
  runtime.grpc.bindAsync(`${config.host ?? "0.0.0.0"}:${config.grpcPort ?? 50051}`, grpc.ServerCredentials.createSsl(readFileSync(config.mtls.ca), [{ cert_chain: readFileSync(config.mtls.cert), private_key: readFileSync(config.mtls.key) }], true), () => runtime.grpc.start());
}

export const createDefaultPromptHandler = (): PromptHandler => ({ handle: async (envelope, context) => ({ eventId: newEventId(), intent: envelope.intent, accepted: true, output: { status: "accepted", agentId: context.agentId } }) });
