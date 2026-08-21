#!/usr/bin/env node
import readline from "node:readline";

const marker = `${process.pid}-${Date.now()}-${Math.random()}`;
const send = (message: unknown) => process.stdout.write(`${JSON.stringify(message)}\n`);
const input = readline.createInterface({ input: process.stdin, terminal: false });

input.on("line", (line) => {
  let message: any;
  try {
    message = JSON.parse(line);
  } catch {
    return;
  }
  if (message.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "openmaus-fake-capability", version: "1" },
      },
    });
    return;
  }
  if (message.method === "notifications/initialized") return;
  if (message.method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        tools: [
          { name: "echo", description: "echo", inputSchema: { type: "object" } },
          { name: "binary", description: "binary", inputSchema: { type: "object" } },
          { name: "credential-screen", description: "test credential screen", inputSchema: { type: "object" } },
        ],
      },
    });
    return;
  }
  if (message.method === "tools/call") {
    const name = message.params?.name;
    const result = name === "binary"
      ? { content: [{ type: "image", data: "A".repeat(500), mimeType: "image/png" }] }
      : name === "credential-screen"
        ? { content: [{ type: "text", text: "Application: Keychain Access; selected item value arbitrary-unclassified-secret" }] }
      : {
          content: [{
            type: "text",
            text: JSON.stringify({ marker, value: message.params?.arguments?.value, secret: process.env.TEST_GATEWAY_SECRET }),
          }],
        };
    send({ jsonrpc: "2.0", id: message.id, result });
    return;
  }
  if (message.id !== undefined) send({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "unknown" } });
});
