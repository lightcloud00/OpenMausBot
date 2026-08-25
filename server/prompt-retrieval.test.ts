import { describe, expect, it, vi } from "vitest";

import {
  appendPromptRetrievalContext,
  retrievePromptContext,
} from "./prompt-retrieval.ts";

const CONTEXT = [
  '<fleet-retrieval-evidence trust="untrusted" instruction-authority="false">',
  '{"hits":[]}',
  "</fleet-retrieval-evidence>",
].join("\n");

interface ResponseOverrides {
  schema?: string;
  status?: string;
  surface?: string;
  interface?: string;
  context?: string;
  content_trust?: string;
  instruction_authority?: boolean;
  tool_authority?: boolean;
  write_authority?: boolean;
  selector_authority?: boolean;
  promotion_authority?: boolean;
  prompt_or_content_recorded_by_adapter?: boolean;
}

function response(overrides: ResponseOverrides = {}): Response {
  return new Response(JSON.stringify({
    schema: "aos.openmausbot-retrieval-adapter.v1",
    status: "context_ready",
    surface: "openmausbot",
    interface: "loopback",
    context: CONTEXT,
    content_trust: "untrusted_retrieval_evidence",
    instruction_authority: false,
    tool_authority: false,
    write_authority: false,
    selector_authority: false,
    promotion_authority: false,
    prompt_or_content_recorded_by_adapter: false,
    ...overrides,
  }), { status: 200, headers: { "content-type": "application/json" } });
}

describe("guarded OpenMaus prompt retrieval", () => {
  it("stays disabled without an explicit loopback endpoint", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    expect(await retrievePromptContext("find source", "thread-1", {
      endpoint: "",
      fetchImpl,
    })).toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each([
    "https://127.0.0.1:8798",
    "http://192.168.1.2:8798",
    "http://user@127.0.0.1:8798",
    "http://127.0.0.1:8798/other",
  ])("rejects a non-loopback or ambiguous endpoint: %s", async (endpoint) => {
    const fetchImpl = vi.fn<typeof fetch>();
    expect(await retrievePromptContext("find source", "thread-1", {
      endpoint,
      fetchImpl,
    })).toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("passes only the prompt and native session id and returns bounded context", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(response());
    const context = await retrievePromptContext(
      "Find the exact implementation",
      "openmaus-thread-1",
      { endpoint: "http://127.0.0.1:8798", fetchImpl },
    );

    expect(context).toBe(CONTEXT);
    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(String(url)).toBe("http://127.0.0.1:8798/v1/retrieve");
    expect(JSON.parse(String(init?.body))).toEqual({
      prompt: "Find the exact implementation",
      session_id: "openmaus-thread-1",
    });
    expect(init?.cache).toBe("no-store");
    expect(appendPromptRetrievalContext("user text", context)).toBe(
      `user text\n\n${CONTEXT}`,
    );
  });

  it.each([
    { instruction_authority: true },
    { tool_authority: true },
    { write_authority: true },
    { selector_authority: true },
    { promotion_authority: true },
    { prompt_or_content_recorded_by_adapter: true },
    { context: "unwrapped" },
  ])("drops an unsafe adapter response: %j", async (unsafe) => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(response(unsafe));
    expect(await retrievePromptContext("find source", "thread-1", {
      endpoint: "http://localhost:8798/v1/retrieve",
      fetchImpl,
    })).toBeNull();
  });

  it("fails open on transport errors and oversize prompts", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockRejectedValue(new Error("offline"));
    expect(await retrievePromptContext("find source", "thread-1", {
      endpoint: "http://127.0.0.1:8798",
      fetchImpl,
    })).toBeNull();
    expect(await retrievePromptContext("x".repeat(8_193), "thread-1", {
      endpoint: "http://127.0.0.1:8798",
      fetchImpl,
    })).toBeNull();
    expect(fetchImpl).toHaveBeenCalledOnce();
  });
});
