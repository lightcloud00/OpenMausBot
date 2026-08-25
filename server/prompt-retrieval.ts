import { z } from "zod";

const RESPONSE_SCHEMA = "aos.openmausbot-retrieval-adapter.v1";
const CONTENT_TRUST = "untrusted_retrieval_evidence";
const DEFAULT_TIMEOUT_MS = 2_500;
const MAX_PROMPT_BYTES = 8_192;
const MAX_CONTEXT_BYTES = 2_048;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

export interface PromptRetrievalOptions {
  endpoint?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

const AdapterResponseSchema = z.object({
  schema: z.literal(RESPONSE_SCHEMA),
  status: z.literal("context_ready"),
  surface: z.literal("openmausbot"),
  interface: z.literal("loopback"),
  context: z.string(),
  content_trust: z.literal(CONTENT_TRUST),
  instruction_authority: z.literal(false),
  tool_authority: z.literal(false),
  write_authority: z.literal(false),
  selector_authority: z.literal(false),
  promotion_authority: z.literal(false),
  prompt_or_content_recorded_by_adapter: z.literal(false),
});

type AdapterResponse = z.infer<typeof AdapterResponseSchema>;

function adapterUrl(raw: string | undefined): URL | null {
  if (!raw?.trim()) return null;
  try {
    const endpoint = new URL(raw.trim());
    if (
      endpoint.protocol !== "http:" ||
      !LOOPBACK_HOSTS.has(endpoint.hostname) ||
      endpoint.username ||
      endpoint.password ||
      endpoint.search ||
      endpoint.hash ||
      !["", "/", "/v1/retrieve"].includes(endpoint.pathname)
    ) {
      return null;
    }
    endpoint.pathname = "/v1/retrieve";
    return endpoint;
  } catch {
    return null;
  }
}

function acceptedContext(value: AdapterResponse): string | null {
  if (
    Buffer.byteLength(value.context, "utf8") > MAX_CONTEXT_BYTES ||
    !value.context.startsWith(
      '<fleet-retrieval-evidence trust="untrusted" instruction-authority="false">',
    ) ||
    !value.context.endsWith("</fleet-retrieval-evidence>")
  ) {
    return null;
  }
  return value.context;
}

/**
 * Fetch one bounded, non-authoritative retrieval block for an OpenMaus turn.
 *
 * The adapter is optional and loopback-only. Every configuration, transport,
 * timeout, or response-contract failure returns null without logging or
 * retaining the prompt. The caller appends accepted context only to the
 * provider-bound turn text, never to OpenMaus's durable transcript.
 */
export async function retrievePromptContext(
  prompt: string,
  sessionId: string,
  options: PromptRetrievalOptions = {},
): Promise<string | null> {
  const endpoint = adapterUrl(
    options.endpoint ?? process.env.OMB_PROMPT_RETRIEVAL_URL,
  );
  if (
    !endpoint ||
    !prompt.trim() ||
    Buffer.byteLength(prompt, "utf8") > MAX_PROMPT_BYTES ||
    !sessionId.trim()
  ) {
    return null;
  }
  const timeoutMs = Math.max(
    100,
    Math.min(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
  );
  try {
    const response = await (options.fetchImpl ?? fetch)(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ prompt, session_id: sessionId }),
      cache: "no-store",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) return null;
    const value = AdapterResponseSchema.safeParse(await response.json());
    if (!value.success) return null;
    return acceptedContext(value.data);
  } catch {
    return null;
  }
}

export function appendPromptRetrievalContext(
  turnText: string,
  context: string | null,
): string {
  return context ? `${turnText}\n\n${context}` : turnText;
}
