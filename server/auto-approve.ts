// Guarded autonomy: routine scoped work keeps moving without asking.
//
// Permission requests have three outcomes: safe scoped work is allowed,
// broad irreversible destruction asks, and raw secret output is denied.
//
// The guard is deliberately tiny and literal. It is NOT a security
// boundary (an agent set on damage has a thousand spellings for `rm`);
// it is a "you probably didn't mean to hand THIS one over unattended"
// backstop for the obvious catastrophes. Real containment is the
// sandbox and the bot's own computer, not a regex.

const DESTRUCTIVE = [
  /\brm\s+(-[a-z]*\s+)*-[a-z]*[rf]/i, // rm -rf, rm -fr, rm -r -f
  /\brm\s+[^|;&\n]*(?:--recursive|--force)[^|;&\n]*(?:--recursive|--force)/i,
  /\bmkfs\b|\bdiskutil\s+erase|\bdd\s+[^|]*\bof=\/dev\//i,
  /\bshutdown\b|\breboot\b|\bhalt\b/i,
  /:\(\)\s*\{.*\}\s*;?\s*:/, // fork bomb
  /\bgit\s+push\s+[^|]*--force(-with-lease)?\b|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[^\s]*f/i,
  /\bgit\s+(?:branch|tag)\s+-D\b|\bgh\s+repo\s+delete\b/i,
  /\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b/i,
  /\bsudo\s+rm\b|\bchmod\s+-R\s+777\s+\//i,
  /\b(?:terraform\s+destroy|kubectl\s+delete\s+(?:namespace|cluster)|docker\s+system\s+prune)\b/i,
  /\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/i,
];

// Names and paths that may contain protected values. A mention alone is
// safe; matchRawValueAccess combines these with an output/transfer action.
const SENSITIVE_NAME = [
  /(^|[\s/"'])\.env(\.|$|["'\s])/i,
  /\.ssh\/|id_rsa|id_ed25519|authorized_keys/i,
  /\.aws\/credentials|\.netrc|\.npmrc|\.pypirc|\.docker\/config\.json/i,
  /security\s+find-(generic|internet)-password|\bkeychain\b/i,
  /\bcredentials?\.json\b|\bserviceaccount\b/i,
];

// A path/name is not itself a leak. Require an operation that emits or
// transfers its contents; brokered execution by logical name stays routine.
const VALUE_READ_VERB = /\b(?:read|cat|head|tail|less|more|sed|awk|grep|strings|base64|xxd|cp|scp|rsync)\b/i;
const VALUE_OUTPUT_OPERATIONS = [
  /\bsecurity\s+find-(?:generic|internet)-password\b[^|;&\n]*\s-w(?:\s|$)/i,
  /\bcredvault[_-]?(?:get[_-]?secret|read[_-]?secret|show[_-]?secret|reveal|export|raw)\b/i,
  /\b(?:get|read|show|reveal|dump|export)[_-]?(?:secret|credential|token|password)[_-]?(?:value|raw)?\b/i,
  /^\s*(?:sudo\s+)?(?:\/usr\/bin\/)?(?:env|set)\s*(?:$|[|>&])/i,
  /^\s*(?:sudo\s+)?(?:\/usr\/bin\/)?printenv(?:\s*$|\s+[A-Z0-9_]*(?:KEY|TOKEN|PASSWORD|SECRET|CREDENTIAL)[A-Z0-9_]*\s*$)/i,
  /\b(?:echo|printf)\b[^|;&\n]*\$(?:\{)?[A-Z0-9_]*(?:KEY|TOKEN|PASSWORD|SECRET|CREDENTIAL)[A-Z0-9_]*(?:\})?/i,
  /\b(?:show|print|reveal|return|dump|export|copy)\b.{0,48}\b(?:api[- ]?key|access[- ]?token|password|secret|credential)\s+(?:value|contents?)\b/i,
];

/** First matching pattern's source, so a verdict can NAME the rule that
 * made it — the decision log's whole value is "which rule", and deriving
 * the match a second time at the call site is how the log and the verdict
 * drift apart. */
function matchFirst(rules: RegExp[], text: string): string | null {
  for (const re of rules) if (re.test(text)) return re.source;
  return null;
}

function matchRawValueAccess(text: string): string | null {
  const direct = matchFirst(VALUE_OUTPUT_OPERATIONS, text);
  if (direct) return direct;
  const path = matchFirst(SENSITIVE_NAME, text);
  return path && VALUE_READ_VERB.test(text) ? `${VALUE_READ_VERB.source} + ${path}` : null;
}

export function looksSensitive(text: string): boolean {
  return matchRawValueAccess(text) !== null;
}

export function looksDestructive(text: string): boolean {
  return matchFirst(DESTRUCTIVE, text) !== null;
}

/** The key an "Always allow" remembers.
 *
 * A bare tool name is far too coarse for a command runner: remembering
 * "Bash" would hand the bot a permanent unattended shell, which is the
 * opposite of what someone pressing "always allow" on `git status`
 * intends. Command tools are therefore keyed by their program —
 * `Bash:git`, `Bash:npm` — so the grant is as narrow as the thing you
 * actually looked at. Computed once, server-side, and echoed back by the
 * client so the two sides can never disagree about what was granted. */
const COMMAND_TOOLS = new Set(["bash", "shell", "execute", "run_command", "computer_exec", "terminal"]);

export function approvalKey(tool: string, summary: string, scope?: "local-computer"): string {
  const bare = tool.replace(/^mcp__[^_]+__/, "").toLowerCase();
  if (!COMMAND_TOOLS.has(bare)) return scope ? `${scope}:${tool}` : tool;
  // first bare word of the command, skipping env assignments and sudo
  const words = summary.trim().split(/\s+/);
  let i = 0;
  while (i < words.length && (/^[A-Z_][A-Z0-9_]*=/.test(words[i]) || words[i] === "sudo")) i += 1;
  const program = (words[i] ?? "").split("/").pop()?.replace(/[^\w.-]/g, "") ?? "";
  const key = program ? `${tool}:${program}` : tool;
  return scope ? `${scope}:${key}` : key;
}

export interface AutoApprover {
  autoApprove?: boolean;
  alwaysAllow?: string[];
}

/** Why a verdict landed the way it did. `unattended-block` remains for old
 * decision-log rows; safe webhook work now uses guarded autonomy. */
export type AutoVerdictSource =
  | "always-allow"
  | "auto-mode"
  | "guarded-autonomy"
  | "unattended-block"
  | "local-computer-block"
  | "destructive-guard"
  | "sensitive-guard"
  | "no-grant";

export interface AutoVerdict {
  /** Provider behavior. `ask` leaves the request open for a human. */
  behavior: "allow" | "deny" | "ask";
  /** Chip text for an automatic allow; null for ask or deny.
   * The string becomes the chip in the transcript, so an auto-approved
   * action is never invisible. */
  approve: string | null;
  source: AutoVerdictSource;
  /** What identifies the rule that decided: the matched regex (guards) or
   * the granted key (always-allow, and unattended-block over one). Auto
   * mode has no narrower identity than the mode itself, so it carries none. */
  rule?: string;
}

/** The verdict AND its provenance. The decision itself is unchanged from
 * autoDecision below — this exists so the decision log can record which
 * rule decided without the call site re-deriving (and eventually
 * mis-deriving) the match. */
export function autoVerdict(
  bot: AutoApprover,
  tool: string,
  summary: string,
  context?: {
    /** the turn was started by an outside event, with nobody at the keyboard */
    unattended?: boolean;
    /** the request controls the user's active desktop */
    scope?: "local-computer";
  },
): AutoVerdict {
  // Guards outrank every grant. Destruction asks; raw value access denies.
  const destructive = matchFirst(DESTRUCTIVE, summary) ?? matchFirst(DESTRUCTIVE, tool);
  const sensitive = destructive ? null : matchRawValueAccess(`${tool} ${summary}`);
  if (sensitive) return { behavior: "deny", approve: null, source: "sensitive-guard", rule: sensitive };
  if (destructive) return { behavior: "ask", approve: null, source: "destructive-guard", rule: destructive };

  const key = approvalKey(tool, summary, context?.scope);
  // Host click/type metadata can be too weak to classify safely. Auto mode
  // remains the explicit opt-in for the user's active desktop.
  if (context?.scope === "local-computer" && !bot.autoApprove) {
    return {
      behavior: "ask",
      approve: null,
      source: "local-computer-block",
      rule: bot.alwaysAllow?.includes(key) ? key : undefined,
    };
  }

  // Safe scoped work is automatic. Webhook origin is provenance, not a
  // blanket veto; the same destructive and raw-value guards still apply.
  const grant =
    bot.alwaysAllow?.includes(key)
      ? { approve: `auto-approved ${key} (always allowed)`, source: "always-allow" as const, rule: key }
      : bot.autoApprove
        ? { approve: `auto-approved ${tool}`, source: "auto-mode" as const, rule: undefined }
        : {
            approve: `auto-approved ${tool} (guarded autonomy)`,
            source: "guarded-autonomy" as const,
            rule: undefined,
          };
  return { behavior: "allow", ...grant };
}

/** Why this request may be answered without the human, or null to ask. */
export function autoDecision(
  bot: AutoApprover,
  tool: string,
  summary: string,
  context?: {
    /** the turn was started by an outside event, with nobody at the keyboard */
    unattended?: boolean;
    /** the request controls the user's active desktop */
    scope?: "local-computer";
  },
): string | null {
  const verdict = autoVerdict(bot, tool, summary, context);
  return verdict.behavior === "allow" ? verdict.approve : null;
}
