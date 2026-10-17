/**
 * Credential-literal detection. Patterns are deliberately specific: a false
 * positive here blocks a legitimate edit, so prefixed token formats are
 * preferred over entropy heuristics. The generic assignment pattern is the one
 * exception and only ever asks.
 *
 * The first eight entries are ported from legion-cli (`packages/cli/src/secrets.ts`).
 */

export type SecretSeverity = "deny" | "ask";

export interface SecretPattern {
  name: string;
  re: RegExp;
  severity: SecretSeverity;
}

export interface SecretHit {
  name: string;
  match: string;
  severity: SecretSeverity;
}

/**
 * A PEM private key is a header followed by a body: either a line of 40 or
 * more base64 characters right after the header (a real or an escaped line
 * break), or a non-empty body of base64, whitespace and PEM header fields
 * closed by the matching END marker. A bare header, or a header and footer
 * with code between them, is a string a PEM parser, a secret scanner or a
 * grep needs, not key material.
 */
const PEM_TYPE = "(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?";
// A real or an escaped (`\n` inside a string literal) line break.
const LINE_BREAK = "(?:\\r?\\n|(?:\\\\r)?\\\\n)";
// Base64, whitespace, the `Proc-Type:` / `DEK-Info:` fields of an encrypted key, escaped line breaks.
// A dash may not start a `-----` marker, so the body never runs across another header.
const PEM_BODY_CHAR = "(?:[A-Za-z0-9+/=:,\\s]|-(?!----)|\\\\[rn])";
const PRIVATE_KEY_BLOCK = new RegExp(
  `-----BEGIN (${PEM_TYPE})-----(?:[ \\t]*${LINE_BREAK}[ \\t]*[A-Za-z0-9+/=]{40,}|\\s*[A-Za-z0-9+/=:,-]${PEM_BODY_CHAR}*?-----END \\1-----)`,
  "g",
);

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { name: "aws-access-key", re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g, severity: "deny" },
  { name: "openai-project-key", re: /\bsk-proj-[A-Za-z0-9_-]{20,}/g, severity: "deny" },
  { name: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, severity: "deny" },
  { name: "sk-prefixed-key", re: /\bsk-[A-Za-z0-9]{20,}\b/g, severity: "deny" },
  { name: "xai-key", re: /\bxai-[A-Za-z0-9]{20,}\b/g, severity: "deny" },
  { name: "private-key-block", re: PRIVATE_KEY_BLOCK, severity: "deny" },
  { name: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, severity: "deny" },
  { name: "github-fine-grained-token", re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, severity: "deny" },
  { name: "aws-secret-key", re: /\baws_secret_access_key\b\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}\b/gi, severity: "deny" },
  { name: "slack-token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, severity: "deny" },
  { name: "slack-webhook", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g, severity: "deny" },
  { name: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "deny" },
  { name: "stripe-live-key", re: /\b[sr]k_live_[A-Za-z0-9]{20,}\b/g, severity: "deny" },
  { name: "npm-token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "deny" },
  { name: "pypi-token", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}/g, severity: "deny" },
  { name: "huggingface-token", re: /\bhf_[A-Za-z0-9]{30,}\b/g, severity: "deny" },
  { name: "supabase-access-token", re: /\bsbp_[a-f0-9]{40}\b/g, severity: "deny" },
  { name: "sendgrid-key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: "deny" },
  { name: "telegram-bot-token", re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, severity: "deny" },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: "ask" },
  { name: "generic-secret-assignment", re: /\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*["'][^"'\s]{16,}["']/gi, severity: "ask" },
];

const PLACEHOLDER_WORDS = /xxxx|\*\*\*\*|\.\.\.|<|>|\$\{|\{\{|example|placeholder|your[_-]|changeme|change-me|dummy|fake|redacted|sample|insert|replace|todo|0{10}|1234567890|abcdefghij/i;

/** True when a match is obviously documentation rather than a live credential. */
export function isPlaceholder(match: string): boolean {
  if (PLACEHOLDER_WORDS.test(match)) return true;
  const body = match.replace(/^[A-Za-z_-]+[_-]/, "");
  if (body.length === 0) return false;
  const counts = new Map<string, number>();
  for (const ch of body) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const top = Math.max(...counts.values());
  return top / body.length >= 0.6;
}

export function findSecrets(text: string): SecretHit[] {
  const hits: SecretHit[] = [];
  if (!text) return hits;
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(text)) !== null) {
      if (!isPlaceholder(m[0])) hits.push({ name: p.name, match: m[0], severity: p.severity });
      if (m[0].length === 0) p.re.lastIndex++;
    }
  }
  return hits;
}

/** Shorten a secret for a log line: first four characters, then a mask. */
export function redact(match: string): string {
  const head = match.slice(0, 4);
  return `${head}${"*".repeat(Math.min(8, Math.max(0, match.length - 4)))}`;
}
