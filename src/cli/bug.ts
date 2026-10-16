/**
 * `ah bug add`: the only sanctioned way to write under .harness/memory/bugs/.
 * Every rule change starts here, so the record exists before the rule does.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { ruleInfo } from "../guard/rules/registry.ts";

export interface BugAddOptions {
  rule?: string;
  title?: string;
  command?: string;
  agent?: string;
  observedOn?: string;
  root?: string;
}

function parseArgs(argv: readonly string[]): BugAddOptions {
  const o: BugAddOptions = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => argv[++i] ?? "";
    if (a === "--rule") o.rule = v();
    else if (a === "--title") o.title = v();
    else if (a === "--command") o.command = v();
    else if (a === "--agent") o.agent = v();
    else if (a === "--observed-on") o.observedOn = v();
    else if (a === "--root") o.root = v();
  }
  return o;
}

export function nextIncidentId(dir: string, year: number): string {
  let max = 0;
  if (existsSync(dir)) {
    for (const f of readdirSync(dir)) {
      const m = /^BUG-(\d{4})-(\d{3,})\.ya?ml$/.exec(f);
      if (m && Number(m[1]) === year) max = Math.max(max, Number(m[2]));
    }
  }
  return `BUG-${year}-${String(max + 1).padStart(3, "0")}`;
}

function yamlString(s: string): string {
  return JSON.stringify(s);
}

export function renderBugRecord(id: string, date: string, o: BugAddOptions): string {
  const info = o.rule ? ruleInfo(o.rule) : undefined;
  const lines = [
    `incident_id: ${id}`,
    `date_recorded: ${date}`,
    `status: open`,
    `title: ${yamlString(o.title ?? "")}`,
    `observed_on: ${yamlString(o.observedOn ?? o.agent ?? "unknown")}`,
    `source:`,
    `  - kind: session`,
    `    note: ${yamlString(o.command ? `tool call: ${o.command}` : "recorded with ah bug add")}`,
    `root_cause: ""  # one sentence: what actually went wrong`,
    `impact: ""      # what it cost or would have cost`,
    `countermeasure:`,
    `  kind: ${info ? "rule" : "process"}`,
    `  ref: ${yamlString(o.rule ?? "")}${info ? `  # ${info.title} (${info.verdict})` : ""}`,
    `  change: ""    # what should change: a new fixture, a loosened or tightened rule, a process rule`,
    `must_block_fixture: ""`,
    `must_allow_fixture: ""`,
    `expiry_policy: "re-evaluate on the next major model upgrade"`,
  ];
  return `${lines.join("\n")}\n`;
}

export function runBug(argv: readonly string[], write: (s: string) => void = (s) => process.stdout.write(s)): number {
  const [sub, ...rest] = argv;
  const o = parseArgs(rest);
  const root = resolve(o.root ?? process.cwd());
  const dir = join(root, ".harness", "memory", "bugs");
  if (sub === "list") {
    if (!existsSync(dir)) {
      write(`no bug records under ${dir}\n`);
      return 0;
    }
    for (const f of readdirSync(dir).sort()) {
      if (!/\.ya?ml$/.test(f)) continue;
      const text = readFileSync(join(dir, f), "utf8");
      const title = /^title:\s*(.*)$/m.exec(text)?.[1] ?? "";
      const status = /^status:\s*(.*)$/m.exec(text)?.[1] ?? "";
      write(`${f.replace(/\.ya?ml$/, "").padEnd(14)} ${status.padEnd(10)} ${title.replace(/^"|"$/g, "")}\n`);
    }
    return 0;
  }
  if (sub !== "add") {
    write("usage: ah bug add --rule RULE --title TEXT [--command TEXT] [--agent NAME] [--observed-on TEXT] | ah bug list\n");
    return 1;
  }
  if (!o.title) {
    write("ah bug add: --title is required\n");
    return 1;
  }
  if (o.rule && !ruleInfo(o.rule)) {
    write(`ah bug add: unknown rule "${o.rule}" (see \`ah rules\`)\n`);
    return 1;
  }
  const now = new Date();
  const date = now.toISOString().slice(0, 10);
  const id = nextIncidentId(dir, now.getUTCFullYear());
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${id}.yaml`);
  writeFileSync(file, renderBugRecord(id, date, o), { flag: "wx" });
  write(`${file}\n`);
  return 0;
}
