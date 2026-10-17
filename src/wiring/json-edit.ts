/**
 * Rewrite a JSON file's text so it holds a new value while keeping the text
 * of everything that did not change. ah changes one array in a settings file;
 * reformatting the whole file would turn that into a diff of every line and
 * lose the person's layout. So members and elements whose value is unchanged
 * keep their exact text (indentation, line breaks, number spelling), and only
 * what differs is written fresh, indented like its neighbours.
 *
 * Falls back to a plain reformat when the original cannot be edited in place
 * (a duplicate key, keys that changed order) or when the edited text would not
 * parse back to exactly `value`.
 */
import { formatJson, type JsonStyle } from "./files.ts";

interface Node {
  start: number;
  end: number;
  /** Index of the closing bracket, for objects and arrays. */
  close: number;
  kind: "object" | "array" | "scalar";
  items: Item[];
}

interface Item {
  /** Just after the `{`, `[` or `,` before this item. */
  lead: number;
  /** The key's opening quote for objects, the value's start for arrays. */
  start: number;
  key?: string;
  /** Just after the key's closing quote. */
  keyEnd?: number;
  value: Node;
}

class Unsupported extends Error {}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export function editJson(original: string | undefined, value: unknown, style: JsonStyle): string {
  if (original === undefined || original.replace(/^﻿/, "").trim() === "") return formatJson(value, style);
  try {
    const bom = original.startsWith("﻿") ? "﻿" : "";
    const body = bom ? original.slice(1) : original;
    const before: unknown = JSON.parse(body); // the scanner assumes valid JSON
    const root = new Scanner(body).document();
    const e = new Editor(body, style);
    const out = bom + body.slice(0, root.start) + e.render(root, before, value, body.includes("\n")) + body.slice(root.end);
    if (same(JSON.parse(out.replace(/^﻿/, "")), value)) return out;
  } catch (err) {
    if (!(err instanceof Unsupported) && !(err instanceof SyntaxError)) throw err;
  }
  return formatJson(value, style);
}

/** Records where each value, key and separator sits. Assumes text JSON.parse accepts. */
class Scanner {
  private i = 0;
  private readonly s: string;
  constructor(s: string) {
    this.s = s;
  }

  document(): Node {
    this.ws();
    return this.value();
  }

  private ws(): void {
    while (/[ \t\r\n]/.test(this.s[this.i] ?? "")) this.i++;
  }

  private value(): Node {
    const c = this.s[this.i];
    if (c === "{" || c === "[") return this.container(c);
    const start = this.i;
    if (c === '"') this.string();
    else while (this.i < this.s.length && !/[,\]}\s]/.test(this.s[this.i])) this.i++;
    return { start, end: this.i, close: -1, kind: "scalar", items: [] };
  }

  private string(): string {
    const start = this.i++;
    while (this.s[this.i] !== '"') {
      if (this.i >= this.s.length) throw new Unsupported("unterminated string");
      this.i += this.s[this.i] === "\\" ? 2 : 1;
    }
    this.i++;
    return JSON.parse(this.s.slice(start, this.i)) as string;
  }

  private container(open: string): Node {
    const start = this.i++;
    const object = open === "{";
    const items: Item[] = [];
    const keys = new Set<string>();
    for (;;) {
      const lead = this.i;
      this.ws();
      if (this.i >= this.s.length) throw new Unsupported("unterminated container");
      if (this.s[this.i] === (object ? "}" : "]")) break;
      const itemStart = this.i;
      let key: string | undefined;
      let keyEnd: number | undefined;
      if (object) {
        key = this.string();
        if (keys.has(key)) throw new Unsupported(`duplicate key ${key}`);
        keys.add(key);
        keyEnd = this.i;
        this.ws();
        this.i++; // ':'
        this.ws();
      }
      items.push({ lead, start: itemStart, key, keyEnd, value: this.value() });
      this.ws();
      if (this.s[this.i] === ",") this.i++;
    }
    const close = this.i++;
    return { start, end: this.i, close, kind: object ? "object" : "array", items };
  }
}

interface Piece {
  /** Whitespace before the item; null to copy a neighbour's. */
  lead: string | null;
  body: (lead: string) => string;
}

class Editor {
  private readonly s: string;
  private readonly style: JsonStyle;
  constructor(s: string, style: JsonStyle) {
    this.s = s;
    this.style = style;
  }

  render(n: Node, before: unknown, after: unknown, pretty: boolean): string {
    if (same(before, after)) return this.s.slice(n.start, n.end);
    if (n.kind === "object" && isObj(before) && isObj(after)) return this.object(n, before, after);
    if (n.kind === "array" && Array.isArray(before) && Array.isArray(after)) return this.array(n, before, after);
    return this.fresh(after, pretty ? this.lineIndent(n.start) : null);
  }

  private object(n: Node, before: Obj, after: Obj): string {
    const byKey = new Map(n.items.map((it) => [it.key as string, it]));
    let last = -1;
    for (const k of Object.keys(after)) {
      const it = byKey.get(k);
      if (!it) continue;
      const at = n.items.indexOf(it);
      if (at < last) throw new Unsupported("keys changed order");
      last = at;
    }
    const sample = n.items[0];
    const colon = sample ? this.s.slice(sample.keyEnd, sample.value.start) : this.s.includes("\n") ? ": " : ":";
    const pieces: Piece[] = Object.keys(after).map((k) => {
      const it = byKey.get(k);
      if (it) {
        const head = this.s.slice(it.start, it.value.start);
        return { lead: this.leadOf(it), body: (lead) => head + this.render(it.value, before[k], after[k], lead.includes("\n")) };
      }
      return { lead: null, body: (lead) => JSON.stringify(k) + colon + this.freshFor(after[k], lead) };
    });
    return this.assemble(n, pieces);
  }

  private array(n: Node, before: unknown[], after: unknown[]): string {
    // Align unchanged elements (longest common subsequence), then pair what was
    // dropped with what was added in each gap, so an element edited in place
    // keeps its position's whitespace and the unchanged parts of its text.
    const a = before.map((v) => JSON.stringify(v));
    const b = after.map((v) => JSON.stringify(v));
    const L = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
    for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
    const pieces: Piece[] = [];
    let i = 0;
    let j = 0;
    const gap = (dropped: number[], added: number[]) => {
      added.forEach((jj, k) => {
        const ii = dropped[k];
        if (ii === undefined) pieces.push({ lead: null, body: (lead) => this.freshFor(after[jj], lead) });
        else {
          const it = n.items[ii];
          pieces.push({ lead: this.leadOf(it), body: (lead) => this.render(it.value, before[ii], after[jj], lead.includes("\n")) });
        }
      });
    };
    let dropped: number[] = [];
    let added: number[] = [];
    while (i < a.length || j < b.length) {
      if (i < a.length && j < b.length && a[i] === b[j]) {
        gap(dropped, added);
        dropped = [];
        added = [];
        const it = n.items[i];
        pieces.push({ lead: this.leadOf(it), body: () => this.s.slice(it.value.start, it.value.end) });
        i++;
        j++;
      } else if (j < b.length && (i >= a.length || L[i][j + 1] >= L[i + 1][j])) added.push(j++);
      else dropped.push(i++);
    }
    gap(dropped, added);
    return this.assemble(n, pieces);
  }

  private assemble(n: Node, pieces: Piece[]): string {
    const open = this.s[n.start];
    const close = this.s[n.close];
    if (pieces.length === 0) return open + close;
    let fallbackLead: string;
    let trailing: string;
    if (n.items.length > 0) {
      const lastItem = n.items[n.items.length - 1];
      fallbackLead = this.leadOf(lastItem);
      trailing = this.s.slice(lastItem.value.end, n.close);
    } else {
      // An empty `{}` or `[]` gives no layout to copy: break lines if the file does.
      const multi = this.s.includes("\n");
      const base = this.lineIndent(n.start);
      fallbackLead = multi ? this.style.eol + base + this.unit() : "";
      trailing = multi ? this.style.eol + base : "";
    }
    const parts = pieces.map((p, k) => {
      const lead = p.lead ?? fallbackLead;
      return (k > 0 ? "," : "") + lead + p.body(lead);
    });
    return open + parts.join("") + trailing + close;
  }

  private leadOf(it: Item): string {
    return this.s.slice(it.lead, it.start);
  }

  /** A new value placed after `lead`: indented like its line when the lead breaks the line, else on one line. */
  private freshFor(v: unknown, lead: string): string {
    return this.fresh(v, lead.includes("\n") ? lead.slice(lead.lastIndexOf("\n") + 1) : null);
  }

  private fresh(v: unknown, base: string | null): string {
    if (base === null) return JSON.stringify(v);
    return JSON.stringify(v, null, this.style.indent).replace(/\n/g, this.style.eol + base);
  }

  private unit(): string {
    return typeof this.style.indent === "number" ? " ".repeat(this.style.indent) : this.style.indent;
  }

  private lineIndent(at: number): string {
    const lineStart = this.s.lastIndexOf("\n", at - 1) + 1;
    return /^[ \t]*/.exec(this.s.slice(lineStart))?.[0] ?? "";
  }
}
