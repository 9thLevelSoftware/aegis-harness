/**
 * Rewrite a JSON file's text so it holds a new value while keeping the text
 * of everything that did not change. ah changes one array in a settings file;
 * reformatting the whole file would turn that into a diff of every line and
 * lose the person's layout. So members and elements whose value is unchanged
 * keep their exact text (indentation, line breaks, number spelling) and the
 * whitespace around them, before a comma too; one that moved takes its text
 * along. Only what differs is written fresh, laid out like its neighbours, and
 * a value that cannot be edited in place (its keys would have to change order)
 * is written fresh where it stands, so the rest of the file never notices.
 * Removing what was added gives back the original bytes.
 *
 * Falls back to a plain reformat of the whole file only when the original
 * cannot be mapped (not JSON, a duplicate key) or when the edited text would
 * not parse back to exactly `value`.
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
  /** The `,` after this item, or the closing bracket after the last one. */
  tail: number;
}

class Unsupported extends Error {}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
/** Keys JSON.parse puts first, in numeric order, wherever the text has them. */
const isIndex = (k: string) => /^(0|[1-9]\d{0,9})$/.test(k) && Number(k) < 2 ** 32 - 1;

export function editJson(original: string | undefined, value: unknown, style: JsonStyle): string {
  if (original === undefined || original.replace(/^﻿/, "").trim() === "") return formatJson(value, style);
  try {
    const bom = original.startsWith("﻿") ? "﻿" : "";
    const body = bom ? original.slice(1) : original;
    const before: unknown = JSON.parse(body); // the scanner assumes valid JSON
    const scan = new Scanner(body);
    const root = scan.document();
    const e = new Editor(body, style, scan.colon);
    const out = bom + body.slice(0, root.start) + e.document(root, before, value) + body.slice(root.end);
    if (same(JSON.parse(out.replace(/^﻿/, "")), value)) return out;
  } catch (err) {
    if (!(err instanceof Unsupported) && !(err instanceof SyntaxError)) throw err;
  }
  return formatJson(value, style);
}

/** Records where each value, key and separator sits. Assumes text JSON.parse accepts. */
class Scanner {
  /** The first key-to-value separator in the file, for members added to an empty object. */
  colon: string | undefined;
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
        this.colon ??= this.s.slice(keyEnd, this.i);
      }
      const value = this.value();
      this.ws();
      items.push({ lead, start: itemStart, key, keyEnd, value, tail: this.i });
      if (this.s[this.i] === ",") this.i++;
    }
    const close = this.i++;
    return { start, end: this.i, close, kind: object ? "object" : "array", items };
  }
}

/** Where a fresh value goes: on lines that start with `base`, or on one line. */
interface At {
  pretty: boolean;
  base: string;
}

interface Piece {
  /** The original item (index) whose surrounding whitespace this piece takes. */
  from?: number;
  body: (at: At) => string;
}

class Editor {
  private readonly s: string;
  private readonly style: JsonStyle;
  private readonly colon: string;
  /** Whether one-line JSON here has a space after `:` and `,`. */
  private readonly spaced: boolean;
  constructor(s: string, style: JsonStyle, colon: string | undefined) {
    this.s = s;
    this.style = style;
    this.colon = colon ?? (s.includes("\n") ? ": " : ":");
    this.spaced = /[ \t]$/.test(this.colon);
  }

  document(root: Node, before: unknown, after: unknown): string {
    return this.render(root, before, after, { pretty: this.s.includes("\n"), base: this.lineIndent(root.start) });
  }

  private render(n: Node, before: unknown, after: unknown, at: At): string {
    if (same(before, after)) return this.text(n);
    if (n.kind === "object" && isObj(before) && isObj(after)) return this.object(n, before, after, at);
    if (n.kind === "array" && Array.isArray(before) && Array.isArray(after)) return this.array(n, before, after, at);
    return this.fresh(after, at);
  }

  private object(n: Node, before: Obj, after: Obj, at: At): string {
    const index = new Map(n.items.map((it, i) => [it.key as string, i]));
    const keys = this.order(n, after, index);
    // Members still in their old order keep their whitespace; the others move with their text.
    const stay = increasing(keys.flatMap((k) => index.get(k) ?? []));
    const sample = n.items[0];
    const colon = sample ? this.s.slice(sample.keyEnd, sample.value.start) : this.colon;
    const pieces = keys.map((k): Piece => {
      const i = index.get(k);
      if (i === undefined) return { body: (a) => JSON.stringify(k) + colon + this.fresh(after[k], a) };
      const it = n.items[i];
      const head = this.s.slice(it.start, it.value.start);
      return { from: stay.has(i) ? i : undefined, body: (a) => head + this.render(it.value, before[k], after[k], a) };
    });
    return this.assemble(n, pieces, at);
  }

  /**
   * `after`'s keys in an order that parses back the same. JSON.parse lists
   * integer-like keys first wherever the text has them, so those keep their
   * place among the others.
   */
  private order(n: Node, after: Obj, index: Map<string, number>): string[] {
    const keys = Object.keys(after);
    if (!keys.some(isIndex)) return keys;
    const held = n.items.flatMap((it, i) => (isIndex(it.key as string) && Object.hasOwn(after, it.key as string) ? [i] : []));
    const named = keys.filter((k) => !isIndex(k));
    const out: string[] = [];
    named.forEach((k, x) => {
      const next = named.slice(x).find((m) => index.has(m));
      const bound = next === undefined ? Infinity : (index.get(next) as number);
      while (held.length > 0 && held[0] < bound) out.push(n.items[held.shift() as number].key as string);
      out.push(k);
    });
    return [...out, ...held.map((i) => n.items[i].key as string), ...keys.filter((k) => isIndex(k) && !index.has(k))];
  }

  private array(n: Node, before: unknown[], after: unknown[], at: At): string {
    // Align unchanged elements (longest common subsequence). In each gap between
    // them an added element takes the text of an equal one dropped elsewhere (it
    // moved), or is edited in place from the dropped one it shares most with, or
    // is written fresh in a dropped one's place.
    const a = before.map((v) => JSON.stringify(v));
    const b = after.map((v) => JSON.stringify(v));
    const L = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
    for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
    type Gap = { dropped: number[]; added: number[] };
    const steps: (number | Gap)[] = [];
    let gap: Gap = { dropped: [], added: [] };
    for (let i = 0, j = 0; i < a.length || j < b.length; ) {
      if (i < a.length && j < b.length && a[i] === b[j]) {
        steps.push(gap, i++);
        gap = { dropped: [], added: [] };
        j++;
      } else if (j < b.length && (i >= a.length || L[i][j + 1] >= L[i + 1][j])) gap.added.push(j++);
      else gap.dropped.push(i++);
    }
    steps.push(gap);
    const gaps = steps.filter((x): x is Gap => typeof x !== "number");
    // Equal elements never share a gap (they would extend the alignment), so a match is a move.
    const moved = new Map<number, number>();
    for (const j of gaps.flatMap((g) => g.added)) {
      for (const g of gaps) {
        const k = g.dropped.findIndex((i) => a[i] === b[j]);
        if (k < 0) continue;
        moved.set(j, g.dropped[k]);
        g.dropped.splice(k, 1);
        break;
      }
    }
    const pieces: Piece[] = [];
    for (const step of steps) {
      if (typeof step === "number") {
        pieces.push({ from: step, body: () => this.text(n.items[step].value) });
        continue;
      }
      const { content, slot } = pair(before, after, step.dropped, step.added, moved);
      for (const j of step.added) {
        const m = moved.get(j);
        const i = content.get(j);
        let body: Piece["body"];
        if (m !== undefined) body = () => this.text(n.items[m].value);
        else if (i !== undefined) body = (at) => this.render(n.items[i].value, before[i], after[j], at);
        else body = (at) => this.fresh(after[j], at);
        pieces.push({ from: slot.get(j), body });
      }
    }
    return this.assemble(n, pieces, at);
  }

  private assemble(n: Node, pieces: Piece[], at: At): string {
    const items = n.items;
    const open = this.s[n.start];
    const close = this.s[n.close];
    const inner = this.s.slice(n.start + 1, n.close);
    if (pieces.length === 0) {
      // Emptied: keep what sat inside the brackets when the first item was on their line.
      const lead = items.length > 0 ? this.leadOf(items[0]) : inner;
      return open + (lead.includes("\n") ? "" : lead) + close;
    }
    // Whitespace for an item that is new or changes place, copied from the old
    // ones: `first` after the opening bracket, `lead` after a comma, `sep` before
    // a comma, `end` before the closing bracket.
    let first: string;
    let lead: string;
    let sep = "";
    let end: string;
    if (items.length > 0) {
      first = this.leadOf(items[0]);
      lead = items.length > 1 ? this.leadOf(items[items.length - 1]) : first === "" && this.spaced ? " " : first;
      if (items.length > 1) sep = this.trailOf(items[items.length - 2]);
      end = this.trailOf(items[items.length - 1]);
    } else if (inner !== "" && !inner.includes("\n")) {
      first = lead = end = inner; // `{ }` stays on its line
    } else if (inner !== "" || at.pretty) {
      first = lead = this.style.eol + at.base + this.unit();
      end = this.style.eol + at.base;
    } else {
      first = end = "";
      lead = this.spaced ? " " : "";
    }
    // Containers written `[{` with their elements on lines of their own.
    const spans = items.some((it) => this.text(it.value).includes("\n"));
    let out = open;
    let prev = "";
    pieces.forEach((p, k) => {
      const last = k === pieces.length - 1;
      const own = p.from;
      const l = own !== undefined && (own === 0) === (k === 0) ? this.leadOf(items[own]) : k === 0 ? first : lead;
      const t = own !== undefined && (own === items.length - 1) === last ? this.trailOf(items[own]) : last ? end : sep;
      const gap = (k === 0 ? "" : prev + ",") + l;
      const nl = gap.lastIndexOf("\n");
      const here: At = nl >= 0 ? { pretty: true, base: gap.slice(nl + 1).replace(/[^\t]/g, " ") } : { pretty: spans, base: this.lineIndent(n.start) };
      out += (k === 0 ? "" : ",") + l + p.body(here) + t;
      prev = t;
    });
    return out + close;
  }

  private text(n: Node): string {
    return this.s.slice(n.start, n.end);
  }

  private leadOf(it: Item): string {
    return this.s.slice(it.lead, it.start);
  }

  private trailOf(it: Item): string {
    return this.s.slice(it.value.end, it.tail);
  }

  private fresh(v: unknown, at: At): string {
    if (at.pretty) return JSON.stringify(v, null, this.style.indent).replace(/\n/g, this.style.eol + at.base);
    if (!this.spaced) return JSON.stringify(v);
    // One line, spaced like `{"a": 1, "b": [2, 3]}`. Strings never hold a raw line break.
    return JSON.stringify(v, null, 1).replace(/([[{])\n */g, "$1").replace(/\n *([\]}])/g, "$1").replace(/\n */g, " ");
  }

  private unit(): string {
    return typeof this.style.indent === "number" ? " ".repeat(this.style.indent) : this.style.indent;
  }

  private lineIndent(at: number): string {
    const lineStart = this.s.lastIndexOf("\n", at - 1) + 1;
    return /^[ \t]*/.exec(this.s.slice(lineStart))?.[0] ?? "";
  }
}

/**
 * Match the dropped elements of a gap to its added ones, in order, keeping the
 * most text. `content` pairs are edited in place; `slot` says whose whitespace
 * each added element takes, so one written fresh still sits where its
 * predecessor sat. Elements that moved here keep their own text and take a slot only.
 */
function pair(before: unknown[], after: unknown[], dropped: number[], added: number[], moved: Map<number, number>) {
  const score = dropped.map((i) => added.map((j) => (moved.has(j) ? null : overlap(before[i], after[j]))));
  const best = Array.from({ length: dropped.length + 1 }, () => new Array<number>(added.length + 1).fill(0));
  for (let x = dropped.length - 1; x >= 0; x--) {
    for (let y = added.length - 1; y >= 0; y--) {
      const s = score[x][y];
      best[x][y] = Math.max(best[x + 1][y], best[x][y + 1], s === null ? 0 : s + 1 + best[x + 1][y + 1]);
    }
  }
  const content = new Map<number, number>();
  const slot = new Map<number, number>();
  let fx = 0;
  let fy = 0;
  const zip = (tx: number, ty: number) => {
    for (let k = 0; fx + k < tx && fy + k < ty; k++) slot.set(added[fy + k], dropped[fx + k]);
  };
  for (let x = 0, y = 0; x < dropped.length && y < added.length; ) {
    const s = score[x][y];
    if (s !== null && best[x][y] === s + 1 + best[x + 1][y + 1]) {
      zip(x, y);
      content.set(added[y], dropped[x]);
      slot.set(added[y], dropped[x]);
      fx = ++x;
      fy = ++y;
    } else if (best[x][y] === best[x + 1][y]) x++;
    else y++;
  }
  zip(dropped.length, added.length);
  return { content, slot };
}

/**
 * How much text editing `a` into `b` in place keeps, or null when it cannot:
 * a different type, or keys both have in a different order (an entry written
 * `{"hooks": ..., "matcher": ...}` is replaced, not rearranged).
 */
function overlap(a: unknown, b: unknown): number | null {
  if (isObj(a) && isObj(b)) {
    const ka = Object.keys(a).filter((k) => Object.hasOwn(b, k));
    const kb = Object.keys(b).filter((k) => Object.hasOwn(a, k));
    if (ka.some((k, i) => k !== kb[i])) return null;
    return ka.reduce((sum, k) => sum + k.length + (same(a[k], b[k]) ? JSON.stringify(a[k]).length : (overlap(a[k], b[k]) ?? 0)), 0);
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    const left = a.map((v) => JSON.stringify(v));
    return b.reduce((sum: number, v) => {
      const k = left.indexOf(JSON.stringify(v));
      if (k < 0) return sum;
      left.splice(k, 1);
      return sum + JSON.stringify(v).length;
    }, 0);
  }
  return isObj(a) || isObj(b) || Array.isArray(a) || Array.isArray(b) ? null : 0;
}

/** The values of a longest increasing run (subsequence) of `xs`. */
function increasing(xs: number[]): Set<number> {
  const len = xs.map(() => 1);
  const prev = xs.map(() => -1);
  xs.forEach((x, i) => {
    for (let k = 0; k < i; k++) {
      if (xs[k] < x && len[k] + 1 > len[i]) {
        len[i] = len[k] + 1;
        prev[i] = k;
      }
    }
  });
  const out = new Set<number>();
  for (let i = len.indexOf(Math.max(0, ...len)); i >= 0; i = prev[i]) out.add(xs[i]);
  return out;
}
