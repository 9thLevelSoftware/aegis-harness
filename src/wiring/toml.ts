/**
 * A TOML reader for what `ah doctor` looks up in Codex's config.toml and
 * requirements.toml: `[features]`, `[projects."<path>"]`, `[hooks.state."<key>"]`
 * and `allow_managed_hooks_only`. It reads tables, dotted and quoted keys,
 * strings (all four forms), booleans, numbers, arrays and inline tables;
 * dates come back as strings. Read only: ah never writes TOML. Throws
 * TomlError on anything it cannot read, and the caller reports the file as
 * unreadable instead of guessing.
 */
export class TomlError extends Error {}

type Table = Record<string, unknown>;

export function parseToml(text: string): Table {
  const p = new Parser(text.replace(/^﻿/, ""));
  return p.document();
}

class Parser {
  private i = 0;
  private readonly root: Table = {};
  private current: Table = this.root;
  private readonly s: string;
  constructor(s: string) {
    this.s = s;
  }

  document(): Table {
    for (;;) {
      this.skipBlank();
      if (this.i >= this.s.length) return this.root;
      if (this.s[this.i] === "[") this.header();
      else {
        const path = this.keyPath("=");
        this.expect("=");
        const value = this.value();
        setPath(this.current, path, value);
      }
      this.endOfLine();
    }
  }

  private header(): void {
    const array = this.s.startsWith("[[", this.i);
    this.i += array ? 2 : 1;
    const path = this.keyPath("]");
    this.expect("]");
    if (array) this.expect("]");
    if (array) {
      const parent = tableAt(this.root, path.slice(0, -1));
      const last = path[path.length - 1];
      const list = Array.isArray(parent[last]) ? (parent[last] as Table[]) : [];
      parent[last] = list;
      const t: Table = {};
      list.push(t);
      this.current = t;
    } else {
      this.current = tableAt(this.root, path);
    }
  }

  private keyPath(stop: string): string[] {
    const parts: string[] = [];
    for (;;) {
      this.skipSpaces();
      const c = this.s[this.i];
      if (c === '"') parts.push(this.basicString());
      else if (c === "'") parts.push(this.literalString());
      else {
        const m = /^[A-Za-z0-9_-]+/.exec(this.s.slice(this.i));
        if (!m) throw this.error(`expected a key before ${stop}`);
        parts.push(m[0]);
        this.i += m[0].length;
      }
      this.skipSpaces();
      if (this.s[this.i] === ".") {
        this.i++;
        continue;
      }
      return parts;
    }
  }

  private value(): unknown {
    this.skipSpaces();
    const rest = this.s.slice(this.i);
    if (rest.startsWith('"""')) return this.multiline('"""');
    if (rest.startsWith("'''")) return this.multiline("'''");
    const c = rest[0];
    if (c === '"') return this.basicString();
    if (c === "'") return this.literalString();
    if (c === "[") return this.array();
    if (c === "{") return this.inlineTable();
    const m = /^[^\s,\]}#]+/.exec(rest);
    if (!m) throw this.error("expected a value");
    this.i += m[0].length;
    const w = m[0];
    if (w === "true") return true;
    if (w === "false") return false;
    const n = Number(w.replace(/_/g, ""));
    return Number.isNaN(n) ? w : n;
  }

  private array(): unknown[] {
    this.i++;
    const out: unknown[] = [];
    for (;;) {
      this.skipBlank();
      if (this.s[this.i] === "]") {
        this.i++;
        return out;
      }
      out.push(this.value());
      this.skipBlank();
      if (this.s[this.i] === ",") this.i++;
      else if (this.s[this.i] !== "]") throw this.error("expected , or ] in an array");
    }
  }

  private inlineTable(): Table {
    this.i++;
    const t: Table = {};
    this.skipSpaces();
    if (this.s[this.i] === "}") {
      this.i++;
      return t;
    }
    for (;;) {
      const path = this.keyPath("=");
      this.expect("=");
      setPath(t, path, this.value());
      this.skipSpaces();
      if (this.s[this.i] === ",") {
        this.i++;
        continue;
      }
      this.expect("}");
      return t;
    }
  }

  private basicString(): string {
    this.i++;
    let out = "";
    while (this.i < this.s.length) {
      const c = this.s[this.i++];
      if (c === '"') return out;
      if (c === "\n") break;
      if (c !== "\\") {
        out += c;
        continue;
      }
      const e = this.s[this.i++];
      const map: Record<string, string> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\", e: "\x1b" };
      if (e in map) out += map[e];
      else if (e === "u" || e === "U") {
        const len = e === "u" ? 4 : 8;
        const hex = this.s.slice(this.i, this.i + len);
        if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) throw this.error("bad unicode escape");
        out += String.fromCodePoint(parseInt(hex, 16));
        this.i += len;
      } else throw this.error(`bad escape \\${e}`);
    }
    throw this.error("unterminated string");
  }

  private literalString(): string {
    const end = this.s.indexOf("'", this.i + 1);
    const nl = this.s.indexOf("\n", this.i + 1);
    if (end < 0 || (nl >= 0 && nl < end)) throw this.error("unterminated string");
    const out = this.s.slice(this.i + 1, end);
    this.i = end + 1;
    return out;
  }

  private multiline(q: string): string {
    const end = this.s.indexOf(q, this.i + 3);
    if (end < 0) throw this.error("unterminated multi-line string");
    let body = this.s.slice(this.i + 3, end);
    this.i = end + 3;
    while (this.s.startsWith(q[0], this.i)) {
      body += q[0];
      this.i++;
    }
    return body.replace(/^\r?\n/, "");
  }

  private skipSpaces(): void {
    while (this.s[this.i] === " " || this.s[this.i] === "\t") this.i++;
  }

  private skipBlank(): void {
    for (;;) {
      this.skipSpaces();
      const c = this.s[this.i];
      if (c === "\n" || c === "\r") this.i++;
      else if (c === "#") while (this.i < this.s.length && this.s[this.i] !== "\n") this.i++;
      else return;
    }
  }

  private endOfLine(): void {
    this.skipSpaces();
    if (this.s[this.i] === "#") while (this.i < this.s.length && this.s[this.i] !== "\n") this.i++;
    if (this.i < this.s.length && this.s[this.i] !== "\n" && this.s[this.i] !== "\r") throw this.error("expected the end of the line");
  }

  private expect(c: string): void {
    this.skipSpaces();
    if (this.s[this.i] !== c) throw this.error(`expected ${c}`);
    this.i++;
  }

  private error(msg: string): TomlError {
    const line = this.s.slice(0, this.i).split("\n").length;
    return new TomlError(`line ${line}: ${msg}`);
  }
}

function tableAt(root: Table, path: string[]): Table {
  let t = root;
  for (const k of path) {
    const v = t[k];
    if (Array.isArray(v)) t = v[v.length - 1] as Table;
    else if (v !== null && typeof v === "object") t = v as Table;
    else {
      const n: Table = {};
      t[k] = n;
      t = n;
    }
  }
  return t;
}

function setPath(t: Table, path: string[], value: unknown): void {
  const parent = tableAt(t, path.slice(0, -1));
  parent[path[path.length - 1]] = value;
}

/** `get(doc, "projects", "/home/dev/project", "trust_level")`, or undefined. */
export function get(doc: unknown, ...path: string[]): unknown {
  let v: unknown = doc;
  for (const k of path) {
    if (v === null || typeof v !== "object" || Array.isArray(v)) return undefined;
    v = (v as Table)[k];
  }
  return v;
}
