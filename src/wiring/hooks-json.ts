/**
 * Put ah's PreToolUse entry into a settings value (Claude Code settings.json,
 * Codex hooks.json; both use event -> matcher group -> handlers) or take it out.
 *
 * Only entries that run the guard (owned.ts) are touched. A matcher group that
 * held nothing but ah entries is ah's and is replaced by the canonical group;
 * an ah entry someone added to their own group is lifted out and that group is
 * otherwise left alone. Everything else keeps its value and its position.
 */
import { isOwnedEntry } from "./owned.ts";

export type HookAction = "added" | "updated" | "unchanged" | "removed" | "absent";

export interface HookPlan {
  value: Record<string, unknown>;
  action: HookAction;
  /** The ah entries found before the change, as they were. */
  found: Record<string, unknown>[];
  notes: string[];
}

export class HookShapeError extends Error {}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** The ah entries in `settings`, wherever they sit under `hooks[event]`. */
export function ownedEntries(settings: unknown, event = "PreToolUse"): { group: Obj; entry: Obj; groupIndex: number }[] {
  if (!isObj(settings) || !isObj(settings.hooks)) return [];
  const groups = settings.hooks[event];
  if (!Array.isArray(groups)) return [];
  const out: { group: Obj; entry: Obj; groupIndex: number }[] = [];
  groups.forEach((g, groupIndex) => {
    if (!isObj(g) || !Array.isArray(g.hooks)) return;
    for (const e of g.hooks) if (isOwnedEntry(e)) out.push({ group: g, entry: e as Obj, groupIndex });
  });
  return out;
}

/**
 * Plan the change. `build` receives the ah entries found (so it can carry a
 * person's options over) and returns the canonical group, or null to remove.
 */
export function planHooks(settings: unknown, file: string, build: (found: Obj[]) => Obj | null, event = "PreToolUse"): HookPlan {
  if (!isObj(settings)) throw new HookShapeError(`${file} is not a JSON object; ah will not rewrite it`);
  if (settings.hooks !== undefined && !isObj(settings.hooks)) throw new HookShapeError(`${file}: "hooks" is not an object; ah will not rewrite it`);
  const hooks = (settings.hooks ?? {}) as Obj;
  if (hooks[event] !== undefined && !Array.isArray(hooks[event])) throw new HookShapeError(`${file}: "hooks.${event}" is not an array; ah will not rewrite it`);
  const groups = (hooks[event] ?? []) as unknown[];

  const found: Obj[] = [];
  const notes: string[] = [];
  const kept: unknown[] = [];
  let insertAt = -1;
  for (const g of groups) {
    if (!isObj(g) || !Array.isArray(g.hooks)) {
      kept.push(g);
      continue;
    }
    const mine = g.hooks.filter(isOwnedEntry) as Obj[];
    if (mine.length === 0) {
      kept.push(g);
      continue;
    }
    found.push(...mine);
    if (insertAt < 0) insertAt = kept.length;
    if (mine.length === g.hooks.length) continue; // ah's own group: dropped, replaced below
    kept.push({ ...g, hooks: g.hooks.filter((e) => !isOwnedEntry(e)) });
    notes.push(`moved the ah entry out of a matcher group that also holds other hooks (matcher ${JSON.stringify(g.matcher ?? "")})`);
  }
  if (found.length > 1) notes.push(`found ${found.length} ah entries for ${event}; kept one`);

  const want = build(found);
  if (want) kept.splice(insertAt < 0 ? kept.length : insertAt, 0, want);

  const nextHooks: Obj = { ...hooks };
  if (kept.length > 0) nextHooks[event] = kept;
  else delete nextHooks[event];
  const next: Obj = { ...settings };
  if (Object.keys(nextHooks).length > 0) next.hooks = nextHooks;
  else if (found.length > 0) delete next.hooks; // removing ah emptied it

  const same = JSON.stringify(next) === JSON.stringify(settings);
  let action: HookAction;
  if (want) action = same ? "unchanged" : found.length > 0 ? "updated" : "added";
  else action = found.length > 0 ? "removed" : "absent";
  return { value: same ? settings : next, action, found, notes };
}
