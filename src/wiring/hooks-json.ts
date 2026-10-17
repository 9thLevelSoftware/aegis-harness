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
export interface PlanOptions {
  event?: string;
  /**
   * "first-owned" (default): the canonical group takes the place of the first
   * group that held an ah entry. "keep-indexes": it takes the place of ah's own
   * group, or goes at the end, so no other group moves forward or back. Codex
   * keys its hook trust by group index, so inserting before a user's group
   * would make Codex distrust it.
   */
  placement?: "first-owned" | "keep-indexes";
}

function isOwnedOnly(g: unknown): boolean {
  return isObj(g) && Array.isArray(g.hooks) && g.hooks.length > 0 && g.hooks.every(isOwnedEntry);
}

export function planHooks(settings: unknown, file: string, build: (found: Obj[]) => Obj | null, opts: PlanOptions = {}): HookPlan {
  const event = opts.event ?? "PreToolUse";
  const keepIndexes = opts.placement === "keep-indexes";
  if (!isObj(settings)) throw new HookShapeError(`${file} is not a JSON object; ah will not rewrite it`);
  if (settings.hooks !== undefined && !isObj(settings.hooks)) throw new HookShapeError(`${file}: "hooks" is not an object; ah will not rewrite it`);
  const hooks = (settings.hooks ?? {}) as Obj;
  if (hooks[event] !== undefined && !Array.isArray(hooks[event])) throw new HookShapeError(`${file}: "hooks.${event}" is not an array; ah will not rewrite it`);
  const groups = (hooks[event] ?? []) as unknown[];

  const found: Obj[] = [];
  const notes: string[] = [];
  /** Each group after ah's entries are taken out; null marks a group that held only ah entries. */
  const rest: (unknown | null)[] = [];
  let firstAny = -1;
  let firstOwn = -1;
  let splitMixed = false;
  for (const g of groups) {
    const mine = isObj(g) && Array.isArray(g.hooks) ? (g.hooks.filter(isOwnedEntry) as Obj[]) : [];
    if (mine.length === 0) {
      rest.push(g);
      continue;
    }
    found.push(...mine);
    const hooksOf = (g as Obj).hooks as unknown[];
    if (firstAny < 0) firstAny = rest.length;
    if (mine.length === hooksOf.length) {
      if (firstOwn < 0) firstOwn = rest.length;
      rest.push(null);
      continue;
    }
    const others = hooksOf.filter((e) => !isOwnedEntry(e));
    if (hooksOf.findIndex(isOwnedEntry) < hooksOf.length - mine.length) splitMixed = true;
    rest.push({ ...(g as Obj), hooks: others });
    notes.push(`moved the ah entry out of a matcher group that also holds other hooks (matcher ${JSON.stringify((g as Obj).matcher ?? "")})`);
  }
  if (found.length > 1) notes.push(`found ${found.length} ah entries for ${event}; kept one`);

  const want = build(found);
  // Where the canonical group goes, as an index into `rest`.
  let at: number;
  if (keepIndexes) at = firstOwn >= 0 ? firstOwn : rest.length;
  else at = firstAny >= 0 ? firstAny : rest.length;
  const kept: unknown[] = [];
  rest.forEach((g, i) => {
    if (i === at && want) kept.push(want);
    if (g !== null) kept.push(g);
  });
  if (at >= rest.length && want) kept.push(want);

  if (keepIndexes) {
    // Codex files trust under "<file>:<event>:<group index>:<handler index>", so a user's
    // hook that changes index is untrusted until the user reviews it again.
    const moved = groups.some((g, i) => g !== undefined && !isOwnedOnly(g) && kept.indexOf(rest[i] as unknown) !== -1 && kept.indexOf(rest[i] as unknown) !== i);
    if (moved || splitMixed) notes.push("some of your other hooks changed position, so Codex will ask you to trust them again in /hooks");
  }
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
