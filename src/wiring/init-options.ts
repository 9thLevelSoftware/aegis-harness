/**
 * The `ah init` options that take a value. Shared by `ah init`'s parser and by
 * the guard's shell.hook-tamper rule, which must read an agent's `ah init`
 * command the way `ah init` will, so a value is never taken for a flag.
 */
export const AH_INIT_VALUED_OPTIONS: ReadonlySet<string> = new Set(["--agents", "--scope", "--root", "--ask-fallback", "--guard", "--node"]);
