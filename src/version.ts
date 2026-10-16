declare const __AH_VERSION__: string | undefined;

/** Set by the build; "0.0.0-dev" when running from source. */
export const VERSION: string = typeof __AH_VERSION__ === "string" ? __AH_VERSION__ : "0.0.0-dev";
