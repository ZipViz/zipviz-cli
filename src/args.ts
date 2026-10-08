import { usageError } from "./errors.js";

export type Parsed = {
  positional: string[];
  flags: Map<string, string | true | string[]>;
};

export type FlagSpec = { bool?: readonly string[]; value?: readonly string[]; repeat?: readonly string[] };

export const GLOBAL_FLAGS: Required<Pick<FlagSpec, "bool" | "value">> = { bool: ["json", "help"], value: ["api"] };

/** Strict parser: unknown flags and missing values are usage errors. */
export function parseArgs(argv: readonly string[], spec: FlagSpec): Parsed {
  const bool = new Set([...(spec.bool ?? []), ...GLOBAL_FLAGS.bool]);
  const repeat = new Set(spec.repeat ?? []);
  const value = new Set([...(spec.value ?? []), ...repeat, ...GLOBAL_FLAGS.value]);
  const flags = new Map<string, string | true | string[]>();
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "-h") {
      flags.set("help", true);
      continue;
    }
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf("=");
    const name = arg.slice(2, eq === -1 ? undefined : eq);
    if (bool.has(name) && eq === -1) {
      flags.set(name, true);
    } else if (value.has(name)) {
      const v = eq === -1 ? argv[++i] : arg.slice(eq + 1);
      if (v === undefined || v === "") throw usageError(`--${name} needs a value`);
      if (repeat.has(name)) {
        const previous = flags.get(name);
        const values = Array.isArray(previous) ? previous : typeof previous === "string" ? [previous] : [];
        flags.set(name, [...values, v]);
      } else {
        flags.set(name, v);
      }
    } else {
      throw usageError(`unknown option: --${name}`);
    }
  }
  return { positional, flags };
}

export function flagValue(p: Parsed, name: string): string | undefined {
  const v = p.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

export function flagValues(p: Parsed, name: string): string[] {
  const value = p.flags.get(name);
  if (Array.isArray(value)) return value;
  return typeof value === "string" ? [value] : [];
}
