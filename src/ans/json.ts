export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function stringEnd(text: string, start: number): number {
  let index = start + 1;
  while (index < text.length) {
    const character = text[index];
    if (character === "\\") index += 2;
    else if (character === "\"") return index + 1;
    else index++;
  }
  return text.length;
}

/** Reject duplicate object members before JSON.parse keeps only the last one. */
export function hasDuplicateMembers(text: string): boolean {
  const stack: Array<{ kind: "object" | "array"; expectKey: boolean; keys: Set<string> }> = [];
  for (let index = 0; index < text.length; index++) {
    const character = text[index]!;
    if (character === "\"") {
      const end = stringEnd(text, index);
      const frame = stack[stack.length - 1];
      if (frame?.kind === "object" && frame.expectKey) {
        let key: string;
        try {
          const parsed = JSON.parse(text.slice(index, end)) as unknown;
          if (typeof parsed !== "string") return false;
          key = parsed;
        } catch {
          return false;
        }
        if (frame.keys.has(key)) return true;
        frame.keys.add(key);
        frame.expectKey = false;
      }
      index = end - 1;
    } else if (character === "{") {
      stack.push({ kind: "object", expectKey: true, keys: new Set<string>() });
    } else if (character === "[") {
      stack.push({ kind: "array", expectKey: false, keys: new Set<string>() });
    } else if (character === "}") {
      stack.pop();
    } else if (character === "]") {
      stack.pop();
    } else if (character === ",") {
      const frame = stack[stack.length - 1];
      if (frame?.kind === "object") frame.expectKey = true;
    }
  }
  return false;
}
