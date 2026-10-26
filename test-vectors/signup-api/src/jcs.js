// ELU-634 build 3b. JSON Canonicalization Scheme (RFC 8785) and duplicate-member
// detection, ported from zipviz-cli (src/a2a/jcs.ts, src/ans/json.ts).
//
// Every ANS signature is over JCS bytes, so this is part of the trust boundary:
// a document is only accepted when its own text is exactly its canonical form,
// which is what stops a second spelling of a signed object from verifying.

const MAX_DEPTH = 128;

export function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

function assertWellFormedString(value) {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('lone surrogate');
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError('lone surrogate');
    }
  }
}

function encodeString(value) {
  assertWellFormedString(value);
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError('value is not JSON');
  return encoded;
}

function serialise(value, depth, stack) {
  if (depth > MAX_DEPTH) throw new RangeError('JSON nesting exceeds 128 levels');
  if (value === null) return 'null';
  if (typeof value === 'string') return encodeString(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('number is not finite');
    const encoded = JSON.stringify(Object.is(value, -0) ? 0 : value);
    if (encoded === undefined) throw new TypeError('number is not JSON');
    return encoded;
  }
  if (typeof value !== 'object') throw new TypeError('value is not JSON');
  if (stack.has(value)) throw new TypeError('cyclic values are not JSON');
  if (Object.getOwnPropertySymbols(value).length > 0) throw new TypeError('symbol keys');

  stack.add(value);
  try {
    if (Array.isArray(value)) {
      const ownKeys = Object.keys(value);
      if (ownKeys.length !== value.length
          || ownKeys.some((key, index) => key !== String(index))) {
        throw new TypeError('array properties are not JSON');
      }
      return `[${value.map((item) => serialise(item, depth + 1, stack)).join(',')}]`;
    }
    if (!isPlainObject(value)) throw new TypeError('value is not a plain object');
    const members = Object.keys(value).sort().map(
      (key) => `${encodeString(key)}:${serialise(value[key], depth + 1, stack)}`
    );
    return `{${members.join(',')}}`;
  } finally {
    stack.delete(value);
  }
}

export function canonicalizeJson(value) {
  return serialise(value, 0, new Set());
}

function stringEnd(text, start) {
  let index = start + 1;
  while (index < text.length) {
    const character = text[index];
    if (character === '\\') index += 2;
    else if (character === '"') return index + 1;
    else index++;
  }
  return text.length;
}

// JSON.parse keeps the last of two members with the same name, so a document
// with a duplicate member has two readings. Refuse it before parsing.
export function hasDuplicateMembers(text) {
  const stack = [];
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (character === '"') {
      const end = stringEnd(text, index);
      const frame = stack[stack.length - 1];
      if (frame?.kind === 'object' && frame.expectKey) {
        let key;
        try {
          key = JSON.parse(text.slice(index, end));
        } catch {
          return false;
        }
        if (typeof key !== 'string') return false;
        if (frame.keys.has(key)) return true;
        frame.keys.add(key);
        frame.expectKey = false;
      }
      index = end - 1;
    } else if (character === '{') {
      stack.push({ kind: 'object', expectKey: true, keys: new Set() });
    } else if (character === '[') {
      stack.push({ kind: 'array', expectKey: false, keys: new Set() });
    } else if (character === '}' || character === ']') {
      stack.pop();
    } else if (character === ',') {
      const frame = stack[stack.length - 1];
      if (frame?.kind === 'object') frame.expectKey = true;
    }
  }
  return false;
}

// A JSON document is only accepted when its text is already its canonical
// form: same bytes in, same bytes a signer would have produced.
export function parseCanonicalJson(text) {
  if (typeof text !== 'string' || hasDuplicateMembers(text)) return null;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  try {
    if (canonicalizeJson(parsed) !== text) return null;
  } catch {
    return null;
  }
  return parsed;
}
