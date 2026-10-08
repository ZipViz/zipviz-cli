import { createReadStream } from "node:fs";
import { CliError, usageError } from "./errors.js";
import type { Context } from "./commands.js";
import { verifyBuzzEvent } from "./buzz/index.js";

export const MAX_INPUT_BYTES = 1024 * 1024;
export type CheckDeps = { readStdin?: () => Promise<Uint8Array> };

export async function readLimited(
  stream: AsyncIterable<Uint8Array | string>,
  maxBytes: number,
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  for await (const chunk of stream) {
    const bytes = typeof chunk === "string" ? encoder.encode(chunk) : chunk;
    totalBytes += bytes.byteLength;
    if (totalBytes > maxBytes) {
      const limit = maxBytes % (1024 * 1024) === 0
        ? `${maxBytes / (1024 * 1024)} MiB`
        : `${maxBytes} byte`;
      const message = `input exceeds the ${limit} limit`;
      throw new CliError("E_INPUT_TOO_LARGE", message, 6);
    }
    chunks.push(bytes);
  }

  const result = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function inputBytes(filename: string, deps: CheckDeps): Promise<Uint8Array> {
  if (filename !== "-") {
    try {
      return await readLimited(createReadStream(filename, { end: MAX_INPUT_BYTES }), MAX_INPUT_BYTES);
    } catch (error) {
      if (error instanceof CliError) throw error;
      throw new CliError("E_INPUT_UNREADABLE", "input file could not be read", 6);
    }
  }

  if (!deps.readStdin) throw new CliError("E_INPUT_UNREADABLE", "stdin could not be read", 6);
  let bytes: Uint8Array;
  try {
    bytes = await deps.readStdin();
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("E_INPUT_UNREADABLE", "stdin could not be read", 6);
  }
  // Injected stdin readers may bypass readLimited, so keep this size safety net.
  if (bytes.byteLength > MAX_INPUT_BYTES) throw new CliError("E_INPUT_TOO_LARGE", "input exceeds the 1 MiB limit", 6);
  return bytes;
}

/** Read a JSON object from a file or stdin under the same 1 MiB cap; shared with `zipviz link`. */
export async function readJsonObject(filename: string, deps: CheckDeps): Promise<Record<string, unknown>> {
  const bytes = await inputBytes(filename, deps);

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CliError("E_INPUT_NOT_UTF8", "input is not valid UTF-8", 6);
  }

  let parsedInput: unknown;
  try {
    parsedInput = JSON.parse(text) as unknown;
  } catch {
    throw new CliError("E_INPUT_NOT_JSON", "input is not valid JSON", 6);
  }
  if (typeof parsedInput !== "object" || parsedInput === null || Array.isArray(parsedInput)) {
    throw new CliError("E_INPUT_NOT_OBJECT", "input must be a JSON object", 6);
  }
  return parsedInput as Record<string, unknown>;
}

export async function check({ parsed }: Context, deps: CheckDeps) {
  if (parsed.positional.length !== 1) throw usageError("usage: zipviz check <file|->");
  const [filename] = parsed.positional;
  const verification = verifyBuzzEvent(await readJsonObject(filename!, deps));
  const lines: string[] = [];
  if (verification.event.valid) {
    lines.push(`signed by agent ${verification.event.agent_npub}`);
    lines.push(`event id ${verification.event.id} (kind ${verification.event.kind}, created_at ${verification.event.created_at})`);
  } else {
    lines.push(`event invalid: ${verification.event.reason} (${verification.event.message})`);
  }

  if (!verification.event.valid) {
    lines.push(verification.owner_auth.present
      ? "owner authorisation: not checked (event invalid)"
      : "owner authorisation: none");
  } else if (verification.owner_auth.valid) {
    lines.push(`authorised by owner ${verification.owner_auth.owner_npub}`);
    lines.push(`conditions: ${verification.owner_auth.conditions || "(none)"}`);
  } else if (verification.owner_auth.present) {
    lines.push(`owner authorisation: invalid: ${verification.owner_auth.reason} (${verification.owner_auth.message})`);
  } else {
    lines.push("owner authorisation: none");
  }

  const exitCode = !verification.event.valid ? 4 : verification.owner_auth.present && !verification.owner_auth.valid ? 5 : 0;
  return {
    ok: verification.ok,
    data: { event: verification.event, owner_auth: verification.owner_auth },
    lines,
    exitCode,
  };
}
