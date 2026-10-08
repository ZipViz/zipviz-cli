import { CliError } from "./errors.js";
import { escapeTerminal } from "./terminal.js";

export type Writer = (s: string) => void;

/** `exitCode` (default 0) lets a command succeed with a non-zero exit, e.g. whoami with skipped keys. */
export type Result = {
  data: Record<string, unknown>;
  lines: string[];
  exitCode?: number;
  ok?: boolean;
  rawOutput?: string;
};

export class Output {
  constructor(private readonly json: boolean, private readonly stdout: Writer, private readonly stderr: Writer) {}

  success(command: string, result: Result): number {
    if (this.json) this.stdout(`${JSON.stringify({ ok: result.ok ?? true, command, ...result.data })}\n`);
    else if (result.rawOutput !== undefined) this.stdout(result.rawOutput);
    else for (const line of result.lines) this.stdout(`${line}\n`);
    return result.exitCode ?? 0;
  }

  failure(command: string, error: CliError, usage?: string): number {
    if (this.json) {
      const err: Record<string, unknown> = { code: error.code, message: error.message };
      if (error.httpStatus !== undefined) err.http_status = error.httpStatus;
      this.stdout(`${JSON.stringify({ ok: false, command, error: err })}\n`);
    } else {
      const prefix = error.exitCode === 9 && error.code.startsWith("FETCH_")
        ? `error: ${error.code}: `
        : "";
      this.stderr(`zipviz: ${prefix}${escapeTerminal(error.message)}\n`);
      if (usage && error.exitCode === 2) this.stderr(`\n${usage}\n`);
    }
    return error.exitCode;
  }
}
