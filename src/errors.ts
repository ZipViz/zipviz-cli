export class CliError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly exitCode = 1,
    readonly httpStatus?: number,
  ) {
    super(message);
  }
}

export const usageError = (message: string) => new CliError("E_USAGE", message, 2);

export const INVITES_DISABLED = "invites are not enabled on this registry";
