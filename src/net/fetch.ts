import dns from "node:dns";
import https from "node:https";
import net from "node:net";
import type { IncomingMessage } from "node:http";
import type { LookupFunction } from "node:net";
import { VERSION } from "../version.js";

export const FETCH_TIMEOUT_MS = 5000;
export const FETCH_MAX_BYTES = 256 * 1024;

export const FETCH_REASONS = [
  "FETCH_URL_INVALID",
  "FETCH_NOT_HTTPS",
  "FETCH_HOST_NOT_ALLOWED",
  "FETCH_DNS_FAILED",
  "FETCH_ADDRESS_REFUSED",
  "FETCH_TOO_MANY_REDIRECTS",
  "FETCH_TIMEOUT",
  "FETCH_TOO_LARGE",
  "FETCH_HTTP_STATUS",
  "FETCH_CONTENT_TYPE",
  "FETCH_CONTENT_ENCODING",
  "FETCH_NOT_UTF8",
  "FETCH_TLS",
  "FETCH_FAILED",
] as const;

export type FetchCode = (typeof FETCH_REASONS)[number];

const FETCH_MESSAGES: Record<FetchCode, string> = {
  FETCH_URL_INVALID: "URL is invalid or contains forbidden user information or fragment",
  FETCH_NOT_HTTPS: "only HTTPS URLs are allowed",
  FETCH_HOST_NOT_ALLOWED: "host is not allowed",
  FETCH_DNS_FAILED: "DNS resolution failed",
  FETCH_ADDRESS_REFUSED: "host resolved to a refused address",
  FETCH_TOO_MANY_REDIRECTS: "more than three redirects",
  FETCH_TIMEOUT: "request exceeded the total timeout",
  FETCH_TOO_LARGE: "response exceeded the configured size limit",
  FETCH_HTTP_STATUS: "server returned an unsuccessful HTTP status",
  FETCH_CONTENT_TYPE: "response Content-Type is not an accepted JSON media type",
  FETCH_CONTENT_ENCODING: "compressed or unsupported response encoding is not accepted",
  FETCH_NOT_UTF8: "response body is not valid UTF-8",
  FETCH_TLS: "TLS certificate validation failed",
  FETCH_FAILED: "HTTPS request failed",
};

export class FetchError extends Error {
  constructor(
    readonly code: FetchCode,
    message: string = FETCH_MESSAGES[code],
    readonly url?: string,
  ) {
    super(message);
    this.name = "FetchError";
  }
}

export type NetDeps = {
  resolve?: (hostname: string) => Promise<string[]>;
  isAllowedAddress?: (ip: string) => boolean;
  ca?: string | Buffer;
  httpsPort?: number;
  timeoutMs?: number;
  maxBytes?: number;
};

type FetchOptions = { allowedHosts?: (host: string) => boolean; accept: string };
type FetchResult = { finalUrl: string; text: string; contentType: string; redirects: string[] };
type ParsedUrl = { url: URL; hostname: string; host: string; port: number };
type HopResult = { redirect?: string; text?: string; contentType?: string };

const isInRange = (value: number, low: number, high: number): boolean => value >= low && value <= high;

function displayUrl(url: URL): string {
  return `${url.origin}${url.pathname}`;
}

function ipv4Octets(address: string): number[] | undefined {
  if (net.isIP(address) !== 4) return undefined;
  const octets = address.split(".").map(Number);
  return octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? octets
    : undefined;
}

function ipv6Words(address: string): number[] | undefined {
  if (net.isIP(address) !== 6 || address.includes("%")) return undefined;
  let source = address.toLowerCase();
  if (source.includes(".")) {
    const split = source.lastIndexOf(":");
    if (split < 0) return undefined;
    const octets = ipv4Octets(source.slice(split + 1));
    if (!octets) return undefined;
    const high = ((octets[0]! << 8) | octets[1]!).toString(16);
    const low = ((octets[2]! << 8) | octets[3]!).toString(16);
    source = `${source.slice(0, split)}:${high}:${low}`;
  }
  const halves = source.split("::");
  if (halves.length > 2) return undefined;
  const left = halves[0] ? halves[0]!.split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1]!.split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return undefined;
  const words = [
    ...left,
    ...Array.from({ length: halves.length === 2 ? missing : 0 }, () => "0"),
    ...right,
  ];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return undefined;
  return words.map((word) => Number.parseInt(word, 16));
}

export function isPublicAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) {
    const octets = ipv4Octets(ip);
    if (!octets) return false;
    const [a, b, c] = octets as [number, number, number, number];
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && isInRange(b, 64, 127)) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && isInRange(b, 16, 31)) return false;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
    if (a === 192 && b === 88 && c === 99) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && isInRange(b, 18, 19)) return false;
    if (a === 198 && b === 51 && c === 100) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  if (family !== 6) return false;
  const words = ipv6Words(ip);
  if (!words) return false;
  const [a, b, c, d, e, f] = words as [number, number, number, number, number, number, number, number];
  if (words.every((word) => word === 0)) return false;
  if (words.slice(0, 6).every((word) => word === 0)) return false;
  if (words.slice(0, 5).every((word) => word === 0) && f === 0xffff) return false;
  if (a === 0 && b === 0 && c === 0 && d === 0 && e === 0xffff && f === 0) return false;
  if (a === 0x0064 && b === 0xff9b && c === 0 && d === 0 && e === 0 && f === 0) return false;
  if (a === 0x0064 && b === 0xff9b && c === 1) return false;
  if ((a & 0xff00) === 0) return false;
  if (a === 0x0100 && b === 0 && c === 0 && d === 0) return false;
  if (a === 0x2001 && b === 0x0db8) return false;
  if (a === 0x2001 && b <= 0x01ff) return false;
  if (a === 0x2002) return false;
  if (a === 0x3ffe) return false;
  if ((a & 0xfe00) === 0xfc00) return false;
  if ((a & 0xffc0) === 0xfe80) return false;
  if ((a & 0xffc0) === 0xfec0) return false;
  if ((a & 0xff00) === 0xff00) return false;
  return true;
}

function parseUrl(value: string, deps: NetDeps, isRedirect = false): ParsedUrl {
  if (value !== value.trim()) throw new FetchError("FETCH_URL_INVALID", undefined, value);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new FetchError("FETCH_URL_INVALID", undefined, value);
  }
  if (url.protocol !== "https:") {
    const prefix = isRedirect ? "redirect to" : "URL";
    throw new FetchError("FETCH_NOT_HTTPS", `${prefix} ${displayUrl(url)} is not HTTPS`, value);
  }
  const authority = value.match(/^https:\/\/([^/?#]*)/i)?.[1] ?? "";
  if (authority.includes("@") || url.username !== "" || url.password !== "" ||
    value.includes("#") || url.hash !== "" || url.hostname === "") {
    throw new FetchError("FETCH_URL_INVALID", undefined, value);
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const port = url.port === "" ? (deps.httpsPort ?? 443) : Number(url.port);
  return { url, hostname, host: url.host.toLowerCase(), port };
}

function publicAddressCheck(address: string, policy: (ip: string) => boolean, url: string): void {
  if (!policy(address)) {
    const host = new URL(url).host;
    throw new FetchError("FETCH_ADDRESS_REFUSED", `host ${host} resolved to a refused address (${address})`, url);
  }
}

async function resolvePinned(parsed: ParsedUrl, deps: NetDeps, url: string): Promise<string> {
  if (net.isIP(parsed.hostname) !== 0) {
    publicAddressCheck(parsed.hostname, deps.isAllowedAddress ?? isPublicAddress, url);
    return parsed.hostname;
  }
  let addresses: string[];
  try {
    if (deps.resolve) {
      addresses = await deps.resolve(parsed.hostname);
    } else {
      const answers = await dns.promises.lookup(parsed.hostname, { all: true, verbatim: true });
      addresses = answers.map((answer) => answer.address);
    }
  } catch {
    throw new FetchError("FETCH_DNS_FAILED", undefined, url);
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new FetchError("FETCH_ADDRESS_REFUSED", `host ${parsed.host} resolved to no addresses`, url);
  }
  const policy = deps.isAllowedAddress ?? isPublicAddress;
  for (const address of addresses) publicAddressCheck(address, policy, url);
  return addresses[0]!;
}

function tlsFailure(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("code" in error)) return false;
  const code = String((error as { code: unknown }).code);
  return code.startsWith("ERR_TLS_") || code === "CERT_HAS_EXPIRED" ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" || code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
}

function errorForSocket(error: unknown, url: string, timedOut: boolean): FetchError {
  if (timedOut) return new FetchError("FETCH_TIMEOUT", undefined, url);
  if (tlsFailure(error)) return new FetchError("FETCH_TLS", undefined, url);
  return new FetchError("FETCH_FAILED", undefined, url);
}

function contentType(value: string | string[] | undefined, url: string): string {
  if (typeof value !== "string") throw new FetchError("FETCH_CONTENT_TYPE", undefined, url);
  const parts = value.split(";");
  const mediaType = parts.shift()?.trim().toLowerCase() ?? "";
  if (!/^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/.test(mediaType)) {
    throw new FetchError("FETCH_CONTENT_TYPE", undefined, url);
  }
  for (const parameter of parts) {
    const charset = parameter.match(/^\s*charset\s*=\s*(.*?)\s*$/i)?.[1];
    if (charset !== undefined && charset.replace(/^["']|["']$/g, "").toLowerCase() !== "utf-8") {
      throw new FetchError("FETCH_CONTENT_TYPE", undefined, url);
    }
  }
  return mediaType;
}

function requestHop(
  parsed: ParsedUrl,
  pinned: string,
  options: FetchOptions,
  deps: NetDeps,
  setAbort: (abort: (() => void) | undefined) => void,
  isTimedOut: () => boolean,
): Promise<HopResult> {
  return new Promise((resolve, reject) => {
    const agent = new https.Agent({ keepAlive: false, maxCachedSessions: 0 });
    const secureOptions: https.RequestOptions = {
      host: pinned,
      port: parsed.port,
      method: "GET",
      path: `${parsed.url.pathname}${parsed.url.search}`,
      servername: net.isIP(parsed.hostname) === 0 ? parsed.hostname : undefined,
      rejectUnauthorized: true,
      agent,
      headers: {
        host: parsed.port === 443 ? parsed.host : `${parsed.hostname.includes(":") ? `[${parsed.hostname}]` : parsed.hostname}:${parsed.port}`,
        accept: options.accept,
        "user-agent": `zipviz-cli/${VERSION}`,
        connection: "close",
      },
      lookup: ((hostname, lookupOptions, callback) => {
        const done = typeof lookupOptions === "function" ? lookupOptions : callback;
        done(null, pinned, net.isIP(pinned));
      }) as LookupFunction,
      ...(deps.ca === undefined ? {} : { ca: deps.ca }),
    };
    let request: ReturnType<typeof https.request> | undefined;
    let settled = false;
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      setAbort(undefined);
      agent.destroy();
      action();
    };
    const fail = (error: FetchError): void => {
      if (settled) return;
      settled = true;
      setAbort(undefined);
      request?.destroy();
      agent.destroy();
      reject(error);
    };
    setAbort(() => fail(new FetchError("FETCH_TIMEOUT", undefined, parsed.url.href)));
    try {
      request = https.request(secureOptions, (response: IncomingMessage) => {
        if (settled) {
          response.destroy();
          return;
        }
        const status = response.statusCode ?? 0;
        if ([301, 302, 303, 307, 308].includes(status)) {
          const location = response.headers.location;
          response.destroy();
          if (typeof location !== "string" || location.length === 0) {
            fail(new FetchError("FETCH_HTTP_STATUS", undefined, parsed.url.href));
          } else {
            finish(() => resolve({ redirect: location }));
          }
          return;
        }
        if (status !== 200) {
          response.destroy();
          fail(new FetchError("FETCH_HTTP_STATUS", undefined, parsed.url.href));
          return;
        }
        let mediaType: string;
        try {
          mediaType = contentType(response.headers["content-type"], parsed.url.href);
        } catch (error) {
          response.destroy();
          fail(error instanceof FetchError ? error : new FetchError("FETCH_CONTENT_TYPE", undefined, parsed.url.href));
          return;
        }
        const encoding = response.headers["content-encoding"];
        if (encoding !== undefined && String(encoding).trim().toLowerCase() !== "identity") {
          response.destroy();
          fail(new FetchError("FETCH_CONTENT_ENCODING", undefined, parsed.url.href));
          return;
        }
        const maxBytes = deps.maxBytes ?? FETCH_MAX_BYTES;
        const length = response.headers["content-length"];
        if (typeof length === "string" && Number(length) > maxBytes) {
          response.destroy();
          fail(new FetchError("FETCH_TOO_LARGE", undefined, parsed.url.href));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer | string) => {
          if (settled) return;
          const buffer = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
          size += buffer.byteLength;
          if (size > maxBytes) {
            fail(new FetchError("FETCH_TOO_LARGE", undefined, parsed.url.href));
            response.destroy();
            return;
          }
          chunks.push(buffer);
        });
        response.on("aborted", () => {
          if (!settled) fail(errorForSocket(new Error("response aborted"), parsed.url.href, isTimedOut()));
        });
        response.on("error", (error: Error) => {
          if (!settled) fail(errorForSocket(error, parsed.url.href, isTimedOut()));
        });
        response.on("end", () => {
          if (settled) return;
          const body = Buffer.concat(chunks);
          let text: string;
          try {
            text = new TextDecoder("utf-8", { fatal: true }).decode(body);
          } catch {
            fail(new FetchError("FETCH_NOT_UTF8", undefined, parsed.url.href));
            return;
          }
          finish(() => resolve({ text, contentType: mediaType }));
        });
      });
      request.on("error", (error: Error) => {
        if (!settled) fail(errorForSocket(error, parsed.url.href, isTimedOut()));
      });
      request.end();
    } catch {
      fail(new FetchError("FETCH_FAILED", undefined, parsed.url.href));
    }
  });
}

export async function fetchJson(
  inputUrl: string,
  options: FetchOptions,
  deps: NetDeps = {},
): Promise<FetchResult> {
  const timeoutMs = deps.timeoutMs ?? FETCH_TIMEOUT_MS;
  const maxRedirects = 3;
  let timedOut = false;
  let abortCurrent: (() => void) | undefined;
  let rejectTimeout: ((error: FetchError) => void) | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    rejectTimeout = reject;
  });
  const timer = setTimeout(() => {
    timedOut = true;
    abortCurrent?.();
    rejectTimeout?.(new FetchError("FETCH_TIMEOUT", undefined, inputUrl));
  }, timeoutMs);
  const execute = async (): Promise<FetchResult> => {
    let current = inputUrl;
    const redirects: string[] = [];
    try {
      while (true) {
        if (timedOut) throw new FetchError("FETCH_TIMEOUT", undefined, current);
        const parsed = parseUrl(current, deps, redirects.length > 0);
        const requestHost = parsed.host.toLowerCase();
        if (options.allowedHosts) {
          let allowed = false;
          try {
            allowed = options.allowedHosts(requestHost);
          } catch {
            allowed = false;
          }
          if (!allowed) {
            throw new FetchError("FETCH_HOST_NOT_ALLOWED", `host ${requestHost} is not allowed`, current);
          }
        }
        const pinned = await resolvePinned(parsed, deps, current);
        if (timedOut) throw new FetchError("FETCH_TIMEOUT", undefined, current);
        const hop = await requestHop(parsed, pinned, options, deps, (abort) => {
          abortCurrent = abort;
        }, () => timedOut);
        if (hop.redirect !== undefined) {
          let next: URL;
          try {
            next = new URL(hop.redirect, parsed.url);
          } catch {
            throw new FetchError("FETCH_URL_INVALID", undefined, hop.redirect);
          }
          if (redirects.length >= maxRedirects) {
            const origin = next.origin === "null" ? next.protocol : next.origin;
            throw new FetchError(
              "FETCH_TOO_MANY_REDIRECTS",
              `redirect limit exceeded at ${origin}`,
              current,
            );
          }
          current = next.href;
          redirects.push(current);
          continue;
        }
        if (hop.text === undefined || hop.contentType === undefined) {
          throw new FetchError("FETCH_FAILED", undefined, current);
        }
        return { finalUrl: parsed.url.href, text: hop.text, contentType: hop.contentType, redirects };
      }
    } catch (error) {
      if (timedOut) throw new FetchError("FETCH_TIMEOUT", undefined, current);
      if (error instanceof FetchError) throw error;
      throw new FetchError("FETCH_FAILED", undefined, current);
    }
  };
  try {
    return await Promise.race([execute(), timeout]);
  } finally {
    clearTimeout(timer);
    abortCurrent?.();
  }
}
