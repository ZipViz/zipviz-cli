import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  FETCH_MAX_BYTES,
  FETCH_TIMEOUT_MS,
  fetchJson,
  isPublicAddress,
  type NetDeps,
} from "../src/net/fetch.js";

let tempDir: string;
let certificate: string;
let server: https.Server;
let port: number;
const requests: Array<{ url: string; headers: http.IncomingHttpHeaders }> = [];
let streamingClosed: Promise<number> = Promise.resolve(0);

function startServer(): Promise<void> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
    port = (server.address() as net.AddressInfo).port;
    resolve();
  }));
}

function deps(overrides: Partial<NetDeps> = {}): NetDeps {
  return {
    resolve: async () => ["127.0.0.1"],
    isAllowedAddress: (ip) => ip === "127.0.0.1" || isPublicAddress(ip),
    ca: certificate,
    httpsPort: port,
    timeoutMs: 1000,
    ...overrides,
  };
}

function get(url: string, extra: Partial<NetDeps> = {}, allowedHosts?: (host: string) => boolean) {
  return fetchJson(url, { accept: "application/json", ...(allowedHosts ? { allowedHosts } : {}) }, deps(extra));
}

beforeAll(async () => {
  tempDir = mkdtempSync(path.join(tmpdir(), "zipviz-net-test-"));
  const key = path.join(tempDir, "key.pem");
  const cert = path.join(tempDir, "cert.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
    "-subj", "/CN=card.test", "-addext", "subjectAltName=DNS:card.test,DNS:other.test,DNS:jwks.test",
    "-keyout", key, "-out", cert,
  ], { stdio: "ignore" });
  certificate = readFileSync(cert, "utf8");
  server = https.createServer({ key: readFileSync(key), cert: certificate }, (req, res) => {
    requests.push({ url: req.url ?? "/", headers: req.headers });
    const url = req.url ?? "/";
    if (url === "/redirect-private") {
      res.writeHead(302, { location: "https://private.test/private" }).end();
    } else if (url === "/redirect-private-literal") {
      res.writeHead(302, { location: "https://127.0.0.2/private" }).end();
    } else if (url === "/redirect-http") {
      res.writeHead(302, { location: "http://card.test/plain" }).end();
    } else if (url === "/redirect-outside") {
      res.writeHead(302, { location: "https://other.test/final" }).end();
    } else if (url.startsWith("/chain/")) {
      const level = Number(url.split("/").at(-1));
      if (level < 4) res.writeHead(302, { location: `/chain/${level + 1}` }).end();
      else res.writeHead(200, { "content-type": "application/a2a+json" }).end('{"ok":true}');
    } else if (url === "/cookie-start") {
      res.writeHead(302, { location: "/cookie-final", "set-cookie": "private=secret" }).end();
    } else if (url === "/cookie-final") {
      res.writeHead(200, { "content-type": "application/a2a+json" }).end(JSON.stringify({ cookie: req.headers.cookie ?? null }));
    } else if (url === "/json-only") {
      res.writeHead(200, { "content-type": "application/json" }).end("{}");
    } else if (url === "/jwks-type") {
      res.writeHead(200, { "content-type": "application/jwk-set+json" }).end('{"keys":[]}');
    } else if (url === "/status") {
      res.writeHead(404, { "content-type": "application/json" }).end("{}");
    } else if (url === "/missing-type") {
      res.writeHead(200).end("{}");
    } else if (url === "/html") {
      res.writeHead(200, { "content-type": "text/html" }).end("<html/>");
    } else if (url === "/latin") {
      res.writeHead(200, { "content-type": "application/a2a+json; charset=iso-8859-1" }).end("{}");
    } else if (url === "/gzip") {
      res.writeHead(200, { "content-type": "application/a2a+json", "content-encoding": "gzip" }).end("{}");
    } else if (url === "/invalid-utf8") {
      res.writeHead(200, { "content-type": "application/a2a+json" }).end(Buffer.from([0xff]));
    } else if (url === "/large-length") {
      res.writeHead(200, { "content-type": "application/a2a+json", "content-length": "100" }).end("x".repeat(100));
    } else if (url === "/large-streaming") {
      let bytesWritten = 0;
      streamingClosed = new Promise((resolve) => {
        res.once("close", () => {
          resolve(bytesWritten);
        });
      });
      res.writeHead(200, { "content-type": "application/a2a+json", "transfer-encoding": "chunked" });
      const chunk = Buffer.alloc(1024, 0x78);
      const writeChunk = () => {
        if (res.destroyed || res.writableEnded) return;
        if (bytesWritten >= 1024 * 1024) {
          res.end();
          return;
        }
        bytesWritten += chunk.byteLength;
        if (!res.write(chunk)) res.once("drain", () => setImmediate(writeChunk));
        else setImmediate(writeChunk);
      };
      setImmediate(writeChunk);
    } else if (url === "/default-limit-exact" || url === "/default-limit-over") {
      const size = FETCH_MAX_BYTES + (url === "/default-limit-over" ? 1 : 0);
      res.writeHead(200, { "content-type": "application/a2a+json", "transfer-encoding": "chunked" });
      res.end(Buffer.alloc(size, 0x78));
    } else if (url === "/stall") {
      res.writeHead(200, { "content-type": "application/a2a+json" });
    } else if (url === "/slow-drip") {
      res.writeHead(200, { "content-type": "application/a2a+json", "transfer-encoding": "chunked" });
      let n = 0;
      const interval = setInterval(() => {
        if (res.destroyed || res.writableEnded || n++ > 20) clearInterval(interval);
        else res.write("x");
      }, 100);
      res.on("close", () => clearInterval(interval));
    } else if (url === "/reset") {
      req.socket.destroy();
    } else {
      res.writeHead(200, { "content-type": "application/a2a+json; charset=utf-8" }).end('{"ok":true}');
    }
  });
  await startServer();
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(tempDir, { recursive: true, force: true });
});

describe("fetch resource defaults", () => {
  it("exports the documented timeout and body-size limits", () => {
    expect(FETCH_TIMEOUT_MS).toBe(5000);
    expect(FETCH_MAX_BYTES).toBe(262144);
  });
});

describe("isPublicAddress", () => {
  it.each([
    "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1",
    "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.51.100.1",
    "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:8.8.8.8",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:10.0.0.5", "::ffff:a00:5", "::ffff:0:a00:5",
    "::ffff:0:8.8.8.8", "::ffff:0:808:808", "::127.0.0.1", "64:ff9b::1", "64:ff9b:1::1",
    "::2:1", "1::1", "ff:ffff::1", "0:1::1", "100::1", "2001:db8::1",
    "2001::1", "2002::1", "3ffe::1", "3ffe:ffff::1", "fc00::1", "fe80::1", "fec0::1", "ff00::1",
    "fe80::1%eth0", "not-an-ip",
  ])("refuses non-public address %s", (ip) => {
    expect(isPublicAddress(ip)).toBe(false);
  });

  it.each(["8.8.8.8", "1.1.1.1", "2606:4700::1111"])("allows public address %s", (ip) => {
    expect(isPublicAddress(ip)).toBe(true);
  });
});

describe("fetchJson URL, DNS and address policy", () => {
  it("refuses malformed, HTTP, userinfo, disallowed-host, DNS-failed, and private-address URLs", async () => {
    await expect(fetchJson("https://[", { accept: "application/json" }, deps())).rejects.toMatchObject({ code: "FETCH_URL_INVALID" });
    await expect(get("http://card.test/plain")).rejects.toMatchObject({
      code: "FETCH_NOT_HTTPS",
      message: "URL http://card.test/plain is not HTTPS",
    });
    await expect(get("https://user:pass@card.test/")).rejects.toMatchObject({ code: "FETCH_URL_INVALID" });
    await expect(get("https://@card.test/")).rejects.toMatchObject({ code: "FETCH_URL_INVALID" });
    await expect(get("https://card.test/#")).rejects.toMatchObject({ code: "FETCH_URL_INVALID" });
    await expect(get("https://other.test/", {}, (host) => host === "card.test")).rejects.toMatchObject({
      code: "FETCH_HOST_NOT_ALLOWED",
      message: "host other.test is not allowed",
    });
    await expect(get("https://card.test/", { resolve: async () => { throw new Error("dns"); } })).rejects.toMatchObject({ code: "FETCH_DNS_FAILED" });
    await expect(get("https://empty.test/", { resolve: async () => [] })).rejects.toMatchObject({
      code: "FETCH_ADDRESS_REFUSED",
      message: "host empty.test resolved to no addresses",
    });
    await expect(get("https://private.test/", { resolve: async () => ["10.0.0.5"] })).rejects.toMatchObject({
      code: "FETCH_ADDRESS_REFUSED",
      message: "host private.test resolved to a refused address (10.0.0.5)",
    });
    await expect(get("https://card.test/", { resolve: async () => [] })).rejects.toMatchObject({ code: "FETCH_ADDRESS_REFUSED" });
    await expect(get("https://10.0.0.1/")).rejects.toMatchObject({ code: "FETCH_ADDRESS_REFUSED" });
    await expect(get("https://[::1]/")).rejects.toMatchObject({ code: "FETCH_ADDRESS_REFUSED" });
  });

  it.each([
    "127.0.0.2", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:10.0.0.5",
  ])("refuses each private DNS answer %s before connecting", async (ip) => {
    const initial = requests.length;
    await expect(get("https://card.test/", { resolve: async () => [ip] })).rejects.toMatchObject({
      code: "FETCH_ADDRESS_REFUSED",
    });
    expect(requests).toHaveLength(initial);
  });

  it.each(["::ffff:8.8.8.8", "::ffff:0:a00:5"])(
    "refuses mapped and translated DNS answer %s before connecting",
    async (ip) => {
      const initial = requests.length;
      await expect(get("https://card.test/", { resolve: async () => [ip] })).rejects.toMatchObject({
        code: "FETCH_ADDRESS_REFUSED",
      });
      expect(requests).toHaveLength(initial);
    },
  );

  it("refuses mixed public/private DNS answers and never uses dns.lookup", async () => {
    const lookup = vi.spyOn(dns, "lookup");
    const initial = requests.length;
    await expect(get("https://card.test/", { resolve: async () => ["8.8.8.8", "10.0.0.1"] })).rejects.toMatchObject({
      code: "FETCH_ADDRESS_REFUSED",
    });
    expect(requests).toHaveLength(initial);
    expect(lookup).not.toHaveBeenCalled();
    lookup.mockRestore();
  });

  it("resolves and pins once per hop so DNS rebinding cannot change the socket destination", async () => {
    let resolves = 0;
    const request = vi.spyOn(https, "request");
    const result = await get("https://card.test/", {
      resolve: async () => [++resolves === 1 ? "127.0.0.1" : "10.0.0.1"],
    });
    expect(JSON.parse(result.text)).toEqual({ ok: true });
    expect(resolves).toBe(1);
    expect(request).toHaveBeenCalled();
    const options = request.mock.calls[0]![0] as https.RequestOptions;
    expect(options.host).toBe("127.0.0.1");
    request.mockRestore();
  });
});

describe("fetchJson redirects and request isolation", () => {
  it("revalidates private, HTTP, and disallowed-host redirects before connecting", async () => {
    const start = requests.length;
    const resolvedHosts: string[] = [];
    await expect(get("https://card.test/redirect-private", {
      resolve: async (host) => {
        resolvedHosts.push(host);
        return host === "private.test" ? ["10.0.0.5"] : ["127.0.0.1"];
      },
    })).rejects.toMatchObject({
      code: "FETCH_ADDRESS_REFUSED",
      message: "host private.test resolved to a refused address (10.0.0.5)",
    });
    expect(requests).toHaveLength(start + 1);
    expect(resolvedHosts).toContain("private.test");

    await expect(get("https://card.test/redirect-private-literal")).rejects.toMatchObject({ code: "FETCH_ADDRESS_REFUSED" });
    await expect(get("https://card.test/redirect-http")).rejects.toMatchObject({
      code: "FETCH_NOT_HTTPS",
      message: "redirect to http://card.test/plain is not HTTPS",
    });
    await expect(get("https://card.test/redirect-outside", {}, (host) => host === "card.test")).rejects.toMatchObject({
      code: "FETCH_HOST_NOT_ALLOWED",
      message: "host other.test is not allowed",
    });
  });

  it("allows three redirects and rejects the fourth", async () => {
    const result = await get("https://card.test/chain/1");
    expect(JSON.parse(result.text)).toEqual({ ok: true });
    expect(result.redirects).toHaveLength(3);
    await expect(get("https://card.test/chain/0")).rejects.toMatchObject({
      code: "FETCH_TOO_MANY_REDIRECTS",
      message: "redirect limit exceeded at https://card.test",
    });
  });

  it("does not forward response cookies and sends only the required headers", async () => {
    const result = await get("https://card.test/cookie-start");
    expect(JSON.parse(result.text)).toEqual({ cookie: null });
    const finalRequest = requests.at(-1)!;
    expect(finalRequest.headers.cookie).toBeUndefined();
    expect(finalRequest.headers.authorization).toBeUndefined();
    expect(finalRequest.headers["proxy-authorization"]).toBeUndefined();
    expect(finalRequest.headers.accept).toBe("application/json");
    expect(finalRequest.headers.connection).toBe("close");
    expect(finalRequest.headers.host).toBe(`card.test:${port}`);
    expect(finalRequest.headers["user-agent"]).toMatch(/^zipviz-cli\//);
    expect(Object.keys(finalRequest.headers).sort()).toEqual(["accept", "connection", "host", "user-agent"]);
  });

  it("ignores proxy environment variables", async () => {
    const previous = { ...process.env };
    let proxyConnections = 0;
    const requestSpy = vi.spyOn(https, "request");
    const proxy = http.createServer(() => { proxyConnections++; });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const proxyPort = (proxy.address() as net.AddressInfo).port;
    for (const name of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"]) {
      process.env[name] = `http://127.0.0.1:${proxyPort}`;
    }
    process.env.NODE_USE_ENV_PROXY = "1";
    try {
      await get("https://card.test/");
      expect(proxyConnections).toBe(0);
      // NODE_USE_ENV_PROXY is read at process start, so the agent assertion is the meaningful check.
      const options = requestSpy.mock.calls[0]![0] as https.RequestOptions;
      expect(options.agent).toBeInstanceOf(https.Agent);
      expect(options.agent).not.toBe(https.globalAgent);
    } finally {
      requestSpy.mockRestore();
      process.env = previous;
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
    }
  });
});

describe("fetchJson response validation and limits", () => {
  it("rejects status, content type, charset, encoding and invalid UTF-8", async () => {
    await expect(get("https://card.test/status")).rejects.toMatchObject({ code: "FETCH_HTTP_STATUS" });
    await expect(get("https://card.test/missing-type")).rejects.toMatchObject({ code: "FETCH_CONTENT_TYPE" });
    await expect(get("https://card.test/html")).rejects.toMatchObject({ code: "FETCH_CONTENT_TYPE" });
    await expect(get("https://card.test/json-only")).resolves.toMatchObject({ contentType: "application/json" });
    await expect(get("https://card.test/latin")).rejects.toMatchObject({ code: "FETCH_CONTENT_TYPE" });
    await expect(get("https://card.test/gzip")).rejects.toMatchObject({ code: "FETCH_CONTENT_ENCODING" });
    await expect(get("https://card.test/invalid-utf8")).rejects.toMatchObject({ code: "FETCH_NOT_UTF8" });
    await expect(fetchJson("https://card.test/jwks-type", { accept: "application/jwk-set+json" }, deps())).resolves.toMatchObject({
      contentType: "application/jwk-set+json",
    });
    await expect(fetchJson("https://card.test/", { accept: "application/a2a+json" }, deps())).resolves.toMatchObject({
      contentType: "application/a2a+json",
    });
  });

  it("enforces content-length and streaming byte limits, closing oversized streams early", async () => {
    await expect(get("https://card.test/large-length", { maxBytes: 10 })).rejects.toMatchObject({ code: "FETCH_TOO_LARGE" });
    const result = get("https://card.test/large-streaming", { maxBytes: 10 * 1024 });
    await expect(result).rejects.toMatchObject({ code: "FETCH_TOO_LARGE" });
    const bytesAtClose = await streamingClosed;
    expect(bytesAtClose).toBeLessThan(512 * 1024);
  });

  it("accepts exactly the default limit and rejects one byte over it", async () => {
    const exact = await get("https://card.test/default-limit-exact");
    expect(Buffer.byteLength(exact.text)).toBe(FETCH_MAX_BYTES);
    await expect(get("https://card.test/default-limit-over")).rejects.toMatchObject({ code: "FETCH_TOO_LARGE" });
  });

  it("enforces one total timeout across stalled and slow-drip responses", async () => {
    await expect(get("https://card.test/stall", { timeoutMs: 300 })).rejects.toMatchObject({ code: "FETCH_TIMEOUT" });
    await expect(get("https://card.test/slow-drip", { timeoutMs: 300 })).rejects.toMatchObject({ code: "FETCH_TIMEOUT" });
  });

  it("reports TLS identity and socket errors without exposing response bodies", async () => {
    await expect(get("https://wrong.test/", { resolve: async () => ["127.0.0.1"] })).rejects.toMatchObject({ code: "FETCH_TLS" });
    await expect(get("https://card.test/reset")).rejects.toMatchObject({ code: "FETCH_FAILED" });
  });
});
