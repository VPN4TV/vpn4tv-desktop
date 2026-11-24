// VPN4TV: Outline dynamic keys — outcomes, waits, the start verdict, the
// lines support reads. Run with scripts/test-converter.sh.

import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

import { BRIDGE_CONFIG_KEY, BRIDGE_PORTS } from "./generator";
import {
  type OutlineKeyFetch,
  type OutlineKeyOutcome,
  deadOutlineTags,
  hasDynamicOutlineKeys,
  outlineKeyLine,
  outlineKeyVerdict,
  resolveDynamicOutlineKeys,
  shortReason,
  withoutAddresses,
} from "./outlineDynamic";

const PORT_A = 43890;
const PORT_B = 43891;
const PORT_C = 43892;

function profile(endpoints: Record<string, unknown>[], tags: string[] = ["a", "b", "c"]): string {
  const ports = [PORT_A, PORT_B, PORT_C];
  return JSON.stringify({
    outbounds: [
      { type: "selector", tag: "select", outbounds: ["auto", ...tags], default: "auto" },
      { type: "urltest", tag: "auto", outbounds: tags },
      ...tags.map((tag, index) => ({
        type: "socks",
        tag,
        server: BRIDGE_PORTS.socksHost,
        server_port: ports[index],
      })),
      { type: "direct", tag: "direct" },
    ],
    [BRIDGE_CONFIG_KEY]: { outline: { endpoints } },
  });
}

function endpointsOf(content: string): Record<string, unknown>[] {
  return JSON.parse(content)[BRIDGE_CONFIG_KEY].outline.endpoints;
}

test("each key gets its outcome; only a fetched key that differs changes the profile", async () => {
  const content = profile([
    { dynamicUrl: "https://new.example/k1", url: "ss://old@1.1.1.1:1#x", port: PORT_A },
    { dynamicUrl: "https://kept.example/k2", url: "ss://kept@2.2.2.2:2#y", port: PORT_B },
    { dynamicUrl: "https://none.example/k3", port: PORT_C },
  ]);
  const answers: Record<string, OutlineKeyFetch> = {
    "https://new.example/k1": { url: "ss://new@3.3.3.3:3#x", error: null },
    "https://kept.example/k2": { url: null, error: "HTTP 503" },
    "https://none.example/k3": { url: null, error: "no answer in 20 s" },
  };
  const resolution = await resolveDynamicOutlineKeys(content, { fetchKey: async (url) => answers[url] });
  assert.deepEqual(
    resolution.outcomes.map((outcome) => [outcome.host, outcome.port, outcome.state, outcome.reason, outcome.changed]),
    [
      ["new.example", PORT_A, "fetched", null, true],
      ["kept.example", PORT_B, "kept", "HTTP 503", false],
      ["none.example", PORT_C, "none", "no answer in 20 s", false],
    ],
  );
  const endpoints = endpointsOf(resolution.content);
  assert.equal(endpoints[0].url, "ss://new@3.3.3.3:3#x");
  assert.equal(endpoints[1].url, "ss://kept@2.2.2.2:2#y");
  assert.equal(endpoints[2].url, undefined);
});

test("the same key leaves the profile string as it was", async () => {
  const content = profile([{ dynamicUrl: "https://same.example/k", url: "ss://same@1.1.1.1:1#x", port: PORT_A }]);
  const resolution = await resolveDynamicOutlineKeys(content, {
    fetchKey: async () => ({ url: "ss://same@1.1.1.1:1#x", error: null }),
  });
  assert.equal(resolution.content, content);
  assert.equal(resolution.outcomes[0].state, "fetched");
  assert.equal(resolution.outcomes[0].changed, false);
});

test("a key with an earlier one is waited for less than a key without", async () => {
  const content = profile([
    { dynamicUrl: "https://earlier.example/k", url: "ss://x@1.1.1.1:1#x", port: PORT_A },
    { dynamicUrl: "https://first.example/k", port: PORT_B },
  ]);
  const limits: Record<string, number> = {};
  await resolveDynamicOutlineKeys(content, {
    fetchKey: async (url, timeoutMs) => {
      limits[new URL(url).hostname] = timeoutMs;
      return { url: null, error: "x" };
    },
  });
  assert.deepEqual(limits, { "earlier.example": 6_000, "first.example": 20_000 });
});

test("keys are fetched at once, and a fetch that ignores its limit does not hold the start", async () => {
  const content = profile([
    { dynamicUrl: "https://hangs.example/k", url: "ss://x@1.1.1.1:1#x", port: PORT_A },
    { dynamicUrl: "https://slow.example/k", port: PORT_B },
  ]);
  const startedAt = Date.now();
  const resolution = await resolveDynamicOutlineKeys(content, {
    waitWithEarlierMs: 100,
    waitWithoutEarlierMs: 400,
    fetchKey: (url) =>
      url.includes("hangs")
        ? new Promise<OutlineKeyFetch>(() => {})
        : new Promise((resolve) => setTimeout(() => resolve({ url: "ss://y@2.2.2.2:2#y", error: null }), 300)),
  });
  const took = Date.now() - startedAt;
  assert.ok(took < 1_500, `took ${took} ms`);
  assert.equal(resolution.outcomes[0].state, "kept");
  assert.equal(resolution.outcomes[0].reason, "no answer in 0 s");
  assert.equal(resolution.outcomes[1].state, "fetched");
});

test("onlyPorts fetches just those endpoints", async () => {
  const content = profile([
    { dynamicUrl: "https://a.example/k", port: PORT_A },
    { dynamicUrl: "https://b.example/k", port: PORT_B },
  ]);
  const asked: string[] = [];
  const resolution = await resolveDynamicOutlineKeys(content, {
    onlyPorts: new Set([PORT_B]),
    fetchKey: async (url) => {
      asked.push(new URL(url).hostname);
      return { url: "ss://b@2.2.2.2:2#b", error: null };
    },
  });
  assert.deepEqual(asked, ["b.example"]);
  assert.equal(resolution.outcomes.length, 1);
  assert.equal(endpointsOf(resolution.content)[0].url, undefined);
  assert.equal(endpointsOf(resolution.content)[1].url, "ss://b@2.2.2.2:2#b");
});

test("a profile without dynamic keys is left alone", async () => {
  const content = profile([{ url: "ss://x@1.1.1.1:1#x", port: PORT_A }]);
  assert.equal(hasDynamicOutlineKeys(content), false);
  const resolution = await resolveDynamicOutlineKeys(content, {
    fetchKey: async () => assert.fail("nothing to fetch"),
  });
  assert.equal(resolution.content, content);
  assert.deepEqual(resolution.outcomes, []);
});

test("the real fetch: a key, a redirect, an error, an answer that is not a key, no answer", async (t) => {
  const server = createServer((request, response) => {
    switch (request.url) {
      case "/key":
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ server: "203.0.113.7", server_port: 8388, password: "p", method: "chacha20-ietf-poly1305", prefix: "\u0016\u0003" }));
        return;
      case "/moved":
        response.statusCode = 302;
        response.setHeader("location", "/key");
        response.end();
        return;
      case "/gone":
        response.statusCode = 404;
        response.end("not here");
        return;
      case "/html":
        response.end("<html>blocked</html>");
        return;
      case "/half":
        response.end(JSON.stringify({ server: "203.0.113.7" }));
        return;
      default:
        // Holds the request: a key host frozen after the connect.
        return;
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const paths = ["/key", "/moved", "/gone", "/html", "/half", "/hold"];
  const content = profile(
    paths.map((path, index) => ({ dynamicUrl: `${base}${path}`, port: PORT_A + index })),
    paths.map((_, index) => `s${index}`),
  );
  const resolution = await resolveDynamicOutlineKeys(content, { waitWithoutEarlierMs: 1_500 });
  const byPort = new Map(resolution.outcomes.map((outcome) => [outcome.port, outcome]));
  const urls = endpointsOf(resolution.content).map((endpoint) => endpoint.url);
  assert.match(String(urls[0]), /^ss:\/\/[A-Za-z0-9+/=]+@203\.0\.113\.7:8388\?prefix=%16%03#127\.0\.0\.1$/u);
  assert.equal(urls[1], urls[0]);
  assert.equal(byPort.get(PORT_A + 2)?.reason, "HTTP 404");
  assert.equal(byPort.get(PORT_A + 3)?.reason, "the answer is not a key");
  assert.equal(byPort.get(PORT_A + 4)?.reason, "the key has no server, port, password or method");
  assert.equal(byPort.get(PORT_A + 5)?.reason, "no answer in 2 s");
  assert.equal(byPort.get(PORT_A + 5)?.state, "none");
});

test("reasons: short, without links or addresses, ports kept", () => {
  const timeout = new Error("The operation was aborted due to timeout");
  timeout.name = "TimeoutError";
  assert.equal(shortReason(timeout, 6_000), "no answer in 6 s");
  const failed = new TypeError("fetch failed", {
    cause: Object.assign(new Error("connect ETIMEDOUT 198.51.100.4:443"), { code: "ETIMEDOUT" }),
  });
  assert.equal(shortReason(failed, 20_000), "connect ETIMEDOUT <address>:443");
  const reset = new TypeError("fetch failed", {
    cause: Object.assign(new Error("Client network socket disconnected before secure TLS connection was established"), {
      code: "ECONNRESET",
    }),
  });
  assert.equal(
    shortReason(reset, 20_000),
    "ECONNRESET: Client network socket disconnected before secure TLS connection was established",
  );
  assert.equal(shortReason(new Error("bad https://keys.example/secret-path"), 1), "bad <link>");
  assert.equal(withoutAddresses("read [2001:db8::1]:443: reset"), "read <address>:443: reset");
  assert.equal(withoutAddresses("dial fe80::1%en0 and 10.0.0.1"), "dial <address> and <address>");
});

test("the start verdict", () => {
  const content = profile([], ["a", "b", "c"]);
  const none = (port: number): OutlineKeyOutcome => ({ host: "h", port, state: "none", reason: "r", changed: false });
  const kept = (port: number): OutlineKeyOutcome => ({ host: "h", port, state: "kept", reason: "r", changed: false });
  const deadA = deadOutlineTags(content, [none(PORT_A), kept(PORT_B)]);
  assert.deepEqual([...deadA], ["a"]);
  assert.equal(outlineKeyVerdict(content, deadA, null), "go-on");
  assert.equal(outlineKeyVerdict(content, deadA, "auto"), "go-on");
  assert.equal(outlineKeyVerdict(content, deadA, "b"), "go-on");
  assert.equal(outlineKeyVerdict(content, deadA, "a"), "pick-another");
  assert.equal(outlineKeyVerdict(content, deadA, "gone"), "go-on");
  const deadAll = deadOutlineTags(content, [none(PORT_A), none(PORT_B), none(PORT_C)]);
  assert.equal(outlineKeyVerdict(content, deadAll, null), "no-other-server");
  assert.equal(outlineKeyVerdict(content, deadAll, "a"), "no-other-server");
  assert.equal(outlineKeyVerdict(content, new Set(), "a"), "go-on");
});

test("the lines support reads", () => {
  const base = { host: "keys.example", port: PORT_A, reason: "no answer in 20 s", changed: false };
  assert.equal(outlineKeyLine({ ...base, state: "fetched", reason: null, changed: true }, false), "outline key from keys.example (port 43890): fetched, a new one");
  assert.equal(outlineKeyLine({ ...base, state: "fetched", reason: null }, true), "outline key from keys.example (port 43890), again after the start: fetched");
  assert.equal(outlineKeyLine({ ...base, state: "kept" }, false), "outline key from keys.example (port 43890): not fetched (no answer in 20 s), the last one that worked is used");
  assert.equal(outlineKeyLine({ ...base, state: "none" }, false), "outline key from keys.example (port 43890): not fetched (no answer in 20 s), none ever was: this server is left out");
});
