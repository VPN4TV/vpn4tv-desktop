import assert from "node:assert/strict";
import { test } from "node:test";

import {
  type ResolvedHostsStore,
  chooseDoh,
  dohCapableIp,
  dohProbeCandidates,
  dohServer,
  hasFakeDns,
  injectProbedDns,
  injectResolvedHosts,
  isDnsAnswer,
  preResolveHosts,
  resolutionEndpoints,
  serverHosts,
  stripFakeDns,
  udpCandidates,
} from "./dns";

test("Quad9 leads the registry (it survived the 2026-07 purge)", () => {
  assert.equal(dohProbeCandidates[0], "https://9.9.9.9/dns-query");
  assert.equal(udpCandidates[0], "9.9.9.9");
  assert.ok(dohProbeCandidates.includes("https://dns.yandex.net/dns-query"), "last resort is still probeable");
});

test("dohServer strips the scheme and path", () => {
  assert.equal(dohServer({ dohUrl: "https://9.9.9.9/dns-query", udpServer: "9.9.9.9", dohWorks: true }), "9.9.9.9");
  assert.equal(
    dohServer({ dohUrl: "https://dns.adguard-dns.com/dns-query", udpServer: "9.9.9.9", dohWorks: true }),
    "dns.adguard-dns.com",
  );
});

test("direct DNS takes only a DoH IP that answered the probe", () => {
  assert.equal(
    dohCapableIp({ dohUrl: "https://1.0.0.1/dns-query", udpServer: "1.1.1.1", dohWorks: true, dohIp: "1.0.0.1" }),
    "1.0.0.1",
  );
  // A winner by name with no IP answering: no guess (it used to be 9.9.9.9, dead where Quad9 is blocked).
  assert.equal(
    dohCapableIp({ dohUrl: "https://dns.adguard-dns.com/dns-query", udpServer: "8.8.8.8", dohWorks: true, dohIp: null }),
    null,
  );
  assert.equal(
    dohCapableIp({ dohUrl: "https://8.8.8.8/dns-query", udpServer: "9.9.9.9", dohWorks: false, dohIp: null }),
    null,
  );
});

test("the DoH choice: Quad9 answering wins both roles at once", async () => {
  const asked: string[] = [];
  const choice = await chooseDoh(dohProbeCandidates, async (url) => (asked.push(url), true));
  assert.deepEqual(choice, { winner: "https://9.9.9.9/dns-query", ip: "9.9.9.9" });
  assert.deepEqual(asked, ["https://9.9.9.9/dns-query"]);
});

test("the DoH choice: Quad9 blocked, AdGuard by name wins, dns-direct gets an IP that answered", async () => {
  const alive = new Set(["https://dns.adguard-dns.com/dns-query", "https://8.8.8.8/dns-query"]);
  const asked: string[] = [];
  const choice = await chooseDoh(dohProbeCandidates, async (url) => (asked.push(url), alive.has(url)));
  assert.deepEqual(choice, { winner: "https://dns.adguard-dns.com/dns-query", ip: "8.8.8.8" });
  assert.ok(!asked.includes("https://dns.google/dns-query"), "after a winner by name only IP candidates are asked");
});

test("the DoH choice: no IP answering leaves dns-direct to UDP, nothing answering gives neither", async () => {
  assert.deepEqual(
    await chooseDoh(dohProbeCandidates, async (url) => url === "https://dns.adguard-dns.com/dns-query"),
    { winner: "https://dns.adguard-dns.com/dns-query", ip: null },
  );
  assert.deepEqual(await chooseDoh(dohProbeCandidates, async () => false), { winner: null, ip: null });
});

test("a UDP answer must match the id, carry the response bit and no format or server error", () => {
  const query = Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
  const reply = (id0: number, flags: number, rcode: number) =>
    Buffer.from([id0, 0x34, flags, rcode, 0, 1, 0, 1, 0, 0, 0, 0]);
  assert.ok(isDnsAnswer(query, reply(0x12, 0x81, 0x80)));
  assert.ok(isDnsAnswer(query, reply(0x12, 0x81, 0x83)), "NXDOMAIN is still an answer");
  assert.ok(!isDnsAnswer(query, reply(0x99, 0x81, 0x80)), "someone else's id");
  assert.ok(!isDnsAnswer(query, reply(0x12, 0x01, 0x80)), "not a response");
  assert.ok(!isDnsAnswer(query, reply(0x12, 0x81, 0x82)), "SERVFAIL");
  assert.ok(!isDnsAnswer(query, reply(0x12, 0x81, 0x80).subarray(0, 8)), "truncated");
});

const profile = JSON.stringify({
  dns: {
    servers: [
      { type: "https", tag: "dns-remote", server: "8.8.8.8", detour: "select" },
      { type: "udp", tag: "dns-direct", server: "1.1.1.1" },
      { type: "fakeip", tag: "dns-fakeip", inet4_range: "198.18.0.0/15" },
    ],
    rules: [{ query_type: ["A"], server: "dns-fakeip" }],
  },
  outbounds: [{ type: "direct", tag: "direct" }],
});

test("a working DoH endpoint rewrites both servers and leaves the rest alone", () => {
  const result = injectProbedDns(profile, {
    dohUrl: "https://149.112.112.112/dns-query",
    udpServer: "9.9.9.9",
    dohWorks: true,
    dohIp: "149.112.112.112",
  });
  const dns = JSON.parse(result).dns;
  assert.deepEqual(dns.servers[0], {
    type: "https",
    tag: "dns-remote",
    server: "149.112.112.112",
    detour: "select",
  });
  assert.deepEqual(dns.servers[1], { type: "https", tag: "dns-direct", server: "149.112.112.112" });
  assert.deepEqual(dns.servers[2], { type: "fakeip", tag: "dns-fakeip", inet4_range: "198.18.0.0/15" });
  assert.deepEqual(dns.rules, [{ query_type: ["A"], server: "dns-fakeip" }]);
});

test("a winner by name with no IP answering: the tunnel keeps it, dns-direct takes the UDP server that answered", () => {
  const servers = JSON.parse(
    injectProbedDns(profile, {
      dohUrl: "https://dns.adguard-dns.com/dns-query",
      udpServer: "8.8.8.8",
      dohWorks: true,
      dohIp: null,
    }),
  ).dns.servers;
  assert.equal(servers[0].server, "dns.adguard-dns.com");
  assert.deepEqual(servers[1], { type: "udp", tag: "dns-direct", server: "8.8.8.8" });
});

test("with no reachable DoH the direct server falls back to plain UDP", () => {
  const result = injectProbedDns(profile, {
    dohUrl: "https://8.8.8.8/dns-query",
    udpServer: "9.9.9.9",
    dohWorks: false,
  });
  const servers = JSON.parse(result).dns.servers;
  assert.deepEqual(servers[1], { type: "udp", tag: "dns-direct", server: "9.9.9.9" });
});

test("a profile without a DNS section is returned untouched", () => {
  const plain = JSON.stringify({ outbounds: [] });
  const probe = { dohUrl: "https://9.9.9.9/dns-query", udpServer: "9.9.9.9", dohWorks: true };
  assert.equal(injectProbedDns(plain, probe), plain);
  assert.equal(injectProbedDns("not json", probe), "not json");
});

function memoryStore(initial: Record<string, string[]> = {}): ResolvedHostsStore & { saved: Record<string, string[]> | null } {
  const store = {
    saved: null as Record<string, string[]> | null,
    load: async () => ({ ...initial }),
    save: async (answers: Record<string, string[]>) => {
      store.saved = answers;
    },
  };
  return store;
}

test("the resolution chain is wireformat first, JSON last, never the Russian resolver", () => {
  assert.deepEqual(resolutionEndpoints[0], { url: "https://9.9.9.9/dns-query", wire: true });
  assert.ok(resolutionEndpoints.every((endpoint) => !endpoint.url.includes("yandex")));
  const firstJson = resolutionEndpoints.findIndex((endpoint) => !endpoint.wire);
  assert.ok(firstJson > 0 && resolutionEndpoints.slice(firstJson).every((endpoint) => !endpoint.wire));
});

test("every start asks the chain again, even with a stored answer", async () => {
  const store = memoryStore({ "srv.example": ["192.0.2.1"] });
  const asked: string[] = [];
  const result = await preResolveHosts(["srv.example"], store, async (host) => {
    asked.push(host);
    return ["192.0.2.9"];
  });
  assert.deepEqual(asked, ["srv.example"]);
  assert.deepEqual(result, { "srv.example": ["192.0.2.9"] });
  assert.deepEqual(store.saved, { "srv.example": ["192.0.2.9"] });
});

test("a silent chain leaves the stored answer, and a name never answered stays out", async () => {
  const store = memoryStore({ "old.example": ["192.0.2.1"] });
  const result = await preResolveHosts(["old.example", "new.example"], store, async () => []);
  assert.deepEqual(result, { "old.example": ["192.0.2.1"] });
  assert.equal(store.saved, null);
});

test("serverHosts takes outbound servers written by name only", () => {
  const config = JSON.stringify({
    outbounds: [
      { type: "vless", tag: "a", server: "srv.example" },
      { type: "vless", tag: "b", server: "192.0.2.1" },
      { type: "socks", tag: "c", server: "127.0.0.1" },
      { type: "vless", tag: "d", server: "2001:db8::1" },
      { type: "vless", tag: "e", server: "srv.example" },
      { type: "direct", tag: "direct" },
    ],
  });
  assert.deepEqual(serverHosts(config), ["srv.example"]);
});

test("injectResolvedHosts pins the answers and the proxies dial them", () => {
  const config = JSON.stringify({
    dns: { servers: [{ type: "https", tag: "dns-direct", server: "9.9.9.9" }], rules: [{ outbound: "any", server: "dns-direct" }] },
    outbounds: [
      { type: "vless", tag: "a", server: "srv.example" },
      { type: "vless", tag: "b", server: "own.example", domain_resolver: "dns-direct" },
      { type: "vless", tag: "c", server: "192.0.2.1" },
    ],
  });
  const root = JSON.parse(injectResolvedHosts(config, { "srv.example": ["192.0.2.9"], "own.example": ["192.0.2.8"] }));
  assert.deepEqual(root.dns.servers.at(-1), {
    type: "hosts",
    tag: "dns-hosts",
    predefined: { "srv.example": ["192.0.2.9"], "own.example": ["192.0.2.8"] },
  });
  assert.deepEqual(root.dns.rules[0], { domain: ["srv.example", "own.example"], server: "dns-hosts" });
  assert.equal(root.dns.rules.length, 2);
  assert.equal(root.outbounds[0].domain_resolver, "dns-hosts");
  assert.equal(root.outbounds[1].domain_resolver, "dns-direct", "an outbound's own resolver stays");
  assert.equal(root.outbounds[2].domain_resolver, undefined);
  assert.equal(injectResolvedHosts(config, {}), config, "nothing resolved: the config as it is");
});

test("stripFakeDns drops FakeDNS and keeps the cache file", () => {
  const config = JSON.stringify({
    dns: {
      servers: [{ type: "https", tag: "dns-direct", server: "9.9.9.9" }, { type: "fakeip", tag: "dns-fakeip" }],
      rules: [
        { outbound: "any", server: "dns-direct" },
        { query_type: ["HTTPS", "SVCB"], action: "reject" },
        { query_type: ["A", "AAAA"], server: "dns-fakeip" },
      ],
    },
    experimental: { cache_file: { enabled: true, store_fakeip: true } },
  });
  assert.ok(hasFakeDns(config));
  const stripped = stripFakeDns(config);
  assert.ok(!hasFakeDns(stripped));
  const root = JSON.parse(stripped);
  assert.deepEqual(root.dns.rules, [{ outbound: "any", server: "dns-direct" }]);
  assert.deepEqual(root.experimental, { cache_file: { enabled: true } });
});
