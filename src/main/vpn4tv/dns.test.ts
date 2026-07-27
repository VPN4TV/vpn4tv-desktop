import assert from "node:assert/strict";
import { test } from "node:test";

import { dohCapableIp, dohProbeCandidates, dohServer, injectProbedDns, udpCandidates } from "./dns";

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

test("direct DNS needs an IP with a matching certificate", () => {
  // An IP-hosted winner is used as-is.
  assert.equal(
    dohCapableIp({ dohUrl: "https://1.0.0.1/dns-query", udpServer: "1.1.1.1", dohWorks: true }),
    "1.0.0.1",
  );
  // A hostname-only winner falls back to a known IP-cert provider.
  assert.equal(
    dohCapableIp({ dohUrl: "https://dns.adguard-dns.com/dns-query", udpServer: "9.9.9.9", dohWorks: true }),
    "9.9.9.9",
  );
  // Nothing answered → no DoH for the direct server at all.
  assert.equal(
    dohCapableIp({ dohUrl: "https://8.8.8.8/dns-query", udpServer: "9.9.9.9", dohWorks: false }),
    null,
  );
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
