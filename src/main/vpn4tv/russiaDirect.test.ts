// applyRussiaDirect, JSON in → JSON out, over what the app itself builds: the
// real parser and generator on made-up links (keys and hosts are fake), then
// the DNS probe's rewrite and the IPv6 trim, exactly as a start runs them.

import assert from "node:assert/strict";
import { test } from "node:test";

import { injectProbedDns } from "./dns";
import { type GenerateOptions, generateConfig } from "./generator";
import { stripTunIPv6 } from "./ipv6";
import { parseSubscription } from "./parser";
import {
  BUNDLED_RULE_SETS,
  GEOIP_TAG,
  GEOSITE_TAG,
  type RussiaDirectOptions,
  applyRussiaDirect,
  legacyDnsReason,
  parseNameList,
  russiaDirectNotOursReason,
  usableRuleSets,
  withoutRuleSetData,
} from "./russiaDirect";
import {
  DNS_RU_SERVER,
  DNS_RU_TAG,
  DNS_RU_TYPE,
  RU_SUFFIXES,
  RU_VPN_EXCEPTIONS,
} from "./russiaDirectLists.generated";

type Json = Record<string, any>;

const b64 = (text: string) => Buffer.from(text).toString("base64url");
const key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const wgKey = encodeURIComponent("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=");
const LINKS = {
  vless: `vless://11111111-2222-3333-4444-555555555555@nl.example.net:443?security=reality&sni=www.example.com&fp=chrome&pbk=${key}&sid=0123abcd&type=tcp&flow=xtls-rprx-vision#NL`,
  hy2: "hy2://fake-password@de.example.net:8443,9443,20000-40000/?sni=de.example.net#DE",
  trojan: "trojan://fake-password@fi.example.net:443?security=tls&sni=fi.example.net&type=tcp#FI",
  ss: `ss://${b64("chacha20-ietf-poly1305:fake-password")}@192.0.2.10:8388#SS`,
  xhttp: `vless://66666666-7777-8888-9999-000000000000@xh.example.net:443?security=reality&sni=www.example.com&fp=chrome&pbk=${key}&sid=abcd&type=xhttp&path=%2Fx&mode=auto#XH`,
  outline: `ss://${b64("chacha20-ietf-poly1305:fake-password")}@192.0.2.20:443/?outline=1&prefix=%16%03%01#OL`,
  awg: `wg://192.0.2.30:51820?private_key=${wgKey}&peer_public_key=${wgKey}&local_address=10.8.0.2%2F32&awg_jc=4&awg_h1=1&awg_h2=2&awg_h3=3&awg_h4=4#AWG`,
  tt: "tt://?AAEBAQtleGFtcGxlLm5ldA#TT",
  olcrtc: `olcrtc://telemost?mode=x@https://telemost.example.net/j/1#${"ab".repeat(32)}$OLC`,
} as const;

const PROBE = { dohUrl: "https://9.9.9.9/dns-query", udpServer: "9.9.9.9", dohWorks: true };

/** What a start hands to the daemon before the block: generator → DNS probe → (IPv6 trim). */
function base(kinds: (keyof typeof LINKS)[], options: GenerateOptions = {}, noIPv6 = false): string {
  const proxies = parseSubscription(kinds.map((kind) => LINKS[kind]).join("\n"));
  assert.equal(proxies.length, kinds.length);
  const probed = injectProbedDns(generateConfig(proxies, options), PROBE);
  return noIPv6 ? stripTunIPv6(probed) : probed;
}

const MIXED = base(["vless", "hy2", "trojan", "ss"]);
const MIXED_NO_FAKEDNS = base(["vless", "hy2", "trojan", "ss"], { fakeDns: false });
const ONLY_SELECTED = base(["vless", "trojan"], { perApp: { mode: "include", apps: ["chrome.exe", "Telegram"] } });
const ALL_EXCEPT = base(["vless", "trojan"], { perApp: { mode: "exclude", apps: ["steam.exe"] } });
const NO_LAN = base(["vless"], { lanBypass: false });
const XHTTP = base(["xhttp", "vless"]);
const TCP_BRIDGES = base(["outline", "awg", "tt", "olcrtc"]);
const NO_IPV6 = base(["vless"], {}, true);
const FIXTURES: Record<string, string> = {
  MIXED,
  MIXED_NO_FAKEDNS,
  ONLY_SELECTED,
  ALL_EXCEPT,
  NO_LAN,
  XHTTP,
  TCP_BRIDGES,
  NO_IPV6,
};

const ON: RussiaDirectOptions = { sets: BUNDLED_RULE_SETS };

const parse = (text: string): Json => JSON.parse(text) as Json;
const dnsServers = (config: Json): Json[] => config.dns.servers;
const dnsRules = (config: Json): Json[] => config.dns.rules ?? [];
const routeRules = (config: Json): Json[] => config.route.rules;

/** Order-insensitive for object keys, as the core reads JSON. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    return `{${Object.keys(value)
      .sort()
      .map((name) => `${JSON.stringify(name)}:${canonical((value as Json)[name])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

const same = (a: unknown, b: unknown) => canonical(a) === canonical(b);

const isTorrent = (rule: Json) =>
  same(rule.protocol, ["bittorrent"]) && rule.outbound === "direct" && rule.action === "route";

const isPerApp = (rule: Json) =>
  rule.process_name !== undefined || rule.process_path !== undefined || rule.process_path_regex !== undefined;

/** M: the Russian names; with sets, geosite-category-ru or the suffixes. */
function assertM(m: Json, withSets: boolean): void {
  assert.deepEqual(m.domain_suffix, RU_SUFFIXES);
  if (withSets) {
    assert.deepEqual(m.rule_set, [GEOSITE_TAG]);
  } else {
    assert.equal(m.rule_set, undefined);
  }
  assert.notEqual(m.invert, true);
}

/** E: not an exception. */
function assertE(e: Json, extra: string[] = []): void {
  assert.equal(e.invert, true);
  assert.deepEqual(e.domain_suffix, [...new Set([...RU_VPN_EXCEPTIONS, ...extra])]);
}

/** The full block, and what must not change around it. */
function assertBlock(
  input: Json,
  out: Json,
  { withSets, dnsServer = DNS_RU_TAG, extra = [] }: { withSets: boolean; dnsServer?: string; extra?: string[] },
): void {
  // DNS servers: as before, dns-ru last (TCP to Yandex, no detour); dns-remote stays first.
  const inServers = dnsServers(input);
  const outServers = dnsServers(out);
  assert.equal(outServers[0].tag, "dns-remote");
  if (dnsServer === DNS_RU_TAG) {
    assert.equal(outServers.length, inServers.length + 1);
    inServers.forEach((server, index) => assert.ok(same(server, outServers[index])));
    assert.deepEqual(outServers.at(-1), { type: DNS_RU_TYPE, tag: DNS_RU_TAG, server: DNS_RU_SERVER });
    assert.equal(DNS_RU_TYPE, "tcp");
  } else {
    assert.equal(outServers.length, inServers.length);
    assert.ok(outServers.every((server) => server.tag !== DNS_RU_TAG));
  }

  // DNS rules: ours right before the HTTPS/SVCB reject and the fakeip rule, or last.
  const inRules = dnsRules(input);
  const outRules = dnsRules(out);
  assert.equal(outRules.length, inRules.length + 2);
  let at = inRules.findIndex((rule) => rule.server === "dns-fakeip" || rule.action === "reject");
  if (at < 0) {
    at = inRules.length;
  }
  for (let index = 0; index < at; index++) {
    assert.ok(same(inRules[index], outRules[index]));
  }
  for (let index = at; index < inRules.length; index++) {
    assert.ok(same(inRules[index], outRules[index + 2]));
  }
  const empty = outRules[at];
  assert.equal(empty.action, "predefined");
  assert.equal(empty.rcode, undefined);
  assert.deepEqual(empty.rules[0].query_type, ["AAAA", "HTTPS", "SVCB"]);
  assertM(empty.rules[1], withSets);
  assertE(empty.rules[2], extra);
  const resolve = outRules[at + 1];
  assert.equal(resolve.action, "route");
  assert.equal(resolve.server, dnsServer);
  assert.equal(resolve.rules.length, 2);
  assertM(resolve.rules[0], withSets);
  assertE(resolve.rules[1], extra);

  // Route: everything as before; ours ahead of the first per-app rule, else last.
  const inRoute = routeRules(input);
  const outRoute = routeRules(out);
  const added = withSets ? 3 : 2;
  assert.equal(outRoute.length, inRoute.length + added);
  let routeAt = inRoute.findIndex(isPerApp);
  if (routeAt < 0) {
    routeAt = inRoute.length;
  }
  for (let index = 0; index < routeAt; index++) {
    assert.ok(same(inRoute[index], outRoute[index]));
  }
  for (let index = routeAt; index < inRoute.length; index++) {
    assert.ok(same(inRoute[index], outRoute[index + added]));
  }
  assert.ok(isTorrent(outRoute[routeAt]));
  const names = outRoute[routeAt + 1];
  assert.equal(names.outbound, "direct");
  assertM(names.rules[0], withSets);
  assertE(names.rules[1], extra);
  if (withSets) {
    const addresses = outRoute[routeAt + 2];
    assert.equal(addresses.outbound, "direct");
    assert.deepEqual(addresses.rules[0].rule_set, [GEOIP_TAG]);
    assertE(addresses.rules[1], extra);
    assert.equal(addresses.rules[2].ip_version, 4);
    const sets: Json[] = out.route.rule_set;
    assert.deepEqual(
      sets.map((set) => [set.tag, set.type]),
      [
        [GEOSITE_TAG, "inline"],
        [GEOIP_TAG, "inline"],
      ],
    );
    assert.deepEqual(sets[0].rules, BUNDLED_RULE_SETS.geosite);
    assert.deepEqual(sets[1].rules, BUNDLED_RULE_SETS.geoip);
    assert.ok(sets.every((set) => set.path === undefined && set.url === undefined));
  } else {
    assert.equal(out.route.rule_set, undefined);
    assert.ok(!JSON.stringify(out).includes(GEOIP_TAG));
  }

  // The rest of the config is the input's: inbounds, outbounds, the bridges,
  // route.final, default_domain_resolver, auto_detect_interface, cache_file.
  for (const name of Object.keys(input)) {
    if (name !== "dns" && name !== "route") {
      assert.ok(same(input[name], out[name]), `${name} changed`);
    }
  }
  for (const name of Object.keys(input.route)) {
    if (name !== "rules") {
      assert.ok(same(input.route[name], out.route[name]), `route.${name} changed`);
    }
  }
  for (const name of Object.keys(input.dns)) {
    if (name !== "servers" && name !== "rules") {
      assert.ok(same(input.dns[name], out.dns[name]), `dns.${name} changed`);
    }
  }
  assertNoRefusedFields(out);
}

/** What the 1.14 core refuses or warns about must not come from us. */
function assertNoRefusedFields(out: Json): void {
  const text = JSON.stringify(out);
  for (const field of ["download_detour", "http_client", "initial_path", "domain_regex", "update_interval"]) {
    assert.ok(!text.includes(field), field);
  }
  for (const rule of dnsRules(out)) {
    if (rule.type === "logical") {
      assert.equal(rule.strategy, undefined);
      assert.ok(!JSON.stringify(rule).includes(GEOIP_TAG));
    }
  }
}

test("our profile with FakeDNS: ours go ahead of the HTTPS/SVCB reject, the LAN bypass stays above", () => {
  const input = parse(MIXED);
  const result = applyRussiaDirect(MIXED, ON);
  assert.equal(result.state, "on");
  assert.ok(result.applied);
  assert.ok(result.usesDnsRu);
  const out = parse(result.content);
  assertBlock(input, out, { withSets: true });
  const rules = dnsRules(out);
  assert.equal(rules[0].action, "predefined");
  assert.equal(rules[1].server, DNS_RU_TAG);
  assert.equal(rules[2].action, "reject");
  assert.equal(rules[3].server, "dns-fakeip");
  const route = routeRules(out);
  assert.equal(route[0].action, "sniff");
  assert.equal(route[1].action, "hijack-dns");
  assert.equal(route[2].ip_is_private, true);
  assert.ok(isTorrent(route[3]));
  assert.equal(route.length, 6);
  assert.equal(out.route.final, "select");
});

test("without FakeDNS our DNS rules are the only ones", () => {
  const input = parse(MIXED_NO_FAKEDNS);
  const out = parse(applyRussiaDirect(MIXED_NO_FAKEDNS, ON).content);
  assertBlock(input, out, { withSets: true });
  assert.equal(dnsRules(out).length, 2);
  assert.ok(!JSON.stringify(out).includes("dns-fakeip"));
});

test("per-app modes: ours go ahead of the process rules", () => {
  for (const fixture of [ONLY_SELECTED, ALL_EXCEPT]) {
    const input = parse(fixture);
    const out = parse(applyRussiaDirect(fixture, ON).content);
    assertBlock(input, out, { withSets: true });
    const route = routeRules(out);
    const perApp = route.findIndex(isPerApp);
    assert.ok(perApp > 0);
    assert.ok(isTorrent(route[perApp - 3]));
    assert.equal(route[perApp - 1].rules[0].rule_set[0], GEOIP_TAG);
  }
  // "Only selected": everything unmatched stays direct, as before.
  assert.equal(parse(applyRussiaDirect(ONLY_SELECTED, ON).content).route.final, "direct");
});

test("all the other shapes the generator makes", () => {
  for (const fixture of [NO_LAN, XHTTP, NO_IPV6]) {
    const input = parse(fixture);
    assertBlock(input, parse(applyRussiaDirect(fixture, ON).content), { withSets: true });
  }
  // The bridges stay in the profile for the core to start.
  const xhttp = parse(applyRussiaDirect(XHTTP, ON).content);
  assert.ok(xhttp.vpn4tv?.xray);
});

test("bridges only: ipv4_only stays, Outline and AmneziaWG carry UDP so nothing refuses it", () => {
  const input = parse(TCP_BRIDGES);
  const out = parse(applyRussiaDirect(TCP_BRIDGES, ON).content);
  assertBlock(input, out, { withSets: true });
  assert.equal(out.dns.strategy, "ipv4_only");
  assert.equal(routeRules(out).some((rule) => rule.network === "udp"), false);
  for (const bridge of ["outline", "wireproxy", "olcrtc", "trusttunnel"]) {
    assert.ok(out.vpn4tv?.[bridge], bridge);
  }
});

test("TCP-only bridges: Russia direct goes ahead of the clock sync and the UDP refusal", () => {
  const out = parse(applyRussiaDirect(base(["tt", "olcrtc"]), ON).content);
  const rules = routeRules(out);
  assert.deepEqual(rules.at(-1), { network: "udp", action: "reject" });
  assert.deepEqual(rules.at(-2), { network: "udp", port: 123, action: "route", outbound: "direct" });
  const torrents = rules.findIndex((rule) => JSON.stringify(rule).includes("bittorrent"));
  assert.ok(torrents >= 0 && torrents < rules.length - 2, "torrents direct before the refusal");
  const geoip = rules.findIndex((rule) => JSON.stringify(rule).includes("geoip"));
  assert.ok(geoip >= 0 && geoip < rules.length - 2, "Russian addresses direct before the refusal");
});

test("Everything through VPN and our server's off switch leave only the torrent rule", () => {
  for (const [offReason, expected] of [
    ["user", "off (user); torrents direct"],
    ["head", "off (head); torrents direct"],
  ] as const) {
    for (const [name, fixture] of Object.entries(FIXTURES)) {
      const input = parse(fixture);
      const result = applyRussiaDirect(fixture, { offReason, sets: BUNDLED_RULE_SETS });
      assert.equal(result.state, expected, name);
      assert.ok(!result.applied);
      assert.ok(!result.usesDnsRu);
      const out = parse(result.content);
      assert.ok(same(input.dns, out.dns), name);
      const inRoute = routeRules(input);
      const outRoute = routeRules(out);
      assert.equal(outRoute.length, inRoute.length + 1);
      let at = inRoute.findIndex(isPerApp);
      if (at < 0) {
        at = inRoute.length;
      }
      assert.ok(isTorrent(outRoute[at]), name);
      assert.equal(out.route.rule_set, undefined);
      assert.ok(!result.content.includes(DNS_RU_TAG));
    }
  }
});

test("without rule-set data Russian names go by the suffixes", () => {
  for (const fixture of [MIXED, MIXED_NO_FAKEDNS, TCP_BRIDGES, ONLY_SELECTED]) {
    const result = applyRussiaDirect(fixture, { sets: null });
    assert.equal(result.state, "on (suffixes)");
    assert.ok(result.applied);
    assertBlock(parse(fixture), parse(result.content), { withSets: false });
  }
});

test("the dns-ru fallback resolves through dns-direct", () => {
  const result = applyRussiaDirect(MIXED, { ...ON, dnsRuFallback: true });
  assert.equal(result.state, "on (dns-direct)");
  assert.ok(!result.usesDnsRu);
  assertBlock(parse(MIXED), parse(result.content), { withSets: true, dnsServer: "dns-direct" });
  assert.equal(applyRussiaDirect(MIXED, { sets: null, dnsRuFallback: true }).state, "on (suffixes, dns-direct)");
});

test("extra exceptions from our server join the built-in ones", () => {
  const extra = ["blocked-one.ru", "jut.su", "blocked-two.su"];
  const out = parse(applyRussiaDirect(MIXED, { ...ON, extraExceptions: extra }).content);
  assertBlock(parse(MIXED), out, { withSets: true, extra });
});

test("old DNS rule fields keep the block out, the torrent rule goes in", () => {
  const legacy = parse(MIXED_NO_FAKEDNS);
  legacy.dns.rules = [{ domain_suffix: [".example"], server: "dns-direct", strategy: "prefer_ipv4" }];
  const text = JSON.stringify(legacy);
  const result = applyRussiaDirect(text, ON);
  assert.equal(result.state, "off (legacy: dns.rules[0].strategy); torrents direct");
  assert.ok(!result.applied);
  const out = parse(result.content);
  assert.ok(same(legacy.dns, out.dns));
  assert.ok(isTorrent(routeRules(out).at(-1)!));
});

test("every legacy DNS field is seen", () => {
  const withRule = (rule: Json): Json => {
    const config = parse(MIXED_NO_FAKEDNS);
    config.dns.rules = [rule];
    return config;
  };
  const legacy: Json[] = [
    { domain: ["a.example"], server: "dns-direct", strategy: "ipv4_only" },
    { ip_cidr: ["10.0.0.0/8"], server: "dns-direct" },
    { ip_is_private: true, server: "dns-direct" },
    { ip_accept_any: true, server: "dns-direct" },
    { response_rcode: "NXDOMAIN", server: "dns-direct" },
    { rule_set: ["some-set"], server: "dns-direct" },
    { rule_set_ip_cidr_accept_empty: true, server: "dns-direct" },
    {
      type: "logical",
      mode: "or",
      server: "dns-direct",
      rules: [{ domain: ["a.example"] }, { ip_cidr: ["10.0.0.0/8"] }],
    },
  ];
  for (const rule of legacy) {
    assert.notEqual(legacyDnsReason(withRule(rule)), null, JSON.stringify(rule));
    assert.ok(!applyRussiaDirect(JSON.stringify(withRule(rule)), ON).applied);
  }
  const fine: Json[] = [
    { ip_cidr: ["10.0.0.0/8"], match_response: true, server: "dns-direct" },
    { domain: ["a.example"], server: "dns-direct", strategy: "as_is" },
    { ip_is_private: false, server: "dns-direct" },
    { ip_cidr: [], server: "dns-direct" },
  ];
  for (const rule of fine) {
    assert.equal(legacyDnsReason(withRule(rule)), null, JSON.stringify(rule));
  }
});

test("a foreign sing-box config is left alone, byte for byte", () => {
  const foreign = JSON.stringify(
    {
      log: { level: "info" },
      dns: { servers: [{ type: "udp", tag: "google", server: "8.8.8.8" }] },
      inbounds: [{ type: "tun", tag: "tun-in", address: ["172.19.0.1/30"], auto_route: true }],
      outbounds: [
        { type: "vless", tag: "proxy", server: "192.0.2.50", server_port: 443, uuid: "11111111-2222-3333-4444-555555555555" },
        { type: "direct", tag: "direct" },
      ],
      route: { rules: [{ action: "sniff" }], final: "proxy" },
    },
    null,
    2,
  );
  // What the generator passes through for a pasted sing-box config.
  const passthrough = generateConfig(parseSubscription(foreign));
  for (const text of [foreign, passthrough]) {
    for (const options of [ON, { offReason: "user", sets: BUNDLED_RULE_SETS }, { sets: null }]) {
      const result = applyRussiaDirect(text, options);
      assert.equal(result.content, text);
      assert.ok(!result.applied);
      assert.match(result.state, /^off \(not ours/u);
    }
  }
});

test("our shape is required", () => {
  const edits: ((config: Json) => void)[] = [
    (config) => delete config.outbounds,
    (config) => (config.outbounds = config.outbounds.filter((outbound: Json) => outbound.tag !== "direct")),
    (config) => (config.outbounds = config.outbounds.filter((outbound: Json) => outbound.tag !== "select")),
    (config) => (config.dns.servers = config.dns.servers.filter((server: Json) => server.tag !== "dns-direct")),
    (config) => config.dns.servers.push({ type: "udp", tag: "dns-ru", server: "192.0.2.1" }),
    (config) => (config.route.rule_set = [{ tag: "geoip-ru", type: "inline", rules: [{ ip_cidr: ["192.0.2.0/24"] }] }]),
    (config) => config.route.rules.push({ protocol: "bittorrent", action: "reject" }),
    (config) => delete config.route,
    (config) => delete config.dns,
  ];
  for (const edit of edits) {
    const config = parse(MIXED);
    edit(config);
    assert.notEqual(russiaDirectNotOursReason(config), null);
    const text = JSON.stringify(config);
    assert.equal(applyRussiaDirect(text, ON).content, text);
  }
});

test("applying twice changes nothing", () => {
  const variants: RussiaDirectOptions[] = [
    ON,
    { sets: null },
    { ...ON, dnsRuFallback: true },
    { offReason: "user" },
    { offReason: "head", sets: BUNDLED_RULE_SETS },
  ];
  for (const options of variants) {
    const once = applyRussiaDirect(MIXED, options).content;
    const twice = applyRussiaDirect(once, options);
    assert.equal(twice.content, once);
    assert.ok(!twice.applied);
  }
});

test("not JSON comes back as is; the result is compact", () => {
  const text = "not a config";
  const result = applyRussiaDirect(text, ON);
  assert.equal(result.content, text);
  assert.ok(!result.applied);
  assert.equal(result.state, "off (not a JSON object)");
  const applied = applyRussiaDirect(MIXED, ON).content;
  assert.ok(!applied.includes("\n"));
  // The inline data is the bulk; formatted it would double the size.
  assert.ok(applied.length < 400_000, `${applied.length}`);
});

test("the bundled rule sets are usable, broken ones are not", () => {
  assert.equal(usableRuleSets(), BUNDLED_RULE_SETS);
  assert.ok(BUNDLED_RULE_SETS.geosite.length > 0 && BUNDLED_RULE_SETS.geoip.length > 0);
  assert.equal(usableRuleSets({ geosite: [], geoip: BUNDLED_RULE_SETS.geoip }), null);
  assert.equal(usableRuleSets({ geosite: BUNDLED_RULE_SETS.geosite, geoip: [{ ip_cidr: [] }] }), null);
  assert.equal(usableRuleSets({ geosite: BUNDLED_RULE_SETS.geoip, geoip: BUNDLED_RULE_SETS.geosite }), null);
  assert.equal(usableRuleSets({ geosite: [{ domain: ["a.example"] }], geoip: [{ ip_cidr: ["192.0.2.0/24"] }] })?.geosite.length, 1);
});

test("x-vpn4tv-ru-vpn: names are cleaned up, anything else is dropped", () => {
  assert.deepEqual(parseNameList(" A.ru , b.su,,.c.ru "), ["a.ru", "b.su", ".c.ru"]);
  assert.deepEqual(parseNameList("xn--p1ai"), ["xn--p1ai"]);
  assert.deepEqual(parseNameList(null), []);
  assert.deepEqual(parseNameList("  "), []);
  assert.deepEqual(parseNameList(`ok.ru,bad name.ru,"q".ru,a/b.ru,..,x..y.ru,${"a".repeat(254)}`), ["ok.ru"]);
  assert.deepEqual(parseNameList("dup.ru,DUP.ru"), ["dup.ru"]);
  assert.equal(parseNameList(Array.from({ length: 600 }, (_, index) => `n${index}.ru`).join(",")).length, 500);
});

test("the lists hold together", () => {
  assert.ok(RU_SUFFIXES.length > 0 && RU_VPN_EXCEPTIONS.length > 0);
  assert.equal(new Set(RU_SUFFIXES).size, RU_SUFFIXES.length);
  assert.equal(new Set(RU_VPN_EXCEPTIONS).size, RU_VPN_EXCEPTIONS.length);
  assert.ok(RU_SUFFIXES.every((suffix) => !RU_VPN_EXCEPTIONS.includes(suffix)));
  assert.match(DNS_RU_SERVER, /^\d+\.\d+\.\d+\.\d+$/u);
});

test("a crash report's config snapshot goes without the rule-set data", () => {
  const applied = applyRussiaDirect(MIXED, ON).content;
  const trimmed = withoutRuleSetData(applied);
  assert.ok(trimmed.length < applied.length / 5, `${trimmed.length} of ${applied.length}`);
  const config = parse(trimmed);
  assert.deepEqual(
    config.route.rule_set.map((set: Json) => [set.tag, set.type, typeof set.rules]),
    [
      [GEOSITE_TAG, "inline", "string"],
      [GEOIP_TAG, "inline", "string"],
    ],
  );
  assert.ok(same(parse(applied).route.rules, config.route.rules));
  for (const text of [MIXED, "not json", applyRussiaDirect(MIXED, { sets: null }).content]) {
    assert.equal(withoutRuleSetData(text), text);
  }
});
