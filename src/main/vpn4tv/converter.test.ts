// VPN4TV converter tests. Run with:  node --test out-test/**/*.test.js
// (see scripts/test-converter.sh — the repo's Node/pnpm toolchain is not needed).

import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateSync } from "node:zlib";

import { BRIDGE_CONFIG_KEY, BRIDGE_PORTS, NoProxiesError, generateConfig } from "./generator";
import { stripTunIPv6 } from "./ipv6";
import { decodeVpn4tvLink, parseSubscription, resetLastDns } from "./parser";

function parseGenerated(proxies: Parameters<typeof generateConfig>[0]): Record<string, any> {
  return JSON.parse(generateConfig(proxies));
}

test("vless reality URI becomes a native sing-box outbound", () => {
  const uri =
    "vless://11111111-2222-3333-4444-555555555555@example.com:443" +
    "?security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision&type=tcp#Server%20A";
  const [proxy] = parseSubscription(uri);
  assert.equal(proxy.tag, "Server A");
  assert.equal(proxy.server, "example.com");
  assert.equal(proxy.serverPort, 443);
  assert.equal(proxy.outbound.type, "vless");
  assert.equal(proxy.outbound.flow, "xtls-rprx-vision");
  const tls = proxy.outbound.tls as Record<string, any>;
  assert.equal(tls.server_name, "www.apple.com");
  assert.equal(tls.reality.public_key, "PUBKEY");
  assert.equal(tls.utls.fingerprint, "chrome");
  assert.equal(proxy.xrayOutbound, undefined, "reality/tcp must not need the xray bridge");
});

test("vless xhttp goes through the xray bridge", () => {
  const uri =
    "vless://11111111-2222-3333-4444-555555555555@example.com:8443" +
    "?security=tls&sni=cdn.example.com&type=xhttp&path=%2Fdl&mode=packet-up#XH";
  const [proxy] = parseSubscription(uri);
  assert.ok(proxy.xrayOutbound, "xhttp is not a native sing-box transport");
  const stream = proxy.xrayOutbound!.streamSettings as Record<string, any>;
  assert.equal(stream.network, "xhttp");
  assert.equal(stream.xhttpSettings.path, "/dl");
  assert.equal(stream.xhttpSettings.mode, "packet-up");

  const config = parseGenerated([proxy]);
  const outbound = (config.outbounds as any[]).find((entry) => entry.tag === "XH");
  assert.equal(outbound.type, "socks", "the bridge is reached over loopback socks");
  assert.equal(outbound.server, BRIDGE_PORTS.socksHost);
  assert.equal(outbound.server_port, BRIDGE_PORTS.base);
  assert.ok(config[BRIDGE_CONFIG_KEY].xray, "bridge config must travel with the profile");
  assert.equal(config[BRIDGE_CONFIG_KEY].xray.inbounds[0].port, BRIDGE_PORTS.base);
});

test("olcrtc: the link goes to the bridge whole, the comment names the server", () => {
  const key = "0123456789abcdef".repeat(4);
  const link = `olcrtc://jitsi?datachannel@https://meet.example.org/room-42#${key}$RU%20/%20whitelist`;
  const [proxy] = parseSubscription(link);
  assert.equal(proxy.type, "olcrtc");
  assert.equal(proxy.tag, "RU / whitelist");
  assert.equal(proxy.server, "meet.example.org");
  assert.equal(proxy.olcrtcUrl, link);
  const config = parseGenerated([proxy]);
  const outbound = (config.outbounds as any[]).find((entry) => entry.tag === "RU / whitelist");
  assert.equal(outbound.type, "socks");
  assert.equal(outbound.server_port, BRIDGE_PORTS.base + BRIDGE_PORTS.olcrtcOffset);
  assert.equal(config[BRIDGE_CONFIG_KEY].olcrtc.endpoints[0].url, link);
  assert.equal(config[BRIDGE_CONFIG_KEY].olcrtc.endpoints[0].listen, BRIDGE_PORTS.socksHost);
  // A link without a valid key is not a server.
  assert.equal(parseSubscription("olcrtc://jitsi?datachannel@https://meet.example.org/r#short").length, 0);
});

test("shadowsocks: plain is native, prefixed goes to the outline bridge", () => {
  const userInfo = Buffer.from("aes-256-gcm:secret", "utf8").toString("base64");
  const [plain] = parseSubscription(`ss://${userInfo}@1.2.3.4:8388#Plain`);
  assert.equal(plain.outbound.type, "shadowsocks");
  assert.equal(plain.outbound.method, "aes-256-gcm");
  assert.equal(plain.outlineUrl, undefined);

  const [outline] = parseSubscription(`ss://${userInfo}@1.2.3.4:8388?prefix=%16%03%01#Outline`);
  assert.ok(outline.outlineUrl, "a SIP002 prefix requires the outline bridge");
  const config = parseGenerated([outline]);
  const outbound = (config.outbounds as any[]).find((entry) => entry.tag === "Outline");
  assert.equal(outbound.server_port, BRIDGE_PORTS.base + BRIDGE_PORTS.outlineOffset);
  assert.equal(
    config[BRIDGE_CONFIG_KEY].outline.endpoints[0].port,
    BRIDGE_PORTS.base + BRIDGE_PORTS.outlineOffset,
  );
});

test("vmess base64 payload", () => {
  const payload = Buffer.from(
    JSON.stringify({
      v: "2",
      ps: "VM",
      add: "vm.example.com",
      port: "443",
      id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      aid: "0",
      net: "ws",
      path: "/ws",
      host: "vm.example.com",
      tls: "tls",
    }),
    "utf8",
  ).toString("base64");
  const [proxy] = parseSubscription(`vmess://${payload}`);
  assert.equal(proxy.tag, "VM");
  assert.equal(proxy.outbound.type, "vmess");
  assert.equal((proxy.outbound.transport as any).type, "ws");
  assert.equal((proxy.outbound.transport as any).path, "/ws");
  assert.equal((proxy.outbound.tls as any).server_name, "vm.example.com");
});

test("hysteria2 and trojan", () => {
  const [hy] = parseSubscription("hy2://pass@h2.example.com:443?sni=h2.example.com&obfs=salamander&obfs-password=x#H2");
  assert.equal(hy.outbound.type, "hysteria2");
  assert.equal((hy.outbound.obfs as any).type, "salamander");

  const [trojan] = parseSubscription("trojan://pw@tj.example.com:443?sni=tj.example.com&type=ws&path=/t#TJ");
  assert.equal(trojan.outbound.type, "trojan");
  assert.equal((trojan.outbound.transport as any).path, "/t");
});

test("wg:// URI becomes an AmneziaWG INI on the wireproxy bridge", () => {
  const uri =
    "wg://wg.example.com:51820?private_key=PRIV&peer_public_key=PUB&local_address=10.8.0.2%2F32" +
    "&awg_jc=4&fake_packets=10-50&fake_packets_size=20-80#WG";
  const [proxy] = parseSubscription(uri);
  assert.ok(proxy.awgIni);
  assert.match(proxy.awgIni!, /PrivateKey = PRIV/);
  assert.match(proxy.awgIni!, /Jc = 4/);
  assert.match(proxy.awgIni!, /Jmin = 10/);
  assert.match(proxy.awgIni!, /Endpoint = wg\.example\.com:51820/);

  const config = parseGenerated([proxy]);
  const outbound = (config.outbounds as any[]).find((entry) => entry.tag === "WG");
  assert.equal(outbound.server_port, BRIDGE_PORTS.base + BRIDGE_PORTS.wireguardOffset);
  assert.equal(outbound.domain_strategy, "ipv4_only");
  assert.ok(config[BRIDGE_CONFIG_KEY].wireproxy.endpoints[0].ini.includes("PrivateKey"));
  assert.equal(config.dns.strategy, "ipv4_only", "an all-TCP-bridged profile resolves v4 only");
});

test("base64-wrapped subscription with several lines", () => {
  const userInfo = Buffer.from("aes-256-gcm:secret", "utf8").toString("base64");
  const lines = [
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&sni=a#A",
    `ss://${userInfo}@1.2.3.4:8388#B`,
  ].join("\n");
  const proxies = parseSubscription(Buffer.from(lines, "utf8").toString("base64"));
  assert.equal(proxies.length, 2);
  assert.deepEqual(
    proxies.map((proxy) => proxy.tag),
    ["A", "B"],
  );
});

test("native sing-box config passes through untouched", () => {
  const singbox = {
    inbounds: [{ type: "tun", tag: "tun-in" }],
    outbounds: [{ type: "direct", tag: "direct" }],
  };
  const proxies = parseSubscription(JSON.stringify(singbox));
  assert.equal(proxies.length, 1);
  assert.deepEqual(JSON.parse(generateConfig(proxies)), singbox);
});

test("xray JSON subscription: native transports inline, DNS captured", () => {
  resetLastDns();
  const xray = {
    dns: { servers: ["https+local://dns.google/dns-query", "1.0.0.1"] },
    outbounds: [
      {
        tag: "X1",
        protocol: "vless",
        settings: { vnext: [{ address: "x.example.com", port: 443, users: [{ id: "uuid-1", flow: "" }] }] },
        streamSettings: {
          network: "ws",
          security: "tls",
          tlsSettings: { serverName: "x.example.com", fingerprint: "chrome" },
          wsSettings: { path: "/ws", headers: { Host: "x.example.com" } },
        },
      },
    ],
  };
  const proxies = parseSubscription(JSON.stringify(xray));
  assert.equal(proxies.length, 1);
  assert.equal(proxies[0].outbound.type, "vless");
  assert.equal((proxies[0].outbound.transport as any).path, "/ws");

  const config = parseGenerated(proxies);
  const dnsServers = config.dns.servers as any[];
  assert.equal(dnsServers[0].server, "dns.google", "remote DNS from the subscription");
  assert.equal(dnsServers[1].server, "1.0.0.1", "direct DNS from the subscription");
});

test("AmneziaVPN vpn:// payload (zlib) yields the embedded wg config", () => {
  const inner = {
    description: "Amnezia RU",
    dns1: "9.9.9.9",
    dns2: "149.112.112.112",
    containers: [
      {
        awg: {
          last_config: JSON.stringify({
            config:
              "[Interface]\nPrivateKey = PRIV\nAddress = 10.8.1.2/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\n\n[Peer]\nPublicKey = PUB\nAllowedIPs = 0.0.0.0/0\nEndpoint = amnezia.example.com:35000\n",
          }),
        },
      },
    ],
  };
  const compressed = deflateSync(Buffer.from(JSON.stringify(inner), "utf8"));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(Buffer.byteLength(JSON.stringify(inner)), 0);
  const payload = Buffer.concat([length, compressed]).toString("base64url");

  const proxies = parseSubscription(`vpn://${payload}`);
  assert.equal(proxies.length, 1);
  assert.equal(proxies[0].tag, "Amnezia RU");
  assert.match(proxies[0].awgIni!, /Endpoint = amnezia\.example\.com:35000/);
  assert.match(proxies[0].awgIni!, /DNS = 9\.9\.9\.9, 149\.112\.112\.112/, "DNS placeholders are substituted");
});

test("duplicate tags are made unique", () => {
  const uri = (name: string) =>
    `vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&sni=a#${name}`;
  const proxies = parseSubscription([uri("Same"), uri("Same"), uri("Same")].join("\n"));
  const config = parseGenerated(proxies);
  const tags = (config.outbounds as any[])
    .filter((entry) => entry.type === "vless")
    .map((entry) => entry.tag);
  assert.deepEqual(tags, ["Same", "Same_2", "Same_3"]);
});

test("generated profile shape: selector, urltest, route and fakeip", () => {
  const [proxy] = parseSubscription(
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&sni=a#A",
  );
  const config = parseGenerated([proxy]);
  const outbounds = config.outbounds as any[];
  assert.equal(outbounds[0].type, "urltest");
  assert.equal(outbounds[1].type, "selector");
  assert.deepEqual(outbounds[1].outbounds, ["auto", "A"]);
  assert.equal(config.route.final, "select");
  assert.deepEqual(config.route.default_domain_resolver, { server: "dns-direct" });
  assert.equal(config.experimental.cache_file.store_fakeip, true);
  assert.equal(config[BRIDGE_CONFIG_KEY], undefined, "no bridges → no private key in the profile");
});

test("the server choice survives a restart, and LAN stays off the tunnel", () => {
  const [proxy] = parseSubscription(
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&sni=a#A",
  );
  // Defaults: the cache file remembers the selection even with FakeDNS off.
  const plain = JSON.parse(generateConfig([proxy], { fakeDns: false }));
  // The selector persists its choice as soon as the cache file exists.
  assert.equal(plain.experimental.cache_file.enabled, true);
  assert.equal(plain.experimental.cache_file.store_selected, undefined);
  assert.equal(plain.experimental.cache_file.store_fakeip, undefined);
  const privateRule = (plain.route.rules as any[]).find((rule) => rule.ip_is_private === true);
  assert.deepEqual(privateRule, { ip_is_private: true, outbound: "direct" });
  // …and the sniff/hijack rules still come first.
  assert.equal(plain.route.rules[0].action, "sniff");
  assert.equal(plain.route.rules[1].action, "hijack-dns");

  const noBypass = JSON.parse(generateConfig([proxy], { lanBypass: false }));
  assert.equal(
    (noBypass.route.rules as any[]).some((rule) => rule.ip_is_private === true),
    false,
  );
});

test("split tunnelling by application", () => {
  const [proxy] = parseSubscription(
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&sni=a#A",
  );
  const apps = ["chrome.exe", "Telegram"];

  // Exclude: the listed applications go direct, everything else is proxied.
  const exclude = JSON.parse(
    generateConfig([proxy], { perApp: { mode: "exclude", apps } }),
  );
  assert.deepEqual(
    (exclude.route.rules as any[]).find((rule) => rule.process_name !== undefined),
    { process_name: apps, outbound: "direct" },
  );
  assert.equal(exclude.route.final, "select");

  // Include: only the listed applications are proxied, so the default flips.
  const include = JSON.parse(
    generateConfig([proxy], { perApp: { mode: "include", apps } }),
  );
  assert.deepEqual(
    (include.route.rules as any[]).find((rule) => rule.process_name !== undefined),
    { process_name: apps, outbound: "select" },
  );
  assert.equal(include.route.final, "direct");

  // An empty list must not flip the default and strand the user offline.
  const empty = JSON.parse(generateConfig([proxy], { perApp: { mode: "include", apps: [] } }));
  assert.equal(empty.route.final, "select");
  assert.equal(
    (empty.route.rules as any[]).some((rule) => rule.process_name !== undefined),
    false,
  );
});

test("vpn4tv:// links unwrap to whatever they carry", () => {
  const keys =
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&sni=a#A\n" +
    "vless://11111111-2222-3333-4444-555555555555@b.example.com:443?security=tls&sni=b#B";
  const wrap = (payload: string) =>
    "vpn4tv://" + Buffer.from(payload).toString("base64url");

  // Server links inside are parsed exactly as if they had been pasted.
  const proxies = parseSubscription(wrap(keys));
  assert.deepEqual(proxies.map((proxy) => proxy.tag), ["A", "B"]);

  // base64url: "-" and "_" must survive, and a #name is not part of the payload.
  assert.equal(decodeVpn4tvLink(wrap("https://example.com/sub?a=1") + "#My%20VPN"),
    "https://example.com/sub?a=1");

  // A subscription URL comes back intact, so the caller can keep it remote.
  assert.equal(decodeVpn4tvLink(wrap("https://example.com/sub")), "https://example.com/sub");

  // Not ours, or undecodable, or decodes to noise → null, so callers fall through.
  assert.equal(decodeVpn4tvLink("vless://x@y:443#Z"), null);
  assert.equal(decodeVpn4tvLink("vpn4tv://"), null);
  assert.equal(decodeVpn4tvLink("vpn4tv://" + Buffer.from("hello").toString("base64")), null);
});

test("ssconf:// is carried into the profile, not resolved at import", () => {
  const proxies = parseSubscription("ssconf://keys.example.com/abc123#Outline");
  assert.equal(proxies.length, 1);
  assert.equal(proxies[0].outlineDynamicUrl, "https://keys.example.com/abc123");
  assert.equal(proxies[0].tag, "Outline");
  // No static key is invented — that is the client's job at connect time.
  assert.equal(proxies[0].outlineUrl, undefined);

  const config = JSON.parse(generateConfig(proxies));
  const endpoints = config[BRIDGE_CONFIG_KEY].outline.endpoints as any[];
  assert.equal(endpoints.length, 1);
  assert.equal(endpoints[0].dynamicUrl, "https://keys.example.com/abc123");
  // The outbound still points at the bridge, so routing works before the fetch.
  const outbound = (config.outbounds as any[]).find((o) => o.tag === "Outline");
  assert.equal(outbound.type, "socks");
});

test("a machine without IPv6 gets an IPv4-only tunnel", () => {
  const [proxy] = parseSubscription(
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&sni=a#A",
  );
  const profile = generateConfig([proxy]);
  const before = JSON.parse(profile);
  assert.equal((before.inbounds[0].address as string[]).length, 2, "profile is dual-stack to begin with");

  const stripped = JSON.parse(stripTunIPv6(profile));
  assert.deepEqual(stripped.inbounds[0].address, ["172.19.0.1/30"]);
  // The fake-IP pool must not hand out AAAA answers either.
  const fakeip = (stripped.dns.servers as any[]).find((s) => s.type === "fakeip");
  if (fakeip !== undefined) {
    assert.equal(fakeip.inet6_range, undefined);
    assert.ok(fakeip.inet4_range, "the IPv4 pool stays");
  }
  // Everything else is left alone.
  assert.equal(stripped.inbounds[0].auto_route, before.inbounds[0].auto_route);
  assert.deepEqual(stripped.outbounds, before.outbounds);

  // Nothing to strip → the exact same string back, so this is safe every start.
  assert.equal(stripTunIPv6(stripTunIPv6(profile)), stripTunIPv6(profile));
  assert.equal(stripTunIPv6("not json"), "not json");
});

test("xhttp carries the provider's extra settings through to xray", () => {
  const extra = encodeURIComponent(JSON.stringify({ xmux: { maxConnections: 1, cMaxReuseTimes: 0 } }));
  const proxies = parseSubscription(
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443" +
      `?encryption=none&type=xhttp&path=%2Fabc&mode=stream-one&extra=${extra}` +
      "&security=tls&sni=a.example.com&fp=chrome#X",
  );
  assert.equal(proxies.length, 1);
  const settings = (proxies[0].xrayOutbound as any).streamSettings.xhttpSettings;
  assert.equal(settings.path, "/abc");
  assert.equal(settings.mode, "stream-one");
  // xray-core unmarshals `extra` itself, so it travels as an object, untouched.
  assert.deepEqual(settings.extra, { xmux: { maxConnections: 1, cMaxReuseTimes: 0 } });

  // Malformed extra must not cost the user the whole server.
  const broken = parseSubscription(
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443" +
      "?encryption=none&type=xhttp&path=%2Fabc&extra=not-json&security=tls&sni=a#X",
  );
  assert.equal(broken.length, 1);
  assert.equal((broken[0].xrayOutbound as any).streamSettings.xhttpSettings.extra, undefined);
});

test("empty input is rejected", () => {
  assert.throws(() => generateConfig([]), NoProxiesError);
  assert.deepEqual(parseSubscription("   \n # comment\n"), []);
});
