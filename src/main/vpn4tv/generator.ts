// VPN4TV: TypeScript port of the config generator (Kotlin ConfigGenerator →
// Swift Library/Config/ConfigGenerator.swift → here).
//
// Difference from the mobile ports: the apps write the bridge configs to sidecar
// files and hand them to the tunnel process, because only the app can call the
// gomobile bridge entry points. The desktop client cannot — it only speaks gRPC
// to the daemon — so the bridge configs are embedded in the profile itself under
// the private "vpn4tv" key, and the core starts them (see the Go package
// experimental/vpn4tvbridge in our sing-box fork).

import { randomUUID } from "node:crypto";

import { type Json, str } from "./support";
import { SINGBOX_PASSTHROUGH_TAG, lastDns, type ProxyConfig } from "./parser";

/** Loopback SOCKS ports for the embedded bridges. */
export const BRIDGE_PORTS = {
  // Desktop uses plain localhost: only 127.0.0.1 is assigned on macOS and
  // Windows (Linux/Android bind the whole 127.0.0.0/8, which is why the mobile
  // ports can afford 127.0.0.127 to stay off the busy localhost).
  socksHost: "127.0.0.1",
  base: 42890, // xray bucket
  outlineOffset: 1000, // outline bucket = base + 1000
  wireguardOffset: 2000, // wireproxy bucket = base + 2000
  olcrtcOffset: 3000, // olcrtc bucket = base + 3000
  trusttunnelOffset: 4000, // trusttunnel bucket = base + 4000
} as const;

/** Config key the core strips and interprets (must match vpn4tvbridge.Key). */
export const BRIDGE_CONFIG_KEY = "vpn4tv";

export class NoProxiesError extends Error {
  constructor() {
    super("No servers found in the subscription.");
    this.name = "NoProxiesError";
  }
}

/**
 * Build a complete sing-box profile (JSON string) from parsed proxies, with the
 * bridge configs embedded when bridge transports are present.
 */
export interface GenerateOptions {
  /** FakeDNS bypasses DNS blocking; users on networks where the fakeip path is
   *  broken can turn it off (the mobile clients expose the same switch). */
  fakeDns?: boolean;
  /** Keep LAN traffic off the tunnel — otherwise a network drive, a printer or
   *  the router's own page stops answering while connected. Default on, as on
   *  Android. */
  lanBypass?: boolean;
  /** Split tunnelling by application. Android matches package names; here the
   *  core matches executable names (process_name), which works the same way on
   *  Windows, macOS and Linux. */
  perApp?: PerAppProxy;
}

export type PerAppMode = "off" | "exclude" | "include";

export interface PerAppProxy {
  mode: PerAppMode;
  /** Executable names, e.g. "chrome.exe" or "Telegram". */
  apps: string[];
}

export function generateConfig(input: ProxyConfig[], options: GenerateOptions = {}): string {
  if (input.length === 0) {
    throw new NoProxiesError();
  }
  // Native sing-box config — pass through untouched.
  if (input.length === 1 && input[0].type === "singbox" && input[0].tag === SINGBOX_PASSTHROUGH_TAG) {
    return JSON.stringify(input[0].outbound, null, 2);
  }

  const proxies = input.map((proxy) => ({ ...proxy, outbound: { ...proxy.outbound } }));

  // xray-managed (xhttp/splithttp). TCP and UDP: UDP rides inside the TCP
  // connection to the bridge as XUDP (see xrayBridgeOutbound). One client id
  // per profile, in sing-box's outbound and in the bridge's inbound.
  const xrayOutbounds: Json[] = [];
  const xrayUuid = randomUUID();
  for (const proxy of proxies) {
    if (!proxy.xrayOutbound) {
      continue;
    }
    const port = BRIDGE_PORTS.base + xrayOutbounds.length;
    xrayOutbounds.push(proxy.xrayOutbound);
    proxy.outbound = xrayBridgeOutbound(proxy.tag, port, xrayUuid);
  }

  // outline-managed (ss SIP002 with a prefix, or a dynamic ssconf:// key). TCP
  // and UDP: UDP rides inside the TCP connection to the bridge (udp_over_tcp),
  // and the bridge sends it to the Outline server as Shadowsocks UDP.
  const outlineUrls: { url?: string; dynamicUrl?: string }[] = [];
  for (const proxy of proxies) {
    if (proxy.outlineDynamicUrl) {
      const dynamicPort = BRIDGE_PORTS.base + BRIDGE_PORTS.outlineOffset + outlineUrls.length;
      outlineUrls.push({ dynamicUrl: proxy.outlineDynamicUrl });
      proxy.outbound = socksLoopback(proxy.tag, dynamicPort, true);
      continue;
    }
    if (!proxy.outlineUrl) {
      continue;
    }
    const port = BRIDGE_PORTS.base + BRIDGE_PORTS.outlineOffset + outlineUrls.length;
    outlineUrls.push({ url: proxy.outlineUrl });
    proxy.outbound = socksLoopback(proxy.tag, port, true);
  }

  // AmneziaWG: ipv4_only so sing-box resolves before CONNECT. TCP and UDP, UDP
  // inside the TCP connection like Outline's; the bridge sends it through the
  // tunnel's netstack.
  const wireguardInis: string[] = [];
  for (const proxy of proxies) {
    if (!proxy.awgIni) {
      continue;
    }
    const port = BRIDGE_PORTS.base + BRIDGE_PORTS.wireguardOffset + wireguardInis.length;
    wireguardInis.push(proxy.awgIni);
    proxy.outbound = { ...socksLoopback(proxy.tag, port, true), domain_strategy: "ipv4_only" };
  }

  // olcRTC: the link goes to the bridge whole; sing-box resolves before CONNECT,
  // the far end only dials what the SOCKS request names. TCP only by design.
  const olcrtcUrls: string[] = [];
  for (const proxy of proxies) {
    if (!proxy.olcrtcUrl) {
      continue;
    }
    const port = BRIDGE_PORTS.base + BRIDGE_PORTS.olcrtcOffset + olcrtcUrls.length;
    olcrtcUrls.push(proxy.olcrtcUrl);
    proxy.outbound = { ...socksLoopback(proxy.tag, port), domain_strategy: "ipv4_only" };
  }

  // TrustTunnel: the official client next to the daemon, one per link. TCP
  // only: the client's SOCKS UDP relay takes datagrams from any local process.
  const ttUrls: string[] = [];
  for (const proxy of proxies) {
    if (!proxy.ttUrl) {
      continue;
    }
    const port = BRIDGE_PORTS.base + BRIDGE_PORTS.trusttunnelOffset + ttUrls.length;
    ttUrls.push(proxy.ttUrl);
    proxy.outbound = { ...socksLoopback(proxy.tag, port), domain_strategy: "ipv4_only" };
  }

  dedupeTags(proxies);

  const fakeDns = options.fakeDns !== false && fakeDnsPossible(proxies);
  const config: Json = {
    log: { level: "info", timestamp: true },
    dns: buildDns(proxies, fakeDns),
    inbounds: [
      {
        type: "tun",
        tag: "tun-in",
        address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        auto_route: true,
        strict_route: true,
        stack: "mixed",
      },
    ],
    outbounds: buildOutbounds(proxies),
    route: buildRoute(proxies, options.lanBypass !== false, options.perApp),
  };
  // The cache file is what remembers the user's server choice across restarts;
  // fakeip storage rides along when FakeDNS is on.
  config.experimental = {
    cache_file: { enabled: true, ...(fakeDns ? { store_fakeip: true } : {}) },
  };

  const bridges: Json = {};
  if (xrayOutbounds.length > 0) {
    bridges.xray = buildXrayConfig(xrayOutbounds, xrayUuid);
  }
  if (outlineUrls.length > 0) {
    bridges.outline = buildEndpointConfig(
      outlineUrls,
      BRIDGE_PORTS.base + BRIDGE_PORTS.outlineOffset,
    );
  }
  if (wireguardInis.length > 0) {
    bridges.wireproxy = buildEndpointConfig(
      wireguardInis.map((ini) => ({ ini })),
      BRIDGE_PORTS.base + BRIDGE_PORTS.wireguardOffset,
    );
  }
  if (olcrtcUrls.length > 0) {
    bridges.olcrtc = buildEndpointConfig(
      olcrtcUrls.map((url) => ({ url })),
      BRIDGE_PORTS.base + BRIDGE_PORTS.olcrtcOffset,
    );
  }
  if (ttUrls.length > 0) {
    bridges.trusttunnel = buildEndpointConfig(
      ttUrls.map((url) => ({ url })),
      BRIDGE_PORTS.base + BRIDGE_PORTS.trusttunnelOffset,
    );
  }
  if (Object.keys(bridges).length > 0) {
    config[BRIDGE_CONFIG_KEY] = bridges;
  }

  return JSON.stringify(config, null, 2);
}

/**
 * A socks outbound to a bridge on the loopback. With udpOverTcp, sing-box's UDP
 * over TCP: the datagrams travel framed inside the same TCP connection (the
 * core's bridges serve it since bridge-udp), so nothing listens for UDP on the
 * loopback. Without it the outbound carries TCP only.
 */
function socksLoopback(tag: string, port: number, udpOverTcp = false): Json {
  return {
    type: "socks",
    tag,
    server: BRIDGE_PORTS.socksHost,
    server_port: port,
    version: "5",
    ...(udpOverTcp ? { udp_over_tcp: { enabled: true, version: 2 } } : { network: "tcp" }),
    // No bind_interface: "lo" is a Linux/Android-ism (macOS calls it lo0 and
    // Windows has no such name). The bridge lives in the daemon process, whose
    // own sockets auto_route already excludes, so there is no routing loop.
  };
}

/**
 * sing-box's outbound to the xray bridge inbound on port: VLESS without TLS over
 * the loopback. UDP goes as XUDP inside the same TCP connection, which xray
 * takes on through the outbound it was given; no network limit. As Android's
 * ConfigGenerator.toXrayBridgeOutbound.
 */
function xrayBridgeOutbound(tag: string, port: number, uuid: string): Json {
  return {
    type: "vless",
    tag,
    server: BRIDGE_PORTS.socksHost,
    server_port: port,
    uuid,
    packet_encoding: "xudp",
  };
}

/** Its outbound goes to one of our local bridges (xray included): DNS through it goes over TCP. */
function reachesBridge(proxy: ProxyConfig): boolean {
  return (
    proxy.xrayOutbound !== undefined ||
    proxy.outlineUrl !== undefined ||
    proxy.outlineDynamicUrl !== undefined ||
    proxy.awgIni !== undefined ||
    proxy.olcrtcUrl !== undefined ||
    proxy.ttUrl !== undefined
  );
}

/**
 * The TCP form of a DNS server type, for DNS that must not go over UDP: plain
 * DNS over TCP for udp, DNS over TLS for DNS over QUIC, DoH over HTTP/2 for DoH
 * over HTTP/3.
 */
export function tcpDnsType(type: string): string {
  switch (type) {
    case "udp":
      return "tcp";
    case "quic":
      return "tls";
    case "h3":
      return "https";
    default:
      return type;
  }
}

/**
 * Whether sing-box can send UDP through outbound, one of a generated profile's
 * proxies: the socks outbounds to olcRTC and TrustTunnel carry TCP only, the
 * vless outbound to the xray bridge carries XUDP, Outline and AmneziaWG carry
 * UDP over TCP, naive only with UDP over TCP on, http never.
 */
export function carriesUdp(outbound: Json): boolean {
  switch (str(outbound, "type")) {
    case "selector":
    case "urltest":
    case "direct":
    case "block":
    case "dns":
    case "http":
      return false;
    case "naive": {
      const udpOverTcp = outbound.udp_over_tcp;
      return (
        udpOverTcp === true ||
        (typeof udpOverTcp === "object" && udpOverTcp !== null && (udpOverTcp as Json).enabled === true)
      );
    }
    default:
      return str(outbound, "network") !== "tcp";
  }
}

/** sing-box requires unique outbound tags. */
function dedupeTags(proxies: ProxyConfig[]): void {
  const seen = new Set<string>();
  for (const proxy of proxies) {
    const original = str(proxy.outbound, "tag", proxy.tag);
    let tag = original;
    if (seen.has(tag)) {
      let index = 2;
      while (seen.has(`${original}_${index}`)) {
        index += 1;
      }
      tag = `${original}_${index}`;
      proxy.outbound.tag = tag;
    }
    seen.add(tag);
  }
}

/** Routed through a local bridge other than xray: what FakeDNS and the IPv4-only strategy look at. */
function allTcpBridged(proxies: ProxyConfig[]): boolean {
  return proxies.every(
    (proxy) =>
      proxy.outlineUrl !== undefined ||
      proxy.outlineDynamicUrl !== undefined ||
      proxy.awgIni !== undefined ||
      proxy.olcrtcUrl !== undefined ||
      proxy.ttUrl !== undefined,
  );
}

/** FakeDNS stays off for profiles made only of bridges, as before. */
function fakeDnsPossible(proxies: ProxyConfig[]): boolean {
  return !allTcpBridged(proxies);
}

function parseDnsUrl(url: string): { type: string; server: string } {
  for (const [prefix, type] of [
    ["https://", "https"],
    ["tls://", "tls"],
    ["quic://", "quic"],
    ["h3://", "h3"],
  ] as const) {
    if (url.startsWith(prefix)) {
      return { type, server: url.slice(prefix.length).split("/")[0] };
    }
  }
  return { type: "udp", server: url.replace("udp://", "") };
}

function buildDns(proxies: ProxyConfig[], fakeDns: boolean): Json {
  // DNS goes through the tunnel ("select") for every profile. Profiles made only
  // of bridges used to resolve without a detour, i.e. around the tunnel with the
  // real address, because no bridge carried UDP. Where a bridge can be picked,
  // the remote server is asked over TCP.
  const tcpOnly = allTcpBridged(proxies);
  const remote = parseDnsUrl(lastDns.remoteDns);
  const direct = parseDnsUrl(lastDns.directDns);

  const remoteServer: Json = {
    type: proxies.some(reachesBridge) ? tcpDnsType(remote.type) : remote.type,
    tag: "dns-remote",
    server: remote.server,
    domain_resolver: "dns-direct",
    detour: "select",
  };
  const servers: Json[] = [remoteServer, { type: direct.type, tag: "dns-direct", server: direct.server }];
  if (fakeDns) {
    servers.push({
      type: "fakeip",
      tag: "dns-fakeip",
      inet4_range: "198.18.0.0/15",
      inet6_range: "fc00::/18",
    });
  }

  // sing-box 1.12+: dial-field resolution comes from route.default_domain_resolver,
  // so only the fakeip/reject query-type rules belong here.
  const rules: Json[] = [];
  if (fakeDns) {
    rules.push({ query_type: ["HTTPS", "SVCB"], action: "reject" });
    rules.push({ query_type: ["A", "AAAA"], server: "dns-fakeip" });
  }
  const dns: Json = { servers, rules };
  if (tcpOnly) {
    dns.strategy = "ipv4_only";
  }
  return dns;
}

function buildOutbounds(proxies: ProxyConfig[]): Json[] {
  const tags = proxies.map((proxy) => str(proxy.outbound, "tag", proxy.tag));
  return [
    {
      type: "urltest",
      tag: "auto",
      outbounds: tags,
      url: "https://cp.cloudflare.com/",
      interval: "5m",
      tolerance: 50,
    },
    { type: "selector", tag: "select", outbounds: ["auto", ...tags], default: "auto" },
    ...proxies.map((proxy) => proxy.outbound),
    { type: "direct", tag: "direct" },
  ];
}

function buildRoute(proxies: ProxyConfig[], lanBypass: boolean, perApp?: PerAppProxy): Json {
  const rules: Json[] = [{ action: "sniff" }, { protocol: "dns", action: "hijack-dns" }];
  if (lanBypass) {
    // Before anything else: private destinations never belong in the tunnel.
    rules.push({ ip_is_private: true, outbound: "direct" });
  }
  // Split tunnelling. The router turns on process lookup by itself as soon as a
  // rule mentions a process, so no extra switch is needed.
  const apps = perApp?.apps.filter((app) => app.trim() !== "") ?? [];
  const perAppMode = apps.length === 0 ? "off" : (perApp?.mode ?? "off");
  if (perAppMode === "exclude") {
    rules.push({ process_name: apps, outbound: "direct" });
  } else if (perAppMode === "include") {
    rules.push({ process_name: apps, outbound: "select" });
  }
  // UDP never goes "direct" behind the user's back: that sent QUIC, calls and
  // WebRTC around the tunnel with the real address. A profile where no proxy
  // carries UDP (only olcRTC or TrustTunnel) refuses UDP outright, last: apps
  // take it as "no QUIC" and fall back to TCP at once. The clock sync (NTP)
  // goes direct just ahead of it; Russia direct goes ahead of both.
  if (!proxies.some((proxy) => carriesUdp(proxy.outbound))) {
    rules.push(ntpDirectRule(), udpRejectRule());
  }
  return {
    rules,
    auto_detect_interface: true,
    // In "only these applications" mode everything unmatched stays direct.
    final: perAppMode === "include" ? "direct" : "select",
    default_domain_resolver: { server: "dns-direct" },
  };
}

/** The clock sync goes direct where UDP is refused: a clock that is off fails every TLS handshake. */
export function ntpDirectRule(): Json {
  return { network: "udp", port: 123, action: "route", outbound: "direct" };
}

/** The refusal of UDP in a profile where no proxy carries it; the last generated rule. */
export function udpRejectRule(): Json {
  return { network: "udp", action: "reject" };
}

// ---- bridge configs (shapes the libbox entry points already expect) ----

/**
 * One VLESS inbound per xray-managed outbound, not SOCKS5: sing-box's vless
 * outbound sends UDP as XUDP inside the same TCP connection, so UDP gets through
 * without a UDP port on the loopback, and the client id covers it as it covers TCP.
 */
function buildXrayConfig(xrayOutbounds: Json[], uuid: string): Json {
  const inbounds: Json[] = [];
  const outbounds: Json[] = [];
  const rules: Json[] = [];
  xrayOutbounds.forEach((xrayOutbound, index) => {
    const inboundTag = `vless-in-${index}`;
    const outboundTag = `proxy-${index}`;
    inbounds.push({
      tag: inboundTag,
      listen: BRIDGE_PORTS.socksHost,
      port: BRIDGE_PORTS.base + index,
      protocol: "vless",
      settings: { clients: [{ id: uuid }], decryption: "none" },
      sniffing: { enabled: true, destOverride: ["http", "tls"] },
    });
    outbounds.push({ ...xrayOutbound, tag: outboundTag });
    rules.push({ type: "field", inboundTag: [inboundTag], outboundTag });
  });
  outbounds.push({ tag: "direct", protocol: "freedom" });
  return {
    log: { loglevel: "debug" },
    inbounds,
    outbounds,
    routing: { domainStrategy: "AsIs", rules },
  };
}

function buildEndpointConfig(entries: Array<Record<string, string>>, firstPort: number): Json {
  return {
    // The bridges bind 127.0.0.127 by default — fine on Android and Linux, which
    // have all of 127.0.0.0/8, but macOS and Windows only assign 127.0.0.1 and
    // the listener fails with "can't assign requested address".
    endpoints: entries.map((entry, index) => ({
      ...entry,
      port: firstPort + index,
      listen: BRIDGE_PORTS.socksHost,
    })),
  };
}
