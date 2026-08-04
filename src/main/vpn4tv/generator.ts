// VPN4TV: TypeScript port of the config generator (Kotlin ConfigGenerator →
// Swift Library/Config/ConfigGenerator.swift → here).
//
// Difference from the mobile ports: the apps write the bridge configs to sidecar
// files and hand them to the tunnel process, because only the app can call the
// gomobile bridge entry points. The desktop client cannot — it only speaks gRPC
// to the daemon — so the bridge configs are embedded in the profile itself under
// the private "vpn4tv" key, and the core starts them (see the Go package
// experimental/vpn4tvbridge in our sing-box fork).

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

  // xray-managed (xhttp/splithttp)
  const xrayOutbounds: Json[] = [];
  for (const proxy of proxies) {
    if (!proxy.xrayOutbound) {
      continue;
    }
    const port = BRIDGE_PORTS.base + xrayOutbounds.length;
    xrayOutbounds.push(proxy.xrayOutbound);
    proxy.outbound = socksLoopback(proxy.tag, port);
  }

  // outline-managed (ss SIP002 with a prefix, or a dynamic ssconf:// key)
  const outlineUrls: { url?: string; dynamicUrl?: string }[] = [];
  for (const proxy of proxies) {
    if (proxy.outlineDynamicUrl) {
      const dynamicPort = BRIDGE_PORTS.base + BRIDGE_PORTS.outlineOffset + outlineUrls.length;
      outlineUrls.push({ dynamicUrl: proxy.outlineDynamicUrl });
      proxy.outbound = socksLoopback(proxy.tag, dynamicPort);
      continue;
    }
    if (!proxy.outlineUrl) {
      continue;
    }
    const port = BRIDGE_PORTS.base + BRIDGE_PORTS.outlineOffset + outlineUrls.length;
    outlineUrls.push({ url: proxy.outlineUrl });
    proxy.outbound = socksLoopback(proxy.tag, port);
  }

  // AmneziaWG: ipv4_only so sing-box resolves before CONNECT
  const wireguardInis: string[] = [];
  for (const proxy of proxies) {
    if (!proxy.awgIni) {
      continue;
    }
    const port = BRIDGE_PORTS.base + BRIDGE_PORTS.wireguardOffset + wireguardInis.length;
    wireguardInis.push(proxy.awgIni);
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
    bridges.xray = buildXrayConfig(xrayOutbounds);
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
  if (Object.keys(bridges).length > 0) {
    config[BRIDGE_CONFIG_KEY] = bridges;
  }

  return JSON.stringify(config, null, 2);
}

function socksLoopback(tag: string, port: number): Json {
  return {
    type: "socks",
    tag,
    server: BRIDGE_PORTS.socksHost,
    server_port: port,
    version: "5",
    network: "tcp",
    // No bind_interface: "lo" is a Linux/Android-ism (macOS calls it lo0 and
    // Windows has no such name). The bridge lives in the daemon process, whose
    // own sockets auto_route already excludes, so there is no routing loop.
  };
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

function allTcpBridged(proxies: ProxyConfig[]): boolean {
  return proxies.every((proxy) => proxy.outlineUrl !== undefined || proxy.awgIni !== undefined);
}

/** All-TCP-bridged profiles resolve upstream, so fakeip has nothing to do. */
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
  const tcpOnly = allTcpBridged(proxies);
  const remote = parseDnsUrl(lastDns.remoteDns);
  const direct = parseDnsUrl(lastDns.directDns);

  const remoteServer: Json = {
    type: remote.type,
    tag: "dns-remote",
    server: remote.server,
    domain_resolver: "dns-direct",
  };
  if (!tcpOnly) {
    remoteServer.detour = "select";
  }
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
  if (allTcpBridged(proxies)) {
    rules.push({ network: "udp", outbound: "direct" });
  }
  return {
    rules,
    auto_detect_interface: true,
    // In "only these applications" mode everything unmatched stays direct.
    final: perAppMode === "include" ? "direct" : "select",
    default_domain_resolver: { server: "dns-direct" },
  };
}

// ---- bridge configs (shapes the libbox entry points already expect) ----

function buildXrayConfig(xrayOutbounds: Json[]): Json {
  const inbounds: Json[] = [];
  const outbounds: Json[] = [];
  const rules: Json[] = [];
  xrayOutbounds.forEach((xrayOutbound, index) => {
    const inboundTag = `socks-in-${index}`;
    const outboundTag = `proxy-${index}`;
    inbounds.push({
      tag: inboundTag,
      listen: BRIDGE_PORTS.socksHost,
      port: BRIDGE_PORTS.base + index,
      protocol: "socks",
      settings: { auth: "noauth", udp: true },
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
    endpoints: entries.map((entry, index) => ({ ...entry, port: firstPort + index })),
  };
}
