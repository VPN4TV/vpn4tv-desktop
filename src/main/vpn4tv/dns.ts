// VPN4TV: DNS resilience — a TypeScript port of DnsProviders + DnsProber +
// the DNS half of ConfigTransforms from the mobile clients.
//
// Russian ISPs kill resolvers in waves (July 2026 took out Google and Cloudflare
// DoH on the same day, Quad9 survived), so the client probes the known
// endpoints before connecting and rewrites the profile's DNS servers to
// whichever one actually answers. Ordering below is preference.

import { type Json, asObject, parseJsonObject, str } from "./support";

interface Provider {
  name: string;
  /** RFC 8484 endpoints; IP-hosted ones need no bootstrap resolver. */
  dohUrls: string[];
  /** Plain UDP:53 resolver IPs. */
  udpIps?: string[];
  /** The DoH certificate covers the raw IP, so sing-box can use it directly. */
  ipCertSan?: boolean;
  /** RU jurisdiction: probe only, never in the in-app chain. */
  lastResort?: boolean;
}

const PROVIDERS: Provider[] = [
  {
    name: "quad9",
    dohUrls: ["https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"],
    udpIps: ["9.9.9.9", "149.112.112.112"],
    ipCertSan: true,
  },
  { name: "adguard", dohUrls: ["https://dns.adguard-dns.com/dns-query"] },
  {
    name: "google",
    dohUrls: ["https://8.8.8.8/dns-query", "https://dns.google/dns-query"],
    udpIps: ["8.8.8.8", "8.8.4.4"],
    ipCertSan: true,
  },
  {
    name: "cloudflare",
    dohUrls: ["https://1.0.0.1/dns-query", "https://1.1.1.1/dns-query"],
    udpIps: ["1.1.1.1"],
    ipCertSan: true,
  },
  { name: "yandex", dohUrls: ["https://dns.yandex.net/dns-query"], udpIps: ["77.88.8.8"], lastResort: true },
];

const PROBE_TIMEOUT_MILLISECONDS = 3_000;

/** The host of a DoH URL when it is a bare IPv4 address, else null. */
function ipHost(url: string): string | null {
  const host = url.replace("https://", "").split("/")[0];
  return /^\d+\.\d+\.\d+\.\d+$/.test(host) ? host : null;
}

export const dohProbeCandidates: string[] = PROVIDERS.flatMap((provider) => provider.dohUrls);
export const udpCandidates: string[] = PROVIDERS.flatMap((provider) => provider.udpIps ?? []);

const dohCapableIps = new Set(
  PROVIDERS.filter((provider) => provider.ipCertSan === true).flatMap((provider) => [
    ...(provider.udpIps ?? []),
    ...provider.dohUrls.map(ipHost).filter((host): host is string => host !== null),
  ]),
);

const preferredDohIp =
  PROVIDERS.find((provider) => provider.ipCertSan === true)
    ?.dohUrls.map(ipHost)
    .find((host): host is string => host !== null) ?? "9.9.9.9";

export interface DnsProbeResult {
  dohUrl: string;
  udpServer: string;
  dohWorks: boolean;
}

/** Probe the known DoH endpoints; the first that answers wins. */
export async function probeDns(): Promise<DnsProbeResult> {
  for (const url of dohProbeCandidates) {
    if (await probeEndpoint(url)) {
      return { dohUrl: url, udpServer: udpCandidates[0] ?? "9.9.9.9", dohWorks: true };
    }
  }
  return {
    dohUrl: "https://8.8.8.8/dns-query",
    udpServer: udpCandidates[0] ?? "9.9.9.9",
    dohWorks: false,
  };
}

async function probeEndpoint(dohUrl: string): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MILLISECONDS);
  try {
    const response = await fetch(`${dohUrl}?name=google.com&type=A`, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    // Anything 2xx–4xx means reachable and not intercepted; a 400 just means the
    // endpoint wanted the wireformat path instead of the JSON one.
    return response.status >= 200 && response.status < 500;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/** Host part of the winning DoH URL (what sing-box wants as `server`). */
export function dohServer(result: DnsProbeResult): string {
  return result.dohUrl.replace("https://", "").split("/")[0];
}

/**
 * An IP that serves DoH with a certificate valid for the IP itself — dns-direct
 * has no bootstrap resolver, so it must be addressed by IP. Null when no DoH
 * endpoint answered at all.
 */
export function dohCapableIp(result: DnsProbeResult): string | null {
  if (!result.dohWorks) {
    return null;
  }
  const host = dohServer(result);
  if (/^[0-9.]+$/.test(host)) {
    return host;
  }
  if (dohCapableIps.has(result.udpServer)) {
    return result.udpServer;
  }
  return preferredDohIp;
}

/**
 * Point the profile's DNS servers at what the probe found. Best effort: a
 * profile we cannot understand is returned untouched rather than broken.
 */
export function injectProbedDns(configContent: string, result: DnsProbeResult): string {
  const root = parseJsonObject(configContent);
  const dns = root === null ? null : asObject(root.dns);
  const servers = dns === null ? null : (dns.servers as unknown);
  if (root === null || dns === null || !Array.isArray(servers)) {
    return configContent;
  }

  const directIp = dohCapableIp(result);
  const rewritten = servers.map((entry) => {
    const server = asObject(entry);
    if (server === null) {
      return entry;
    }
    switch (str(server, "tag")) {
      case "dns-remote":
        // Remote DNS resolves through the proxy, so only the endpoint matters.
        return { ...server, type: "https", server: dohServer(result) };
      case "dns-direct":
        // Direct DNS is dialled before the tunnel exists: DoH by IP when we have
        // one, plain UDP otherwise.
        return directIp !== null
          ? { ...server, type: "https", server: directIp }
          : { ...server, type: "udp", server: result.udpServer };
      default:
        return server;
    }
  });

  const updated: Json = { ...root, dns: { ...dns, servers: rewritten } };
  return JSON.stringify(updated, null, 2);
}
