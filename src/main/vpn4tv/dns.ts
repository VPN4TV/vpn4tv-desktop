// VPN4TV: DNS resilience — a TypeScript port of DnsProviders + DnsProber +
// the DNS half of ConfigTransforms from the mobile clients.
//
// Russian ISPs kill resolvers in waves (July 2026 took out Google and Cloudflare
// DoH on the same day, Quad9 survived), so the client probes the known
// endpoints before connecting and rewrites the profile's DNS servers to
// whichever one actually answers. Ordering below is preference.

import { buildDnsQuery, parseDnsAnswers } from "./russiaDirectProbe";
import { type Json, asObject, parseJsonObject, str } from "./support";

interface Provider {
  name: string;
  /** RFC 8484 endpoints; IP-hosted ones need no bootstrap resolver. */
  dohUrls: string[];
  /** Google-style JSON API endpoints, the last links of the resolution chain. */
  jsonUrls?: string[];
  /** Plain UDP:53 resolver IPs. */
  udpIps?: string[];
  /** The DoH certificate covers the raw IP, so sing-box can use it directly. */
  ipCertSan?: boolean;
  /** RU jurisdiction: probe only, never in the in-app chain. ("Russia direct"
   *  sends Russian names to Yandex on purpose, through its own dns-ru server
   *  that this rewrite leaves alone — see russiaDirect.ts.) */
  lastResort?: boolean;
}

const PROVIDERS: Provider[] = [
  {
    name: "quad9",
    dohUrls: ["https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"],
    udpIps: ["9.9.9.9", "149.112.112.112"],
    ipCertSan: true,
  },
  {
    name: "adguard",
    dohUrls: ["https://dns.adguard-dns.com/dns-query"],
    jsonUrls: ["https://dns.adguard-dns.com/resolve"],
  },
  {
    name: "google",
    dohUrls: ["https://8.8.8.8/dns-query", "https://dns.google/dns-query"],
    jsonUrls: ["https://dns.google/resolve"],
    udpIps: ["8.8.8.8", "8.8.4.4"],
    ipCertSan: true,
  },
  {
    name: "cloudflare",
    dohUrls: ["https://1.0.0.1/dns-query", "https://1.1.1.1/dns-query"],
    jsonUrls: ["https://one.one.one.one/dns-query"],
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

// ---- server names resolved before the start (Android's preResolveHosts) ----
//
// sing-box has no failover between DNS servers: a server written by name is
// resolved through dns-direct alone, and where that resolver is blocked the
// server cannot be reached. So the chain lives here: every server name is
// resolved through the DoH endpoints in turn before the start and pinned into
// the config, and the proxies dial those addresses. As HwidService.preResolveHosts
// and BoxService.injectResolvedHosts on Android, DoHResolver and
// ConfigTransforms on Apple.

interface ResolutionEndpoint {
  url: string;
  /** RFC 8484 wireformat; otherwise the JSON API. */
  wire: boolean;
}

/**
 * Every DoH endpoint in order (wireformat), then the JSON APIs. Never the
 * last-resort ones: resolving circumvention servers at a Russian resolver
 * leaks exactly the wrong queries. As Android's DnsProviders.resolutionEndpoints.
 */
export const resolutionEndpoints: ResolutionEndpoint[] = [
  ...PROVIDERS.filter((provider) => provider.lastResort !== true).flatMap((provider) =>
    provider.dohUrls.map((url) => ({ url, wire: true })),
  ),
  ...PROVIDERS.filter((provider) => provider.lastResort !== true).flatMap((provider) =>
    (provider.jsonUrls ?? []).map((url) => ({ url, wire: false })),
  ),
];

const RESOLVE_TIMEOUT_MILLISECONDS = 5_000;
/** How long the start waits for the chain. */
const RESOLVE_BUDGET_MILLISECONDS = 6_000;
/** With an answer stored for every name: the start waits no longer, and a slow or blocked chain leaves the stored ones. */
const REFRESH_BUDGET_MILLISECONDS = 2_000;
const RESOLVE_PARALLEL = 4;

/** fetch, given up after its own timeout or when `signal` fires. */
async function fetchWithin(url: string, accept: string, signal: AbortSignal): Promise<Response | null> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  const timer = setTimeout(abort, RESOLVE_TIMEOUT_MILLISECONDS);
  signal.addEventListener("abort", abort);
  try {
    const response = await fetch(url, { headers: { Accept: accept }, signal: controller.signal });
    return response.ok ? response : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", abort);
  }
}

async function resolveWire(dohUrl: string, hostname: string, signal: AbortSignal): Promise<string[]> {
  const query = buildDnsQuery(hostname).toString("base64url");
  const response = await fetchWithin(`${dohUrl}?dns=${query}`, "application/dns-message", signal);
  try {
    return response === null ? [] : parseDnsAnswers(Buffer.from(await response.arrayBuffer()));
  } catch {
    return [];
  }
}

async function resolveJson(url: string, hostname: string, signal: AbortSignal): Promise<string[]> {
  const response = await fetchWithin(
    `${url}?name=${encodeURIComponent(hostname)}&type=A`,
    "application/dns-json",
    signal,
  );
  try {
    const answers = response === null ? null : (asObject(await response.json())?.Answer as unknown);
    if (!Array.isArray(answers)) {
      return [];
    }
    return answers
      .map(asObject)
      .filter((answer) => answer !== null && answer.type === 1)
      .map((answer) => str(answer, "data"))
      .filter((address) => /^\d+\.\d+\.\d+\.\d+$/u.test(address));
  } catch {
    return [];
  }
}

/** All A records of `hostname` from the first endpoint of the chain that answers; [] when none does. */
export async function resolveAllViaDoH(
  hostname: string,
  signal: AbortSignal = new AbortController().signal,
  endpoints: readonly ResolutionEndpoint[] = resolutionEndpoints,
): Promise<string[]> {
  for (const endpoint of endpoints) {
    if (signal.aborted) {
      return [];
    }
    const addresses = endpoint.wire
      ? await resolveWire(endpoint.url, hostname, signal)
      : await resolveJson(endpoint.url, hostname, signal);
    if (addresses.length > 0) {
      return addresses;
    }
  }
  return [];
}

/** Where the last answers live between starts (a file in the app's data folder). */
export interface ResolvedHostsStore {
  load(): Promise<Record<string, string[]>>;
  save(answers: Record<string, string[]>): Promise<void>;
}

/**
 * Resolve `hosts` through the DoH chain, a few at a time, within the budget.
 * Every start asks again: a provider moves a blocked server to a new address by
 * changing its A record, and a reconnect must pick that up. A name the chain
 * does not answer in time gets its last known answer, whatever its age (a
 * blocked resolver gives nothing at all). Never throws; returns what it has.
 */
export async function preResolveHosts(
  hosts: readonly string[],
  store: ResolvedHostsStore,
  resolve: (hostname: string, signal: AbortSignal) => Promise<string[]> = resolveAllViaDoH,
): Promise<Record<string, string[]>> {
  const unique = [...new Set(hosts)];
  if (unique.length === 0) {
    return {};
  }
  const stored = await store.load().catch(() => ({}) as Record<string, string[]>);
  const budget = unique.every((host) => (stored[host]?.length ?? 0) > 0)
    ? REFRESH_BUDGET_MILLISECONDS
    : RESOLVE_BUDGET_MILLISECONDS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), budget);
  const answered: Record<string, string[]> = {};
  const queue = [...unique];
  try {
    await Promise.all(
      Array.from({ length: Math.min(RESOLVE_PARALLEL, unique.length) }, async () => {
        for (let host = queue.shift(); host !== undefined && !controller.signal.aborted; host = queue.shift()) {
          const addresses = await resolve(host, controller.signal).catch(() => []);
          if (addresses.length > 0 && !controller.signal.aborted) {
            answered[host] = addresses;
          }
        }
      }),
    );
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
  const result: Record<string, string[]> = { ...answered };
  for (const host of unique) {
    if (result[host] === undefined && (stored[host]?.length ?? 0) > 0) {
      result[host] = stored[host];
    }
  }
  if (Object.keys(answered).length > 0) {
    await store.save({ ...stored, ...answered }).catch(() => {});
  }
  console.info(
    `vpn4tv: preResolveHosts: ${Object.keys(result).length}/${unique.length} resolved ` +
      `(${Object.keys(answered).length} answered, ${budget} ms)`,
  );
  return result;
}

/** The servers of the outbounds written by name: what preResolveHosts gets. */
export function serverHosts(configContent: string): string[] {
  const outbounds = asObject(parseJsonObject(configContent))?.outbounds as unknown;
  if (!Array.isArray(outbounds)) {
    return [];
  }
  const hosts = outbounds
    .map((entry) => str(asObject(entry), "server"))
    .filter((server) => server !== "" && server !== "localhost" && !server.includes(":"))
    .filter((server) => !/^\d+\.\d+\.\d+\.\d+$/u.test(server));
  return [...new Set(hosts)];
}

/**
 * Pin the answers into the config: a `hosts` DNS server with them, a DNS rule
 * for exactly those names ahead of the others, and domain_resolver on each
 * outbound whose server was resolved. An outbound dials its server through its
 * own domain_resolver, else route.default_domain_resolver (dns-direct), and
 * never asks dns.rules: without the last step the pins only answered queries.
 * Nothing resolved: the config as it is, dns-direct still applies.
 */
export function injectResolvedHosts(configContent: string, resolved: Record<string, string[]>): string {
  const names = Object.keys(resolved);
  const root = parseJsonObject(configContent);
  const dns = root === null ? null : asObject(root.dns);
  const servers = dns === null ? null : (dns.servers as unknown);
  const outbounds = root === null ? null : (root.outbounds as unknown);
  if (names.length === 0 || root === null || dns === null || !Array.isArray(servers) || !Array.isArray(outbounds)) {
    return configContent;
  }
  const rules = Array.isArray(dns.rules) ? (dns.rules as unknown[]) : [];
  const updated: Json = {
    ...root,
    dns: {
      ...dns,
      servers: [...servers, { type: "hosts", tag: "dns-hosts", predefined: resolved }],
      rules: [{ domain: names, server: "dns-hosts" }, ...rules],
    },
    outbounds: outbounds.map((entry) => {
      const outbound = asObject(entry);
      if (outbound === null || !names.includes(str(outbound, "server")) || "domain_resolver" in outbound) {
        return entry;
      }
      return { ...outbound, domain_resolver: "dns-hosts" };
    }),
  };
  console.info(`vpn4tv: DNS: pinned ${names.length} outbound hostnames via DoH chain`);
  return JSON.stringify(updated, null, 2);
}

/**
 * The config without FakeDNS: the fakeip server, the rules that send names to
 * it and the HTTPS/SVCB reject that goes with it, and the stored fake
 * addresses. The cache file stays: it remembers the chosen server. As
 * Android's BoxService.stripFakeDns.
 */
export function stripFakeDns(configContent: string): string {
  const root = parseJsonObject(configContent);
  const dns = root === null ? null : asObject(root.dns);
  if (root === null || dns === null) {
    return configContent;
  }
  const servers = Array.isArray(dns.servers) ? (dns.servers as unknown[]) : [];
  const rules = Array.isArray(dns.rules) ? (dns.rules as unknown[]) : [];
  const isHttpsReject = (rule: Json) => {
    const types = rule.query_type;
    return (
      str(rule, "action") === "reject" &&
      Array.isArray(types) &&
      types.length === 2 &&
      types.includes("HTTPS") &&
      types.includes("SVCB")
    );
  };
  const updated: Json = {
    ...root,
    dns: {
      ...dns,
      servers: servers.filter((entry) => str(asObject(entry), "tag") !== "dns-fakeip"),
      rules: rules.filter((entry) => {
        const rule = asObject(entry);
        return rule === null || (str(rule, "server") !== "dns-fakeip" && !isHttpsReject(rule));
      }),
    },
  };
  const experimental = asObject(root.experimental);
  const cacheFile = experimental === null ? null : asObject(experimental.cache_file);
  if (experimental !== null && cacheFile !== null && "store_fakeip" in cacheFile) {
    const { store_fakeip: _dropped, ...rest } = cacheFile;
    updated.experimental = { ...experimental, cache_file: rest };
  }
  return JSON.stringify(updated, null, 2);
}

/** The config carries FakeDNS (the generator wrote it, the user has it on). */
export function hasFakeDns(configContent: string): boolean {
  const servers = asObject(asObject(parseJsonObject(configContent))?.dns)?.servers as unknown;
  return Array.isArray(servers) && servers.some((entry) => str(asObject(entry), "tag") === "dns-fakeip");
}
