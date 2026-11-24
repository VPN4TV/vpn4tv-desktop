// VPN4TV: Outline dynamic access keys (ssconf://).
//
// The provider rotates servers behind such a key, so resolving it once at
// import and storing the result — which is what the backend used to do — hands
// the user a snapshot that goes stale. Outline's own clients fetch the key
// before connecting; this does the same, right before the service starts.
//
// The resolved URL is written back into the profile, so a failed fetch (blocked
// host, no network yet) falls back to the last key that worked instead of
// leaving the user with nothing.
//
// Support case of 2026-11-24 (Android 5.6.7, the same design): the key's host
// was frozen at the TLS handshake by most Russian home ISPs, the key had never
// been fetched, so its server was left without a bridge. The app said
// "Connected", every connection through that server was refused at the
// bridge's port, and nothing in the log said why. What becomes of each key is
// now an OutlineKeyOutcome the start writes to the log and acts on. As
// Android OutlineDynamicKeys and OutlineKeyCheck.

import { BRIDGE_CONFIG_KEY, BRIDGE_PORTS } from "./generator";
import { type Json, asObject, int, parseJsonObject, str } from "./support";

/** How long a start waits for a key when the last one that worked is there to fall back on. */
export const WAIT_WITH_EARLIER_MS = 6_000;
/** How long it waits when there is none. */
export const WAIT_WITHOUT_EARLIER_MS = 20_000;
const MAXIMUM_REDIRECTS = 3;

/** fetched: the key came (the same or a new one); kept: it did not, the last one that worked is used; none: it did not, and none ever did. */
export type OutlineKeyState = "fetched" | "kept" | "none";

/**
 * What became of one dynamic key. [host] is the key's host (never its path,
 * which is the secret); [port] is the endpoint's, the one the core's socks
 * outbound dials; [reason] says why it was not fetched; [changed] is true when
 * a fetched key differs from the one kept.
 */
export interface OutlineKeyOutcome {
  host: string;
  port: number;
  state: OutlineKeyState;
  reason: string | null;
  changed: boolean;
}

export interface OutlineKeyResolution {
  /** The profile with every key that came filled in; the same string when nothing changed. */
  content: string;
  outcomes: OutlineKeyOutcome[];
}

/** One fetch: the key as a SIP002 link, or why there is none. */
export interface OutlineKeyFetch {
  url: string | null;
  error: string | null;
}

export interface ResolveOptions {
  /** Only the endpoints on these ports. */
  onlyPorts?: ReadonlySet<number>;
  waitWithEarlierMs?: number;
  waitWithoutEarlierMs?: number;
  fetchKey?: (dynamicUrl: string, timeoutMs: number) => Promise<OutlineKeyFetch>;
}

interface DynamicKeyResponse {
  server?: unknown;
  server_port?: unknown;
  password?: unknown;
  method?: unknown;
  prefix?: unknown;
}

const IPV4_ADDRESS = /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/gu;
const IPV6_ADDRESS = /\[?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[\w.-]+)?\]?/giu;
const LINK = /\b[a-z][a-z0-9+.-]*:\/\/\S+/giu;

/** Addresses out, ports kept: "connect ETIMEDOUT 1.2.3.4:443" → "connect ETIMEDOUT <address>:443". */
export function withoutAddresses(text: string): string {
  return text
    .replace(IPV4_ADDRESS, "<address>")
    .replace(IPV6_ADDRESS, (match) => (match.endsWith(":") && !match.endsWith("::") ? match : "<address>"));
}

/**
 * Why a fetch failed, short and without the link or addresses. Node's fetch
 * says "fetch failed" and puts the cause (ECONNRESET, a connect timeout, the
 * TLS socket closed early) in error.cause.
 */
export function shortReason(error: unknown, timeoutMs: number): string {
  const name = error instanceof Error ? error.name : "";
  if (name === "TimeoutError" || name === "AbortError") {
    return `no answer in ${Math.round(timeoutMs / 1000)} s`;
  }
  let text = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error ? (error.cause as { code?: unknown; message?: unknown } | undefined) : undefined;
  if (cause !== undefined && cause !== null) {
    const code = typeof cause.code === "string" ? cause.code : "";
    const message = typeof cause.message === "string" ? cause.message : "";
    text = message !== "" ? (code !== "" && !message.includes(code) ? `${code}: ${message}` : message) : code || text;
  }
  const short = withoutAddresses(text.replace(/\s+/gu, " ").replace(LINK, "<link>").trim()).slice(0, 160);
  return short === "" ? "unknown error" : short;
}

/** Follow redirects by hand — providers use them, and each hop needs checking. One limit for all of them. */
async function fetchDynamicKey(url: string, timeoutMs: number): Promise<OutlineKeyFetch> {
  const signal = AbortSignal.timeout(timeoutMs);
  let current = url;
  try {
    for (let hop = 0; hop <= MAXIMUM_REDIRECTS; hop += 1) {
      const response = await fetch(current, { redirect: "manual", signal });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (location === null) {
          return { url: null, error: `HTTP ${response.status} without a location` };
        }
        current = new URL(location, current).toString();
        continue;
      }
      if (!response.ok) {
        return { url: null, error: `HTTP ${response.status}` };
      }
      let key: DynamicKeyResponse | null;
      try {
        key = asObject(JSON.parse(await response.text())) as DynamicKeyResponse | null;
      } catch (error) {
        if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
          throw error;
        }
        key = null;
      }
      if (key === null) {
        return { url: null, error: "the answer is not a key" };
      }
      const link = toShadowsocksUrl(key, new URL(url).hostname);
      return link === null
        ? { url: null, error: "the key has no server, port, password or method" }
        : { url: link, error: null };
    }
    return { url: null, error: "too many redirects" };
  } catch (error) {
    return { url: null, error: shortReason(error, timeoutMs) };
  }
}

/** SIP002, the shape the outline bridge already takes. */
function toShadowsocksUrl(key: DynamicKeyResponse, name: string): string | null {
  const { server, server_port: port, password, method, prefix } = key;
  if (
    typeof server !== "string" ||
    server === "" ||
    typeof port !== "number" ||
    port === 0 ||
    typeof password !== "string" ||
    password === "" ||
    typeof method !== "string" ||
    method === ""
  ) {
    return null;
  }
  const userInfo = Buffer.from(`${method}:${password}`, "utf-8").toString("base64");
  const host = server.includes(":") ? `[${server}]` : server;
  const query =
    typeof prefix === "string" && prefix !== "" ? `?${new URLSearchParams({ prefix }).toString()}` : "";
  return `ss://${userInfo}@${host}:${port}${query}#${encodeURIComponent(name)}`;
}

/** The key's host for the log: "https://keys.example/abc" → "keys.example". */
export function keyHost(dynamicUrl: string): string {
  try {
    return new URL(dynamicUrl).hostname || "?";
  } catch {
    return "?";
  }
}

function outlineEndpoints(root: Json | null): { bridges: Json; outline: Json; endpoints: unknown[] } | null {
  const bridges = root === null ? null : asObject(root[BRIDGE_CONFIG_KEY]);
  const outline = bridges === null ? null : asObject(bridges.outline);
  const endpoints = outline === null ? null : (outline.endpoints as unknown);
  if (bridges === null || outline === null || !Array.isArray(endpoints)) {
    return null;
  }
  return { bridges, outline, endpoints };
}

/**
 * Fetch the dynamic keys of the profile (of the endpoints on [onlyPorts], or
 * all) at once, each waited for 6 s when it has a key that worked before and
 * 20 s when it has none. Never throws: a key that does not come keeps the
 * previous one.
 */
export async function resolveDynamicOutlineKeys(
  configContent: string,
  options: ResolveOptions = {},
): Promise<OutlineKeyResolution> {
  const root = parseJsonObject(configContent);
  const found = outlineEndpoints(root);
  if (root === null || found === null) {
    return { content: configContent, outcomes: [] };
  }
  const { bridges, outline, endpoints } = found;
  const waitWithEarlier = options.waitWithEarlierMs ?? WAIT_WITH_EARLIER_MS;
  const waitWithoutEarlier = options.waitWithoutEarlierMs ?? WAIT_WITHOUT_EARLIER_MS;
  const fetchKey = options.fetchKey ?? fetchDynamicKey;

  let changed = false;
  const outcomes: OutlineKeyOutcome[] = [];
  const resolved = await Promise.all(
    endpoints.map(async (entry: unknown) => {
      const server = asObject(entry);
      const dynamicUrl = server === null ? "" : str(server, "dynamicUrl");
      if (server === null || dynamicUrl === "") {
        return { entry, outcome: null };
      }
      const port = int(server, "port");
      if (options.onlyPorts !== undefined && !options.onlyPorts.has(port)) {
        return { entry, outcome: null };
      }
      const previous = str(server, "url").trim();
      const limit = previous === "" ? waitWithoutEarlier : waitWithEarlier;
      // The fetch keeps its own limit; this one makes sure a fetch that
      // ignores it does not hold the start.
      let timer: ReturnType<typeof setTimeout> | undefined;
      const result = await Promise.race([
        fetchKey(dynamicUrl, limit).catch(
          (error: unknown): OutlineKeyFetch => ({ url: null, error: shortReason(error, limit) }),
        ),
        new Promise<OutlineKeyFetch>((resolve) => {
          timer = setTimeout(
            () => resolve({ url: null, error: `no answer in ${Math.round(limit / 1000)} s` }),
            limit + 1_000,
          );
        }),
      ]);
      clearTimeout(timer);
      const host = keyHost(dynamicUrl);
      if (result.url === null) {
        const outcome: OutlineKeyOutcome = {
          host,
          port,
          state: previous === "" ? "none" : "kept",
          reason: result.error ?? "unknown error",
          changed: false,
        };
        return { entry, outcome };
      }
      const differs = result.url !== previous;
      const outcome: OutlineKeyOutcome = { host, port, state: "fetched", reason: null, changed: differs };
      if (!differs) {
        return { entry, outcome };
      }
      changed = true;
      return { entry: { ...server, url: result.url }, outcome };
    }),
  );
  for (const item of resolved) {
    if (item.outcome !== null) {
      outcomes.push(item.outcome);
    }
  }
  if (!changed) {
    return { content: configContent, outcomes };
  }
  const updated: Json = {
    ...root,
    [BRIDGE_CONFIG_KEY]: { ...bridges, outline: { ...outline, endpoints: resolved.map((item) => item.entry) } },
  };
  return { content: JSON.stringify(updated, null, 2), outcomes };
}

/** True when the profile carries at least one dynamic key. */
export function hasDynamicOutlineKeys(configContent: string): boolean {
  const found = outlineEndpoints(parseJsonObject(configContent));
  return (
    found !== null &&
    found.endpoints.some((entry: unknown) => {
      const server = asObject(entry);
      return server !== null && str(server, "dynamicUrl") !== "";
    })
  );
}

/** The line support reads for one key; [again]: fetched after the start, through the tunnel. */
export function outlineKeyLine(outcome: OutlineKeyOutcome, again: boolean): string {
  const head = `outline key from ${outcome.host} (port ${outcome.port})${again ? ", again after the start" : ""}`;
  switch (outcome.state) {
    case "fetched":
      return `${head}: fetched${outcome.changed ? ", a new one" : ""}`;
    case "kept":
      return `${head}: not fetched (${outcome.reason}), the last one that worked is used`;
    case "none":
      return `${head}: not fetched (${outcome.reason}), none ever was: this server is left out`;
  }
}

/**
 * Whether a start can go on when some keys never came and their servers were
 * left without a bridge (the bridge gives an endpoint without a key no
 * listener: outline-sdk takes an empty key for a direct dialer, which would
 * carry traffic past the VPN). go-on: "auto" or the chosen server has servers
 * that work; no-other-server: every server of the profile is one left out;
 * pick-another: the chosen one is, and others are there. [chosen]: the tag the
 * "select" group has, or "auto"/null for the automatic choice.
 */
export type OutlineKeyVerdict = "go-on" | "no-other-server" | "pick-another";

/** The tags of the socks outbounds that dial an endpoint left without a key. */
export function deadOutlineTags(configContent: string, outcomes: readonly OutlineKeyOutcome[]): Set<string> {
  const deadPorts = new Set(outcomes.filter((outcome) => outcome.state === "none").map((outcome) => outcome.port));
  const dead = new Set<string>();
  if (deadPorts.size === 0) {
    return dead;
  }
  const outbounds = parseJsonObject(configContent)?.outbounds;
  if (!Array.isArray(outbounds)) {
    return dead;
  }
  for (const entry of outbounds) {
    const outbound = asObject(entry);
    if (
      outbound !== null &&
      str(outbound, "type") === "socks" &&
      str(outbound, "server") === BRIDGE_PORTS.socksHost &&
      deadPorts.has(int(outbound, "server_port"))
    ) {
      dead.add(str(outbound, "tag"));
    }
  }
  return dead;
}

function groupMembers(configContent: string, type: string, tag: string): string[] {
  const outbounds = parseJsonObject(configContent)?.outbounds;
  if (!Array.isArray(outbounds)) {
    return [];
  }
  for (const entry of outbounds) {
    const outbound = asObject(entry);
    if (outbound !== null && str(outbound, "type") === type && str(outbound, "tag") === tag) {
      const members = outbound.outbounds;
      return Array.isArray(members) ? members.filter((member): member is string => typeof member === "string") : [];
    }
  }
  return [];
}

export function outlineKeyVerdict(
  configContent: string,
  dead: ReadonlySet<string>,
  chosen: string | null,
): OutlineKeyVerdict {
  if (dead.size === 0) {
    return "go-on";
  }
  const alive = groupMembers(configContent, "urltest", "auto").filter((tag) => !dead.has(tag));
  const select = groupMembers(configContent, "selector", "select");
  const choice = chosen !== null && chosen !== "auto" && select.includes(chosen) ? chosen : "auto";
  if (choice === "auto") {
    return alive.length === 0 ? "no-other-server" : "go-on";
  }
  if (dead.has(choice)) {
    return alive.length === 0 ? "no-other-server" : "pick-another";
  }
  return "go-on";
}
