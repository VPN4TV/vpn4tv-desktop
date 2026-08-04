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

import { BRIDGE_CONFIG_KEY } from "./generator";
import { type Json, asObject, parseJsonObject, str } from "./support";

const FETCH_TIMEOUT_MILLISECONDS = 8_000;
const MAXIMUM_REDIRECTS = 3;

interface DynamicKeyResponse {
  server?: string;
  server_port?: number;
  password?: string;
  method?: string;
  prefix?: string;
}

/** Follow redirects by hand — providers use them, and each hop needs checking. */
async function fetchDynamicKey(url: string): Promise<DynamicKeyResponse | null> {
  let current = url;
  for (let hop = 0; hop <= MAXIMUM_REDIRECTS; hop += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MILLISECONDS);
    try {
      const response = await fetch(current, { redirect: "manual", signal: controller.signal });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (location === null) {
          return null;
        }
        current = new URL(location, current).toString();
        continue;
      }
      if (!response.ok) {
        return null;
      }
      return (await response.json()) as DynamicKeyResponse;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

/** SIP002, the shape the outline bridge already takes. */
function toShadowsocksUrl(key: DynamicKeyResponse, name: string): string | null {
  if (!key.server || !key.server_port || !key.password || !key.method) {
    return null;
  }
  const userInfo = Buffer.from(`${key.method}:${key.password}`, "utf-8").toString("base64");
  const host = key.server.includes(":") ? `[${key.server}]` : key.server;
  const query = key.prefix ? `?${new URLSearchParams({ prefix: key.prefix }).toString()}` : "";
  return `ss://${userInfo}@${host}:${key.server_port}${query}#${encodeURIComponent(name)}`;
}

/**
 * Resolve every dynamic key in the profile. Returns the profile unchanged when
 * there are none, so this is safe to call before every start.
 */
export async function resolveDynamicOutlineKeys(configContent: string): Promise<string> {
  const root = parseJsonObject(configContent);
  const bridges = root === null ? null : asObject(root[BRIDGE_CONFIG_KEY]);
  const outline = bridges === null ? null : asObject(bridges.outline);
  const endpoints = outline === null ? null : (outline.endpoints as unknown);
  if (root === null || outline === null || !Array.isArray(endpoints)) {
    return configContent;
  }

  let changed = false;
  const resolved = await Promise.all(
    endpoints.map(async (entry: unknown) => {
      const server = asObject(entry);
      const dynamicUrl = server === null ? "" : str(server, "dynamicUrl");
      if (server === null || dynamicUrl === "") {
        return entry;
      }
      const key = await fetchDynamicKey(dynamicUrl);
      const url = key === null ? null : toShadowsocksUrl(key, new URL(dynamicUrl).hostname);
      if (url === null) {
        // Keep whatever worked last time; an unreachable key is not a reason to
        // drop the server from the profile.
        return entry;
      }
      if (str(server, "url") === url) {
        return entry;
      }
      changed = true;
      return { ...server, url };
    }),
  );

  if (!changed) {
    return configContent;
  }
  const updated: Json = {
    ...root,
    [BRIDGE_CONFIG_KEY]: { ...bridges, outline: { ...outline, endpoints: resolved } },
  };
  return JSON.stringify(updated, null, 2);
}

/** True when the profile carries at least one dynamic key. */
export function hasDynamicOutlineKeys(configContent: string): boolean {
  const root = parseJsonObject(configContent);
  const bridges = root === null ? null : asObject(root[BRIDGE_CONFIG_KEY]);
  const outline = bridges === null ? null : asObject(bridges.outline);
  const endpoints = outline === null ? null : (outline.endpoints as unknown);
  if (!Array.isArray(endpoints)) {
    return false;
  }
  return endpoints.some((entry: unknown) => {
    const server = asObject(entry);
    return server !== null && str(server, "dynamicUrl") !== "";
  });
}
