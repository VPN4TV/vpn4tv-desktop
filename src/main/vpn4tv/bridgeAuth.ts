// VPN4TV: credentials for the SOCKS5 inbounds of the bridges, as Android's
// BridgeAuth.
//
// The bridges listen on 127.0.0.1, which every process on the machine can
// reach. Without credentials any of them can connect to a bridge, go out
// through our server and learn its address: the "local proxy" leak
// (runetfreedom, 2026-04). So every SOCKS5 bridge inbound (Outline, AmneziaWG,
// olcRTC, TrustTunnel) requires a username and password, and every socks
// outbound sing-box aims at one carries them. xray's inbound is VLESS with a
// random UUID that the generator writes, which serves the same purpose.
//
// Applied at each start, in memory: profiles on disk stay as they are, so the
// ones imported before this change are covered at once. One random pair per
// run of the app. UDP to these bridges rides inside the TCP connection (UDP
// over TCP) or is not offered at all (TrustTunnel), so the password covers it.
import { randomBytes } from "node:crypto";

import { BRIDGE_CONFIG_KEY, BRIDGE_PORTS } from "./generator";
import { type Json, asObject, parseJsonObject, str } from "./support";

const SOCKS_BRIDGES = ["outline", "wireproxy", "olcrtc", "trusttunnel"];

export const bridgeUsername = randomBytes(8).toString("hex");
export const bridgePassword = randomBytes(24).toString("hex");

/**
 * The pair on every SOCKS5 bridge endpoint under the "vpn4tv" key and on each
 * socks outbound aimed at one of their ports. An endpoint or outbound that
 * already names a user is left alone.
 */
export function applyBridgeAuth(configContent: string): string {
  const root = parseJsonObject(configContent);
  const bridges = root === null ? null : asObject(root[BRIDGE_CONFIG_KEY]);
  const outbounds = root === null ? null : (root.outbounds as unknown);
  if (root === null || bridges === null || !Array.isArray(outbounds)) {
    return configContent;
  }
  const ports = new Set<number>();
  const updatedBridges: Json = { ...bridges };
  for (const name of SOCKS_BRIDGES) {
    const bridge = asObject(bridges[name]);
    const endpoints = bridge === null ? null : (bridge.endpoints as unknown);
    if (bridge === null || !Array.isArray(endpoints)) {
      continue;
    }
    updatedBridges[name] = {
      ...bridge,
      endpoints: endpoints.map((entry) => {
        const endpoint = asObject(entry);
        if (endpoint === null || typeof endpoint.port !== "number" || str(endpoint, "username") !== "") {
          return entry;
        }
        ports.add(endpoint.port);
        return { ...endpoint, username: bridgeUsername, password: bridgePassword };
      }),
    };
  }
  if (ports.size === 0) {
    return configContent;
  }
  const updated: Json = {
    ...root,
    [BRIDGE_CONFIG_KEY]: updatedBridges,
    outbounds: outbounds.map((entry) => {
      const outbound = asObject(entry);
      if (
        outbound === null ||
        str(outbound, "type") !== "socks" ||
        str(outbound, "server") !== BRIDGE_PORTS.socksHost ||
        typeof outbound.server_port !== "number" ||
        !ports.has(outbound.server_port) ||
        str(outbound, "username") !== ""
      ) {
        return entry;
      }
      return { ...outbound, username: bridgeUsername, password: bridgePassword };
    }),
  };
  return JSON.stringify(updated, null, 2);
}

