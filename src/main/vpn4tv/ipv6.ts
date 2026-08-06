// VPN4TV: machines with IPv6 switched off cannot start the tunnel.
//
// The generated profile always gives the TUN interface both an IPv4 and an IPv6
// address. On Windows where IPv6 is disabled (registry DisabledComponents, or
// the checkbox cleared on every adapter) assigning the second one fails and the
// whole start aborts with:
//
//   configure tun interface: set ipv6 address: Element not found.
//
// So the addresses are trimmed to what the system can actually take, right
// before connecting — the profile itself stays dual-stack for machines that can
// use it.

import { networkInterfaces } from "node:os";

import { type Json, asObject, parseJsonObject } from "./support";

/**
 * Whether the OS has an IPv6 stack at all. Link-local (fe80::) counts: we need
 * the stack to exist, not to route anywhere. Loopback alone does not, because
 * ::1 survives even when IPv6 is disabled on every adapter.
 */
export function systemHasIPv6(): boolean {
  return Object.values(networkInterfaces()).some((addresses) =>
    (addresses ?? []).some((address) => address.family === "IPv6" && !address.internal),
  );
}

function isIPv6(address: unknown): boolean {
  return typeof address === "string" && address.includes(":");
}

/**
 * Drop IPv6 from the TUN interface and from the fake-IP pool. Returns the
 * profile unchanged when there is nothing to strip, so this is safe to call
 * before every start.
 */
export function stripTunIPv6(configContent: string): string {
  const root = parseJsonObject(configContent);
  const inbounds = root === null ? null : (root.inbounds as unknown);
  if (root === null || !Array.isArray(inbounds)) {
    return configContent;
  }

  let changed = false;
  const rewritten = inbounds.map((entry: unknown) => {
    const inbound = asObject(entry);
    if (inbound === null || inbound.type !== "tun" || !Array.isArray(inbound.address)) {
      return entry;
    }
    const kept = (inbound.address as unknown[]).filter((address) => !isIPv6(address));
    if (kept.length === (inbound.address as unknown[]).length) {
      return entry;
    }
    // Never strip the last address: an interface with none would fail harder
    // than the IPv6 assignment we are working around.
    if (kept.length === 0) {
      return entry;
    }
    changed = true;
    return { ...inbound, address: kept };
  });

  // The fake-IP pool hands out AAAA answers an app cannot reach without a stack.
  const dns = asObject(root.dns);
  let dnsUpdated: Json | null = null;
  if (dns !== null && Array.isArray(dns.servers)) {
    const servers = (dns.servers as unknown[]).map((entry) => {
      const server = asObject(entry);
      if (server === null || server.type !== "fakeip" || server.inet6_range === undefined) {
        return entry;
      }
      changed = true;
      const { inet6_range: _dropped, ...rest } = server;
      return rest;
    });
    dnsUpdated = { ...dns, servers };
  }

  if (!changed) {
    return configContent;
  }
  const updated: Json = { ...root, inbounds: rewritten };
  if (dnsUpdated !== null) {
    updated.dns = dnsUpdated;
  }
  return JSON.stringify(updated, null, 2);
}

/** Trim the profile to what this machine's IP stack supports. */
export function applyIPv6Support(configContent: string): string {
  return systemHasIPv6() ? configContent : stripTunIPv6(configContent);
}
