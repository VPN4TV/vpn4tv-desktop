// The seam that matters most: whatever the backend serves must come out as a
// profile sing-box can start. These cover convertSubscription's contract
// without touching Electron or the settings database.

import assert from "node:assert/strict";
import { test } from "node:test";

import { generateConfig } from "./generator";
import { parseSubscription } from "./parser";

// convertSubscription without the database-backed hwid (imported separately so
// this file stays runnable outside Electron).
function convertSubscription(content: string): string {
  const proxies = parseSubscription(content);
  if (proxies.length === 0) {
    throw new Error("No servers found in the subscription.");
  }
  return generateConfig(proxies);
}

test("a proxy-URI subscription becomes a startable sing-box profile", () => {
  const subscription = [
    "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=reality&sni=www.apple.com&pbk=K&sid=00#A",
    "trojan://pw@b.example.com:443?sni=b.example.com#B",
  ].join("\n");
  const profile = JSON.parse(convertSubscription(subscription));

  assert.ok(profile.inbounds.some((inbound: any) => inbound.type === "tun"), "needs a tun inbound");
  assert.equal(profile.route.final, "select");
  const tags = profile.outbounds.map((outbound: any) => outbound.tag);
  assert.deepEqual(tags, ["auto", "select", "A", "B", "direct"]);
  assert.equal(profile.vpn4tv, undefined, "no bridge transports → no private key");
});

test("an already-native sing-box config passes through unchanged", () => {
  const native = {
    log: { level: "warn" },
    inbounds: [{ type: "tun", tag: "tun-in" }],
    outbounds: [{ type: "direct", tag: "direct" }],
  };
  assert.deepEqual(JSON.parse(convertSubscription(JSON.stringify(native))), native);
});

test("a bridge transport travels inside the profile for the core to start", () => {
  const subscription =
    "vless://11111111-2222-3333-4444-555555555555@c.example.com:443?security=tls&sni=c&type=xhttp&path=%2Fx#C";
  const profile = JSON.parse(convertSubscription(subscription));
  assert.ok(profile.vpn4tv?.xray, "xhttp must be handed to the xray bridge");
  const outbound = profile.outbounds.find((entry: any) => entry.tag === "C");
  assert.equal(outbound.type, "socks");
  assert.equal(outbound.server, "127.0.0.1", "desktop loopback, not the mobile 127.0.0.127");
  assert.equal(
    outbound.server_port,
    profile.vpn4tv.xray.inbounds[0].port,
    "the socks outbound and the bridge listener must agree on the port",
  );
});

test("an empty or unparsable subscription is rejected, not silently stored", () => {
  assert.throws(() => convertSubscription(""), /No servers/);
  assert.throws(() => convertSubscription("nonsense without any uri"), /No servers/);
});
