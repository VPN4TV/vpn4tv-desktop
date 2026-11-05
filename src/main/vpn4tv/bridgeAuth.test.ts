import assert from "node:assert/strict";
import { test } from "node:test";

import { applyBridgeAuth, bridgePassword, bridgeUsername } from "./bridgeAuth";
import { BRIDGE_CONFIG_KEY } from "./generator";

test("every SOCKS5 bridge endpoint and its outbound get the pair", () => {
  const config = JSON.stringify({
    outbounds: [
      { type: "socks", tag: "outline", server: "127.0.0.1", server_port: 43890 },
      { type: "socks", tag: "tt", server: "127.0.0.1", server_port: 46890, network: "tcp" },
      { type: "socks", tag: "own proxy", server: "127.0.0.1", server_port: 1080 },
      { type: "vless", tag: "xray", server: "127.0.0.1", server_port: 42890, uuid: "u" },
    ],
    [BRIDGE_CONFIG_KEY]: {
      outline: { endpoints: [{ url: "ss://x", port: 43890, listen: "127.0.0.1" }] },
      trusttunnel: { endpoints: [{ url: "tt://?x", port: 46890, listen: "127.0.0.1" }] },
      xray: { inbounds: [] },
    },
  });
  const root = JSON.parse(applyBridgeAuth(config));
  assert.equal(bridgeUsername.length, 16);
  assert.equal(bridgePassword.length, 48);
  for (const name of ["outline", "trusttunnel"]) {
    const endpoint = root[BRIDGE_CONFIG_KEY][name].endpoints[0];
    assert.equal(endpoint.username, bridgeUsername);
    assert.equal(endpoint.password, bridgePassword);
  }
  assert.equal(root.outbounds[0].password, bridgePassword);
  assert.equal(root.outbounds[1].username, bridgeUsername);
  assert.equal(root.outbounds[2].username, undefined, "a socks outbound to another port is not ours");
  assert.equal(root.outbounds[3].username, undefined);
  assert.deepEqual(root[BRIDGE_CONFIG_KEY].xray, { inbounds: [] });
});

test("a profile without bridges is returned as it is", () => {
  const config = JSON.stringify({ outbounds: [{ type: "vless", tag: "a", server: "srv.example" }] });
  assert.equal(applyBridgeAuth(config), config);
});
