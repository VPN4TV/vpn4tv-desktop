import assert from "node:assert/strict";
import { test } from "node:test";

import {
  decodeProfileTitle,
  deviceHeaders,
  formatPairingCode,
  isExpired,
  mirrorUrl,
  newHwid,
  newPairingCode,
  parseUserInfo,
  telegramDeepLink,
  telegramQRLink,
} from "./onboarding";

test("hwid is a hyphen-free uuid, stable per call site", () => {
  const hwid = newHwid();
  assert.match(hwid, /^[0-9a-f]{32}$/i);
  assert.notEqual(hwid, newHwid(), "each install gets its own id");
});

test("pairing code is 10 digits and formats into groups", () => {
  const code = newPairingCode();
  assert.match(code, /^\d{10}$/);
  assert.equal(formatPairingCode("1234567890"), "1 234 567 890");
  assert.equal(formatPairingCode("short"), "short");
});

test("telegram links: QR uses https, the button uses tg://", () => {
  const uuid = "abc123";
  assert.equal(telegramQRLink(uuid), "https://telegram.me/VPN4TV_Bot?start=abc123");
  assert.equal(telegramDeepLink(uuid), "tg://resolve?domain=VPN4TV_Bot&start=abc123");
});

test("device headers carry the id, platform and version", () => {
  const headers = deviceHeaders({ hwid: "deadbeef", version: "1.0.0" });
  assert.equal(headers["x-hwid"], "deadbeef");
  assert.equal(headers["x-device-os"], "desktop");
  assert.equal(headers["x-ver-os"], "1.0.0");
  assert.equal(headers["User-Agent"], "VPN4TV-Desktop/1.0.0");
});

test("api host is mirrored to bell for the infra anchor", () => {
  assert.equal(mirrorUrl("https://api.vpn4tv.com/poll?uuid=x"), "https://bell.a4e.ar/poll?uuid=x");
  assert.equal(mirrorUrl("https://example.com/poll"), "https://example.com/poll");
});

test("subscription-userinfo parsing", () => {
  const info = parseUserInfo("upload=100; download=200; total=1000; expire=1805410844");
  assert.deepEqual(info, { upload: 100, download: 200, total: 1000, expireEpochSec: 1805410844 });
  assert.equal(parseUserInfo(""), undefined);
  assert.equal(parseUserInfo("garbage"), undefined);
});

test("expiry check uses seconds", () => {
  assert.equal(isExpired({ expireEpochSec: 1 }), true);
  assert.equal(isExpired({ expireEpochSec: Math.floor(Date.now() / 1000) + 3600 }), false);
  assert.equal(isExpired(undefined), false);
  assert.equal(isExpired({}), false);
});

test("profile-title decodes plain and base64 forms", () => {
  assert.equal(decodeProfileTitle("VPN4TV Premium"), "VPN4TV Premium");
  const encoded = Buffer.from("Подписка", "utf8").toString("base64");
  assert.equal(decodeProfileTitle(`base64:${encoded}`), "Подписка");
  assert.equal(decodeProfileTitle(null), undefined);
});
