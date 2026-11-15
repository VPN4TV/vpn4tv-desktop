import assert from "node:assert/strict";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";

import {
  type ProcessGoneLog,
  PROCESS_GONE_LOG_LIMIT,
  appendProcessGone,
  describeNativeCrash,
  formatExitCode,
  matchProcessGone,
  minidumpUploadSection,
  parseProcessGoneLog,
} from "./crashDumps";

const since = 1_000_000;

function log(...events: ProcessGoneLog["events"]): ProcessGoneLog {
  return { since, events };
}

test("a missing or damaged log starts counting from now", () => {
  assert.deepEqual(parseProcessGoneLog("", 5), { since: 5, events: [] });
  assert.deepEqual(parseProcessGoneLog("{not json", 5), { since: 5, events: [] });
});

test("the log round-trips and drops malformed events", () => {
  const text = JSON.stringify({
    since,
    events: [
      { at: since + 1, type: "GPU", reason: "crashed", exitCode: -1073741819 },
      { at: "x", type: "GPU", reason: "crashed", exitCode: 1 },
      null,
    ],
  });
  assert.deepEqual(parseProcessGoneLog(text, 0), log({ at: since + 1, type: "GPU", reason: "crashed", exitCode: -1073741819 }));
});

test("the log keeps only the newest events and its start", () => {
  let current = log();
  for (let index = 0; index < PROCESS_GONE_LOG_LIMIT + 5; index++) {
    current = appendProcessGone(current, { at: since + index, type: "Utility", reason: "killed", exitCode: 1 });
  }
  assert.equal(current.events.length, PROCESS_GONE_LOG_LIMIT);
  assert.equal(current.events[0].at, since + 5);
  assert.equal(current.since, since);
});

test("a dump is matched to the nearest event within 30 s, a crash before a kill", () => {
  const gpu = { at: since + 10_000, type: "GPU", reason: "crashed", exitCode: -1073741819 };
  const killed = { at: since + 10_500, type: "Utility", reason: "killed", exitCode: 1 };
  assert.equal(matchProcessGone(log(gpu, killed), since + 10_400), gpu);
  assert.equal(matchProcessGone(log(killed), since + 10_400), killed);
  assert.equal(matchProcessGone(log(gpu), since + 50_000), null);
});

test("descriptions: matched child, main process, before the log", () => {
  const gpu = { at: since + 10_000, type: "GPU", reason: "crashed", exitCode: -1073741819 };
  assert.deepEqual(describeNativeCrash(log(gpu), since + 10_200), {
    processType: "GPU",
    exceptionReason: "The GPU process went away: crashed, exit code -1073741819 (0xC0000005).",
  });
  const network = { at: since + 1, type: "Utility", reason: "oom", exitCode: 7, name: "Network Service" };
  assert.equal(describeNativeCrash(log(network), since).processType, "Utility (Network Service)");
  assert.equal(describeNativeCrash(log({ ...gpu, name: "GPU" }), since + 10_000).processType, "GPU");
  assert.equal(describeNativeCrash(log(gpu), since + 100_000).processType, "main");
  assert.equal(describeNativeCrash(log(gpu), since - 50_000).processType, "unknown");
});

test("exit codes: Windows crash codes as hex, small codes as is", () => {
  assert.equal(formatExitCode(-1073741819), "-1073741819 (0xC0000005)");
  assert.equal(formatExitCode(3221225786), "3221225786 (0xC000013A)");
  assert.equal(formatExitCode(1), "1");
});

test("a dump that fits travels as gzip base64 lines and decodes back", () => {
  const bytes = new Uint8Array(200_000);
  bytes.set([0x4d, 0x44, 0x4d, 0x50], 0); // "MDMP"
  const section = minidumpUploadSection("native.dmp", bytes, 1_000_000);
  const [header, ...lines] = section.split("\n");
  assert.equal(header, "===== native.dmp.gz.b64 =====");
  assert.ok(lines.every((line) => line.length <= 76));
  assert.deepEqual(new Uint8Array(gunzipSync(Buffer.from(lines.join(""), "base64"))), bytes);
});

test("a dump over the budget is not cut, only reported", () => {
  const bytes = new Uint8Array(4096).map((_value, index) => (index * 7919) % 251);
  const section = minidumpUploadSection("native.dmp", bytes, 100);
  assert.match(section, /^===== native\.dmp =====\nnot sent: 4096 bytes, \d+ as gzip base64, over the upload limit$/);
});
