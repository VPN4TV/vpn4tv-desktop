// The crash guard, the check and the session flags around applyRussiaDirect,
// with an in-memory store, a hand-driven clock and a stub check in place of
// the settings database, the timers and the worker.

import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
import { createServer } from "node:net";
import { test } from "node:test";

import { generateConfig } from "./generator";
import { parseSubscription } from "./parser";
import { BUNDLED_RULE_SETS } from "./russiaDirect";
import { RU_DIRECT_LISTS_REVISION } from "./russiaDirectLists.generated";
import { buildDnsQuery, parseDnsAnswers, probeDnsRu, probeProxyAlive } from "./russiaDirectProbe";
import {
  type Prepared,
  type RuntimeStore,
  type Wanted,
  RussiaDirectRuntime,
  SURVIVE_MILLISECONDS,
  checkKey,
  russiaDirectLabel,
  russiaDirectLine,
} from "./russiaDirectRuntime";

const BASE = generateConfig(
  parseSubscription(
    "vless://11111111-2222-3333-4444-555555555555@nl.example.net:443?security=reality&sni=www.example.com&fp=chrome&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=00#NL",
  ),
);
const WANTED: Wanted = { offReason: null, extraExceptions: [], sets: BUNDLED_RULE_SETS };

class MemoryStore implements RuntimeStore {
  readonly values = new Map<string, unknown>();
  get(name: string): unknown {
    const value = this.values.get(name);
    return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
  }
  set(name: string, value: unknown): void {
    this.values.set(name, JSON.parse(JSON.stringify(value)));
  }
  remove(name: string): void {
    this.values.delete(name);
  }
}

class Harness {
  readonly store: MemoryStore;
  running = true;
  checks: string[] = [];
  /** Content → error message; anything else passes. */
  refuse = new Map<string, string>();
  logs: string[] = [];
  timers: { at: number; callback: () => void; cancelled: boolean }[] = [];
  now = 0;
  readonly runtime: RussiaDirectRuntime;

  constructor(store = new MemoryStore(), appVersion = "1.0.0-beta.14") {
    this.store = store;
    this.runtime = new RussiaDirectRuntime({
      store,
      appVersion,
      checkConfig: async (content) => {
        this.checks.push(content);
        const problem = this.refuse.get(content);
        if (problem !== undefined) {
          throw new Error(problem);
        }
      },
      serviceRunning: () => this.running,
      log: (_warn, message) => this.logs.push(message),
      schedule: (milliseconds, callback) => {
        const timer = { at: this.now + milliseconds, callback, cancelled: false };
        this.timers.push(timer);
        return () => {
          timer.cancelled = true;
        };
      },
    });
  }

  /** Let [milliseconds] pass, firing the timers due in order. */
  advance(milliseconds: number): void {
    const until = this.now + milliseconds;
    for (;;) {
      const due = this.timers
        .filter((timer) => !timer.cancelled && timer.at <= until)
        .sort((a, b) => a.at - b.at)[0];
      if (due === undefined) {
        break;
      }
      due.cancelled = true;
      this.now = due.at;
      due.callback();
    }
    this.now = until;
  }

  /** A start of ours that went through: arm, start, run. */
  async start(wanted: Wanted = WANTED): Promise<Prepared> {
    const prepared = await this.runtime.prepare(BASE, wanted);
    this.runtime.armForStart(prepared);
    this.runtime.recordApplied(russiaDirectLabel(wanted.offReason), prepared);
    this.runtime.onRunning(prepared);
    return prepared;
  }

  pending(): unknown {
    return this.store.get("vpn4tv-ru-direct-pending");
  }
}

test("a start with the block that runs 30 s takes the guard off", async () => {
  const harness = new Harness();
  const prepared = await harness.start();
  assert.equal(prepared.state, "on");
  assert.ok(prepared.guarded && prepared.usesDnsRu && !prepared.warn);
  assert.deepEqual(harness.pending(), { key: `1.0.0-beta.14:${RU_DIRECT_LISTS_REVISION}`, crashed: false });
  harness.advance(SURVIVE_MILLISECONDS - 1);
  assert.notEqual(harness.pending(), undefined);
  harness.advance(1);
  assert.equal(harness.pending(), undefined);
  assert.equal(russiaDirectLine(prepared), `russia-direct: on [lists ${RU_DIRECT_LISTS_REVISION}]`);
});

test("the daemon going down within 30 s costs the block a strike, two strikes keep it off", async () => {
  const harness = new Harness();
  await harness.start();
  harness.runtime.onDaemonLost();
  assert.deepEqual(harness.pending(), { key: `1.0.0-beta.14:${RU_DIRECT_LISTS_REVISION}`, crashed: true });
  assert.ok(harness.runtime.repairPending);
  harness.advance(SURVIVE_MILLISECONDS * 2); // no survival after the crash

  // The restart after the crash: torrents only, not guarded.
  harness.runtime.newSession();
  const repaired = await harness.runtime.prepare(BASE, WANTED);
  assert.equal(repaired.state, "off (crash guard: the last start with it did not survive, 1 of 2)");
  assert.ok(!repaired.guarded && repaired.warn);
  assert.ok(repaired.content.includes('"bittorrent"') && !repaired.content.includes("dns-ru"));
  assert.equal(harness.pending(), undefined);
  // The rest of the session goes without it.
  assert.match((await harness.runtime.prepare(BASE, WANTED)).state, /^off \(crash guard/u);

  // Next connect: one strike is not enough to keep it off; a second crash is.
  harness.runtime.newSession();
  const second = await harness.start();
  assert.equal(second.state, "on");
  harness.runtime.onDaemonLost();
  harness.runtime.newSession();
  assert.equal(
    (await harness.runtime.prepare(BASE, WANTED)).state,
    "off (crash guard: the last start with it did not survive, 2 of 2)",
  );
  harness.runtime.newSession();
  const later = await harness.runtime.prepare(BASE, WANTED);
  assert.equal(later.state, "off (crash guard: off until the next version or lists)");
  assert.ok(!later.guarded);

  // A new app version forgets the strikes.
  const updated = new Harness(harness.store, "1.0.0-beta.15");
  assert.equal((await updated.runtime.prepare(BASE, WANTED)).state, "on");
});

test("a block that survives once clears the earlier strike", async () => {
  const harness = new Harness();
  await harness.start();
  harness.runtime.onDaemonLost();
  harness.runtime.newSession();
  await harness.runtime.prepare(BASE, WANTED); // strike 1
  harness.runtime.newSession();
  await harness.start();
  harness.advance(SURVIVE_MILLISECONDS);
  assert.equal(harness.store.get("vpn4tv-ru-direct-strikes"), undefined);
});

test("a mark an earlier run of the app left without a crash is not counted", async () => {
  const first = new Harness();
  await first.start();
  // The app quits within 30 s: the mark stays, unresolved.
  const second = new Harness(first.store);
  const prepared = await second.runtime.prepare(BASE, WANTED);
  assert.equal(prepared.state, "on");
  assert.equal(second.pending(), undefined);
  assert.equal(second.store.get("vpn4tv-ru-direct-strikes"), undefined);
  // A crash record from an earlier run counts.
  second.runtime.armForStart(prepared);
  second.runtime.onDaemonLost();
  const third = new Harness(second.store);
  assert.match((await third.runtime.prepare(BASE, WANTED)).state, /^off \(crash guard: .* 1 of 2\)$/u);
});

test("an orderly stop takes the guard off without clearing strikes; a stop is no crash", async () => {
  const harness = new Harness();
  await harness.start();
  harness.runtime.onStopped();
  assert.equal(harness.pending(), undefined);
  harness.runtime.onDaemonLost();
  assert.equal(harness.pending(), undefined);
  assert.ok(!harness.runtime.repairPending);
});

test("a reload under way at the 30 s mark: the guard looks again instead of staying armed", async () => {
  const harness = new Harness();
  await harness.start();
  harness.running = false;
  harness.advance(SURVIVE_MILLISECONDS);
  assert.notEqual(harness.pending(), undefined);
  harness.running = true;
  harness.advance(5_000);
  assert.equal(harness.pending(), undefined);
  // A service that never settles gives up without a strike.
  const stuck = new Harness();
  await stuck.start();
  stuck.running = false;
  stuck.advance(SURVIVE_MILLISECONDS + 5_000 * 20);
  assert.equal(stuck.pending(), undefined);
  assert.equal(stuck.store.get("vpn4tv-ru-direct-strikes"), undefined);
});

test("a reload while armed keeps the one mark and restarts the 30 s", async () => {
  const harness = new Harness();
  await harness.start();
  harness.advance(20_000);
  await harness.start();
  harness.advance(20_000);
  assert.notEqual(harness.pending(), undefined);
  harness.advance(10_000);
  assert.equal(harness.pending(), undefined);
});

test("the service the daemon brought back is guarded for what is left of 30 s", async () => {
  const harness = new Harness();
  await harness.start();
  harness.advance(SURVIVE_MILLISECONDS);
  assert.equal(harness.pending(), undefined);
  // A later process: the daemon restored the service 10 s ago.
  const later = new Harness(harness.store);
  later.runtime.onRestored(10_000);
  assert.notEqual(later.pending(), undefined);
  later.runtime.onDaemonLost();
  assert.ok(later.runtime.repairPending);
  assert.match((await later.runtime.prepare(BASE, WANTED)).state, /^off \(crash guard/u);
  // Too old, or the last start had nothing guarded: nothing to do.
  const old = new Harness(harness.store);
  old.runtime.onRestored(SURVIVE_MILLISECONDS);
  assert.equal(old.pending(), undefined);
  const unguarded = new Harness();
  unguarded.runtime.recordApplied(russiaDirectLabel(null), {
    content: BASE,
    state: "off (not ours)",
    warn: false,
    guarded: false,
    usesDnsRu: false,
  });
  unguarded.runtime.onRestored(1_000);
  assert.equal(unguarded.pending(), undefined);
  // A restored service that survives clears like any other.
  const survived = new Harness(harness.store);
  survived.runtime.onRestored(25_000);
  survived.advance(5_000);
  assert.equal(survived.pending(), undefined);
});

test("checkConfig blames the block only when the config without it passes", async () => {
  const harness = new Harness();
  const content = (await new Harness().runtime.prepare(BASE, WANTED)).content;
  harness.refuse.set(content, "dns rule: something the core refuses");
  const prepared = await harness.runtime.prepare(BASE, WANTED);
  assert.equal(prepared.state, "off (check: dns rule: something the core refuses)");
  assert.ok(!prepared.guarded && prepared.warn);
  assert.deepEqual(harness.checks, [content, BASE]);
  // Kept for the process, not in the store.
  await harness.runtime.prepare(BASE, WANTED);
  assert.equal(harness.checks.length, 2);
  assert.equal(harness.store.get("vpn4tv-ru-direct-checked"), undefined);

  // Both refused: the block is not to blame, the start decides.
  const both = new Harness();
  both.refuse.set(content, "broken");
  both.refuse.set(BASE, "broken");
  assert.equal((await both.runtime.prepare(BASE, WANTED)).state, "on");

  // A pass is kept in the store: a new process does not ask again.
  const passing = new Harness();
  await passing.runtime.prepare(BASE, WANTED);
  assert.equal(passing.checks.length, 1);
  const next = new Harness(passing.store);
  await next.runtime.prepare(BASE, WANTED);
  assert.equal(next.checks.length, 0);
  // A new app version asks again.
  const updated = new Harness(passing.store, "1.0.0-beta.15");
  await updated.runtime.prepare(BASE, WANTED);
  assert.equal(updated.checks.length, 1);
});

test("the check key ignores the DNS server addresses the probe picks", () => {
  const one = JSON.parse(BASE);
  const two = JSON.parse(BASE);
  two.dns.servers[0].server = "149.112.112.112";
  assert.equal(checkKey("v", JSON.stringify(one)), checkKey("v", JSON.stringify(two)));
  two.route.final = "direct";
  assert.notEqual(checkKey("v", JSON.stringify(one)), checkKey("v", JSON.stringify(two)));
  assert.notEqual(checkKey("v", BASE), checkKey("w", BASE));
});

test("a failed start rolls back for the session; a new connect tries again", async () => {
  const harness = new Harness();
  const prepared = await harness.runtime.prepare(BASE, WANTED);
  harness.runtime.armForStart(prepared);
  harness.runtime.rolledBack("start service: boom");
  assert.equal(harness.pending(), undefined);
  assert.equal((await harness.runtime.prepare(BASE, WANTED)).state, "off (session: the start with it failed: start service: boom)");
  harness.runtime.newSession();
  assert.equal((await harness.runtime.prepare(BASE, WANTED)).state, "on");
});

test("Everything through VPN: the torrent rule alone, guarded; the label says what was wanted", async () => {
  const harness = new Harness();
  const prepared = await harness.runtime.prepare(BASE, { ...WANTED, offReason: "user" });
  assert.equal(prepared.state, "off (user); torrents direct");
  assert.ok(prepared.guarded && !prepared.usesDnsRu && !prepared.warn);
  assert.equal(harness.checks.length, 0);
  assert.equal(russiaDirectLabel("user"), `1:${RU_DIRECT_LISTS_REVISION}:user`);
  assert.equal(russiaDirectLabel(null), `1:${RU_DIRECT_LISTS_REVISION}:on`);
  await harness.start({ ...WANTED, offReason: "head" });
  assert.equal(harness.runtime.appliedLabel(), `1:${RU_DIRECT_LISTS_REVISION}:head`);
  assert.ok(harness.runtime.lastStartGuarded());
});

test("suffixes only and the dns-ru fallback are worth a warning", async () => {
  const harness = new Harness();
  const suffixes = await harness.runtime.prepare(BASE, { ...WANTED, sets: null });
  assert.equal(suffixes.state, "on (suffixes)");
  assert.ok(suffixes.warn);
  harness.runtime.dnsRuFallback = true;
  const fallback = await harness.runtime.prepare(BASE, WANTED);
  assert.equal(fallback.state, "on (dns-direct)");
  assert.ok(fallback.warn && !fallback.usesDnsRu);
});

test("the dns-ru self-check runs once per session", async () => {
  const harness = new Harness();
  const prepared = await harness.runtime.prepare(BASE, WANTED);
  assert.ok(harness.runtime.claimDnsCheck(prepared));
  assert.ok(!harness.runtime.claimDnsCheck(prepared));
  harness.runtime.newSession();
  assert.ok(harness.runtime.claimDnsCheck(prepared));
  harness.runtime.newSession();
  harness.runtime.dnsRuFallback = true;
  assert.ok(!harness.runtime.claimDnsCheck(prepared));
});

test("a config that is not ours is started as it is, unguarded", async () => {
  const harness = new Harness();
  const foreign = JSON.stringify({ outbounds: [{ type: "direct", tag: "direct" }] });
  const prepared = await harness.runtime.prepare(foreign, WANTED);
  assert.equal(prepared.content, foreign);
  assert.ok(!prepared.guarded);
  assert.match(prepared.state, /^off \(not ours/u);
});

test("DNS probe packets: a query for ya.ru and the A records of an answer", () => {
  const query = buildDnsQuery("ya.ru", 0x1234);
  assert.equal(query.readUInt16BE(0), 0x1234);
  assert.equal(query.readUInt16BE(4), 1);
  assert.deepEqual([...query.subarray(12)], [2, 0x79, 0x61, 2, 0x72, 0x75, 0, 0, 1, 0, 1]);
  // The answer: the question, then two A records named by a compression pointer.
  const answer = Buffer.concat([
    Buffer.from([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]),
    query.subarray(12),
    Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 77, 88, 55, 242]),
    Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 5, 255, 255, 242]),
  ]);
  assert.deepEqual(parseDnsAnswers(answer), ["77.88.55.242", "5.255.255.242"]);
  assert.deepEqual(parseDnsAnswers(answer.subarray(0, answer.length - 3)), ["77.88.55.242"]);
  assert.deepEqual(parseDnsAnswers(Buffer.from([0, 1])), []);
});

test("the dns-ru probe: an answer with an address passes, silence and an empty answer do not", async () => {
  const server = createSocket("udp4");
  let mode: "answer" | "empty" | "silent" = "answer";
  let queries = 0;
  server.on("message", (message, peer) => {
    queries += 1;
    if (mode === "silent") {
      return;
    }
    const question = message.subarray(12);
    const header = Buffer.from([message[0], message[1], 0x81, 0x80, 0, 1, 0, mode === "answer" ? 1 : 0, 0, 0, 0, 0]);
    const record = mode === "answer" ? Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 77, 88, 55, 242]) : Buffer.alloc(0);
    server.send(Buffer.concat([header, question, record]), peer.port, peer.address);
  });
  await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", resolve));
  const targets = { dnsAddress: "127.0.0.1", dnsPort: server.address().port, timeoutMilliseconds: 300, pauseMilliseconds: 10 };
  try {
    assert.ok(await probeDnsRu(3, () => true, () => {}, targets));
    assert.equal(queries, 1);
    mode = "empty";
    const logs: string[] = [];
    assert.ok(!(await probeDnsRu(2, () => true, (message) => logs.push(message), targets)));
    assert.equal(logs.length, 2);
    mode = "silent";
    assert.ok(!(await probeDnsRu(2, () => true, () => {}, targets)));
    // Not wanted any more (stopped, fallen back): no query at all.
    const before = queries;
    assert.ok(!(await probeDnsRu(3, () => false, () => {}, targets)));
    assert.equal(queries, before);
  } finally {
    server.close();
  }
});

test("the proxy probe: a TCP connect by address", async () => {
  const listener = createServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const port = (listener.address() as { port: number }).port;
  try {
    assert.ok(await probeProxyAlive(() => true, { proxyAddresses: ["127.0.0.1"], proxyPort: port, timeoutMilliseconds: 500 }));
    // Nothing listens there: refused, then the next address.
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const deadPort = (closed.address() as { port: number }).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    assert.ok(!(await probeProxyAlive(() => true, { proxyAddresses: ["127.0.0.1"], proxyPort: deadPort, timeoutMilliseconds: 500 })));
    assert.ok(!(await probeProxyAlive(() => false, { proxyAddresses: ["127.0.0.1"], proxyPort: port })));
  } finally {
    listener.close();
  }
});
