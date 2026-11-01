// VPN4TV: what surrounds applyRussiaDirect at every start and reload of the
// service on the desktop: whether the block goes in, and what keeps a bad block
// from costing the user the VPN. RussiaDirectRuntime.kt by meaning, adapted to
// a core that runs in the daemon — a separate process that the system restarts
// by itself and that brings back the last config it started.
//
// - Off when the user sends everything through the VPN and when our server
//   turned it off for the profile (x-vpn4tv-ru-direct: 0); plain BitTorrent
//   goes direct then too. Off for the rest of the session after the crash
//   guard or a failed start: then only the torrent rule goes in.
// - Crash guard. A start with the block leaves a mark (app version + lists
//   revision, written synchronously) until the service has run 30 s or stops
//   in order. If the daemon goes down while the mark is armed (a Go panic, an
//   out-of-memory kill), the mark turns into a crash record: the system
//   restarts the daemon, the daemon brings the same config back, so the client
//   restarts the service without the block as soon as it is up, and the next
//   start counts a strike. After two strikes in a row the block stays off
//   until the app version or the lists change. A mark left by an earlier run
//   of the app that saw no crash (the app quit or the computer went down
//   within those 30 s) is dropped: the client dying says nothing about the
//   core. A service the daemon brought back by itself within the last 30 s
//   (after a crash or a reboot) is guarded the same way when the last config
//   the client started carried the block.
// - Before a config with the block reaches the daemon it goes once through
//   the worker's checkConfig (the same box.New, unprivileged), cached by app
//   version and the parts the block touches. That catches what the core would
//   refuse without dropping the tunnel. The block is blamed only if the config
//   without it passes the same check.
// - A start that fails with the block is retried without it (profiles.ts);
//   the block then stays off for the session.
// - After connect a DNS query for a Russian name goes through the tunnel; if
//   dns-ru does not answer while the proxy does, our DNS rule resolves through
//   dns-direct for the session.
//
// Electron-free: the store, the clock and the check are handed in, so the
// tests run it as is.

import { createHash } from "node:crypto";

import { type Json, asObject, parseJsonObject } from "./support";
import { RU_DIRECT_LISTS_REVISION } from "./russiaDirectLists.generated";
import { RU_DIRECT_REVISION, type RuleSetData, applyRussiaDirect } from "./russiaDirect";

/** How long a start with the block has to run before the guard comes off. */
export const SURVIVE_MILLISECONDS = 30_000;
const SURVIVAL_RECHECK_MILLISECONDS = 5_000;
const MAX_SURVIVAL_RECHECKS = 12;
const MAX_STRIKES = 2;

const PENDING = "vpn4tv-ru-direct-pending";
const STRIKES = "vpn4tv-ru-direct-strikes";
const CHECKED = "vpn4tv-ru-direct-checked";
const APPLIED = "vpn4tv-ru-direct-applied";

/** Synchronous key-value storage (the settings database). */
export interface RuntimeStore {
  get(name: string): unknown;
  set(name: string, value: unknown): void;
  remove(name: string): void;
}

export interface RuntimeEnvironment {
  store: RuntimeStore;
  /** The app version: a new one forgets the strikes and the cached check. */
  appVersion: string;
  /** The worker's checkConfig; rejects with the core's error. */
  checkConfig(content: string): Promise<void>;
  /** Whether the service runs right now (the daemon is connected and says STARTED). */
  serviceRunning(): boolean;
  log(warn: boolean, message: string): void;
  /** Runs [callback] after [milliseconds]; returns a function that cancels it. */
  schedule(milliseconds: number, callback: () => void): () => void;
}

/** What the user and our server want for the profile being started. */
export interface Wanted {
  /** "user" (Everything through VPN), "head" (x-vpn4tv-ru-direct: 0) or null. */
  offReason: string | null;
  /** Names our server keeps on the VPN for the profile, besides the built-in exceptions. */
  extraExceptions: readonly string[];
  /** Rule-set data to inline, or null for the suffixes alone. */
  sets: RuleSetData | null;
}

export interface Prepared {
  /** What to start. */
  content: string;
  /** Summary for the log line. */
  state: string;
  /** Log it as a warning: the block is degraded or off for a reason worth a look. */
  warn: boolean;
  /** The crash guard covers this start. */
  guarded: boolean;
  /** dns-ru is in it, so its self-check is worth running. */
  usesDnsRu: boolean;
}

/** The line for the log after every start and reload. */
export function russiaDirectLine(prepared: Pick<Prepared, "state">): string {
  return `russia-direct: ${prepared.state} [lists ${RU_DIRECT_LISTS_REVISION}]`;
}

/**
 * What a start tries to apply, for the one-time restart after an update: the
 * block's shape, the lists and what the user and our server want. A start that
 * had to fall back still records what it tried, so a block that keeps failing
 * does not restart the service at every launch.
 */
export function russiaDirectLabel(offReason: string | null): string {
  return `${RU_DIRECT_REVISION}:${RU_DIRECT_LISTS_REVISION}:${offReason ?? "on"}`;
}

interface PendingMark {
  key: string;
  crashed: boolean;
}

interface Strikes {
  key: string;
  count: number;
}

interface Applied {
  label: string;
  /** The config started carried a guarded part (the block or the torrent rule). */
  guarded: boolean;
}

function parsePending(value: unknown): PendingMark | null {
  const object = asObject(value);
  return object !== null && typeof object.key === "string"
    ? { key: object.key, crashed: object.crashed === true }
    : null;
}

function parseStrikes(value: unknown): Strikes | null {
  const object = asObject(value);
  return object !== null && typeof object.key === "string" && typeof object.count === "number"
    ? { key: object.key, count: object.count }
    : null;
}

function parseApplied(value: unknown): Applied | null {
  const object = asObject(value);
  return object !== null && typeof object.label === "string"
    ? { label: object.label, guarded: object.guarded === true }
    : null;
}

export class RussiaDirectRuntime {
  /** dns-ru did not answer the self-check: our DNS rule uses dns-direct until the next connect. */
  dnsRuFallback = false;
  /**
   * The daemon went down while a start with the block was guarded: once the
   * service is up again (the daemon brings the same config back), restart it,
   * and the start leaves the block out.
   */
  repairPending = false;

  private sessionOffReason: string | null = null;
  private dnsCheckStarted = false;
  // Whether the mark in the store is this process's own and still armed, and
  // which arming the survival timer belongs to.
  private armedHere = false;
  private armToken = 0;
  private cancelSurvival: (() => void) | null = null;
  // What checkConfig said in this process, by key: the problem, or null when
  // there is nothing to hold against the block. Only a pass is kept in the
  // store; a new process, maybe a new app version, asks again.
  private readonly checkVerdicts = new Map<string, string | null>();

  constructor(private readonly environment: RuntimeEnvironment) {}

  /** A connect the user asked for: what the last session learned starts over. */
  newSession(): void {
    this.sessionOffReason = null;
    this.dnsRuFallback = false;
    this.dnsCheckStarted = false;
  }

  /** The config to start for [base], the config without the block. Never throws. */
  async prepare(base: string, wanted: Wanted): Promise<Prepared> {
    try {
      return await this.prepare0(base, wanted);
    } catch (error) {
      const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      this.environment.log(true, `russia-direct: not applied: ${message}`);
      return { content: base, state: `off (error: ${message})`, warn: true, guarded: false, usesDnsRu: false };
    }
  }

  /**
   * [base] with the plain-BitTorrent rule alone: what runs while the block is
   * off for safety (crash guard, a failed start or check). Torrents go direct
   * in every mode, and that rule alone cannot fail a start.
   */
  torrentsOnly(base: string, reason: string): string {
    try {
      return applyRussiaDirect(base, { offReason: reason }).content;
    } catch {
      return base;
    }
  }

  private async prepare0(base: string, wanted: Wanted): Promise<Prepared> {
    const admitted = this.admit();
    if (admitted !== null) {
      return this.safetyOff(base, admitted);
    }
    if (this.sessionOffReason !== null) {
      return this.safetyOff(base, this.sessionOffReason);
    }
    const result = applyRussiaDirect(base, {
      offReason: wanted.offReason,
      sets: wanted.sets,
      dnsRuFallback: this.dnsRuFallback,
      extraExceptions: wanted.extraExceptions,
    });
    const warn =
      (result.applied && (wanted.sets === null || this.dnsRuFallback)) ||
      result.state.startsWith("off (legacy") ||
      result.state.startsWith("off (error");
    if (result.content === base) {
      return { content: base, state: result.state, warn, guarded: false, usesDnsRu: false };
    }
    if (result.applied) {
      const problem = await this.checkProblem(result.content, base);
      if (problem !== null) {
        return this.safetyOff(base, `check: ${problem}`);
      }
    }
    return { content: result.content, state: result.state, warn, guarded: true, usesDnsRu: result.usesDnsRu };
  }

  private safetyOff(base: string, reason: string): Prepared {
    return { content: this.torrentsOnly(base, reason), state: `off (${reason})`, warn: true, guarded: false, usesDnsRu: false };
  }

  /** Right before [prepared] goes to the daemon: arm the crash guard if it covers it. */
  armForStart(prepared: Prepared): void {
    if (!prepared.guarded) {
      return;
    }
    // A reload while armed: the mark is in the store already, only the 30 s start over.
    if (!this.armedHere) {
      this.environment.store.set(PENDING, { key: this.guardKey(), crashed: false } satisfies PendingMark);
    }
    this.armedHere = true;
    this.armToken += 1;
    this.cancelSurvivalTimer();
  }

  /** The daemon runs [prepared]: once it has run a while, the crash guard comes off. */
  onRunning(prepared: Prepared, milliseconds = SURVIVE_MILLISECONDS): void {
    if (!prepared.guarded || !this.armedHere) {
      return;
    }
    this.startSurvivalTimer(milliseconds);
  }

  /**
   * The daemon brought the service back by itself [age] ms ago (after a crash
   * or a reboot), with the config the client started last. Guard what is left
   * of its first 30 s when that config carried the block.
   */
  onRestored(age: number): void {
    if (this.armedHere || age < 0 || age >= SURVIVE_MILLISECONDS || !this.lastStartGuarded()) {
      return;
    }
    this.environment.store.set(PENDING, { key: this.guardKey(), crashed: false } satisfies PendingMark);
    this.armedHere = true;
    this.armToken += 1;
    this.startSurvivalTimer(SURVIVE_MILLISECONDS - age);
    this.environment.log(false, "russia-direct: guarding the service the daemon brought back");
  }

  /** The start or reload with the block failed, and the base started in its place. */
  rolledBack(error: string): void {
    this.sessionOffReason = `session: the start with it failed: ${error}`;
    // The config that runs now is ours and has no block: nothing to repair.
    this.repairPending = false;
    this.disarm(false);
  }

  /** The service stopped in order, or a start failed with an error the daemon reported: no crash to guard against. */
  onStopped(): void {
    this.disarm(false);
  }

  /**
   * The daemon went away (the connection broke). While a start with the block
   * is guarded that means the core died with it: keep a crash record for the
   * next start, and restart the service once the daemon has brought it back.
   */
  onDaemonLost(): void {
    if (!this.armedHere) {
      return;
    }
    this.armedHere = false;
    this.armToken += 1;
    this.cancelSurvivalTimer();
    this.environment.store.set(PENDING, { key: this.guardKey(), crashed: true } satisfies PendingMark);
    this.repairPending = true;
    this.environment.log(true, "russia-direct: the service went down within 30 s of a start with it; the next start goes without it");
  }

  /** Whether to start the dns-ru self-check now: once per session, while dns-ru is in use. */
  claimDnsCheck(prepared: Prepared): boolean {
    if (!prepared.usesDnsRu || this.dnsRuFallback || this.dnsCheckStarted) {
      return false;
    }
    this.dnsCheckStarted = true;
    return true;
  }

  /** What the last start tried to apply (russiaDirectLabel), or null before the first one. */
  appliedLabel(): string | null {
    return parseApplied(this.environment.store.get(APPLIED))?.label ?? null;
  }

  /** The last config the client started carried a guarded part. */
  lastStartGuarded(): boolean {
    return parseApplied(this.environment.store.get(APPLIED))?.guarded === true;
  }

  /** A start went through: remember what it tried to apply and whether what runs is guarded. */
  recordApplied(label: string, ran: Prepared): void {
    this.environment.store.set(APPLIED, { label, guarded: ran.guarded } satisfies Applied);
  }

  private guardKey(): string {
    return `${this.environment.appVersion}:${RU_DIRECT_LISTS_REVISION}`;
  }

  /** Consumes a mark an earlier start left. Null: the block may go in. */
  private admit(): string | null {
    const store = this.environment.store;
    const key = this.guardKey();
    const stored = parseStrikes(store.get(STRIKES));
    let strikes = stored !== null && stored.key === key ? stored.count : 0;
    const pending = parsePending(store.get(PENDING));
    if (pending !== null && !this.armedHere) {
      store.remove(PENDING);
      // An older version's mark says nothing about this one.
      if (pending.key === key && pending.crashed) {
        strikes += 1;
        store.set(STRIKES, { key, count: strikes } satisfies Strikes);
        const reason = `crash guard: the last start with it did not survive, ${strikes} of ${MAX_STRIKES}`;
        this.environment.log(true, `russia-direct: ${reason}`);
        this.sessionOffReason = reason;
        return reason;
      }
      if (pending.key === key) {
        this.environment.log(false, "russia-direct: crash guard: an earlier run of the app left its mark without a crash, not counted");
      }
    }
    if (strikes >= MAX_STRIKES) {
      return "crash guard: off until the next version or lists";
    }
    return null;
  }

  private startSurvivalTimer(milliseconds: number): void {
    this.cancelSurvivalTimer();
    const token = this.armToken;
    let rechecks = 0;
    const check = () => {
      this.cancelSurvival = null;
      if (token !== this.armToken || !this.armedHere) {
        return;
      }
      if (this.environment.serviceRunning()) {
        this.disarm(true);
        return;
      }
      // Not running at this very moment: a reload is under way, or the
      // connection to the daemon is being set up again. A stop or a crash ends
      // the arming by itself; otherwise look again shortly, and give up
      // (without counting anything) if the service never settles.
      rechecks += 1;
      if (rechecks > MAX_SURVIVAL_RECHECKS) {
        this.disarm(false);
        return;
      }
      this.cancelSurvival = this.environment.schedule(SURVIVAL_RECHECK_MILLISECONDS, check);
    };
    this.cancelSurvival = this.environment.schedule(milliseconds, check);
  }

  private cancelSurvivalTimer(): void {
    this.cancelSurvival?.();
    this.cancelSurvival = null;
  }

  private disarm(survived: boolean): void {
    if (!this.armedHere) {
      return;
    }
    this.armedHere = false;
    this.armToken += 1;
    this.cancelSurvivalTimer();
    const store = this.environment.store;
    store.remove(PENDING);
    // Only a block that ran proves the earlier strikes were bad luck.
    if (survived) {
      store.remove(STRIKES);
    }
  }

  /**
   * Why checkConfig refuses [content], the config with the block, or null. The
   * block is blamed only if [base], the same config without it, passes: a
   * check that refuses both says nothing about the block, and the start (with
   * its retry without the block) decides as before.
   */
  private async checkProblem(content: string, base: string): Promise<string | null> {
    let key: string;
    try {
      key = checkKey(this.environment.appVersion, content);
    } catch {
      return null;
    }
    const store = this.environment.store;
    if (store.get(CHECKED) === key) {
      return null;
    }
    if (this.checkVerdicts.has(key)) {
      return this.checkVerdicts.get(key) ?? null;
    }
    let verdict: string | null;
    try {
      await this.environment.checkConfig(content);
      store.set(CHECKED, key);
      verdict = null;
    } catch (error) {
      const problem = (error instanceof Error ? error.message : String(error)).slice(0, 200);
      const baseRefused = await this.environment.checkConfig(base).then(
        () => false,
        () => true,
      );
      if (baseRefused) {
        this.environment.log(true, `russia-direct: checkConfig refuses the config without it too, leaving it to the start: ${problem}`);
        verdict = null;
      } else {
        this.environment.log(true, `russia-direct: checkConfig refused the config with it: ${problem}`);
        verdict = problem;
      }
    }
    this.checkVerdicts.set(key, verdict);
    return verdict;
  }
}

/**
 * App version and the sha256 of what the block touches: the DNS section
 * without the server addresses (the DNS probe picks them anew at every start)
 * and the route.
 */
export function checkKey(appVersion: string, content: string): string {
  const root = parseJsonObject(content);
  if (root === null) {
    throw new Error("not a JSON object");
  }
  const dns: Json = { ...(asObject(root.dns) ?? {}) };
  if (Array.isArray(dns.servers)) {
    dns.servers = dns.servers.map((entry) => {
      const server = asObject(entry);
      if (server === null) {
        return entry;
      }
      const { server: _address, server_port: _port, ...rest } = server;
      return rest;
    });
  }
  const material = JSON.stringify({ dns, route: asObject(root.route) ?? {} });
  return `${appVersion}:${createHash("sha256").update(material).digest("hex")}`;
}
