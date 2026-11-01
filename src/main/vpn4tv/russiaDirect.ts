// VPN4TV: "Russia direct" — Russian names and Russian IPv4 addresses leave
// through the computer's own network, everything else goes as before. The same
// block as RussiaDirect.kt on Android and RussiaDirect.swift on Apple, with the
// same lists (russiaDirectLists.generated.ts) and the same summary for the log.
//
// The owner's rules (2026-10-31): our exits must not show up at Russian
// services, so a Russian name goes direct at any address and a Russian IPv4
// goes direct with or without a name; names blocked in Russia (the exceptions)
// stay on the VPN; plain BitTorrent goes direct always, the "Everything
// through VPN" toggle included (DMCA). Added after the rules already there, in
// this order:
//  1. {protocol: bittorrent} → direct
//  2. and[M, E] → direct, where M = geosite-category-ru or the built-in
//     suffixes and E = not an exception
//  3. and[geoip-ru, E, IPv4] → direct
// IPv6 without a Russian name keeps going through the VPN: a Russian IPv6 sent
// direct breaks on networks without IPv6.
//
// DNS: Russian names resolve at Yandex (dns-ru, TCP, dialed directly), and
// their AAAA/HTTPS/SVCB queries get an empty answer here; both rules go ahead
// of the HTTPS/SVCB reject and the fakeip rule. Without usable rule-set data M
// is the suffixes alone and rule 3 is left out ("on (suffixes)").
//
// Desktop specifics:
//  - the rule sets travel inline (type "inline"): the daemon on Windows and
//    Linux may not read files outside its own folder;
//  - the route rules go in ahead of the first per-app rule (process_name /
//    process_path), else last, so in "only these applications" mode Russian
//    traffic of the chosen applications goes direct too, as on Android, where
//    the VpnService does the choosing;
//  - the result is compact JSON: the inline sets are some 200 KB.
//
// Applied in memory at every start and reload on top of the config the other
// transforms produced (dynamic Outline keys, injectProbedDns, applyIPv6Support),
// so old and local profiles get it too and the toggle needs no subscription
// refresh. Only configs of our own shape are touched; a foreign sing-box config
// comes back unchanged. Pure and Electron-free: the tests run it as is.

import { type Json, asObject, parseJsonObject } from "./support";
import {
  DNS_RU_SERVER,
  DNS_RU_TAG,
  DNS_RU_TYPE,
  RU_DIRECT_LISTS_REVISION,
  RU_SUFFIXES,
  RU_VPN_EXCEPTIONS,
} from "./russiaDirectLists.generated";
import {
  GEOIP_RU_RULES,
  GEOIP_RU_SOURCE,
  GEOSITE_CATEGORY_RU_RULES,
  GEOSITE_CATEGORY_RU_SOURCE,
  type InlineRuleSetRule,
} from "./ruleSets.generated";

/**
 * The shape of the block. Bump it when the block changes in a way a running
 * service should pick up: the one-time restart after an update compares it.
 */
export const RU_DIRECT_REVISION = 1;

export const GEOSITE_TAG = GEOSITE_CATEGORY_RU_SOURCE.tag;
export const GEOIP_TAG = GEOIP_RU_SOURCE.tag;

const SELECT = "select";
const DIRECT = "direct";
const DNS_REMOTE = "dns-remote";
const DNS_DIRECT = "dns-direct";
const DNS_FAKEIP = "dns-fakeip";
const BITTORRENT = "bittorrent";

/** The rule-set data that goes inline. */
export interface RuleSetData {
  geosite: readonly InlineRuleSetRule[];
  geoip: readonly InlineRuleSetRule[];
}

/** The data bundled with this build. */
export const BUNDLED_RULE_SETS: RuleSetData = {
  geosite: GEOSITE_CATEGORY_RU_RULES,
  geoip: GEOIP_RU_RULES,
};

/**
 * Whether [sets] can go in: both sets hold at least one non-empty rule, the
 * geosite set names only domains and the geoip set only addresses. Anything
 * else would make the core refuse the start or match the wrong things.
 */
export function usableRuleSets(sets: RuleSetData = BUNDLED_RULE_SETS): RuleSetData | null {
  const fields = (rule: InlineRuleSetRule) =>
    Object.entries(rule).filter(([, value]) => Array.isArray(value) && value.length > 0);
  const nonEmpty = (rules: readonly InlineRuleSetRule[], allowed: string[]) =>
    rules.length > 0 &&
    rules.every((rule) => {
      const present = fields(rule);
      return present.length > 0 && present.every(([name]) => allowed.includes(name));
    });
  return nonEmpty(sets.geosite, ["domain", "domain_suffix", "domain_keyword", "domain_regex"]) &&
    nonEmpty(sets.geoip, ["ip_cidr"])
    ? sets
    : null;
}

export interface RussiaDirectOptions {
  /**
   * Null or absent: Russia direct is wanted. Otherwise why it is not ("user",
   * "head", a safety reason), for the log line; plain BitTorrent still goes
   * direct.
   */
  offReason?: string | null;
  /** Rule-set data to inline; null routes Russian names by the built-in suffixes alone. */
  sets?: RuleSetData | null;
  /** dns-ru did not answer this session: our DNS rule resolves through dns-direct. */
  dnsRuFallback?: boolean;
  /** More names kept on the VPN, from the subscription server. */
  extraExceptions?: readonly string[];
}

export interface RussiaDirectResult {
  /** What to start. The input itself when nothing was added. */
  content: string;
  /** The summary for the log line. */
  state: string;
  /** The Russian rules are in it, not only the torrent rule. */
  applied: boolean;
  /** dns-ru is in it, so its self-check is worth running. */
  usesDnsRu: boolean;
}

function unchanged(content: string, state: string): RussiaDirectResult {
  return { content, state, applied: false, usesDnsRu: false };
}

export function applyRussiaDirect(
  content: string,
  options: RussiaDirectOptions = {},
): RussiaDirectResult {
  const root = parseJsonObject(content);
  if (root === null) {
    return unchanged(content, "off (not a JSON object)");
  }
  try {
    const notOurs = russiaDirectNotOursReason(root);
    if (notOurs !== null) {
      return unchanged(content, `off (not ours: ${notOurs})`);
    }

    const route = asObject(root.route)!;
    const routeRules = Array.isArray(route.rules) ? [...(route.rules as unknown[])] : [];
    const at = routeInsertionIndex(routeRules);
    const added: Json[] = [{ protocol: [BITTORRENT], action: "route", outbound: DIRECT }];

    // Our DNS rules carry query_type, which takes the core out of its legacy
    // DNS mode; there a few old rule fields fail the start.
    const legacy = legacyDnsReason(root);
    const off = options.offReason ?? (legacy === null ? null : `legacy: ${legacy}`);
    if (off !== null) {
      route.rules = insertAt(routeRules, at, added);
      return {
        content: JSON.stringify(root),
        state: `off (${off}); torrents direct`,
        applied: false,
        usesDnsRu: false,
      };
    }

    const sets = options.sets ?? null;
    const exceptions = [...new Set([...RU_VPN_EXCEPTIONS, ...(options.extraExceptions ?? [])])];
    const m = (): Json => ({
      ...(sets === null ? {} : { rule_set: [GEOSITE_TAG] }),
      domain_suffix: [...RU_SUFFIXES],
    });
    const e = (): Json => ({ domain_suffix: [...exceptions], invert: true });

    const dns = asObject(root.dns)!;
    const dnsRuFallback = options.dnsRuFallback === true;
    const dnsServer = dnsRuFallback ? DNS_DIRECT : DNS_RU_TAG;
    if (!dnsRuFallback) {
      // Last: dns-remote stays the first server, the default one. No detour:
      // the core dials a DNS server without one directly.
      dns.servers = [
        ...(dns.servers as unknown[]),
        { type: DNS_RU_TYPE, tag: DNS_RU_TAG, server: DNS_RU_SERVER },
      ];
    }
    const dnsRules = Array.isArray(dns.rules) ? [...(dns.rules as unknown[])] : [];
    const dnsAt = dnsRules.findIndex((rule) => {
      const object = asObject(rule);
      return object !== null && isFakeDnsRule(object);
    });
    dns.rules = insertAt(dnsRules, dnsAt < 0 ? dnsRules.length : dnsAt, [
      // No rcode: an empty NOERROR, so Russian names get A records only (no
      // IPv6 stalls) and no HTTPS hints.
      { ...allOf({ query_type: ["AAAA", "HTTPS", "SVCB"] }, m(), e()), action: "predefined" },
      { ...allOf(m(), e()), action: "route", server: dnsServer },
    ]);

    added.push({ ...allOf(m(), e()), action: "route", outbound: DIRECT });
    if (sets !== null) {
      added.push({
        ...allOf({ rule_set: [GEOIP_TAG] }, e(), { ip_version: 4 }),
        action: "route",
        outbound: DIRECT,
      });
      route.rule_set = [
        ...(Array.isArray(route.rule_set) ? (route.rule_set as unknown[]) : []),
        { tag: GEOSITE_TAG, type: "inline", rules: sets.geosite },
        { tag: GEOIP_TAG, type: "inline", rules: sets.geoip },
      ];
    }
    route.rules = insertAt(routeRules, at, added);

    const details = [
      ...(sets === null ? ["suffixes"] : []),
      ...(dnsRuFallback ? ["dns-direct"] : []),
    ];
    return {
      content: JSON.stringify(root),
      state: details.length === 0 ? "on" : `on (${details.join(", ")})`,
      applied: true,
      usesDnsRu: !dnsRuFallback,
    };
  } catch (error) {
    return unchanged(content, `off (error: ${error instanceof Error ? error.message : String(error)})`);
  }
}

/**
 * Null when [root] has our shape: the "select" selector and the "direct"
 * outbound, dns-remote and dns-direct, and nothing of ours yet. A foreign
 * config (a sing-box JSON imported as is) is left alone, and applying twice
 * changes nothing.
 */
export function russiaDirectNotOursReason(root: Json): string | null {
  const outbounds = objects(root.outbounds);
  if (outbounds === null) {
    return "no outbounds";
  }
  if (!outbounds.some((outbound) => outbound.type === "selector" && outbound.tag === SELECT)) {
    return `no selector "${SELECT}"`;
  }
  if (!outbounds.some((outbound) => outbound.type === "direct" && outbound.tag === DIRECT)) {
    return `no outbound "${DIRECT}"`;
  }
  const dns = asObject(root.dns);
  if (dns === null) {
    return "no dns";
  }
  const servers = objects(dns.servers);
  if (servers === null) {
    return "no dns servers";
  }
  const serverTags = new Set(servers.map((server) => server.tag));
  if (!serverTags.has(DNS_REMOTE) || !serverTags.has(DNS_DIRECT)) {
    return `no ${DNS_REMOTE}/${DNS_DIRECT}`;
  }
  if (serverTags.has(DNS_RU_TAG)) {
    return `has ${DNS_RU_TAG}`;
  }
  const route = asObject(root.route);
  if (route === null) {
    return "no route";
  }
  const ruleSetTags = new Set((objects(route.rule_set) ?? []).map((ruleSet) => ruleSet.tag));
  if (ruleSetTags.has(GEOSITE_TAG) || ruleSetTags.has(GEOIP_TAG)) {
    return "has the Russian rule sets";
  }
  const hasTorrentRule = (objects(route.rules) ?? []).some((rule) =>
    Array.isArray(rule.protocol) ? rule.protocol.includes(BITTORRENT) : rule.protocol === BITTORRENT,
  );
  if (hasTorrentRule) {
    return `has a ${BITTORRENT} rule`;
  }
  return null;
}

/**
 * Why the core would refuse [root]'s DNS rules once ours take it out of the
 * legacy DNS mode, or null: a strategy in a rule action, an address filter or
 * response field without match_response, or a rule set (it may hold addresses
 * only, which the new mode refuses in DNS rules).
 */
export function legacyDnsReason(root: Json): string | null {
  const rules = asObject(root.dns)?.rules;
  if (!Array.isArray(rules)) {
    return null;
  }
  for (const [index, entry] of rules.entries()) {
    const rule = asObject(entry);
    if (rule === null) {
      continue;
    }
    const field = legacyField(rule);
    if (field !== null) {
      return `dns.rules[${index}].${field}`;
    }
  }
  return null;
}

const ADDRESS_AND_RESPONSE_FIELDS = [
  "ip_cidr",
  "ip_is_private",
  "ip_accept_any",
  "response_rcode",
  "response_answer",
  "response_ns",
  "response_extra",
];

function legacyField(rule: Json): string | null {
  if (typeof rule.strategy === "string" && rule.strategy !== "" && rule.strategy !== "as_is") {
    return "strategy";
  }
  if (rule.rule_set_ip_cidr_accept_empty === true) {
    return "rule_set_ip_cidr_accept_empty";
  }
  if (rule.type === "logical") {
    const sub = Array.isArray(rule.rules) ? rule.rules : [];
    for (const [index, entry] of sub.entries()) {
      const object = asObject(entry);
      if (object === null) {
        continue;
      }
      const field = legacyField(object);
      if (field !== null) {
        return `rules[${index}].${field}`;
      }
    }
    return null;
  }
  if (rule.match_response === true) {
    return null;
  }
  for (const field of ADDRESS_AND_RESPONSE_FIELDS) {
    if (present(rule[field])) {
      return field;
    }
  }
  if (present(rule.rule_set)) {
    return "rule_set";
  }
  return null;
}

function present(value: unknown): boolean {
  if (value === undefined || value === null || value === false) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === "string") {
    return value.length > 0;
  }
  return true;
}

/** The HTTPS/SVCB reject or the fakeip rule: ours go ahead of the first of them. */
function isFakeDnsRule(rule: Json): boolean {
  if (rule.server === DNS_FAKEIP) {
    return true;
  }
  const queryTypes = Array.isArray(rule.query_type) ? new Set(rule.query_type) : null;
  return (
    rule.action === "reject" &&
    queryTypes !== null &&
    queryTypes.size === 2 &&
    queryTypes.has("HTTPS") &&
    queryTypes.has("SVCB")
  );
}

/** Ahead of the first per-app rule, else at the end. */
function routeInsertionIndex(rules: unknown[]): number {
  const index = rules.findIndex((entry) => {
    const rule = asObject(entry);
    return (
      rule !== null &&
      (rule.process_name !== undefined ||
        rule.process_path !== undefined ||
        rule.process_path_regex !== undefined)
    );
  });
  return index < 0 ? rules.length : index;
}

function allOf(...rules: Json[]): Json {
  return { type: "logical", mode: "and", rules };
}

function insertAt(array: unknown[], at: number, items: unknown[]): unknown[] {
  return [...array.slice(0, at), ...items, ...array.slice(at)];
}

/**
 * A config for a crash report: the inline rule-set data of "Russia direct"
 * (some 200 KB of names and addresses that help nobody reading a crash) gives
 * way to a note, so the report stays well under the receiver's limit. Anything
 * that does not parse goes as it is.
 */
export function withoutRuleSetData(content: string): string {
  const root = parseJsonObject(content);
  const route = root === null ? null : asObject(root.route);
  if (root === null || route === null || !Array.isArray(route.rule_set)) {
    return content;
  }
  let changed = false;
  route.rule_set = route.rule_set.map((entry) => {
    const ruleSet = asObject(entry);
    if (ruleSet === null || ruleSet.type !== "inline" || (ruleSet.tag !== GEOSITE_TAG && ruleSet.tag !== GEOIP_TAG)) {
      return entry;
    }
    changed = true;
    return { ...ruleSet, rules: `omitted: the data bundled with the app, lists ${RU_DIRECT_LISTS_REVISION}` };
  });
  return changed ? JSON.stringify(root, null, 2) : content;
}

/**
 * The x-vpn4tv-ru-vpn header of our server, `a.ru, b.su`, as domain_suffix
 * values: lower case, letters, digits, dots and dashes only, at most 500 of
 * them. Anything else is dropped.
 */
export function parseNameList(raw: string | null | undefined): string[] {
  if (raw === null || raw === undefined || raw.trim() === "") {
    return [];
  }
  const name = /^\.?[a-z0-9-]+(\.[a-z0-9-]+)*$/u;
  const names = raw
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length >= 1 && entry.length <= 253 && name.test(entry));
  return [...new Set(names)].slice(0, 500);
}

function objects(value: unknown): Json[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  return value.map(asObject).filter((item): item is Json => item !== null);
}
