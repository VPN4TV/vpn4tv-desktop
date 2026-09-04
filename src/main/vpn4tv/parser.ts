// VPN4TV: TypeScript port of the subscription parser (Kotlin
// com.vpn4tv.app.converter.ProxyParser → Swift Library/Config/ProxyParser.swift
// → here). Turns proxy URIs / Xray JSON / sing-box JSON / base64 subscriptions
// / AmneziaVPN vpn:// payloads into ProxyConfig values.
//
// Transports sing-box cannot do natively (xhttp/splithttp, Outline SIP002 with
// a prefix, AmneziaWG) are flagged on the result; the generator turns them into
// socks→loopback outbounds and the core starts the embedded bridge.

import { inflateSync } from "node:zlib";

import {
  B64,
  type Json,
  arr,
  bool,
  int,
  obj,
  objArr,
  parseJsonObject,
  parseProxyURI,
  splitHostPort,
  str,
} from "./support";

export interface ProxyConfig {
  tag: string;
  type: string;
  server: string;
  serverPort: number;
  /** sing-box outbound (empty for bridge-managed entries until the generator fills it in). */
  outbound: Json;
  /** xray-core outbound, for transports only xray speaks. */
  xrayOutbound?: Json;
  /** Original ss:// URI, for Outline's SIP002 prefix support. */
  outlineUrl?: string;
  /** Outline dynamic key (ssconf://). Resolved before every connect, because
   *  the provider rotates servers behind it — that is the whole point of it. */
  outlineDynamicUrl?: string;
  /** wg-quick / AmneziaWG INI. */
  awgIni?: string;
}

export interface SubscriptionDns {
  remoteDns: string;
  directDns: string;
}

/** Marker tag for a subscription that already is a full sing-box config. */
export const SINGBOX_PASSTHROUGH_TAG = "__singbox_passthrough__";

// Direct DNS defaults (Quad9 first — see the DnsProviders registry on mobile).
const DIRECT_DNS_FALLBACK = "9.9.9.9";
const DIRECT_DNS_FALLBACK_2 = "149.112.112.112";

/** DNS carried by the last parsed Xray subscription; read by the generator. */
export let lastDns: SubscriptionDns = {
  remoteDns: "https://8.8.8.8/dns-query",
  directDns: DIRECT_DNS_FALLBACK,
};

export function resetLastDns(): void {
  lastDns = { remoteDns: "https://8.8.8.8/dns-query", directDns: DIRECT_DNS_FALLBACK };
}

// Transports sing-box handles natively; anything else goes through xray.
const SINGBOX_TRANSPORTS = new Set(["tcp", "raw", "ws", "websocket", "grpc", "http", "h2", "httpupgrade", "quic"]);

export function parseLine(line: string): ProxyConfig | null {
  const value = line.trim();
  if (value.length === 0 || value.startsWith("#") || value.startsWith("//")) {
    return null;
  }
  if (value.startsWith("vless://")) return parseVless(value);
  if (value.startsWith("vmess://")) return parseVmess(value);
  if (value.startsWith("hysteria2://") || value.startsWith("hy2://")) return parseHysteria2(value);
  if (value.startsWith("trojan://")) return parseTrojan(value);
  if (value.startsWith("ss://")) return parseShadowsocks(value);
  if (value.startsWith("ssconf://")) return parseOutlineDynamicKey(value);
  if (value.startsWith("naive+https://") || value.startsWith("naive+quic://")) return parseNaive(value);
  if (value.startsWith("wg://")) return parseWgUri(value);
  return null;
}

/**
 * VPN4TV: our own link — `vpn4tv://<base64url payload>`, optionally with a
 * `#name` fragment. The payload is whatever we would otherwise ask the user to
 * paste: a subscription URL, server links, or a config. base64url, because `+`
 * and `/` do not survive being put in a link.
 *
 * Returns null when this is not our link or the payload is not decodable, so
 * callers can fall through to the normal handling.
 */
export function decodeVpn4tvLink(content: string): string | null {
  const match = /^vpn4tv:\/\/(.+)$/isu.exec(content.trim());
  if (match === null) {
    return null;
  }
  const fragment = match[1].indexOf("#");
  const payload = (fragment === -1 ? match[1] : match[1].slice(0, fragment)).trim();
  if (payload === "") {
    return null;
  }
  let decoded: string;
  try {
    decoded = Buffer.from(payload.replace(/-/gu, "+").replace(/_/gu, "/"), "base64").toString("utf-8");
  } catch {
    return null;
  }
  decoded = decoded.trim();
  // Base64 decoding never fails loudly, so check the result looks like content
  // we could actually use rather than accepting noise.
  const usable = decoded.includes("://") || decoded.startsWith("{");
  return usable ? decoded : null;
}

export function parseSubscription(content: string): ProxyConfig[] {
  // Our own link carries the real payload; everything below works on that.
  const source = decodeVpn4tvLink(content) ?? content;
  const trimmed = source.trim();

  // AmneziaVPN vpn:// (base64url + 4-byte length + zlib JSON)
  if (trimmed.startsWith("vpn://") || looksLikeAmneziaVpn(trimmed)) {
    const parsed = parseAmneziaVpn(trimmed.startsWith("vpn://") ? trimmed.slice(6) : trimmed);
    if (parsed.length > 0) {
      return parsed;
    }
  }

  // wg-quick / AmneziaWG INI
  if (looksLikeWgIni(trimmed)) {
    const config = parseWgIni(trimmed);
    return config ? [config] : [];
  }

  // JSON config (sing-box or Xray)
  if (trimmed.startsWith("{")) {
    const json = parseJsonObject(trimmed);
    if (json && json.outbounds !== undefined) {
      const inbounds = objArr(json, "inbounds");
      if (inbounds?.some((inbound) => str(inbound, "type") === "tun")) {
        // Already a native sing-box config — pass it through untouched.
        return [
          { tag: SINGBOX_PASSTHROUGH_TAG, type: "singbox", server: "", serverPort: 0, outbound: json },
        ];
      }
      return parseXrayConfig(json);
    }
  }

  // base64-wrapped subscription, else newline-separated URIs
  const decoded = tryBase64Subscription(source) ?? source;
  return decoded
    .split(/[\r\n]+/)
    .map(parseLine)
    .filter((config): config is ProxyConfig => config !== null);
}

function tryBase64Subscription(input: string): string | null {
  const trimmed = input.trim();
  if (trimmed.includes("://")) {
    return null;
  }
  const decoded = B64.decodeToString(trimmed);
  return decoded && decoded.includes("://") ? decoded : null;
}

// ---- VLESS ----

function parseVless(uri: string): ProxyConfig | null {
  const parsed = parseProxyURI(uri);
  if (!parsed?.userInfo || !parsed.host) {
    return null;
  }
  const host = parsed.host;
  const port = parsed.port > 0 ? parsed.port : 443;
  const name = parsed.fragment ?? host;
  const query = parsed.query;
  const security = query.security ?? "";
  const sni = query.sni ?? host;
  const flow = query.flow ?? "";
  const fingerprint = query.fp ?? "chrome";
  const alpn = query.alpn?.split(",");
  const transportType = query.type ?? "tcp";

  if (!SINGBOX_TRANSPORTS.has(transportType)) {
    // xhttp/splithttp and friends → xray bridge
    return {
      tag: name,
      type: "vless",
      server: host,
      serverPort: port,
      outbound: {},
      xrayOutbound: buildXrayVlessOutbound({
        tag: name,
        uuid: parsed.userInfo,
        host,
        port,
        security,
        sni,
        flow,
        fingerprint,
        publicKey: query.pbk ?? "",
        shortId: query.sid ?? "",
        spiderX: query.spx ?? "",
        transportType,
        query,
      }),
    };
  }

  const outbound: Json = {
    type: "vless",
    tag: name,
    server: host,
    server_port: port,
    uuid: parsed.userInfo,
    packet_encoding: "xudp",
  };
  if (flow.length > 0) {
    outbound.flow = flow;
  }
  if (security === "tls" || security === "reality") {
    const tls: Json = { enabled: true, server_name: sni };
    if (alpn) {
      tls.alpn = alpn;
    }
    if (security === "reality") {
      tls.reality = { enabled: true, public_key: query.pbk ?? "", short_id: query.sid ?? "" };
    }
    tls.utls = { enabled: true, fingerprint };
    outbound.tls = tls;
  }
  putTransport(outbound, transportType, query);
  return { tag: name, type: "vless", server: host, serverPort: port, outbound };
}

// ---- HYSTERIA2 ----

function parseHysteria2(uri: string): ProxyConfig | null {
  const parsed = parseProxyURI(uri.replace("hy2://", "hysteria2://"));
  if (!parsed?.userInfo || !parsed.host) {
    return null;
  }
  const host = parsed.host;
  const port = parsed.port > 0 ? parsed.port : 443;
  const name = parsed.fragment ?? host;
  const tls: Json = { enabled: true, server_name: parsed.query.sni ?? host };
  if (parsed.query.insecure === "1") {
    tls.insecure = true;
  }
  const outbound: Json = {
    type: "hysteria2",
    tag: name,
    server: host,
    server_port: port,
    password: parsed.userInfo,
    tls,
  };
  const obfs = parsed.query.obfs ?? "";
  if (obfs.length > 0) {
    outbound.obfs = { type: obfs, password: parsed.query["obfs-password"] ?? "" };
  }
  return { tag: name, type: "hysteria2", server: host, serverPort: port, outbound };
}

// ---- TROJAN ----

function parseTrojan(uri: string): ProxyConfig | null {
  const parsed = parseProxyURI(uri);
  if (!parsed?.userInfo || !parsed.host) {
    return null;
  }
  const host = parsed.host;
  const port = parsed.port > 0 ? parsed.port : 443;
  const name = parsed.fragment ?? host;
  const query = parsed.query;
  const outbound: Json = {
    type: "trojan",
    tag: name,
    server: host,
    server_port: port,
    password: parsed.userInfo,
  };
  if ((query.security ?? "tls") !== "none") {
    const tls: Json = { enabled: true, server_name: query.sni ?? host };
    const alpn = query.alpn?.split(",");
    if (alpn) {
      tls.alpn = alpn;
    }
    if ((query.fp ?? "").length > 0) {
      tls.utls = { enabled: true, fingerprint: query.fp };
    }
    outbound.tls = tls;
  }
  putTransport(outbound, query.type ?? "tcp", query);
  return { tag: name, type: "trojan", server: host, serverPort: port, outbound };
}

// ---- NAIVE ----

/**
 * Outline dynamic access key. Nothing to resolve here — the URL is carried into
 * the profile and fetched at connect time, so a rotated server is picked up.
 */
function parseOutlineDynamicKey(value: string): ProxyConfig | null {
  const withoutFragment = value.split("#")[0];
  const httpsUrl = "https://" + withoutFragment.slice("ssconf://".length);
  let host: string;
  try {
    host = new URL(httpsUrl).hostname;
  } catch {
    return null;
  }
  if (host === "") {
    return null;
  }
  const tag = decodeURIComponent(value.split("#")[1] ?? "") || host;
  return {
    tag,
    type: "shadowsocks",
    server: host,
    serverPort: 0,
    outbound: {},
    outlineDynamicUrl: httpsUrl,
  };
}

function parseNaive(uri: string): ProxyConfig | null {
  const isQuic = uri.startsWith("naive+quic://");
  const parsed = parseProxyURI(uri.slice("naive+".length));
  if (!parsed?.host || !parsed.userInfoEncoded) {
    return null;
  }
  const separator = parsed.userInfoEncoded.indexOf(":");
  if (separator < 0) {
    return null;
  }
  const username = decodeURIComponent(parsed.userInfoEncoded.slice(0, separator));
  const password = decodeURIComponent(parsed.userInfoEncoded.slice(separator + 1));
  if (username.length === 0 || password.length === 0) {
    return null;
  }
  const host = parsed.host;
  const port = parsed.port > 0 ? parsed.port : 443;
  const name = parsed.fragment ?? host;
  const outbound: Json = {
    type: "naive",
    tag: name,
    server: host,
    server_port: port,
    username,
    password,
    tls: { enabled: true, server_name: parsed.query.sni ?? host },
  };
  if (isQuic) {
    outbound.quic = true;
  }
  return { tag: name, type: "naive", server: host, serverPort: port, outbound };
}

// ---- SHADOWSOCKS ----

function parseShadowsocks(uri: string): ProxyConfig | null {
  const withoutScheme = uri.slice("ss://".length);
  const hash = withoutScheme.lastIndexOf("#");
  const name = hash >= 0 ? decodeURIComponent(withoutScheme.slice(hash + 1)) : "";
  const mainPart = hash >= 0 ? withoutScheme.slice(0, hash) : withoutScheme;

  let method = "";
  let password = "";
  let host = "";
  let port = 443;
  const ssParams: Record<string, string> = {};

  const at = mainPart.lastIndexOf("@");
  if (at >= 0) {
    const userInfo = mainPart.slice(0, at);
    let serverPart = mainPart.slice(at + 1);
    const questionMark = serverPart.indexOf("?");
    if (questionMark >= 0) {
      for (const pair of serverPart.slice(questionMark + 1).split("&")) {
        const equals = pair.indexOf("=");
        const key = decodeURIComponent(equals < 0 ? pair : pair.slice(0, equals));
        ssParams[key] = equals < 0 ? "" : decodeURIComponent(pair.slice(equals + 1));
      }
      serverPart = serverPart.slice(0, questionMark);
    }
    while (serverPart.endsWith("/")) {
      serverPart = serverPart.slice(0, -1);
    }
    const decoded = B64.decodeToString(userInfo) ?? userInfo;
    const colon = decoded.indexOf(":");
    if (colon < 0) {
      return null;
    }
    method = decoded.slice(0, colon);
    password = decoded.slice(colon + 1);
    const hostPort = splitHostPort(serverPart);
    if (!hostPort) {
      return null;
    }
    host = hostPort.host;
    port = hostPort.port > 0 ? hostPort.port : 443;
  } else {
    const decoded = B64.decodeToString(mainPart);
    if (!decoded) {
      return null;
    }
    const atDecoded = decoded.lastIndexOf("@");
    const colon = decoded.indexOf(":");
    if (atDecoded < 0 || colon < 0) {
      return null;
    }
    method = decoded.slice(0, colon);
    password = decoded.slice(colon + 1, atDecoded);
    const hostPort = splitHostPort(decoded.slice(atDecoded + 1));
    if (!hostPort) {
      return null;
    }
    host = hostPort.host;
    port = hostPort.port > 0 ? hostPort.port : 443;
  }

  const tag = name.length > 0 ? name : host;
  const isOutline = (ssParams.prefix ?? "").length > 0 || ssParams.outline === "1";
  if (isOutline) {
    // SIP002 prefix — only the Outline bridge implements it.
    return { tag, type: "shadowsocks", server: host, serverPort: port, outbound: {}, outlineUrl: uri };
  }
  return {
    tag,
    type: "shadowsocks",
    server: host,
    serverPort: port,
    outbound: { type: "shadowsocks", tag, server: host, server_port: port, method, password },
  };
}

// ---- VMESS ----

function parseVmess(uri: string): ProxyConfig | null {
  const decoded = B64.decodeToString(uri.slice("vmess://".length));
  if (!decoded) {
    return null;
  }
  const json = parseJsonObject(decoded);
  if (!json) {
    return null;
  }
  const host = str(json, "add");
  const uuid = str(json, "id");
  if (host.length === 0 || uuid.length === 0) {
    return null;
  }
  const port = int(json, "port", 443);
  const name = str(json, "ps", host);
  const tlsMode = str(json, "tls");
  const outbound: Json = {
    type: "vmess",
    tag: name,
    server: host,
    server_port: port,
    uuid,
    security: str(json, "scy", "auto"),
    alter_id: int(json, "aid", 0),
  };
  if (tlsMode === "tls") {
    const tls: Json = { enabled: true, server_name: str(json, "sni", host) };
    const alpn = str(json, "alpn");
    if (alpn.length > 0) {
      tls.alpn = alpn.split(",");
    }
    const fingerprint = str(json, "fp");
    if (fingerprint.length > 0) {
      tls.utls = { enabled: true, fingerprint };
    }
    outbound.tls = tls;
  }
  const params: Record<string, string> = {};
  const path = str(json, "path");
  if (path.length > 0) {
    params.path = path;
  }
  const headerHost = str(json, "host");
  if (headerHost.length > 0) {
    params.host = headerHost;
  }
  const headerType = str(json, "type");
  if (headerType.length > 0 && headerType !== "none") {
    params.headerType = headerType;
  }
  putTransport(outbound, str(json, "net", "tcp"), params);
  return { tag: name, type: "vmess", server: host, serverPort: port, outbound };
}

// ---- AmneziaWG ----

function looksLikeWgIni(text: string): boolean {
  const lower = text.toLowerCase();
  if (!lower.includes("[interface]") || !lower.includes("privatekey")) {
    return false;
  }
  return lower.includes("[peer]") || lower.includes("publickey");
}

function parseWgIni(ini: string): ProxyConfig | null {
  const endpoint = /^[ \t]*Endpoint[ \t]*=[ \t]*(\S+?):(\d+)[ \t]*$/im.exec(ini);
  if (!endpoint) {
    return null;
  }
  const server = endpoint[1];
  const port = Number.parseInt(endpoint[2], 10);
  if (!Number.isFinite(port)) {
    return null;
  }
  let name = server;
  const comment = /^[ \t]*#[ \t]*(.+?)[ \t]*$/m.exec(ini);
  if (comment) {
    name = comment[1].slice(0, 64);
  }
  return { tag: name, type: "wireguard", server, serverPort: port, outbound: {}, awgIni: ini };
}

function parseWgUri(uri: string): ProxyConfig | null {
  const parsed = parseProxyURI(uri);
  if (!parsed?.host) {
    return null;
  }
  const query = parsed.query;
  const privateKey = query.private_key;
  const peerPublicKey = query.peer_public_key;
  if (!privateKey || !peerPublicKey) {
    return null;
  }
  const name = parsed.fragment ?? parsed.host;
  const serverHost = query.server ?? parsed.host;
  const serverPort = query.server_port
    ? Number.parseInt(query.server_port, 10)
    : parsed.port > 0
      ? parsed.port
      : 443;
  const fakePackets = query.fake_packets?.split("-");
  const fakePacketSizes = query.fake_packets_size?.split("-");

  const lines = [
    `# ${name}`,
    "[Interface]",
    `PrivateKey = ${privateKey}`,
    `Address = ${query.local_address ?? "10.0.0.2/32"}`,
    "DNS = 8.8.8.8, 8.8.4.4",
    `MTU = ${query.mtu ?? "1420"}`,
  ];
  const optional: Array<[string, string | undefined]> = [
    ["Jc", query.awg_jc],
    ["Jmin", fakePackets?.length === 2 ? fakePackets[0] : undefined],
    ["Jmax", fakePackets?.length === 2 ? fakePackets[1] : undefined],
    ["S1", fakePacketSizes?.length === 2 ? fakePacketSizes[0] : undefined],
    ["S2", fakePacketSizes?.length === 2 ? fakePacketSizes[1] : undefined],
    ["H1", query.awg_h1],
    ["H2", query.awg_h2],
    ["H3", query.awg_h3],
    ["H4", query.awg_h4],
  ];
  for (const [key, value] of optional) {
    if (value !== undefined && value.length > 0) {
      lines.push(`${key} = ${value}`);
    }
  }
  lines.push("", "[Peer]", `PublicKey = ${peerPublicKey}`);
  if (query.pre_shared_key && query.pre_shared_key.length > 0) {
    lines.push(`PresharedKey = ${query.pre_shared_key}`);
  }
  lines.push("AllowedIPs = 0.0.0.0/0, ::/0", `Endpoint = ${serverHost}:${serverPort}`, "PersistentKeepalive = 25", "");

  return {
    tag: name,
    type: "wireguard",
    server: serverHost,
    serverPort,
    outbound: {},
    awgIni: lines.join("\n"),
  };
}

// AmneziaVPN vpn:// : base64url(4-byte big-endian length + zlib JSON)
function looksLikeAmneziaVpn(text: string): boolean {
  if (text.includes("://") || text.length < 50) {
    return false;
  }
  if (!/^[A-Za-z0-9\-_=]+$/.test(text)) {
    return false;
  }
  return text.startsWith("AAA");
}

function parseAmneziaVpn(body: string): ProxyConfig[] {
  const bytes = B64.decode(body);
  if (!bytes || bytes.length < 5) {
    return [];
  }
  const expectedLength = bytes.readUInt32BE(0);
  if (expectedLength <= 0 || expectedLength > 16 * 1024 * 1024) {
    return [];
  }
  let inflated: Buffer;
  try {
    inflated = inflateSync(bytes.subarray(4));
  } catch {
    return [];
  }
  const root = parseJsonObject(inflated.toString("utf8"));
  const containers = objArr(root, "containers");
  if (!root || !containers || containers.length === 0) {
    return [];
  }
  const dns1 = str(root, "dns1", DIRECT_DNS_FALLBACK);
  const dns2 = str(root, "dns2", DIRECT_DNS_FALLBACK_2);
  const description = str(root, "description") || str(root, "hostName", "AmneziaVPN");

  // Prefer a wg/awg container with an embedded INI.
  for (const container of containers) {
    const wireguard = obj(container, "awg") ?? obj(container, "wg");
    if (!wireguard) {
      continue;
    }
    const lastConfigRaw = str(wireguard, "last_config");
    if (lastConfigRaw.length === 0) {
      continue;
    }
    const lastConfig = parseJsonObject(lastConfigRaw);
    let ini = str(lastConfig, "config");
    if (ini.length === 0) {
      continue;
    }
    ini = ini.replace(/\$PRIMARY_DNS/g, dns1).replace(/\$SECONDARY_DNS/g, dns2);
    const parsed = parseWgIni(`# ${description}\n${ini}`);
    return parsed ? [parsed] : [];
  }

  // Fallback: an amnezia-xray container carries a full Xray JSON.
  for (const container of containers) {
    const xray = obj(container, "xray");
    if (!xray) {
      continue;
    }
    const lastConfigRaw = str(xray, "last_config");
    if (lastConfigRaw.length === 0) {
      continue;
    }
    const xrayJson = parseJsonObject(lastConfigRaw);
    if (!xrayJson) {
      continue;
    }
    const results = parseXrayConfig(xrayJson);
    if (results.length > 0) {
      return results.map((config, index) => ({
        ...config,
        tag: index === 0 ? description : `${description} ${index + 1}`,
      }));
    }
  }
  return [];
}

// ---- Xray JSON ----

function parseXrayConfig(config: Json): ProxyConfig[] {
  const outbounds = objArr(config, "outbounds");
  if (!outbounds) {
    return [];
  }
  const results: ProxyConfig[] = [];

  const dnsServers = arr(obj(config, "dns"), "servers");
  if (dnsServers && dnsServers.length > 0) {
    let remoteDns = "https://8.8.8.8/dns-query";
    let directDns = DIRECT_DNS_FALLBACK;
    for (const server of dnsServers) {
      if (typeof server === "string" && (server.startsWith("https://") || server.startsWith("https+local://"))) {
        remoteDns = server.replace("https+local://", "https://");
        break;
      }
    }
    for (const server of dnsServers) {
      if (typeof server === "string" && /^\d+\.\d+\.\d+\.\d+$/.test(server)) {
        directDns = server;
        break;
      }
    }
    lastDns = { remoteDns, directDns };
  }

  for (const outbound of outbounds) {
    const protocol = str(outbound, "protocol");
    const tag = str(outbound, "tag", protocol);
    const settings = obj(outbound, "settings");
    if (!settings) {
      continue;
    }
    const stream = obj(outbound, "streamSettings");

    if (stream) {
      const network = str(stream, "network", "tcp");
      if (!SINGBOX_TRANSPORTS.has(network)) {
        const server = extractXrayServer(outbound);
        if (!server) {
          continue;
        }
        const xhttpPath = str(obj(stream, "xhttpSettings"), "path");
        if (!isXrayUrlSafe(server, xhttpPath)) {
          continue;
        }
        results.push({
          tag,
          type: protocol,
          server,
          serverPort: extractXrayPort(outbound),
          outbound: {},
          xrayOutbound: outbound,
        });
        continue;
      }
    }

    switch (protocol) {
      case "vless":
      case "vmess": {
        const vnext = objArr(settings, "vnext")?.[0];
        const user = objArr(vnext, "users")?.[0];
        if (!vnext || !user) {
          continue;
        }
        const server = str(vnext, "address");
        const port = int(vnext, "port", 443);
        const singbox: Json = { type: protocol, tag, server, server_port: port, uuid: str(user, "id") };
        if (protocol === "vless") {
          const flow = str(user, "flow");
          if (flow.length > 0) {
            singbox.flow = flow;
          }
          singbox.packet_encoding = "xudp";
        } else {
          singbox.security = str(user, "security", "auto");
          singbox.alter_id = int(user, "alterId", 0);
        }
        if (stream) {
          putXrayTls(singbox, stream);
          putXrayTransport(singbox, stream);
        }
        results.push({ tag, type: protocol, server, serverPort: port, outbound: singbox });
        break;
      }
      case "trojan": {
        const server = objArr(settings, "servers")?.[0];
        if (!server) {
          continue;
        }
        const address = str(server, "address");
        const port = int(server, "port", 443);
        const singbox: Json = {
          type: "trojan",
          tag,
          server: address,
          server_port: port,
          password: str(server, "password"),
        };
        if (stream) {
          putXrayTls(singbox, stream);
          putXrayTransport(singbox, stream);
        }
        results.push({ tag, type: "trojan", server: address, serverPort: port, outbound: singbox });
        break;
      }
      case "shadowsocks": {
        const server = objArr(settings, "servers")?.[0];
        if (!server) {
          continue;
        }
        const address = str(server, "address");
        const port = int(server, "port", 443);
        results.push({
          tag,
          type: "shadowsocks",
          server: address,
          serverPort: port,
          outbound: {
            type: "shadowsocks",
            tag,
            server: address,
            server_port: port,
            method: str(server, "method"),
            password: str(server, "password"),
          },
        });
        break;
      }
      default:
        break;
    }
  }
  return results;
}

interface XrayVlessInput {
  tag: string;
  uuid: string;
  host: string;
  port: number;
  security: string;
  sni: string;
  flow: string;
  fingerprint: string;
  publicKey: string;
  shortId: string;
  spiderX: string;
  transportType: string;
  query: Record<string, string>;
}

function buildXrayVlessOutbound(input: XrayVlessInput): Json {
  const user: Json = { id: input.uuid, encryption: "none" };
  if (input.flow.length > 0) {
    user.flow = input.flow;
  }
  const stream: Json = { network: input.transportType };
  if (input.security === "tls") {
    stream.security = "tls";
    stream.tlsSettings = { serverName: input.sni, fingerprint: input.fingerprint };
  } else if (input.security === "reality") {
    stream.security = "reality";
    const reality: Json = {
      serverName: input.sni,
      fingerprint: input.fingerprint,
      publicKey: input.publicKey,
      shortId: input.shortId,
    };
    if (input.spiderX.length > 0) {
      reality.spiderX = input.spiderX;
    }
    stream.realitySettings = reality;
  }
  if (input.transportType === "xhttp" || input.transportType === "splithttp") {
    const xhttp: Json = {};
    for (const key of ["path", "host", "mode"] as const) {
      const value = input.query[key];
      if (value !== undefined) {
        xhttp[key] = value;
      }
    }
    // `extra` carries the rest of the transport settings — xmux above all, which
    // decides how many connections the client multiplexes over. xray-core
    // unmarshals it into the transport config itself and then re-applies host,
    // path and mode, so it is passed through as an object rather than merged
    // here. Dropping it, as we used to, silently ignored the provider's tuning.
    const extra = input.query.extra;
    if (extra !== undefined) {
      const parsed = parseJsonObject(extra);
      if (parsed !== null) {
        xhttp.extra = parsed;
      }
    }
    stream.xhttpSettings = xhttp;
  }
  return {
    tag: input.tag,
    protocol: "vless",
    settings: { vnext: [{ address: input.host, port: input.port, users: [user] }] },
    streamSettings: stream,
  };
}

function extractXrayServer(outbound: Json): string | null {
  const settings = obj(outbound, "settings");
  const entry = objArr(settings, "vnext")?.[0] ?? objArr(settings, "servers")?.[0];
  const address = str(entry, "address");
  return address.length > 0 ? address : null;
}

function extractXrayPort(outbound: Json): number {
  const settings = obj(outbound, "settings");
  const entry = objArr(settings, "vnext")?.[0] ?? objArr(settings, "servers")?.[0];
  return entry ? int(entry, "port", 443) : 443;
}

function isXrayUrlSafe(host: string, path: string): boolean {
  if (host.trim().length === 0) {
    return false;
  }
  const unsafe = (value: string) => /[\s\u0000-\u001F\u007F]/.test(value);
  if (unsafe(host) || unsafe(path)) {
    return false;
  }
  return path.length === 0 || path.startsWith("/");
}

function putXrayTls(target: Json, stream: Json): void {
  switch (str(stream, "security")) {
    case "tls": {
      const settings = obj(stream, "tlsSettings") ?? {};
      const tls: Json = { enabled: true, server_name: str(settings, "serverName") };
      if (bool(settings, "allowInsecure")) {
        tls.insecure = true;
      }
      const fingerprint = str(settings, "fingerprint");
      if (fingerprint.length > 0) {
        tls.utls = { enabled: true, fingerprint };
      }
      const alpn = arr(settings, "alpn");
      if (alpn && alpn.length > 0) {
        tls.alpn = alpn;
      }
      target.tls = tls;
      break;
    }
    case "reality": {
      const settings = obj(stream, "realitySettings") ?? {};
      target.tls = {
        enabled: true,
        server_name: str(settings, "serverName"),
        reality: { enabled: true, public_key: str(settings, "publicKey"), short_id: str(settings, "shortId") },
        utls: { enabled: true, fingerprint: str(settings, "fingerprint", "chrome") },
      };
      break;
    }
    default:
      break;
  }
}

function putXrayTransport(target: Json, stream: Json): void {
  switch (str(stream, "network", "tcp")) {
    case "ws": {
      const settings = obj(stream, "wsSettings");
      if (!settings) return;
      const transport: Json = { type: "ws" };
      const path = str(settings, "path");
      if (path.length > 0) {
        transport.path = path;
      }
      const headerHost = str(obj(settings, "headers"), "Host");
      if (headerHost.length > 0) {
        transport.headers = { Host: headerHost };
      }
      target.transport = transport;
      break;
    }
    case "grpc": {
      const settings = obj(stream, "grpcSettings");
      if (!settings) return;
      const transport: Json = { type: "grpc" };
      const serviceName = str(settings, "serviceName");
      if (serviceName.length > 0) {
        transport.service_name = serviceName;
      }
      target.transport = transport;
      break;
    }
    case "xhttp":
    case "splithttp": {
      const settings =
        obj(stream, "xhttpSettings") ?? obj(stream, "xHTTPSettings") ?? obj(stream, "splithttpSettings");
      if (!settings) return;
      const transport: Json = { type: "xhttp" };
      for (const key of ["path", "host", "mode"] as const) {
        const value = str(settings, key);
        if (value.length > 0) {
          transport[key] = value;
        }
      }
      target.transport = transport;
      break;
    }
    case "httpupgrade": {
      const settings = obj(stream, "httpupgradeSettings");
      if (!settings) return;
      const transport: Json = { type: "httpupgrade" };
      for (const key of ["path", "host"] as const) {
        const value = str(settings, key);
        if (value.length > 0) {
          transport[key] = value;
        }
      }
      target.transport = transport;
      break;
    }
    case "h2": {
      const settings = obj(stream, "httpSettings");
      if (!settings) return;
      const transport: Json = { type: "http" };
      const path = str(settings, "path");
      if (path.length > 0) {
        transport.path = path;
      }
      const host = arr(settings, "host");
      if (host) {
        transport.host = host;
      }
      target.transport = transport;
      break;
    }
    default:
      break;
  }
}

// ---- transport from URI params ----

function putTransport(target: Json, type: string, params: Record<string, string>): void {
  switch (type) {
    case "ws": {
      const transport: Json = { type: "ws" };
      if (params.host) {
        transport.headers = { Host: params.host };
      }
      if (params.path) {
        transport.path = params.path;
      }
      target.transport = transport;
      break;
    }
    case "grpc": {
      const transport: Json = { type: "grpc" };
      if (params.serviceName) {
        transport.service_name = params.serviceName;
      }
      target.transport = transport;
      break;
    }
    case "http":
    case "h2": {
      const transport: Json = { type: "http" };
      if (params.host) {
        transport.host = [params.host];
      }
      if (params.path) {
        transport.path = params.path;
      }
      target.transport = transport;
      break;
    }
    case "httpupgrade": {
      const transport: Json = { type: "httpupgrade" };
      if (params.host) {
        transport.host = params.host;
      }
      if (params.path) {
        transport.path = params.path;
      }
      target.transport = transport;
      break;
    }
    case "xhttp":
    case "splithttp": {
      const transport: Json = { type: "xhttp" };
      if (params.host) {
        transport.host = params.host;
      }
      if (params.path) {
        transport.path = params.path;
      }
      if (params.mode) {
        transport.mode = params.mode;
      }
      target.transport = transport;
      break;
    }
    default:
      break;
  }
}
