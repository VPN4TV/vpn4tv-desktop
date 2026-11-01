// VPN4TV: the dns-ru self-check of "Russia direct" (RussiaDirectRuntime.kt,
// probeDnsRu + probeProxyAliveByIp on Android).
//
// Russian names resolve at Yandex over TCP 53, outside the tunnel. Where that
// port is closed (hotels, offices, some networks abroad) Russian names would
// stop resolving. The app's own sockets are not bound to the physical
// interface, so with auto_route they go through the tunnel like any other
// application's: a DNS query to the tun's peer address is hijacked by the core
// and sent by our rule to dns-ru, exactly as a browser's would be.
//
// Electron-free (node:dgram and node:net only).

import { createSocket } from "node:dgram";
import { Socket } from "node:net";

/** The tun's peer address (generator.ts: 172.19.0.1/30). Any UDP 53 there is hijacked as DNS. */
export const TUN_DNS_ADDRESS = "172.19.0.2";
/** A Russian name: our DNS rule sends it to dns-ru. */
export const PROBE_NAME = "ya.ru";
/** Stable anycast addresses: a TCP connect by address says whether the proxy is up, with no DNS involved. */
const PROXY_PROBE_ADDRESSES = ["1.1.1.1", "8.8.8.8"];
const PROBE_TIMEOUT_MILLISECONDS = 5_000;

/** A minimal DNS query: one A question, recursion desired. */
export function buildDnsQuery(name: string, id = Math.floor(Math.random() * 0x10000)): Buffer {
  const labels = name.replace(/\.$/u, "").split(".");
  const parts: Buffer[] = [
    Buffer.from([id >> 8, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
  ];
  for (const label of labels) {
    const bytes = Buffer.from(label, "ascii");
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01]));
  return Buffer.concat(parts);
}

/** The A-record addresses of a DNS response; what can be read of a truncated one. */
export function parseDnsAnswers(message: Buffer): string[] {
  const addresses: string[] = [];
  if (message.length < 12) {
    return addresses;
  }
  const questions = message.readUInt16BE(4);
  const answers = message.readUInt16BE(6);
  let position = 12;
  const skipName = () => {
    while (position < message.length) {
      const length = message[position];
      if (length === 0) {
        position += 1;
        return;
      }
      if (length >= 0xc0) {
        position += 2; // compression pointer
        return;
      }
      position += 1 + length;
    }
  };
  for (let index = 0; index < questions; index++) {
    skipName();
    position += 4; // QTYPE + QCLASS
  }
  for (let index = 0; index < answers; index++) {
    skipName();
    if (position + 10 > message.length) {
      return addresses;
    }
    const type = message.readUInt16BE(position);
    const dataLength = message.readUInt16BE(position + 8);
    position += 10;
    if (type === 1 && dataLength === 4 && position + 4 <= message.length) {
      addresses.push([...message.subarray(position, position + 4)].join("."));
    }
    position += dataLength;
  }
  return addresses;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/** Where the probes go and how long they wait; the defaults are the real ones, the tests point them at a stub. */
export interface ProbeTargets {
  dnsAddress?: string;
  dnsPort?: number;
  proxyAddresses?: readonly string[];
  proxyPort?: number;
  timeoutMilliseconds?: number;
  pauseMilliseconds?: number;
}

/** One DNS query for [name] through the tunnel; the addresses in the answer, or [] on silence. */
async function queryThroughTunnel(name: string, targets: ProbeTargets): Promise<string[]> {
  const query = buildDnsQuery(name);
  return await new Promise<string[]>((resolve) => {
    const socket = createSocket("udp4");
    let settled = false;
    const finish = (addresses: string[]) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // already closed after an error
      }
      resolve(addresses);
    };
    const timer = setTimeout(() => finish([]), targets.timeoutMilliseconds ?? PROBE_TIMEOUT_MILLISECONDS);
    socket.on("error", () => finish([]));
    socket.on("message", (message) => {
      if (message.length >= 2 && message.readUInt16BE(0) === query.readUInt16BE(0)) {
        finish(parseDnsAnswers(message));
      }
    });
    socket.send(query, targets.dnsPort ?? 53, targets.dnsAddress ?? TUN_DNS_ADDRESS, (error) => {
      if (error) {
        finish([]);
      }
    });
  });
}

/**
 * A DNS query for a Russian name through the tunnel, as an application's would
 * go. True on an answer with an address.
 */
export async function probeDnsRu(
  attempts: number,
  stillWanted: () => boolean,
  log: (message: string) => void = () => {},
  targets: ProbeTargets = {},
): Promise<boolean> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (!stillWanted()) {
      return false;
    }
    if ((await queryThroughTunnel(PROBE_NAME, targets)).length > 0) {
      return true;
    }
    log(`dns-ru probe ${attempt}/${attempts}: no address in the answer`);
    if (attempt < attempts) {
      await sleep(targets.pauseMilliseconds ?? 1_000);
    }
  }
  return false;
}

/** A TCP connect by address through the tunnel: the proxy (or the network, for applications left direct) is up. */
export async function probeProxyAlive(
  stillWanted: () => boolean,
  targets: ProbeTargets = {},
): Promise<boolean> {
  for (const address of targets.proxyAddresses ?? PROXY_PROBE_ADDRESSES) {
    if (!stillWanted()) {
      return false;
    }
    const connected = await new Promise<boolean>((resolve) => {
      const socket = new Socket();
      const finish = (result: boolean) => {
        socket.destroy();
        resolve(result);
      };
      socket.setTimeout(targets.timeoutMilliseconds ?? PROBE_TIMEOUT_MILLISECONDS, () => finish(false));
      socket.once("error", () => finish(false));
      socket.connect(targets.proxyPort ?? 443, address, () => finish(true));
    });
    if (connected) {
      return true;
    }
  }
  return false;
}
