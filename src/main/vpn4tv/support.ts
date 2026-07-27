// VPN4TV: small helpers shared by the parser and the generator — a TypeScript
// port of Library/Config/ConfigConverterSupport.swift (itself a port of the
// Kotlin original). Kept dependency-free so it can run in the main process, in
// tests, and (if ever needed) in the renderer.

export type Json = Record<string, unknown>;

/** Tolerant base64 (standard or URL-safe, padded or not). */
export const B64 = {
  decode(input: string): Buffer | null {
    const cleaned = input.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
    if (cleaned.length === 0) {
      return null;
    }
    const padded = cleaned.padEnd(cleaned.length + ((4 - (cleaned.length % 4)) % 4), "=");
    try {
      const buffer = Buffer.from(padded, "base64");
      // Buffer.from is famously forgiving: re-encoding must round-trip or the
      // input was not base64 at all (e.g. a bare "vless://..." line).
      if (buffer.length === 0) {
        return null;
      }
      return buffer;
    } catch {
      return null;
    }
  },

  decodeToString(input: string): string | null {
    const buffer = B64.decode(input);
    if (!buffer) {
      return null;
    }
    const text = buffer.toString("utf8");
    // Reject binary garbage: a decoded subscription is always printable text.
    if (/[\u0000-\u0008\u000E-\u001F]/.test(text)) {
      return null;
    }
    return text;
  },
};

export interface ParsedURI {
  scheme: string;
  userInfo?: string;
  userInfoEncoded?: string;
  host?: string;
  port: number;
  fragment?: string;
  query: Record<string, string>;
}

/** Split "host:port" / "[v6]:port" — port is 0 when absent. */
export function splitHostPort(input: string): { host: string; port: number } | null {
  const value = input.trim();
  if (value.length === 0) {
    return null;
  }
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end < 0) {
      return null;
    }
    const host = value.slice(1, end);
    const rest = value.slice(end + 1);
    const port = rest.startsWith(":") ? Number.parseInt(rest.slice(1), 10) : 0;
    return { host, port: Number.isFinite(port) ? port : 0 };
  }
  const colon = value.lastIndexOf(":");
  if (colon < 0) {
    return { host: value, port: 0 };
  }
  const port = Number.parseInt(value.slice(colon + 1), 10);
  if (!Number.isFinite(port)) {
    return { host: value, port: 0 };
  }
  return { host: value.slice(0, colon), port };
}

/**
 * Parse a proxy URI. Deliberately hand-rolled instead of using URL: proxy links
 * carry raw UUIDs / base64 in the user-info and non-ASCII in the fragment, which
 * WHATWG URL mangles or rejects.
 */
export function parseProxyURI(uri: string): ParsedURI | null {
  const schemeEnd = uri.indexOf("://");
  if (schemeEnd <= 0) {
    return null;
  }
  const scheme = uri.slice(0, schemeEnd);
  let rest = uri.slice(schemeEnd + 3);

  let fragment: string | undefined;
  const hash = rest.indexOf("#");
  if (hash >= 0) {
    fragment = safeDecode(rest.slice(hash + 1));
    rest = rest.slice(0, hash);
  }

  const query: Record<string, string> = {};
  const questionMark = rest.indexOf("?");
  if (questionMark >= 0) {
    for (const pair of rest.slice(questionMark + 1).split("&")) {
      if (pair.length === 0) {
        continue;
      }
      const equals = pair.indexOf("=");
      const key = equals < 0 ? pair : pair.slice(0, equals);
      const value = equals < 0 ? "" : pair.slice(equals + 1);
      query[safeDecode(key)] = safeDecode(value);
    }
    rest = rest.slice(0, questionMark);
  }

  let userInfoEncoded: string | undefined;
  const at = rest.lastIndexOf("@");
  if (at >= 0) {
    userInfoEncoded = rest.slice(0, at);
    rest = rest.slice(at + 1);
  }

  while (rest.endsWith("/")) {
    rest = rest.slice(0, -1);
  }
  const hostPort = splitHostPort(rest);
  return {
    scheme,
    userInfo: userInfoEncoded === undefined ? undefined : safeDecode(userInfoEncoded),
    userInfoEncoded,
    host: hostPort?.host,
    port: hostPort?.port ?? 0,
    fragment: fragment && fragment.length > 0 ? fragment : undefined,
    query,
  };
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

// ---- typed accessors over parsed JSON (the Swift dictionary helpers) ----

export function asObject(value: unknown): Json | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Json) : null;
}

export function str(source: Json | null | undefined, key: string, fallback = ""): string {
  const value = source?.[key];
  return typeof value === "string" ? value : fallback;
}

export function int(source: Json | null | undefined, key: string, fallback = 0): number {
  const value = source?.[key];
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return fallback;
}

export function bool(source: Json | null | undefined, key: string): boolean {
  return source?.[key] === true;
}

export function obj(source: Json | null | undefined, key: string): Json | null {
  return asObject(source?.[key]);
}

export function arr(source: Json | null | undefined, key: string): unknown[] | null {
  const value = source?.[key];
  return Array.isArray(value) ? value : null;
}

export function objArr(source: Json | null | undefined, key: string): Json[] | null {
  const value = arr(source, key);
  if (!value) {
    return null;
  }
  return value.map(asObject).filter((item): item is Json => item !== null);
}

export function parseJsonObject(text: string): Json | null {
  try {
    return asObject(JSON.parse(text));
  } catch {
    return null;
  }
}
