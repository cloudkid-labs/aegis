import { sha256Hex } from "../auth";
import type { Asset } from "../types";

// Collision-resistant: a weak rolling hash let distinct values (e.g. /Aa and
// /BB) share an id, and INSERT OR REPLACE then silently dropped one discovery.
async function assetId(scanId: string, kind: string, value: string): Promise<string> {
  return (await sha256Hex(`${scanId}|${kind}|${value}`)).slice(0, 32);
}

function parseLines(data: unknown): Record<string, unknown>[] {
  if (Array.isArray(data)) return data as Record<string, unknown>[];
  if (typeof data === "string") {
    return data.split("\n").filter(Boolean)
      .map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter((x): x is Record<string, unknown> => x !== null);
  }
  return [];
}

type Extracted = { value: string; metadata: string | null };

// One place owns the Asset shape: line parsing, id hashing and createdAt live
// here, so a tool declares only what genuinely varies. idKind is separate from
// type because the id namespace and the displayed type differ for some tools
// (dnsx ids are "dns" but display as subdomain; naabu ids are "port" but display
// as endpoint) — folding them would change ids and silently re-key old assets.
function recordNormalizer(spec: {
  type: Asset["type"];
  idKind: string;
  extract: (e: Record<string, unknown>) => Extracted | null;
}) {
  return async (data: unknown, scanId: string, now: string): Promise<Asset[]> => {
    const out: Asset[] = [];
    for (const e of parseLines(data)) {
      const r = spec.extract(e);
      if (!r) continue;
      out.push({ id: await assetId(scanId, spec.idKind, r.value), scanId, type: spec.type, value: r.value, metadata: r.metadata, createdAt: now });
    }
    return out;
  };
}

export const normalizeSubfinder = recordNormalizer({
  type: "subdomain",
  idKind: "subdomain",
  extract: (e) => {
    const host = e.host as string | undefined;
    return host ? { value: host, metadata: JSON.stringify({ source: (e.source as string) ?? "subfinder" }) } : null;
  },
});

export const normalizeHttpx = recordNormalizer({
  type: "url",
  idKind: "url",
  extract: (e) => {
    const url = (e.url as string) ?? (e.host ? `https://${e.host}` : null);
    return url ? { value: url, metadata: JSON.stringify({ status_code: e.status_code ?? null, title: e.title ?? null, tech: e.tech ?? [] }) } : null;
  },
});

export const normalizeKatana = recordNormalizer({
  type: "endpoint",
  idKind: "endpoint",
  extract: (e) => {
    const url = (e.request as { endpoint?: string } | undefined)?.endpoint ?? (e.endpoint as string | undefined);
    if (!url) return null;
    // katana nests the response under `response` (pkg/navigation/response.go:
    // StatusCode int `json:"status_code,omitempty"`), never on the record
    // root. Invasion selection treats a missing status as not-live, so
    // dropping it here would exclude every katana endpoint.
    const statusCode = (e.response as { status_code?: unknown } | undefined)?.status_code;
    return {
      value: url,
      metadata: JSON.stringify({ status_code: typeof statusCode === "number" ? statusCode : null }),
    };
  },
});

// A dnsx record is a discovery only when it carries an address. Zones like
// cloudkid.link answer NOERROR + SOA authority (not NXDOMAIN) for labels that
// do not exist, and dnsx emits those lines with no `a` field — storing them
// turned 691 alterx permutations into "subdomains". aaaa is captured because
// dnsx now queries AAAA too, and an IPv6-only host is real.
function resolvedExtract(e: Record<string, unknown>, extra?: { source: string }): Extracted | null {
  const host = e.host as string | undefined;
  if (!host) return null;
  const a = Array.isArray(e.a) ? e.a : [];
  const aaaa = Array.isArray(e.aaaa) ? e.aaaa : [];
  if (a.length === 0 && aaaa.length === 0) return null;
  const cname = Array.isArray(e.cname) ? e.cname : [];
  return { value: host, metadata: JSON.stringify({ a, aaaa, cname, resolved: true, ...(extra ?? {}) }) };
}

export const normalizeDnsx = recordNormalizer({
  type: "subdomain",
  idKind: "dns",
  extract: (e) => resolvedExtract(e),
});

export const normalizeNaabu = recordNormalizer({
  type: "endpoint",
  idKind: "port",
  extract: (e) => {
    const host = e.host as string | undefined;
    const port = e.port as number | undefined;
    if (!host || !port) return null;
    return { value: `${host}:${port}`, metadata: JSON.stringify({ port, protocol: (e.protocol as string) ?? "tcp" }) };
  },
});

/** Serialized candidate flag carried by scans stored before alterx output was
 *  resolved. The D1 reads mirror this exact substring, so changing the old
 *  metadata shape here would silently un-hide those rows. */
export const CANDIDATE_MARKER = '"candidate":true';

// alterx permutations go through dnsx before storage (registry resolveWith),
// so what arrives here is dnsx-style resolution records, not a wordlist.
export const normalizeAlterxResolved = recordNormalizer({
  type: "subdomain",
  idKind: "dns",
  extract: (e) => resolvedExtract(e, { source: "alterx" }),
});