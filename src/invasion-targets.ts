import type { Asset } from "./types";

/**
 * Asset hygiene for the Invasion phase. Applied at selection only; Explore
 * storage keeps every asset it discovered. The rule order below is normative
 * (design spec Section 1): an asset is excluded by the FIRST rule it fails, so
 * `/cdn-cgi/scripts/x.js` reports `cdn-cgi` and not `static-asset`.
 *
 * Only an asset that was KEPT can make a later asset a duplicate: a dead URL
 * shares its key with nothing, so a live row for the same value still shows up.
 */
export type ExclusionReason =
  | "not-url"
  | "malformed"
  | "not-live"
  | "cdn-cgi"
  | "static-asset"
  | "duplicate";

export interface InvasionTarget {
  url: string;
  type: Asset["type"];
  statusCode: number | null;
}

export interface ExcludedTarget {
  url: string;
  reason: ExclusionReason;
}

export interface InvasionSelection {
  targets: InvasionTarget[];
  excluded: ExcludedTarget[];
}

const TARGET_TYPES: ReadonlySet<Asset["type"]> = new Set(["url", "endpoint"]);

const STATIC_ASSET = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|map)$/i;

// Katana appends `:line[:col]` source positions to discovered URLs. Tested
// against the pathname, never the raw value: a bare `https://x.example:8443`
// is a legitimate origin and must not be read as a source position.
const SOURCE_POSITION = /:\d+(?::\d+)?$/;

/** Lowercase scheme and host, pathname trailing slashes folded (root stays
 *  `/`), search preserved. Two spellings of one resource share a key. */
function targetKey(url: URL): string {
  const path = url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/, "");
  return `${url.protocol.toLowerCase()}//${url.hostname.toLowerCase()}${path}${url.search}`;
}

/** httpx writes `status_code` as a number; anything else (missing, null,
 *  unparseable metadata) counts as no status at all. */
function statusCodeOf(asset: Asset): number | null {
  if (!asset.metadata) return null;
  try {
    const metadata = JSON.parse(asset.metadata) as { status_code?: unknown };
    return typeof metadata.status_code === "number" ? metadata.status_code : null;
  } catch {
    return null;
  }
}

export function selectInvasionTargets(assets: Asset[]): InvasionSelection {
  const targets: InvasionTarget[] = [];
  const excluded: ExcludedTarget[] = [];
  const seen = new Set<string>();

  const exclude = (url: string, reason: ExclusionReason): void => {
    excluded.push({ url, reason });
  };

  for (const asset of assets) {
    // 1. Only discovered URLs and crawler endpoints can be scanned.
    if (!TARGET_TYPES.has(asset.type)) {
      exclude(asset.value, "not-url");
      continue;
    }

    // 2. A scan target must be an absolute http(s) URL, and not a scraped
    //    fragment or a katana source position.
    if (/\s/.test(asset.value) || asset.value.includes("<")) {
      exclude(asset.value, "malformed");
      continue;
    }
    let url: URL;
    try {
      url = new URL(asset.value);
    } catch {
      exclude(asset.value, "malformed");
      continue;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      exclude(asset.value, "malformed");
      continue;
    }
    if (SOURCE_POSITION.test(url.pathname)) {
      exclude(asset.value, "malformed");
      continue;
    }

    // 3. No live response, no scan.
    const statusCode = statusCodeOf(asset);
    if (statusCode === null || statusCode < 200 || statusCode > 399) {
      exclude(asset.value, "not-live");
      continue;
    }

    // 4. Cloudflare internals are never the operator's target.
    if (url.pathname.startsWith("/cdn-cgi/")) {
      exclude(asset.value, "cdn-cgi");
      continue;
    }

    // 5. Requesting a static file is not an attack surface.
    if (STATIC_ASSET.test(url.pathname)) {
      exclude(asset.value, "static-asset");
      continue;
    }

    // 6. Keep the first spelling of each resource.
    const key = targetKey(url);
    if (seen.has(key)) {
      exclude(asset.value, "duplicate");
      continue;
    }
    seen.add(key);
    targets.push({ url: asset.value, type: asset.type, statusCode });
  }

  return { targets, excluded };
}