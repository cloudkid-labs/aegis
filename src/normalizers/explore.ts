import type { Asset } from "../types";

function assetId(scanId: string, type: string, value: string): string {
  let h = 0;
  const s = `${scanId}|${type}|${value}`;
  for (let i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; }
  return `${scanId.slice(0, 8)}-${type}-${(h >>> 0).toString(36)}`;
}

export function normalizeSubfinder(data: unknown, scanId: string, now: string): Asset[] {
  const lines = Array.isArray(data) ? data : typeof data === "string" ? data.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) : [];
  const out: Asset[] = [];
  for (const entry of lines) {
    const host = (entry as { host?: string }).host;
    if (!host) continue;
    out.push({ id: assetId(scanId, "subdomain", host), scanId, type: "subdomain", value: host, metadata: JSON.stringify({ source: (entry as { source?: string }).source ?? "subfinder" }), createdAt: now });
  }
  return out;
}

export function normalizeHttpx(data: unknown, scanId: string, now: string): Asset[] {
  const lines = Array.isArray(data) ? data : typeof data === "string" ? data.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) : [];
  const out: Asset[] = [];
  for (const entry of lines) {
    const e = entry as { url?: string; status_code?: number; title?: string; tech?: string[]; host?: string };
    const url = e.url ?? (e.host ? `https://${e.host}` : null);
    if (!url) continue;
    out.push({ id: assetId(scanId, "url", url), scanId, type: "url", value: url, metadata: JSON.stringify({ status_code: e.status_code ?? null, title: e.title ?? null, tech: e.tech ?? [] }), createdAt: now });
  }
  return out;
}

export function normalizeKatana(data: unknown, scanId: string, now: string): Asset[] {
  const lines = Array.isArray(data) ? data : typeof data === "string" ? data.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) : [];
  const out: Asset[] = [];
  for (const entry of lines) {
    const e = entry as { request?: { endpoint?: string }; endpoint?: string };
    const url = e.request?.endpoint ?? e.endpoint;
    if (!url) continue;
    out.push({ id: assetId(scanId, "endpoint", url), scanId, type: "endpoint", value: url, metadata: null, createdAt: now });
  }
  return out;
}

export function normalizeDnsx(data: unknown, scanId: string, now: string): Asset[] {
  const lines = Array.isArray(data) ? data : typeof data === "string" ? data.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) : [];
  const out: Asset[] = [];
  for (const entry of lines) {
    const e = entry as { host?: string; a?: string[]; cname?: string[]; resolver?: string };
    if (!e.host) continue;
    out.push({ id: assetId(scanId, "dns", e.host), scanId, type: "subdomain", value: e.host, metadata: JSON.stringify({ a: e.a ?? [], cname: e.cname ?? [], resolved: true }), createdAt: now });
  }
  return out;
}

export function normalizeNaabu(data: unknown, scanId: string, now: string): Asset[] {
  const lines = Array.isArray(data) ? data : typeof data === "string" ? data.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) : [];
  const out: Asset[] = [];
  for (const entry of lines) {
    const e = entry as { host?: string; port?: number; protocol?: string };
    if (!e.host || !e.port) continue;
    const value = `${e.host}:${e.port}`;
    out.push({ id: assetId(scanId, "port", value), scanId, type: "endpoint", value, metadata: JSON.stringify({ port: e.port, protocol: e.protocol ?? "tcp" }), createdAt: now });
  }
  return out;
}

export function normalizeAlterx(data: unknown, scanId: string, now: string): Asset[] {
  const lines = typeof data === "string" ? data.split("\n").filter(Boolean) : Array.isArray(data) ? data.map(String) : [];
  const out: Asset[] = [];
  for (const host of lines) {
    const trimmed = host.trim();
    if (!trimmed) continue;
    out.push({ id: assetId(scanId, "subdomain", trimmed), scanId, type: "subdomain", value: trimmed, metadata: JSON.stringify({ source: "alterx", candidate: true }), createdAt: now });
  }
  return out;
}