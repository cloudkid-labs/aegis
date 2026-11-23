import type { ScanStore } from "../scan-store";
import type { Asset, Finding, ScanEvent, ScanRecord, ScanStatus } from "../types";

/**
 * In-memory ScanStore for the node project. The workers project runs the same
 * contract against real D1; ordering here matches the SQL exactly
 * (created_at then id) so a divergence is a red contract test, not a
 * surprise in production.
 */
export function memoryScanStore(): ScanStore {
  const scans = new Map<string, ScanRecord>();
  const assets = new Map<string, Asset>();
  const findings = new Map<string, Finding>();
  const events = new Map<string, ScanEvent[]>();

  return {
    async create(rec) {
      scans.set(rec.id, { ...rec });
    },

    async get(id) {
      const rec = scans.get(id);
      return rec ? { ...rec } : null;
    },

    async list(limit) {
      return [...scans.values()]
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id))
        .slice(0, limit)
        .map((rec) => ({
          ...rec,
          assetCount: [...assets.values()].filter((a) => a.scanId === rec.id).length,
        }));
    },

    async setStatus(id, status, patch = {}) {
      const rec = scans.get(id);
      if (!rec) return;
      scans.set(id, {
        ...rec,
        status,
        updatedAt: new Date().toISOString(),
        externalUrl: patch.externalUrl !== undefined ? patch.externalUrl : rec.externalUrl,
        error: patch.error !== undefined ? patch.error : rec.error,
        completedAt: patch.completedAt !== undefined ? patch.completedAt : rec.completedAt,
      });
    },

    async transition(id, allowed, to, patch = {}) {
      const rec = scans.get(id);
      if (!rec || !allowed.includes(rec.status)) return false;
      scans.set(id, {
        ...rec,
        status: to,
        updatedAt: new Date().toISOString(),
        externalUrl: patch.externalUrl !== undefined ? patch.externalUrl : rec.externalUrl,
        error: patch.error !== undefined ? patch.error : rec.error,
        completedAt: patch.completedAt !== undefined ? patch.completedAt : rec.completedAt,
      });
      return true;
    },

    async claimOldest(executor, now) {
      const oldest = [...scans.values()]
        .filter((rec) => rec.executor === executor && rec.status === "queued")
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id))[0];
      if (!oldest) return null;
      const claimed: ScanRecord = { ...oldest, status: "running" as ScanStatus, updatedAt: now };
      scans.set(claimed.id, claimed);
      return { ...claimed };
    },

    async addEvent(scanId, event, detail) {
      const list = events.get(scanId) ?? [];
      list.push({ event, detail: detail ?? null, createdAt: new Date().toISOString() });
      events.set(scanId, list);
    },

    async insertAssets(batch) {
      for (const asset of batch) assets.set(asset.id, { ...asset });
    },

    async listAssets(scanId) {
      return [...assets.values()]
        .filter((asset) => asset.scanId === scanId)
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id))
        .map((asset) => ({ ...asset }));
    },

    async insertFindings(batch) {
      for (const finding of batch) findings.set(finding.id, { ...finding });
    },

    async listFindings(scanId) {
      return [...findings.values()]
        .filter((finding) => finding.scanId === scanId)
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id))
        .map((finding) => ({ ...finding }));
    },

    async events(scanId) {
      return (events.get(scanId) ?? []).map((event) => ({ ...event }));
    },
  };
}