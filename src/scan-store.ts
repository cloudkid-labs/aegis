import { CANDIDATE_MARKER } from "./normalizers/explore";
import type {
  Asset, ExecutorName, Finding, ScanAuthorization, ScanEvent, ScanRecord, ScanStatus,
} from "./types";

/**
 * The only persistence interface the rest of the Worker sees. D1 is the
 * production implementation; `memoryScanStore` is the node-test fake. Both
 * are held to `describeScanStoreContract`, so the fake cannot drift.
 */
export interface ScanStore {
  create(rec: ScanRecord): Promise<void>;
  get(id: string): Promise<ScanRecord | null>;
  list(limit: number): Promise<ScanListRow[]>;
  setStatus(id: string, status: ScanStatus, patch?: ScanStatusPatch): Promise<void>;
  /**
   * Atomic conditional status change: writes only if the current status is in
   * `allowed`, returning false otherwise. A late callback, timeout or cancel
   * therefore cannot resurrect or overwrite a scan that already went terminal.
   */
  transition(id: string, allowed: ScanStatus[], to: ScanStatus, patch?: ScanStatusPatch): Promise<boolean>;
  /** Atomically flip the oldest queued scan for one executor to running. */
  claimOldest(executor: ExecutorName, now: string): Promise<ScanRecord | null>;
  /**
   * Insert a scan only when no sibling under the same `parentScanId` is queued
   * or running. Check and insert are one statement, so two retries of one scan
   * cannot both create an active copy even after both read the failed row: the
   * guard holds for the whole dispatch window, not just the status read.
   * Returns false when an active child exists and nothing was inserted.
   */
  createIfNoActiveChild(rec: ScanRecord): Promise<boolean>;
  addEvent(scanId: string, event: string, detail?: string): Promise<void>;
  insertAssets(assets: Asset[]): Promise<void>;
  listAssets(scanId: string): Promise<Asset[]>;
  insertFindings(findings: Finding[]): Promise<void>;
  listFindings(scanId: string): Promise<Finding[]>;
  events(scanId: string): Promise<ScanEvent[]>;
  /**
   * Persist what the operator confirmed for an invasion scan. The scan id is
   * the primary key: a duplicate insert throws, so a scan's authorization is
   * immutable once written.
   */
  createAuthorization(rec: ScanAuthorization): Promise<void>;
  getAuthorization(scanId: string): Promise<ScanAuthorization | null>;
}

export interface ScanStatusPatch {
  externalUrl?: string | null;
  error?: string | null;
  completedAt?: string | null;
}

/** A scan plus the asset count the history table shows beside it. */
export interface ScanListRow extends ScanRecord {
  assetCount: number;
}

interface ScanRow {
  id: string;
  target: string;
  phase: string;
  status: string;
  parent_scan_id: string | null;
  executor: string;
  external_url: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  error: string | null;
  options: string | null;
}

interface AssetRow {
  id: string;
  scan_id: string;
  type: string;
  value: string;
  metadata: string | null;
  created_at: string;
}

interface FindingRow {
  id: string;
  scan_id: string;
  tool: string;
  severity: string;
  confidence: string;
  title: string;
  description: string;
  url: string;
  parameter: string | null;
  evidence: string | null;
  cwe: number | null;
  remediation: string | null;
  raw_ref: string | null;
  created_at: string;
}

interface AuthorizationRow {
  scan_id: string;
  email: string;
  targets: string;
  tools: string;
  active: number;
  confirmed_at: string;
}

function toRecord(row: ScanRow): ScanRecord {
  return {
    id: row.id,
    target: row.target,
    phase: row.phase as ScanRecord["phase"],
    status: row.status as ScanStatus,
    parentScanId: row.parent_scan_id,
    executor: row.executor as ExecutorName,
    externalUrl: row.external_url,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    completedAt: row.completed_at,
    error: row.error,
    options: row.options,
  };
}

function toAsset(row: AssetRow): Asset {
  return {
    id: row.id,
    scanId: row.scan_id,
    type: row.type as Asset["type"],
    value: row.value,
    metadata: row.metadata,
    createdAt: row.created_at,
  };
}

function toFinding(row: FindingRow): Finding {
  return {
    id: row.id,
    scanId: row.scan_id,
    tool: row.tool,
    severity: row.severity as Finding["severity"],
    confidence: row.confidence as Finding["confidence"],
    title: row.title,
    description: row.description,
    url: row.url,
    parameter: row.parameter,
    evidence: row.evidence,
    cwe: row.cwe,
    remediation: row.remediation,
    rawRef: row.raw_ref,
    createdAt: row.created_at,
  };
}

/** D1 stores the lists as JSON text; callers get the arrays back. A row that
 *  does not decode to two arrays was not written by createAuthorization
 *  (corruption or a manual edit), so it reads as no authorization instead of
 *  throwing on every retry and preview. */
function toAuthorization(row: AuthorizationRow): ScanAuthorization | null {
  let targets: unknown;
  let tools: unknown;
  try {
    targets = JSON.parse(row.targets);
    tools = JSON.parse(row.tools);
  } catch {
    return null;
  }
  if (!Array.isArray(targets) || !Array.isArray(tools)) return null;
  return {
    scanId: row.scan_id,
    email: row.email,
    targets: targets as string[],
    tools: tools as string[],
    active: row.active === 1,
    confirmedAt: row.confirmed_at,
  };
}

const SCAN_COLS =
  "id, target, phase, status, parent_scan_id, executor, external_url, created_at, updated_at, completed_at, error, options";

const SCAN_COLS_S = SCAN_COLS.split(", ").map((c) => `s.${c}`).join(", ");

const ASSET_COLS = "id, scan_id, type, value, metadata, created_at";

const FINDING_COLS =
  "id, scan_id, tool, severity, confidence, title, description, url, parameter, evidence, cwe, remediation, raw_ref, created_at";

export function d1ScanStore(db: D1Database): ScanStore {
  return {
    async create(rec) {
      await db
        .prepare(`INSERT INTO scans (${SCAN_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`)
        .bind(
          rec.id, rec.target, rec.phase, rec.status, rec.parentScanId, rec.executor,
          rec.externalUrl, rec.createdAt, rec.updatedAt, rec.completedAt, rec.error, rec.options,
        )
        .run();
    },

    async get(id) {
      const row = await db.prepare(`SELECT ${SCAN_COLS} FROM scans WHERE id=?1`).bind(id).first<ScanRow>();
      return row ? toRecord(row) : null;
    },

    async list(limit) {
      const { results } = await db
        .prepare(
          `SELECT ${SCAN_COLS_S}, COUNT(a.id) AS asset_count
             FROM scans s LEFT JOIN assets a ON a.scan_id = s.id
               AND (a.metadata IS NULL OR a.metadata NOT LIKE '%${CANDIDATE_MARKER}%')
            GROUP BY s.id
            ORDER BY s.created_at DESC, s.id DESC LIMIT ?1`,
        )
        .bind(limit)
        .all<ScanRow & { asset_count: number }>();
      return results.map((row) => ({ ...toRecord(row), assetCount: row.asset_count }));
    },

    async setStatus(id, status, patch = {}) {
      await db
        .prepare(
          `UPDATE scans SET status=?2, updated_at=?3,
             external_url=COALESCE(?4, external_url),
             error=COALESCE(?5, error),
             completed_at=COALESCE(?6, completed_at)
           WHERE id=?1`,
        )
        .bind(id, status, new Date().toISOString(), patch.externalUrl ?? null, patch.error ?? null, patch.completedAt ?? null)
        .run();
    },

    async transition(id, allowed, to, patch = {}) {
      if (allowed.length === 0) return false;
      const ph = allowed.map((_, i) => `?${7 + i}`).join(",");
      const res = await db
        .prepare(
          `UPDATE scans SET status=?2, updated_at=?3,
             external_url=COALESCE(?4, external_url),
             error=COALESCE(?5, error),
             completed_at=COALESCE(?6, completed_at)
           WHERE id=?1 AND status IN (${ph})`,
        )
        .bind(id, to, new Date().toISOString(), patch.externalUrl ?? null, patch.error ?? null, patch.completedAt ?? null, ...allowed)
        .run();
      return (res.meta?.changes ?? 0) > 0;
    },

    async claimOldest(executor, now) {
      // One statement: two concurrent claims can never take the same row.
      const row = await db
        .prepare(
          `UPDATE scans SET status='running', updated_at=?2
           WHERE id = (SELECT id FROM scans WHERE executor=?1 AND status='queued' ORDER BY created_at, id LIMIT 1)
           RETURNING ${SCAN_COLS}`,
        )
        .bind(executor, now)
        .first<ScanRow>();
      return row ? toRecord(row) : null;
    },

    async createIfNoActiveChild(rec) {
      // One statement: the NOT EXISTS check and the insert cannot interleave,
      // so a competing retry can never slip an active child in between. ?5 is
      // parent_scan_id, reused by the subquery. A NULL parent never matches
      // (?5 = NULL is never true), so a parentless record always inserts.
      const res = await db
        .prepare(
          `INSERT INTO scans (${SCAN_COLS})
           SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12
            WHERE NOT EXISTS (
              SELECT 1 FROM scans WHERE parent_scan_id=?5 AND status IN ('queued','running')
            )`,
        )
        .bind(
          rec.id, rec.target, rec.phase, rec.status, rec.parentScanId, rec.executor,
          rec.externalUrl, rec.createdAt, rec.updatedAt, rec.completedAt, rec.error, rec.options,
        )
        .run();
      return (res.meta?.changes ?? 0) > 0;
    },

    async addEvent(scanId, event, detail) {
      await db
        .prepare("INSERT INTO scan_events (scan_id, event, detail, created_at) VALUES (?1,?2,?3,?4)")
        .bind(scanId, event, detail ?? null, new Date().toISOString())
        .run();
    },

    async insertAssets(assets) {
      if (assets.length === 0) return;
      const stmt = db.prepare(`INSERT OR REPLACE INTO assets (${ASSET_COLS}) VALUES (?1,?2,?3,?4,?5,?6)`);
      await db.batch(
        assets.map((a) => stmt.bind(a.id, a.scanId, a.type, a.value, a.metadata, a.createdAt)),
      );
    },

    async listAssets(scanId) {
      // Unresolved alterx permutations from old scans stay in D1 as evidence
      // but are not discoveries; the marker is our own serialized constant.
      const { results } = await db
        .prepare(
          `SELECT ${ASSET_COLS} FROM assets
            WHERE scan_id=?1 AND (metadata IS NULL OR metadata NOT LIKE '%${CANDIDATE_MARKER}%')
            ORDER BY created_at, id`,
        )
        .bind(scanId)
        .all<AssetRow>();
      return results.map(toAsset);
    },

    async insertFindings(findings) {
      if (findings.length === 0) return;
      const stmt = db.prepare(
        `INSERT OR REPLACE INTO findings (${FINDING_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)`,
      );
      await db.batch(
        findings.map((f) =>
          stmt.bind(
            f.id, f.scanId, f.tool, f.severity, f.confidence, f.title, f.description,
            f.url, f.parameter, f.evidence, f.cwe, f.remediation, f.rawRef, f.createdAt,
          ),
        ),
      );
    },

    async listFindings(scanId) {
      const { results } = await db
        .prepare(`SELECT ${FINDING_COLS} FROM findings WHERE scan_id=?1 ORDER BY created_at, id`)
        .bind(scanId)
        .all<FindingRow>();
      return results.map(toFinding);
    },

    async events(scanId) {
      const { results } = await db
        .prepare("SELECT event, detail, created_at FROM scan_events WHERE scan_id=?1 ORDER BY id")
        .bind(scanId)
        .all<{ event: string; detail: string | null; created_at: string }>();
      return results.map((row) => ({ event: row.event, detail: row.detail, createdAt: row.created_at }));
    },

    async createAuthorization(rec) {
      // Plain INSERT on purpose: the primary key is the scan id, so a second
      // authorization for one scan surfaces as a constraint error, not an
      // overwrite of what the operator confirmed.
      await db
        .prepare(
          "INSERT INTO scan_authorizations (scan_id, email, targets, tools, active, confirmed_at) VALUES (?1,?2,?3,?4,?5,?6)",
        )
        .bind(
          rec.scanId, rec.email, JSON.stringify(rec.targets), JSON.stringify(rec.tools),
          rec.active ? 1 : 0, rec.confirmedAt,
        )
        .run();
    },

    async getAuthorization(scanId) {
      const row = await db
        .prepare(
          "SELECT scan_id, email, targets, tools, active, confirmed_at FROM scan_authorizations WHERE scan_id=?1",
        )
        .bind(scanId)
        .first<AuthorizationRow>();
      return row ? toAuthorization(row) : null;
    },
  };
}