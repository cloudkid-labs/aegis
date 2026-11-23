# Phase 2 Invasion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run nuclei + ZAP scans (standalone or chained from Explore) with per-scan authorization, ingest typed findings, and show them severity-ranked with SARIF export.

**Architecture:** Mirror the proven Explore pipeline: a second GitHub workflow, a phase-driven executor, registry-declared tools, callback ingestion routed by registry `outputType`. Authorization and target selection live API-side; the UI confirms before anything dispatches.

**Tech Stack:** Cloudflare Workers + Hono, D1 (migrations), R2, Durable Objects, Astro 7.4 static dashboard, vitest two projects (`node` fakes / `workers` real workerd+D1+R2), GitHub Actions docker executor.

**Spec:** `docs/superpowers/specs/2026-11-23-aegis-phase2-invasion-design.md` (read it first; every task argues from it).

## Global Constraints

- Repo clone: `D:\SourceCode\GitHub\cloudkid-labs\aegis`. Branch `Codex/phase2-invasion` (already exists; spec committed).
- Never push to `main`; never delete remote refs; commit messages conventional, ~72 chars.
- TDD: failing test first, watch it fail, minimal implementation, watch it pass, commit.
- Commands: `npx tsc --noEmit`; `npx vitest run` (both projects); `npm run build` BEFORE workers tests after any markup/CSS change (globalSetup only builds when `dist/` absent).
- No innerHTML in client code; `createElement`/`textContent` only (pinned by `src/assets.workers.test.ts`).
- No inline `<style>`/`<script>` blocks in built HTML (CSP `script-src 'self'`, `style-src 'self'`).
- All colours via existing `:root` tokens in `src/styles/aegis.css`; no literal hex outside the token block.
- Caps and timeouts only in `src/limits.ts`: `INVASION_MAX_URLS = 8`, `INVASION_TIMEOUT_BASELINE = 1800`, `INVASION_TIMEOUT_ACTIVE = 3600`.
- Every response inside `/api/*` is JSON, including errors and geo blocks.
- State-changing API calls ride the existing operator gate (`requireOperator`) and JSON content-type check; do not weaken them.
- Conditional status transitions only (`store.transition(id, allowed, to, patch)`); never resurrect terminal scans.
- Secrets never in git; `.dev.vars` stays gitignored.

## File Structure

| File | Responsibility |
|---|---|
| `migrations/0003_authorizations.sql` | authorization rows |
| `src/scan-store.ts`, `src/test-support/memory-store.ts`, `src/test-support/scan-store-contract.ts` | authorization persistence + contract |
| `src/limits.ts` | invasion caps/timeouts |
| `src/invasion-targets.ts` (+ `.test.ts`) | hygiene rules, one module for preview and server check |
| `src/normalizers/explore.ts` | unchanged except shared helpers if needed |
| `src/normalizers/invasion.ts` (+ fixtures in `src/test-support/fixtures.ts`) | nuclei-jsonl, zap-json → Finding[] |
| `src/normalizers/index.ts` | add `normalizeFindings(key, …)` dispatcher |
| `src/sarif.ts` (+ `.test.ts`) | SARIF 2.1.0 writer from stored findings |
| `src/handlers/callback.ts` | route artifacts by registry outputType; findings counts |
| `src/handlers/scans.ts` | invasion create + preview; launch timeout derivation |
| `src/executors/github.ts` | dispatch inputs gain `targets` |
| `src/server/api.ts` | routes: invasion-preview, findings, sarif |
| `tools.json` | nuclei `-l {{urls}} -jsonl`; new zap-full entry |
| `scripts/run-scan.mjs` (rename of run-explore.mjs) | PHASE, `{{urls}}`, `{{severity}}`, zap exit codes, chmod, targets guard |
| `.github/workflows/aegis-explore.yml` | new script name; per-phase cache key |
| `.github/workflows/aegis-invasion.yml` | new mirror workflow, `targets` input, 70 min |
| `src/pages/index.astro`, `src/styles/aegis.css` | findings table + confirm panel |
| `src/assets.workers.test.ts` | UI wiring pins |

---

### Task 1: Authorization persistence

**Files:** Create `migrations/0003_authorizations.sql`; Modify `src/scan-store.ts`, `src/test-support/memory-store.ts`, `src/test-support/scan-store-contract.ts`.

**Interfaces:** Produces `ScanStore.createAuthorization(rec: ScanAuthorization): Promise<void>` (throws on duplicate scan_id) and `ScanStore.getAuthorization(scanId: string): Promise<ScanAuthorization | null>`; `export interface ScanAuthorization { scanId: string; email: string; targets: string[]; tools: string[]; active: boolean; confirmedAt: string }` in `src/types.ts`. D1 stores targets/tools as JSON strings and active as 0/1; both stores return parsed arrays/boolean.

- [ ] **Step 1: failing contract tests** — append to `describeScanStoreContract`:

```ts
it("authorization roundtrips and is unique per scan", async () => {
  const store = make();
  await store.create(rec("auth-scan"));
  const a = { scanId: "auth-scan", email: "op@example.com", targets: ["https://x.example/"], tools: ["nuclei"], active: false, confirmedAt: "2026-11-23T00:00:00.000Z" };
  await store.createAuthorization(a);
  expect(await store.getAuthorization("auth-scan")).toEqual(a);
  await expect(store.createAuthorization(a)).rejects.toThrow();
  expect(await store.getAuthorization("missing")).toBeNull();
});
```

- [ ] **Step 2:** run `npx vitest run --project node src/scan-store.test.ts -t authorization` → FAIL (method missing).
- [ ] **Step 3:** migration DDL exactly as spec Section 1; implement both stores (D1 `INSERT` plain so PK conflict throws; memory `if (auths.has(rec.scanId)) throw new Error("authorization exists")`).
- [ ] **Step 4:** `npx vitest run` → both projects green (workers applies real migrations).
- [ ] **Step 5:** commit `feat: store per-scan invasion authorizations`.

### Task 2: Limits and hygiene rules

**Files:** Modify `src/limits.ts`; Create `src/invasion-targets.ts`, `src/invasion-targets.test.ts`.

**Interfaces:** Produces `selectInvasionTargets(assets: Asset[]): { targets: { url: string; type: Asset["type"]; statusCode: number | null }[]; excluded: { url: string; reason: ExclusionReason }[] }` and `export type ExclusionReason = "not-url" | "malformed" | "not-live" | "cdn-cgi" | "static-asset" | "duplicate"`.

- [ ] **Step 1: failing tests** — one test per rule plus ordering/dedupe:

```ts
const A = (id: string, type: Asset["type"], value: string, metadata: string | null): Asset =>
  ({ id, scanId: "s", type, value, metadata, createdAt: "2026-11-23T00:00:00.000Z" });
it("keeps live urls and endpoints in asset order", () => {
  const sel = selectInvasionTargets([
    A("1", "url", "https://x.example/", '{"status_code":200}'),
    A("2", "endpoint", "https://x.example/login", '{"status_code":302}'),
  ]);
  expect(sel.targets.map((t) => t.url)).toEqual(["https://x.example/", "https://x.example/login"]);
  expect(sel.excluded).toEqual([]);
});
it("excludes non-url types, malformed values, dead hosts, cdn-cgi, static assets and duplicates", () => {
  const sel = selectInvasionTargets([
    A("a", "subdomain", "x.example", null),
    A("b", "url", "https://x.example/a.js:1:240", '{"status_code":200}'),
    A("c", "url", "https://x.example/dead", '{"status_code":404}'),
    A("d", "url", "https://x.example/cdn-cgi/scripts/x.js", '{"status_code":200}'),
    A("e", "url", "https://x.example/app.css", '{"status_code":200}'),
    A("f", "url", "https://X.example/", '{"status_code":200}'),
    A("g", "url", "https://x.example", '{"status_code":200}'),
  ]);
  expect(sel.targets.map((t) => t.url)).toEqual(["https://x.example/"]);
  expect(sel.excluded.map((e) => e.reason)).toEqual(["not-url", "malformed", "not-live", "cdn-cgi", "static-asset", "duplicate", "duplicate"]);
});
```

(Note: `f` and `g` both fold to the kept key of the first entry only if a live root was kept earlier; in this fixture the first kept root is absent, so `f` is kept and `g` duplicate — adjust the fixture so expectations match the rule order: put a live `https://x.example/` first, then `f`/`g` become duplicates. Write the fixture that way.)

- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement rules in spec order; key = `url.protocol.toLowerCase() + "//" + url.hostname.toLowerCase() + (path === "/" ? "/" : path.replace(/\/+$/, "")) + url.search`; status parsed from metadata JSON, missing → not-live; malformed also for whitespace/`<` and `/:\d+(:\d+)?$/` suffix.
- [ ] **Step 4:** add limits constants; `npx vitest run` green.
- [ ] **Step 5:** commit `feat: invasion target hygiene rules and caps`.

### Task 3: Invasion normalizers and registry

**Files:** Create `src/normalizers/invasion.ts`; Modify `src/normalizers/index.ts`, `src/test-support/fixtures.ts`, `src/normalizers.test.ts`, `tools.json`, `src/registry.test.ts`.

**Interfaces:** Produces `normalizeNucleiJsonl(data: unknown, scanId: string, now: string): Promise<Finding[]>`, `normalizeZapJson(...)` same shape, and `normalizeFindings(key: string, data: unknown, scanId: string, now: string): Promise<Finding[]>` in index.ts (unknown key → `[]`). Finding ids via `sha256Hex(`${scanId}|${tool}|${ruleId}|${url}|${parameter ?? ""}`)`.

- [ ] **Step 1: failing tests** with fixtures: nuclei record `{ "template-id": "CVE-2024-1234", "info": { "name": "X", "severity": "high", "description": "d", "remediation": "r", "classification": { "cwe-id": ["CWE-79"] } }, "matched-at": "https://x.example/a", "extracted-results": ["proof"] }`; zap `{ site: [ { alerts: [ { pluginid: "10021", alert: "Missing CSP", name: "Missing CSP", riskdesc: "Medium", confidence: "Medium", desc: "d", solution: "s", cweid: "693", param: "", evidence: "", uri: "https://x.example/" } ] } ] }`. Assert severity/confidence/cwe/url/evidence/remediation mapping, id stability (same input twice → same id), unknown severity → info and unknown confidence → medium.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement; severity maps: nuclei lowercase set; zap `Informational→info, Low→low, Medium→medium, High→high, Critical→critical`; confidence zap `Confirmed/High→high, Medium→medium, Low→low, False Positive→low`; cwe parse int from `CWE-n` / numeric string, null when absent.
- [ ] **Step 4:** tools.json nuclei args `["-l","{{urls}}","-severity","{{severity}}","-jsonl","-o","/out/nuclei.jsonl","-no-color"]`, outputFormat `jsonl`, normalizer `nuclei-jsonl`; add zap-full entry per spec; registry test asserts both and that invasion tools emit findings.
- [ ] **Step 5:** `npx vitest run` green; commit `feat: nuclei and ZAP findings normalizers`.

### Task 4: Callback findings routing

**Files:** Modify `src/handlers/callback.ts`, `src/server/api.test.ts`, and add a workers-level ingestion test in `src/scan-store.workers.test.ts` or a new `src/handlers/callback.workers.test.ts`.

**Interfaces:** Consumes `normalizeFindings`, `store.insertFindings`. Completion event detail becomes `${allAssets.length} assets; ${allFindings.length} findings${failNote}${truncNote}`; response `{ ok, assets, findings }`.

- [ ] **Step 1: failing node test** in the callback describe: artifacts `[{tool:"nuclei",format:"jsonl",data:[fixture]}]` with accepting DO and capturing R2 → expect status completed, `store.listFindings(ID)` length 1, event detail contains "1 findings".
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** route by `getTool(artifact.tool)?.outputType === "findings"`; raw R2 storage unchanged; insert findings after assets; keep terminal guard and token consume exactly as today.
- [ ] **Step 4:** workers test: real D1/R2, seed running scan, POST callback with nuclei+zap artifacts through `SELF.fetch` with a minted token (reuse the pattern in `src/scan-coordinator.workers.test.ts` for `/start` then consume) → findings persisted, dedupe on repeat id.
- [ ] **Step 5:** `npx vitest run` green; commit `feat: ingest findings through the executor callback`.

### Task 5: SARIF writer

**Files:** Create `src/sarif.ts`, `src/sarif.test.ts`.

**Interfaces:** Produces `buildSarif(scan: ScanRecord, findings: Finding[]): SarifLog` where runs are grouped by `finding.tool` in first-seen order; each result `{ ruleId, level, message: { text: title }, locations: [{ physicalLocation: { artifactLocation: { uri: url } } }], properties: { severity, confidence, cwe, evidence, remediation, parameter, rawRef } }`; level map critical/high→error, medium→warning, low/info→note; log `{ $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs }`.

- [ ] **Step 1: failing test** — two findings same tool + one other tool → 2 runs; level map asserted; empty findings → `runs: []`.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** green. **Step 5:** commit `feat: SARIF 2.1.0 export writer`.

### Task 6: Invasion create, preview, routes, timeouts

**Files:** Modify `src/handlers/scans.ts`, `src/executors/github.ts`, `src/server/api.ts`, `src/server/api.test.ts`.

**Interfaces:** `launch(env, store, id, targetUrl, phase, tools, depth, extra?: { targets?: string[]; severity?: string; timeoutSeconds?: number })`; dispatch inputs gain `targets` (JSON string) when present; `handleInvasionPreview(env, store, id)`; `handleFindings(env, store, id)`; `handleSarif(env, store, id)`. Routes: `app.get(\`/scans/${SCAN_ID}/invasion-preview\`, …)`, `…/findings`, `…/sarif` behind `requireOperator`.

- [ ] **Step 1: failing tests** — create invasion: unconfirmed → 400; targets not subset → 400; 9 targets → 400; unknown tool → 400; valid chained create → 201 with authorization row (`getAuthorization`) and `dispatches[0].body.inputs.targets` equal to selection; standalone create with `target` → targets `[validated]`; preview on explore scan returns kept/excluded per hygiene; findings route sorts critical first; sarif route content-type `application/sarif+json`.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement validation order from spec Section 1; chained `rec.target = parent.target`; `timeoutSeconds = tools.includes("zap-full") ? INVASION_TIMEOUT_ACTIVE : INVASION_TIMEOUT_BASELINE` passed to launch (DO `/start` body and callback token expiry use it); events `created` + `authorized`; authorization conflict → 409.
- [ ] **Step 4:** `npx vitest run` green. **Step 5:** commit `feat: invasion create with authorization, preview and findings routes`.

### Task 7: Executor and workflows

**Files:** Rename `scripts/run-explore.mjs` → `scripts/run-scan.mjs` (git mv); Modify it; Modify `.github/workflows/aegis-explore.yml`; Create `.github/workflows/aegis-invasion.yml`.

**Interfaces:** env `PHASE` (`explore` default), `TARGETS_JSON` (JSON array); templates `{{urls}}` → `/out/urls.txt`, `{{severity}}` → options.severity or `critical,high,medium`.

- [ ] **Step 1:** write the invasion workflow as a copy of explore with: `targets` required input; `timeout-minutes: 70`; cache key `aegis-tool-images-invasion-${{ hashFiles('tools.json') }}`; run step `node scripts/run-scan.mjs` with env `PHASE: invasion`, `TARGETS_JSON: ${{ inputs.targets }}`; explore workflow run step renamed and cache key `aegis-tool-images-explore-…`.
- [ ] **Step 2:** executor changes: filter registry by `PHASE`; write `/out/urls.txt` from TARGETS_JSON before tools when phase invasion; re-validate each URL (http/https, non-private host regex copied from `src/handlers/scans.ts` PRIVATE_HOST) and drop invalid ones with a console warning; `resolve()` gains the two templates; for `zap-*` tools accept exit 0/1/2 when the output file exists; `fs.chmodSync(OUT, 0o777)` before running any zap tool; keep budget/truncation/raw behaviour.
- [ ] **Step 3:** verify mechanically: `node --check scripts/run-scan.mjs`; `gh workflow view aegis-invasion.yml` after push is NOT available pre-push — instead validate YAML by `node -e "require('yaml')…"` unavailable; use `npx --yes js-yaml .github/workflows/aegis-invasion.yml > /dev/null` to parse both workflows.
- [ ] **Step 4:** commit `feat: phase-driven executor and invasion workflow`.

### Task 8: Dashboard findings and confirm panel

**Files:** Modify `src/pages/index.astro`, `src/styles/aegis.css`, `src/assets.workers.test.ts`.

**Interfaces:** consumes `/api/scans/:id/findings`, `/invasion-preview`, POST `/api/scans` invasion payload. New ids: `findings-section`, `finding-severity`, `finding-tool`, `finding-search`, `findings-table`, `invasion-confirm`, `invasion-targets`, `invasion-tools`, `invasion-severity`, `invasion-active-note`, `invasion-confirm-btn`, `invasion-cancel-btn`.

- [ ] **Step 1: failing wiring test** — signed-out HTML unchanged pins still pass; add test asserting the built JS contains `findings-section` and `invasion-confirm` (ids survive minification).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** markup: findings section inside `#detail-section` (hidden unless invasion scan has been loaded); confirm panel as a sibling section hidden by default; `#invade-btn` enabled for completed explore scans. Client: `showDetail` fetches findings when `scan.phase === "invasion"` and renders severity-sorted rows with chip/tool/title/url; row click toggles an expanded `<tr>` with description/evidence/remediation/CWE/rawRef (textContent only); filters + `matchesQuery` search over title/url/tool/evidence; confirm flow: fetch preview, build checkbox list (kept checked, excluded listed with reason, unchecked), tool checkboxes (nuclei+zap-baseline checked, zap-full unchecked), severity select; zap-full tick shows `invasion-active-note` text "Active attack scanning: zap-full sends attack payloads at every selected URL. Expect up to 60 minutes."; Confirm posts `{phase:"invasion", parentScanId, targets, tools, options:{severity}, authorization:{confirmed:true}}` then `showDetail(newId)`; Cancel hides panel.
- [ ] **Step 4:** CSS via tokens only; expanded row and chip styles reuse existing severity colours (`--danger`, `--warn`, `--ok`, `--muted`); mobile collapse.
- [ ] **Step 5:** `npm run build && npx tsc --noEmit && npx vitest run` green; commit `feat: findings table and invasion confirm panel`.

### Task 9: Integration, deploy, test (lead, not delegated)

- [ ] Full gate; local `wrangler dev` with seeded synthetic explore parent + invasion scan + findings; browser-verify findings table, filters, search, expand, confirm panel against the local API; headless screenshots.
- [ ] Push branch, PR, Codex review, address findings, merge (merge commit), watch deploy run whose headSha equals the merge commit.
- [ ] Dispatch `aegis-invasion.yml` via `gh workflow run` with a synthetic scan_id and intentionally invalid callback token: tools must run and log success (ingestion covered locally); read the log for nuclei/ZAP execution and urls file.
- [ ] Prod smoke: `/health/ready`, dashboard HTML carries new ids; report the one owner-click acceptance left (real invasion from the UI).

## Self-review notes

- Spec coverage: Sections 1–5 each map to Tasks 1–8; rollout to Task 9. Open items excluded by design.
- Type consistency: `ScanAuthorization`, `selectInvasionTargets`, `normalizeFindings`, `buildSarif`, launch `extra` bag used identically across tasks.
- The Task 2 fixture comment resolves the dedupe expectation ambiguity: keep a live root first so `f`/`g` are duplicates.