# Aegis Phase 2 — Invasion design

Status: approved by owner 2026-11-23 (Sections 1–5), autonomous implement/deploy/test authorized.
Repo: `cloudkid-labs/aegis`, clone at `D:\SourceCode\GitHub\cloudkid-labs\aegis`. Branch `Codex/phase2-invasion`.

## Goal

Run active scans (nuclei + ZAP) against a target or against the live URLs discovered by a prior
Explore scan, ingest typed findings, and present them severity-ranked with evidence, remediation
and a SARIF export. Explore behaviour stays untouched.

## Locked decisions

1. Per-scan authorization confirmation, stored and audited. No new scan status: the confirmed
   payload rides on `POST /api/scans`; nothing sits queued awaiting a click.
2. nuclei and ZAP together; ZAP baseline default, `zap-full` opt-in (registry `default: false`).
3. Chained Invasion pre-selects the parent Explore's live URL assets; selection editable.
4. Asset hygiene applies at Invasion selection only; Explore storage untouched.
5. Findings UI: severity-sorted table with expandable rows, severity + tool filters and search.
6. Execution architecture A: separate `aegis-invasion.yml` mirroring the explore workflow;
   phase-driven executor; typed findings ingestion into the existing `findings` table.
7. (Shipped separately, PR #12) alterx permutations are resolved through dnsx before storage;
   old candidate rows are hidden at read time. Phase 2 builds on that registry shape.

## Section 1 — Authorization and chaining

Migration `0003_authorizations.sql`:

```sql
CREATE TABLE IF NOT EXISTS scan_authorizations (
  scan_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  targets TEXT NOT NULL,       -- JSON array of absolute http(s) URLs
  tools TEXT NOT NULL,         -- JSON array of tool names
  active INTEGER NOT NULL,     -- 1 iff zap-full selected
  confirmed_at TEXT NOT NULL
);
```

`ScanStore` gains `createAuthorization(rec)` (PK conflict → throw) and `getAuthorization(scanId)`,
contract-tested in both vitest projects.

Create invasion request body:
`{ phase: "invasion", parentScanId?, target?, targets: string[], tools: string[], options?: { severity? }, authorization: { confirmed: true } }`.

Server validation order: rate limit → operator → phase → parent (exists, phase explore, status
completed) or standalone `validateTarget(target)` → allowed set (hygiene over parent assets, or
`[targetUrl]`) → `targets` non-empty, subset of allowed, `length <= INVASION_MAX_URLS` → `tools`
non-empty subset of registry invasion names → `authorization.confirmed === true` else 400 →
severity option, when present, a comma list of known severities else 400.
Then: scan row (queued) + authorization row + events `created`, `authorized` (email, target count,
active flag) + `launch()` with the derived timeout. Authorization insert conflict → 409.

`GET /api/scans/:id/invasion-preview` (id = an explore scan, operator-gated) returns
`{ targets: [{url, type, statusCode}], excluded: [{url, reason}], maxUrls }`.

Hygiene module `src/invasion-targets.ts`, `selectInvasionTargets(assets)`, rules in this order:
1. type not `url`/`endpoint` → `not-url`
2. value not a parseable http(s) URL, contains whitespace/`<`, or ends in a `:line[:col]`
   source-position suffix → `malformed`
3. metadata `status_code` missing or outside 200–399 → `not-live`
4. pathname starts `/cdn-cgi/` → `cdn-cgi`
5. pathname ends `.js .mjs .css .png .jpg .jpeg .gif .svg .webp .ico .woff .woff2 .ttf .map` → `static-asset`
6. duplicate of an earlier kept key (lowercase scheme+host, pathname with trailing slash folded
   except root, plus search) → `duplicate`
Kept order = asset order (created_at, id). Rules pinned by unit tests; the same module feeds the
preview and the server-side subset check.

## Section 2 — Execution

- `.github/workflows/aegis-invasion.yml`: mirror of `aegis-explore.yml` plus a required `targets`
  input (JSON array). Inputs arrive via step env only. Job `timeout-minutes: 70`.
- Cache keys per phase: `aegis-tool-images-explore-<hashFiles('tools.json')>` and
  `aegis-tool-images-invasion-<hashFiles('tools.json')>`; explore's key changes once.
- `scripts/run-explore.mjs` → `scripts/run-scan.mjs`, reads `PHASE`; explore workflow's run step
  points at the new name with identical behaviour. New templates `{{urls}}` (executor-written
  `/out/urls.txt`, one selected URL per line, from the `targets` input) and `{{severity}}`
  (options.severity, default `critical,high,medium`).
- nuclei probes every selected URL (`-l {{urls}}`); ZAP gets one entry point `-t {{target}}`
  because baseline/full spider the site from there. A chained scan's `target` is the parent
  Explore's target, so `{{target}}`/`{{host}}` resolve to the same site the URLs belong to.
- Registry: nuclei args `["-l","{{urls}}","-severity","{{severity}}","-jsonl","-o","/out/nuclei.jsonl","-no-color"]`,
  outputFormat `jsonl`, normalizer `nuclei-jsonl`. New `zap-full` entry: image
  `ghcr.io/zaproxy/zaproxy:stable`, args `["zap-full-scan.py","-t","{{target}}","-J","zap-full.json"]`,
  outputFormat json, outputType findings, normalizer `zap-json`, `default: false`.
- ZAP report paths are relative (`zap.json`, `zap-full.json`) and zap-* containers mount the out
  dir at `/zap/wrk`, not `/out`: both docker scripts exit 3 unless `/zap/wrk` exists when `-J` is
  set (the image never creates it), and resolve the report against `base_dir='/zap/wrk/'`
  (zap-baseline.py/zap-full-scan.py, verified against zaproxy/zaproxy main; fixed in 54d17c8).
- ZAP exit codes 0/1/2 mean pass/warn/fail-with-findings: for `zap-*` tools any of them is success
  if the output file exists; other codes are failures. The executor chmods the shared out dir
  0777 before zap containers run (image runs as non-root).
- Timeouts in `src/limits.ts` only: `INVASION_MAX_URLS = 8`, `INVASION_TIMEOUT_BASELINE = 1800`,
  `INVASION_TIMEOUT_ACTIVE = 3600`. `launch()` derives the DO alarm and callback-token life from
  the selection (active iff zap-full); explore keeps 900.
- Executor re-checks every URL in `targets` for http(s) scheme and non-private host before any
  container runs (defence in depth; the Worker already validated).

## Section 3 — Ingestion and findings

- Callback routes each artifact by the registry's `outputType` (`getTool(artifact.tool)`), never
  by executor-supplied labels: `assets` → existing path, `findings` → normalizers →
  `insertFindings` (idempotent on id).
- `nuclei-jsonl`: template-id → rule/title, `info.severity` → severity, `info.classification.cwe-id`
  → cwe, `matched-at` → url, `extracted-results`/`matcher-name` → evidence, `info.remediation` →
  remediation, `info.description` → description.
- `zap-json`: `site[].alerts[]`; `riskdesc` → severity (Informational→info), `confidence` →
  confidence, `cweid` → cwe, `evidence`, `solution` → remediation, `uri` → url, `param` → parameter,
  `alert`/`name` → title, `desc` → description, `pluginid` → rule id.
- Unknown severity clamps to `info`, unknown confidence to `medium` (pinned).
- Finding id = SHA-256(scanId, tool, ruleId, url, parameter). `rawRef` = the R2 raw artifact key.
- Existing 4 MiB budget, `truncated` reporting and terminal-state guard unchanged. Completion
  event becomes `N assets; M findings` plus the existing failure/truncation notes.

## Section 4 — API and UI

- `GET /api/scans/:id/findings` → `{ findings }` sorted severity rank (critical, high, medium, low,
  info) then createdAt; operator-gated.
- `GET /api/scans/:id/sarif` → SARIF 2.1.0 generated server-side by `src/sarif.ts` from stored
  findings, one run per tool; level map critical/high→error, medium→warning, low/info→note;
  `application/sarif+json`, attachment disposition; operator-gated.
- Scan detail: Findings section for invasion scans — severity chip, tool, title, URL; severity and
  tool selects plus a search box reusing `matchesQuery`; expanding a row shows description,
  evidence, remediation, CWE and the raw-ref key. No innerHTML anywhere.
- "Invoke invasion" on an explore detail opens a confirm panel: editable pre-selected URLs from
  the preview (checkboxes), tool toggles (nuclei, zap-baseline, zap-full), severity select, an
  explicit active-attack warning and runtime class when zap-full is ticked, Confirm and Cancel.
  Confirm posts the Section 1 payload and opens the new scan's detail.

## Section 5 — Testing and rollout

- Contracts both projects: authorization uniqueness, findings dedupe/ordering, preview subset
  enforcement, SARIF shape (version, runs per tool, level map).
- Workers project: end-to-end callback ingestion of findings into real D1/R2; rejection of
  unconfirmed, over-cap and non-subset targets; timeout derivation.
- Node: normalizer fixtures (nuclei jsonl, zap json), hygiene rules, SARIF writer, registry
  resolveWith/validation unchanged.
- UI wiring pins in `src/assets.workers.test.ts` for the findings section and confirm panel ids.
- Local browser pass over seeded synthetic explore parent + invasion scan + findings.
- Workflow mechanics verified by a real `workflow_dispatch` of `aegis-invasion.yml` (callback
  token intentionally invalid: tools must run and log success; ingestion is covered locally).
- Prod acceptance after deploy: health/readiness green; one real baseline-only invasion against an
  owner-operated target, then zap-full opt-in at owner discretion.

## Open items (not in Phase 2)

- Per-account history scoping (today all authorized operators share one history) — owner decision.
- Agent37 executor, registry UI, retention policy, scan diff — Phase 3.