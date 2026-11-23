# Aegis

OSS reconnaissance and penetration testing platform on Cloudflare Workers.

**Zero custom attack rules** — orchestrates [ProjectDiscovery](https://docs.projectdiscovery.io/opensource) tools and OWASP ZAP via GitHub Actions, normalizes output, and presents results in a dashboard.

## Phases

| Phase | Status | Description |
|-------|--------|-------------|
| **Explore** | Phase 1 (MVP) | Passive recon: subfinder, dnsx, httpx, katana (+ optional naabu, alterx) |
| **Invasion** | Phase 2 (MVP) | Active attacks: nuclei, ZAP baseline + opt-in full scan. Findings table, SARIF export, chained from Explore with per-scan authorization. |
| **Reporting** | Phase 3 | Scan diff, reports, tool registry UI, retention, Agent37 executor |

## Architecture

- **Astro + Hono Worker** — static dashboard built by Astro to `./dist` and served through the `ASSETS` binding; `/api/*`, `/auth/*` and `/health` are answered by Hono in `src/index.ts`
- **Google sign-in** — OIDC code flow + PKCE; a verified email must be on `AEGIS_ALLOWED_EMAILS` (deny-by-default). Sessions are SHA-256 hashes in D1, cookie `__Host-aegis_session`.
- **Durable Object** — per-scan timeout alarm + single-use callback tokens
- **D1** — scans, assets, findings, events, sessions
- **R2** — raw tool output, SARIF reports
- **GitHub Actions** — runs tool containers (unlimited minutes, public repo)
- **Tool Registry** — `tools.json` config. Add a tool = add an entry; the executor (`scripts/run-scan.mjs`) reads it, so no workflow edit is needed.

## Quick Start

```bash
yarn install
cp .dev.vars.example .dev.vars   # fill in secrets
yarn dev                         # Astro dev server (dashboard shell only)
yarn build && npx wrangler dev   # full stack: Hono API + built dashboard
yarn test                        # vitest (node + workers projects)
npx tsc --noEmit                 # typecheck
```

## Deploy (owner)

```bash
npx wrangler d1 create aegis              # copy database_id into wrangler.jsonc
npx wrangler r2 bucket create aegis-artifacts
npx wrangler secret put AEGIS_API_KEY
npx wrangler secret put EXECUTOR_TOKEN
npx wrangler secret put CALLBACK_SECRET
npx wrangler secret put GITHUB_TOKEN      # PAT: repo + actions write
npx wrangler secret put GOOGLE_CLIENT_SECRET
# In wrangler.jsonc vars: GOOGLE_CLIENT_ID (OAuth client id) and
# AEGIS_ALLOWED_EMAILS (comma-separated operator emails). Empty allowlist = locked.
# Google OAuth client: authorized redirect URI https://aegis.cloudkid.link/auth/google/callback
npx wrangler d1 migrations apply AEGIS_DB --remote
yarn deploy
```

## API

Operator routes under `/api/*` accept EITHER a dashboard login session (cookie)
OR `Authorization: Bearer <AEGIS_API_KEY>` for headless automation:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Create scan — explore: `{target, phase, options}`; invasion: `{phase, parentScanId, targets, tools, options, authorization}` |
| GET | `/api/scans` | List scans (history) |
| GET | `/api/scans/:id` | Scan detail + events |
| GET | `/api/scans/:id/assets` | Discovered assets |
| GET | `/api/scans/:id/findings` | Findings, severity-sorted |
| GET | `/api/scans/:id/invasion-preview` | Invasion target selection (kept + excluded with reasons) |
| GET | `/api/scans/:id/sarif` | SARIF 2.1.0 export of the scan's findings |
| POST | `/api/scans/:id/cancel` | Cancel running scan |
| POST | `/api/scans/:id/retry` | Re-run a failed/cancelled scan as a new linked scan |

Executor callback (own token): `POST /api/executors/callback/:scanId`

Sign-in (no auth required): `GET /auth/google/start`, `GET /auth/google/callback`,
`GET /auth/logout` (same-site only), `GET /auth/me` (public sign-in state).

## Tool Registry

`tools.json` defines each tool: name, phase, Docker image, args template, output format, normalizer key.

Templates: `{{target}}` (full URL), `{{host}}` (hostname), `{{hosts}}` (host list file), `{{urls}}` (invasion URL list), `{{depth}}` (crawl depth), `{{severity}}` (nuclei).

Tools with `"default": false` (naabu, alterx, zap-full) only run when explicitly selected in the dashboard.

## Tests

Two vitest projects:
- **node** — fast fakes (memory store, mock fetch)
- **workers** — workerd + real D1/R2/DO bindings, and the real Astro build in `./dist` through the `ASSETS` binding (built on demand when absent)

The scan-store contract runs in both. A fake that drifts from D1 fails the workers project.

## License

Proprietary — CK Labs.