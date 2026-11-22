# Aegis

OSS reconnaissance and penetration testing platform on Cloudflare Workers.

**Zero custom attack rules** — orchestrates [ProjectDiscovery](https://docs.projectdiscovery.io/opensource) tools and OWASP ZAP via GitHub Actions, normalizes output, and presents results in a dashboard.

## Phases

| Phase | Status | Description |
|-------|--------|-------------|
| **Explore** | Phase 1 (MVP) | Passive recon: subfinder, dnsx, httpx, katana (+ optional naabu, alterx) |
| **Invasion** | Phase 2 | Active attacks: nuclei, ZAP baseline. SARIF findings. |
| **Reporting** | Phase 3 | Scan diff, reports, tool registry UI, retention, Agent37 executor |

## Architecture

- **Worker + Assets** — API (`/api/*`) and dashboard SPA at `aegis.cloudkid.link`
- **Durable Object** — per-scan timeout alarm + single-use callback tokens
- **D1** — scans, assets, findings, events
- **R2** — raw tool output, SARIF reports
- **GitHub Actions** — runs tool containers (unlimited minutes, public repo)
- **Tool Registry** — `tools.json` config. Add a tool = add an entry.

## Quick Start

```bash
yarn install
cp .dev.vars.example .dev.vars   # fill in secrets
yarn dev                         # local wrangler dev
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
npx wrangler d1 migrations apply AEGIS_DB --remote
yarn deploy
```

## API

All under `/api/*`, `Authorization: Bearer <AEGIS_API_KEY>`:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Create scan `{target, phase, options}` |
| GET | `/api/scans` | List scans (history) |
| GET | `/api/scans/:id` | Scan detail + events |
| GET | `/api/scans/:id/assets` | Discovered assets |
| POST | `/api/scans/:id/cancel` | Cancel running scan |

Executor callback (own token): `POST /api/executors/callback/:scanId`

## Tool Registry

`tools.json` defines each tool: name, phase, Docker image, args template, output format, normalizer key.

Templates: `{{target}}` (full URL), `{{host}}` (hostname), `{{depth}}` (crawl depth), `{{severity}}` (nuclei).

Tools with `"default": false` (naabu, alterx) only run when explicitly selected in the dashboard.

## Tests

Two vitest projects:
- **node** — fast fakes (memory store, mock fetch)
- **workers** — workerd + real D1/R2/DO bindings

The scan-store contract runs in both. A fake that drifts from D1 fails the workers project.

## License

Proprietary — CK Labs.