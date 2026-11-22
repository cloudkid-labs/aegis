/**
 * Bindings and secrets, hand-written instead of generated so `tsc --noEmit`
 * works without running `wrangler types` first. `vitest.config.mts` injects
 * the secret values for the workers project; production reads them from
 * wrangler secrets (plain secrets, not Secrets Store, so `.dev.vars` feeds
 * `wrangler dev` too).
 */
export interface Env {
  AEGIS_DB: D1Database;
  ARTIFACTS: R2Bucket;
  ASSETS: Fetcher;
  SCAN_COORDINATOR: DurableObjectNamespace;
  SCAN_LIMITER: RateLimit;
  AEGIS_API_KEY: string;
  EXECUTOR_TOKEN: string;
  CALLBACK_SECRET: string;
  GITHUB_TOKEN: string;
  GITHUB_OWNER: string;
  GITHUB_REPO: string;
  GITHUB_WORKFLOW: string;
  AEGIS_ORIGIN: string;
}