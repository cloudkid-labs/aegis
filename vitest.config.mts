import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";

/**
 * Two projects, deliberately — same split as cloudkid-link's live-meetings
 * worker.
 *
 * "node" is the bulk: plain Node with hand-rolled fakes, fast.
 *
 * "workers" runs inside workerd via the real wrangler.jsonc, with the real
 * migrations applied to a local D1. The scan-store contract runs in BOTH
 * projects, so a fake that drifts from D1 is a red test rather than a new
 * de-facto spec.
 */
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "node",
          include: ["src/**/*.test.ts"],
          exclude: ["src/**/*.workers.test.ts"],
        },
      },
      {
        plugins: [
          cloudflareTest(async () => ({
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: {
              bindings: {
                TEST_MIGRATIONS: await readD1Migrations("./migrations"),
                AEGIS_API_KEY: "test-api-key",
                EXECUTOR_TOKEN: "test-executor-token",
                CALLBACK_SECRET: "test-callback-secret",
                GITHUB_TOKEN: "test-github-token",
                AEGIS_ORIGIN: "https://aegis.test",
              },
            },
          })),
        ],
        test: {
          name: "workers",
          include: ["src/**/*.workers.test.ts"],
          // The ASSETS binding in wrangler.jsonc resolves to the Astro build
          // in ./dist; build it once when a fresh clone has no output yet.
          globalSetup: ["./vitest.global-setup.mts"],
        },
      },
    ],
  },
});