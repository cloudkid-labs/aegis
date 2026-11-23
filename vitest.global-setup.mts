// The workers project boots the real wrangler.jsonc, whose ASSETS binding
// points at the Astro build in ./dist (astro.config.mjs). Building here when
// the output is absent keeps `npx vitest run` green on a fresh clone; CI
// builds explicitly before running tests.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

export async function setup(): Promise<void> {
  if (existsSync("dist/index.html")) return;
  execFileSync(process.execPath, ["node_modules/astro/bin/astro.mjs", "build"], { stdio: "inherit" });
}