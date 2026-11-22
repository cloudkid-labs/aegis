// Registry-driven Explore executor, run by .github/workflows/aegis-explore.yml.
// tools.json (checked out beside this script) is the source of truth: the
// selected tools' configured images and args are what actually run, so adding
// or retuning a tool is a config edit, never a workflow edit.
//
// All user-controlled values arrive via env (TARGET_URL, TOOLS_JSON,
// OPTIONS_JSON, CB_URL, CB_TOKEN), never as shell-interpolated source.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const OUT = "/tmp/aegis-out";
const target = process.env.TARGET_URL ?? "";
const selected = JSON.parse(process.env.TOOLS_JSON ?? "[]");
const options = JSON.parse(process.env.OPTIONS_JSON ?? "{}");
const callbackUrl = process.env.CB_URL ?? "";
const callbackToken = process.env.CB_TOKEN ?? "";

const host = target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
const depth = Number.isInteger(Number(options.depth)) && Number(options.depth) > 0 ? String(options.depth) : "2";

const registry = JSON.parse(fs.readFileSync(new URL("../tools.json", import.meta.url), "utf8"));
const tools = registry.tools.filter((t) => t.phase === "explore" && selected.includes(t.name));

fs.mkdirSync(OUT, { recursive: true });
const failures = [];
const artifacts = [];

function resolve(arg) {
  return arg
    .replaceAll("{{target}}", target)
    .replaceAll("{{host}}", host)
    .replaceAll("{{depth}}", depth);
}

// The output path is whatever the registry args pass to a write flag; mapping
// /out/ back to the host mount lets the post step find each tool's result.
function outputPath(argv) {
  for (let i = 0; i < argv.length - 1; i++) {
    if (["-o", "--output", "-sarif-export", "-export"].includes(argv[i])) {
      return argv[i + 1].replace(/^\/out\//, `${OUT}/`);
    }
  }
  return null;
}

for (const tool of tools) {
  const argv = tool.args.map(resolve);
  console.log(`=== Running ${tool.name} (${tool.image}) ===`);
  const res = spawnSync("docker", ["run", "--rm", "-v", `${OUT}:/out`, tool.image, ...argv], { stdio: "inherit" });
  if (res.status !== 0) failures.push(tool.name);

  const file = outputPath(argv);
  if (!file || !fs.existsSync(file)) continue;
  const raw = fs.readFileSync(file, "utf8");
  let data;
  if (tool.outputFormat === "text") data = raw;
  else if (tool.outputFormat === "sarif") data = JSON.parse(raw);
  else data = raw.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  artifacts.push({ tool: tool.name, format: tool.outputFormat, data });
}

// Every selected tool failed and nothing was produced: report failure, not a
// misleading "completed with zero discoveries".
const body = artifacts.length === 0 && failures.length > 0
  ? JSON.stringify({ error: `tools failed: ${failures.join(", ")}` })
  : JSON.stringify({ artifacts, failures });

const res = await fetch(callbackUrl, {
  method: "POST",
  headers: { authorization: `Bearer ${callbackToken}`, "content-type": "application/json" },
  body,
});
console.log("callback", res.status);
if (!res.ok) process.exit(1);