// Registry-driven Explore executor, run by .github/workflows/aegis-explore.yml.
// tools.json (checked out beside this script) is the source of truth: the
// selected tools' configured images and args are what actually run, so adding
// or retuning a tool is a config edit, never a workflow edit.
//
// All user-controlled values arrive via env (TARGET_URL, TOOLS_JSON,
// OPTIONS_JSON, CB_URL, CB_TOKEN), never as shell-interpolated source.
import { spawnSync } from "node:child_process";
import fs from "node:fs";

const OUT = "/tmp/aegis-out";
// In-container path of the shared hosts list (the mount maps OUT -> /out).
const HOSTS_ARG = "/out/hosts.txt";
const target = process.env.TARGET_URL ?? "";
const selected = JSON.parse(process.env.TOOLS_JSON ?? "[]");
const options = JSON.parse(process.env.OPTIONS_JSON ?? "{}");
const callbackUrl = process.env.CB_URL ?? "";
const callbackToken = process.env.CB_TOKEN ?? "";

// Derive the host from URL components, not string splitting: a target with
// credentials (https://user:pass@host/) or an IPv6 literal must not yield
// "user" or "[2606" as the {{host}} substituted into host-based tools.
let host = "";
try { host = new URL(target).hostname; } catch { host = ""; }
const depth = Number.isInteger(Number(options.depth)) && Number(options.depth) > 0 ? String(options.depth) : "2";

const registry = JSON.parse(fs.readFileSync(new URL("../tools.json", import.meta.url), "utf8"));
const tools = registry.tools.filter((t) => t.phase === "explore" && selected.includes(t.name));

fs.mkdirSync(OUT, { recursive: true });
const failures = [];
const artifacts = [];

// dnsx (resolution) and alterx (permutations) read a hosts LIST, not -d: dnsx
// v1.2.2 rejects -d without -w, and alterx has no -d input flag. Seed the list
// with the target host and grow it with subfinder's discoveries as they land.
const hosts = new Set(host ? [host] : []);
function writeHosts() {
  fs.writeFileSync(`${OUT}/hosts.txt`, [...hosts].join("\n") + "\n");
}
writeHosts();

function resolve(arg) {
  return arg
    .replaceAll("{{target}}", target)
    .replaceAll("{{host}}", host)
    .replaceAll("{{hosts}}", HOSTS_ARG)
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

// handleCallback rejects bodies over 5 MiB (readJsonBody). Stay under it so a
// large recon never 413s into a timeout with the single-use token already
// consumed: fit what we can, truncate the rest, and report what was cut.
const BUDGET = 4 * 1024 * 1024;
// The raw wordlist rides along as evidence but must not eat the callback
// budget: cap it and report the cut like any other truncation.
const RAW_CAP = 200_000;
let used = 0;
const truncated = [];
function addArtifact(name, format, data, raw) {
  const rawSent = typeof raw === "string" ? raw.slice(0, RAW_CAP) : undefined;
  if (typeof raw === "string" && raw.length > RAW_CAP) truncated.push(name);
  const size = JSON.stringify(data).length + (rawSent ? rawSent.length : 0);
  if (used + size <= BUDGET) {
    used += size;
    artifacts.push({ tool: name, format, data, ...(rawSent !== undefined ? { raw: rawSent } : {}) });
    return;
  }
  const remaining = BUDGET - used;
  let fit = null;
  if (Array.isArray(data)) {
    const kept = [];
    let acc = 2;
    for (const entry of data) {
      const s = JSON.stringify(entry).length + 1;
      if (acc + s > remaining) break;
      kept.push(entry); acc += s;
    }
    if (kept.length > 0) fit = kept;
  } else if (typeof data === "string" && remaining > 0) {
    fit = data.slice(0, remaining);
  }
  truncated.push(name);
  if (fit !== null) { used = BUDGET; artifacts.push({ tool: name, format, data: fit }); }
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
  if (tool.name === "subfinder" && Array.isArray(data)) {
    for (const e of data) if (e && typeof e.host === "string") hosts.add(e.host);
    writeHosts();
  }
  // resolveWith: the tool's output is a wordlist, not a discovery. Run the
  // resolver over it and store only what actually resolved; the wordlist
  // itself rides along as raw evidence for R2.
  if (tool.resolveWith) {
    const resolver = registry.tools.find((t) => t.name === tool.resolveWith);
    const containerIn = file.replace(OUT, "/out");
    const resolvedOut = `/out/${tool.name}-resolved.json`;
    const rargv = resolver.args.map((a) => a.replaceAll("{{hosts}}", containerIn)).map(resolve);
    for (let i = 0; i < rargv.length - 1; i++) {
      if (["-o", "--output"].includes(rargv[i])) rargv[i + 1] = resolvedOut;
    }
    console.log(`=== Resolving ${tool.name} output with ${resolver.name} (${resolver.image}) ===`);
    const rres = spawnSync("docker", ["run", "--rm", "-v", `${OUT}:/out`, resolver.image, ...rargv], { stdio: "inherit" });
    const rfile = resolvedOut.replace(/^\/out\//, `${OUT}/`);
    if (rres.status !== 0 || !fs.existsSync(rfile)) { failures.push(tool.name); continue; }
    const resolved = fs.readFileSync(rfile, "utf8").split("\n").filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    addArtifact(tool.name, "json", resolved, raw);
    continue;
  }
  addArtifact(tool.name, tool.outputFormat, data);
}

// Every selected tool failed and nothing was produced: report failure, not a
// misleading "completed with zero discoveries".
const body = artifacts.length === 0 && failures.length > 0
  ? JSON.stringify({ error: `tools failed: ${failures.join(", ")}` })
  : JSON.stringify({ artifacts, failures, truncated });

const res = await fetch(callbackUrl, {
  method: "POST",
  headers: { authorization: `Bearer ${callbackToken}`, "content-type": "application/json" },
  body,
});
console.log("callback", res.status);
if (!res.ok) process.exit(1);