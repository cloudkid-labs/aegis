// Registry-driven scan executor for both phases, run by
// .github/workflows/aegis-explore.yml and aegis-invasion.yml. tools.json
// (checked out beside this script) is the source of truth: the selected
// tools' configured images and args are what actually run, so adding or
// retuning a tool is a config edit, never a workflow edit.
//
// PHASE (explore default) picks which registry entries may run. Invasion adds
// {{urls}} (the authorized selection, written to /out/urls.txt from
// TARGETS_JSON) and {{severity}}; {{target}}/{{host}} still resolve from
// TARGET_URL, which for a chained invasion is the parent explore target.
//
// All user-controlled values arrive via env (TARGET_URL, TARGETS_JSON,
// TOOLS_JSON, OPTIONS_JSON, CB_URL, CB_TOKEN), never as shell-interpolated
// source.
import { spawnSync } from "node:child_process";
import fs from "node:fs";

const OUT = "/tmp/aegis-out";
// In-container paths of the shared lists (non-ZAP tools mount OUT at /out).
const HOSTS_ARG = "/out/hosts.txt";
const URLS_ARG = "/out/urls.txt";
const phase = process.env.PHASE || "explore";
const target = process.env.TARGET_URL ?? "";
const targetList = JSON.parse(process.env.TARGETS_JSON ?? "[]");
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
// Nuclei's severity filter. The create handler already rejects unknown values;
// the design's default applies when the option is absent.
const severity = typeof options.severity === "string" && options.severity.trim() !== ""
  ? options.severity.trim()
  : "critical,high,medium";

// Mirrors validateTarget in src/handlers/scans.ts. Defence in depth: the
// Worker validated the selection, but a tampered dispatch payload must never
// aim a scanner at a private address. No import path exists into Worker
// source from this script, so the rule is copied and has to be kept in step
// by hand.
const PRIVATE_HOST = /^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.)/i;
function validUrl(raw) {
  let url;
  try { url = new URL(raw); } catch { return false; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  const name = url.hostname.toLowerCase();
  return !(PRIVATE_HOST.test(name) || name.endsWith(".internal") || name.endsWith(".local") || name === "[::1]");
}

const registry = JSON.parse(fs.readFileSync(new URL("../tools.json", import.meta.url), "utf8"));
const tools = registry.tools.filter((t) => t.phase === phase && selected.includes(t.name));

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
    .replaceAll("{{urls}}", URLS_ARG)
    .replaceAll("{{severity}}", severity)
    .replaceAll("{{depth}}", depth);
}

// The output path is whatever the registry args pass to a write flag, mapped
// back from the tool's container mount so the post step finds each tool's result.
// ZAP reports through -J, so it counts as a write flag like the rest.
//
// Load-bearing constraint: ZAP's docker scripts (zap-baseline.py and
// zap-full-scan.py in zaproxy/zaproxy docker/) set base_dir to /zap/wrk/ and,
// when any file-based option such as -J is supplied, warn and exit 3 unless
// that directory exists. Dockerfile-stable never creates it, so it only exists
// when mounted. Both scripts then write the report via
// os.path.join(base_dir, report_json) — and the baseline automation-framework
// path passes base_dir plus the -J value to the report job as reportDir and
// reportFile — so the -J value must be a name relative to /zap/wrk, and the
// zap-* mount below is what puts the report on the host.
function outputPath(argv, mount) {
  for (let i = 0; i < argv.length - 1; i++) {
    if (["-o", "--output", "-J", "-sarif-export", "-export"].includes(argv[i])) {
      const value = argv[i + 1];
      // A relative value (ZAP's "zap.json") is resolved by the tool against its
      // own mount; an absolute value names a path inside that mount.
      return value.startsWith("/") ? value.replace(`${mount}/`, `${OUT}/`) : `${OUT}/${value}`;
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
  } else if (data && typeof data === "object" && Array.isArray(data.site)) {
    // ZAP report: drop whole alerts from the tail until the rest fits. An
    // over-budget report must keep its shape and as many findings as the
    // budget allows — discarding it whole would complete the scan with zero
    // findings and no failure, hiding the loss.
    const clone = JSON.parse(JSON.stringify(data));
    const sites = Array.isArray(clone.site) ? clone.site : [];
    while (JSON.stringify(clone).length > remaining) {
      const site = sites[sites.length - 1];
      const alerts = site && Array.isArray(site.alerts) ? site.alerts : [];
      if (alerts.length > 0) alerts.pop();
      else if (sites.length > 0) sites.pop();
      else break;
    }
    if (JSON.stringify(clone).length <= remaining) fit = clone;
  }
  truncated.push(name);
  if (fit !== null) { used = BUDGET; artifacts.push({ tool: name, format, data: fit }); }
}

async function postCallback(body) {
  const res = await fetch(callbackUrl, {
    method: "POST",
    headers: { authorization: `Bearer ${callbackToken}`, "content-type": "application/json" },
    body,
  });
  console.log("callback", res.status);
  return res;
}

// Invasion scans nuclei across the authorized selection, so the list must be
// on disk before any container starts. Re-check every URL; a value that fails
// is dropped with a warning rather than handed to a scanner.
if (phase === "invasion") {
  const provided = Array.isArray(targetList) ? targetList : [];
  const urls = provided.filter((raw) => {
    const ok = typeof raw === "string" && validUrl(raw);
    if (!ok) console.warn(`dropping invalid invasion target: ${String(raw)}`);
    return ok;
  });
  if (urls.length === 0) {
    // Nothing left to scan. Report through the callback error path — the same
    // shape used when every tool fails — instead of running zero tools and
    // completing a scan that did nothing.
    const reason = `no valid invasion targets (${provided.length} supplied)`;
    console.error(reason);
    await postCallback(JSON.stringify({ error: reason }));
    process.exit(1);
  }
  fs.writeFileSync(`${OUT}/urls.txt`, urls.join("\n") + "\n");
}

for (const tool of tools) {
  const argv = tool.args.map(resolve);
  // ZAP's scan scripts need /zap/wrk mounted (see outputPath) and resolve a
  // relative -J name against it; every other tool keeps the /out convention.
  const isZap = tool.name.startsWith("zap-");
  const mount = isZap ? "/zap/wrk" : "/out";
  // The ZAP image runs as its non-root `zap` user, which must be able to write
  // the host-mounted output directory or the report never lands.
  if (isZap) fs.chmodSync(OUT, 0o777);
  console.log(`=== Running ${tool.name} (${tool.image}) ===`);
  const res = spawnSync("docker", ["run", "--rm", "-v", `${OUT}:${mount}`, tool.image, ...argv], { stdio: "inherit" });

  const file = outputPath(argv, mount);
  const fileExists = Boolean(file && fs.existsSync(file));
  // ZAP exit 0/1/2 mean pass/warn/fail-with-findings, not tool failure; the
  // report file is the real success signal. Any other code is a failure.
  const ok = isZap ? [0, 1, 2].includes(res.status) && fileExists : res.status === 0;
  if (!ok) failures.push(tool.name);
  if (!fileExists) continue;
  const raw = fs.readFileSync(file, "utf8");
  let data;
  if (tool.outputFormat === "text") data = raw;
  else if (tool.outputFormat === "sarif") data = JSON.parse(raw);
  // ZAP's -J report is one JSON document; the explore JSONL tools write one
  // object per line. Per-line parsing would hand zap-json an empty array.
  else if (isZap) data = JSON.parse(raw);
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

const res = await postCallback(body);
if (!res.ok) process.exit(1);