import raw from "../tools.json";
import type { OutputFormat, OutputType, Phase, ToolEntry } from "./types";

/**
 * tools.json is the source of truth for what runs; this module only validates
 * it. Adding a tool is a config edit (plus a normalizer if the output format
 * is new), never a code change here.
 *
 * Validation is hand-written rather than schema-library-driven to keep the
 * dependency surface empty and the error messages specific.
 */

const PHASES: readonly Phase[] = ["explore", "invasion"];
const EXECUTORS = ["github", "selfhosted"] as const;
const OUTPUT_FORMATS: readonly OutputFormat[] = ["json", "jsonl", "text", "sarif"];
const OUTPUT_TYPES: readonly OutputType[] = ["assets", "findings"];

// A slug, not a ToolName membership check: the union in types.ts documents
// the Phase 1 tools, while a new tools.json entry should work without a type
// edit. Anything else (empty, uppercase, spaces, `__proto__`) is rejected.
const TOOL_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/;

function fail(where: string, message: string): never {
  throw new Error(`tools.json: ${where}: ${message}`);
}

function nonEmptyString(value: unknown, where: string, field: string): string {
  if (typeof value !== "string" || value.trim() === "") fail(where, `${field} must be a non-empty string`);
  return value;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], where: string, field: string): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    fail(where, `${field} must be one of ${allowed.join(", ")}`);
  }
  return value as T;
}

/** Validate and normalise a parsed tools.json document. Throws on the first defect. */
export function parseRegistry(input: unknown): ToolEntry[] {
  if (typeof input !== "object" || input === null) fail("root", "must be an object");
  const tools = (input as { tools?: unknown }).tools;
  if (!Array.isArray(tools)) fail("root", "tools must be an array");
  if (tools.length === 0) fail("root", "tools must not be empty");

  const seen = new Set<string>();
  return tools.map((candidate, index): ToolEntry => {
    if (typeof candidate !== "object" || candidate === null) fail(`tools[${index}]`, "must be an object");
    const entry = candidate as Record<string, unknown>;

    const name = nonEmptyString(entry.name, `tools[${index}]`, "name");
    if (!TOOL_NAME.test(name)) fail(`tools[${index}]`, `name "${name}" is not a slug`);
    if (seen.has(name)) fail(`tools[${index}]`, `duplicate name "${name}"`);
    seen.add(name);

    const phase = oneOf(entry.phase, PHASES, `tools[${index}] (${name})`, "phase");
    const executor = oneOf(entry.executor, EXECUTORS, `tools[${index}] (${name})`, "executor");
    const image = nonEmptyString(entry.image, `tools[${index}] (${name})`, "image");

    if (!Array.isArray(entry.args) || entry.args.length === 0) {
      fail(`tools[${index}] (${name})`, "args must be a non-empty array");
    }
    const args = entry.args.map((arg, argIndex) => {
      if (typeof arg !== "string") fail(`tools[${index}] (${name})`, `args[${argIndex}] must be a string`);
      return arg;
    });

    const outputFormat = oneOf(entry.outputFormat, OUTPUT_FORMATS, `tools[${index}] (${name})`, "outputFormat");
    const outputType = oneOf(entry.outputType, OUTPUT_TYPES, `tools[${index}] (${name})`, "outputType");
    const normalizer = nonEmptyString(entry.normalizer, `tools[${index}] (${name})`, "normalizer");

    if (phase === "explore" && outputType !== "assets") {
      fail(`tools[${index}] (${name})`, "explore tools must emit assets");
    }
    if (phase === "invasion" && outputType !== "findings") {
      fail(`tools[${index}] (${name})`, "invasion tools must emit findings");
    }

    return {
      name: name as ToolEntry["name"],
      phase,
      executor,
      image,
      args,
      outputFormat,
      outputType,
      normalizer,
      ...(entry.default === false ? { default: false } : {}),
    };
  });
}

// Validated once at module load: a malformed registry fails the Worker's
// first import (and therefore the deploy) rather than a scan at runtime.
const REGISTRY: readonly ToolEntry[] = Object.freeze(parseRegistry(raw));

/** Every validated entry, in tools.json order. */
export function loadRegistry(): ToolEntry[] {
  return [...REGISTRY];
}

/** Entries for one phase, in tools.json order. */
export function toolsForPhase(phase: Phase): ToolEntry[] {
  return REGISTRY.filter((tool) => tool.phase === phase);
}

/** Look up by exact name; unknown names (including `__proto__`) return null. */
export function getTool(name: string): ToolEntry | null {
  return REGISTRY.find((tool) => tool.name === name) ?? null;
}