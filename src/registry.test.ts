import { describe, expect, it } from "vitest";
import { getTool, loadRegistry, parseRegistry, toolsForPhase } from "./registry";

const EXPLORE = ["subfinder", "dnsx", "alterx", "httpx", "katana", "naabu"];
const INVASION = ["nuclei", "zap-baseline"];

function base(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "test-tool",
    phase: "explore",
    executor: "github",
    image: "example/tool:1.0.0",
    args: ["-u", "{{target}}"],
    outputFormat: "json",
    outputType: "assets",
    normalizer: "test-json",
    ...overrides,
  };
}

describe("loadRegistry", () => {
  it("loads the shipped registry", () => {
    const tools = loadRegistry();
    expect(tools.map((t) => t.name)).toEqual([...EXPLORE, ...INVASION]);
  });

  it("every shipped entry is fully populated", () => {
    for (const tool of loadRegistry()) {
      expect(tool.name).toMatch(/^[a-z0-9][a-z0-9-]*$/);
      expect(["explore", "invasion"]).toContain(tool.phase);
      expect(["github", "selfhosted"]).toContain(tool.executor);
      expect(tool.image).toMatch(/:/);
      expect(tool.args.length).toBeGreaterThan(0);
      expect(["json", "jsonl", "text", "sarif"]).toContain(tool.outputFormat);
      expect(["assets", "findings"]).toContain(tool.outputType);
      expect(tool.normalizer.length).toBeGreaterThan(0);
    }
  });

  it("returns a fresh array each call so callers cannot corrupt the registry", () => {
    const first = loadRegistry();
    first.pop();
    expect(loadRegistry().length).toBe(EXPLORE.length + INVASION.length);
  });
});

describe("toolsForPhase", () => {
  it("splits explore from invasion in registry order", () => {
    expect(toolsForPhase("explore").map((t) => t.name)).toEqual(EXPLORE);
    expect(toolsForPhase("invasion").map((t) => t.name)).toEqual(INVASION);
  });

  it("explore emits assets and invasion emits findings", () => {
    for (const tool of toolsForPhase("explore")) expect(tool.outputType).toBe("assets");
    for (const tool of toolsForPhase("invasion")) expect(tool.outputType).toBe("findings");
  });
});

describe("getTool", () => {
  it("finds a known tool", () => {
    const nuclei = getTool("nuclei");
    expect(nuclei).not.toBeNull();
    expect(nuclei!.image).toBe("projectdiscovery/nuclei:v3.11.1");
    expect(nuclei!.phase).toBe("invasion");
  });

  it("returns null for unknown and hostile names", () => {
    expect(getTool("does-not-exist")).toBeNull();
    expect(getTool("__proto__")).toBeNull();
    expect(getTool("")).toBeNull();
  });
});

describe("parseRegistry", () => {
  it("accepts a well-formed entry", () => {
    const tools = parseRegistry({ tools: [base()] });
    expect(tools).toHaveLength(1);
    expect(tools[0]!.name).toBe("test-tool");
  });

  it("rejects a missing required field", () => {
    expect(() => parseRegistry({ tools: [base({ image: undefined })] })).toThrow(/image/);
    expect(() => parseRegistry({ tools: [base({ normalizer: "" })] })).toThrow(/normalizer/);
    expect(() => parseRegistry({ tools: [base({ args: [] })] })).toThrow(/args/);
  });

  it("rejects an unknown phase, executor or output format", () => {
    expect(() => parseRegistry({ tools: [base({ phase: "recon" })] })).toThrow(/phase/);
    expect(() => parseRegistry({ tools: [base({ executor: "agent37" })] })).toThrow(/executor/);
    expect(() => parseRegistry({ tools: [base({ outputFormat: "yaml" })] })).toThrow(/outputFormat/);
  });

  it("rejects duplicate names and non-slug names", () => {
    expect(() => parseRegistry({ tools: [base(), base()] })).toThrow(/duplicate/);
    expect(() => parseRegistry({ tools: [base({ name: "Test Tool" })] })).toThrow(/slug/);
  });

  it("rejects output types that contradict the phase", () => {
    expect(() => parseRegistry({ tools: [base({ outputType: "findings" })] })).toThrow(/explore/);
    expect(() => parseRegistry({ tools: [base({ phase: "invasion", outputType: "assets" })] })).toThrow(/invasion/);
  });

  it("rejects a non-array root or empty tool list", () => {
    expect(() => parseRegistry(null)).toThrow(/object/);
    expect(() => parseRegistry({ tools: "nope" })).toThrow(/array/);
    expect(() => parseRegistry({ tools: [] })).toThrow(/empty/);
  });
});

describe("opt-in default flag", () => {
  it("preserves default:false through parseRegistry", () => {
    const [tool] = parseRegistry({ tools: [base({ default: false })] });
    expect(tool!.default).toBe(false);
  });

  it("omits default when not set (defaults to enabled)", () => {
    const [tool] = parseRegistry({ tools: [base()] });
    expect(tool!.default).toBeUndefined();
  });

  it("shipped naabu and alterx are opt-in; core explore tools are not", () => {
    expect(getTool("naabu")!.default).toBe(false);
    expect(getTool("alterx")!.default).toBe(false);
    for (const name of ["subfinder", "dnsx", "httpx", "katana"]) {
      expect(getTool(name)!.default).toBeUndefined();
    }
  });

  it("default selection excludes opt-in tools", () => {
    const selected = toolsForPhase("explore").filter((t) => t.default !== false).map((t) => t.name);
    expect(selected).toEqual(["subfinder", "dnsx", "httpx", "katana"]);
    expect(selected).not.toContain("naabu");
    expect(selected).not.toContain("alterx");
  });
});