import { describe, expect, it, vi } from "vitest";
import { dispatchGitHubWorkflow } from "./github";
import type { ExecutorStartRequest } from "./types";

const ENV = { GITHUB_TOKEN: "gh-token", GITHUB_OWNER: "rainiersvn", GITHUB_REPO: "aegis", GITHUB_WORKFLOW: "aegis-explore.yml" };

const REQ: ExecutorStartRequest = {
  scanId: "s1", target: "https://example.com", phase: "explore",
  tools: [{ name: "subfinder", phase: "explore", executor: "github", image: "x", args: [], outputFormat: "json", outputType: "assets", normalizer: "subfinder-json" }],
  callbackUrl: "https://aegis.test/api/executors/callback/s1",
  callbackToken: "v1.123.abc", timeoutSeconds: 900, options: { depth: 2 },
};

describe("dispatchGitHubWorkflow", () => {
  it("posts workflow_dispatch with expected inputs", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    const result = await dispatchGitHubWorkflow(ENV, REQ, fetchImpl as unknown as typeof fetch);
    expect(result.externalUrl).toContain("aegis-explore.yml");
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.github.com/repos/rainiersvn/aegis/actions/workflows/aegis-explore.yml/dispatches");
    const body = JSON.parse(init.body as string);
    expect(body.ref).toBe("main");
    expect(body.inputs.scan_id).toBe("s1");
    expect(body.inputs.target_url).toBe("https://example.com");
    expect(body.inputs.phase).toBe("explore");
    expect(JSON.parse(body.inputs.tools)).toEqual(["subfinder"]);
    expect(body.inputs.callback_url).toBe(REQ.callbackUrl);
    expect(body.inputs.callback_token).toBe("v1.123.abc");
    expect(body.inputs.timeout_seconds).toBe("900");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer gh-token");
  });

  it("throws on non-204", async () => {
    const fetchImpl = vi.fn(async () => new Response("no", { status: 404 }));
    await expect(dispatchGitHubWorkflow(ENV, REQ, fetchImpl as unknown as typeof fetch)).rejects.toThrow(/404/);
  });
});