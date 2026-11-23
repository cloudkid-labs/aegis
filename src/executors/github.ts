import type { Env } from "../env";
import type { ExecutorStartRequest, ExecutorStartResult } from "./types";

type GitHubEnv = Pick<Env, "GITHUB_TOKEN" | "GITHUB_OWNER" | "GITHUB_REPO" | "GITHUB_WORKFLOW">;

export async function dispatchGitHubWorkflow(
  env: GitHubEnv,
  req: ExecutorStartRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<ExecutorStartResult> {
  const url = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/actions/workflows/${env.GITHUB_WORKFLOW}/dispatches`;
  const res = await fetchImpl(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.GITHUB_TOKEN}`,
      accept: "application/vnd.github+json",
      "content-type": "application/json",
      "user-agent": "aegis-worker",
    },
    body: JSON.stringify({
      ref: "main",
      inputs: {
        scan_id: req.scanId,
        target_url: req.target,
        phase: req.phase,
        tools: JSON.stringify(req.tools.map((t) => t.name)),
        callback_url: req.callbackUrl,
        callback_token: req.callbackToken,
        timeout_seconds: String(req.timeoutSeconds),
        options: JSON.stringify(req.options),
      },
    }),
  });
  if (res.status !== 204 && res.status !== 201) {
    throw new Error(`github dispatch failed: ${res.status}`);
  }
  return {
    externalUrl: `https://github.com/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/actions/workflows/${env.GITHUB_WORKFLOW}`,
  };
}