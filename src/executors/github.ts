import type { Env } from "../env";
import type { ExecutorStartRequest, ExecutorStartResult } from "./types";

type GitHubEnv = Pick<
  Env,
  "GITHUB_TOKEN" | "GITHUB_OWNER" | "GITHUB_REPO" | "GITHUB_WORKFLOW" | "GITHUB_WORKFLOW_INVASION"
>;

/** The phases are separate workflow files (design Section 2): explore's
 *  workflow declares no `targets` input and would reject an invasion dispatch
 *  with 422, and its tool set is the recon one. */
function workflowForPhase(env: GitHubEnv, phase: string): string {
  return phase === "invasion" ? env.GITHUB_WORKFLOW_INVASION : env.GITHUB_WORKFLOW;
}

export async function dispatchGitHubWorkflow(
  env: GitHubEnv,
  req: ExecutorStartRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<ExecutorStartResult> {
  const workflow = workflowForPhase(env, req.phase);
  const url = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/actions/workflows/${workflow}/dispatches`;
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
        // Explore's workflow declares no `targets` input; sending one there
        // would at best be ignored and at worst reject the dispatch.
        ...(req.targets ? { targets: JSON.stringify(req.targets) } : {}),
      },
    }),
  });
  if (res.status !== 204 && res.status !== 201) {
    throw new Error(`github dispatch failed: ${res.status}`);
  }
  return {
    externalUrl: `https://github.com/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/actions/workflows/${workflow}`,
  };
}