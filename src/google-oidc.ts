import { createRemoteJWKSet, jwtVerify } from "jose";
import { constantTimeEqual } from "./auth";
import type { Env } from "./env";
import { json } from "./http";
import { base64url, clearedSessionCookie, currentSession, endSession, randomToken, readCookie, startSession } from "./session";
import type { SessionStore } from "./session-store";

/**
 * "Sign in with Google", done by the Worker itself (OpenID Connect
 * authorization-code flow with PKCE). Aegis is a single-operator console, so
 * there are no account rows: a verified Google email is admitted only if it
 * appears in AEGIS_ALLOWED_EMAILS (deny-by-default — an empty list admits no
 * one). The session is keyed by the verified email, which is what the
 * allowlist authorizes.
 *
 *   GET /auth/google/start    -> store state/nonce/PKCE verifier in a cookie,
 *                                redirect to Google.
 *   GET /auth/google/callback -> check state, exchange the code, verify the ID
 *                                token, check the allowlist, set the session.
 *   GET /auth/logout          -> delete the session row, redirect home.
 */

const GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const GOOGLE_CERTS = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

export const OAUTH_COOKIE = "__Host-aegis_oauth";
const OAUTH_COOKIE_MAX_AGE_S = 600;
const CALLBACK_PATH = "/auth/google/callback";
const HOME = "/";

export class GoogleAuthError extends Error {
  override name = "GoogleAuthError";
}

let googleJwks: ReturnType<typeof createRemoteJWKSet> | null = null;
function jwks(): ReturnType<typeof createRemoteJWKSet> {
  googleJwks ??= createRemoteJWKSet(new URL(GOOGLE_CERTS));
  return googleJwks;
}

/**
 * Where to send the user after sign-in. The dashboard is the only page, so
 * anything but "/" falls back to it — `next` can never bounce a freshly
 * signed-in user to another site.
 */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return HOME;
  if (/[\u0000-\u001f\u007f]/.test(next)) return HOME;
  let pathname: string;
  try {
    pathname = new URL(next, "https://aegis.cloudkid.link").pathname;
  } catch {
    return HOME;
  }
  return pathname === "/" ? next : HOME;
}

/** Comma-separated emails, lowercased and trimmed. Empty input = empty set. */
export function parseAllowlist(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? "")
      .split(",")
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function isAllowedEmail(email: string, allowlist: Set<string>): boolean {
  return allowlist.has(email.toLowerCase());
}

/** Configuration, not the Host header, decides where Google sends the user. */
function origin(env: Env): string {
  return (env.AEGIS_ORIGIN ?? "").trim().replace(/\/$/, "");
}

type OAuthState = { state: string; nonce: string; verifier: string; next: string };

function oauthCookie(value: string, maxAge: number): string {
  return `${OAUTH_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

function readOAuthState(request: Request): OAuthState | null {
  const raw = readCookie(request, OAUTH_COOKIE);
  if (!raw) return null;
  try {
    const json = atob(raw.replace(/-/g, "+").replace(/_/g, "/"));
    const parsed = JSON.parse(json) as Partial<OAuthState>;
    if (
      typeof parsed.state === "string" &&
      typeof parsed.nonce === "string" &&
      typeof parsed.verifier === "string" &&
      typeof parsed.next === "string"
    ) {
      return parsed as OAuthState;
    }
  } catch {
    // Junk cookie: treated exactly like a missing one.
  }
  return null;
}

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ location, "cache-control": "no-store" });
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(null, { status: 302, headers });
}

/** GET /auth/google/start */
export async function handleGoogleStart(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405, headers: { allow: "GET" } });
  }
  if (!env.GOOGLE_CLIENT_ID) {
    return new Response("Sign-in is not configured yet. Please try again later.", { status: 503 });
  }

  const flow: OAuthState = {
    state: randomToken(16),
    nonce: randomToken(16),
    verifier: randomToken(32),
    next: safeNext(new URL(request.url).searchParams.get("next")),
  };

  const challenge = base64url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(flow.verifier))),
  );
  const authorize = new URL(GOOGLE_AUTHORIZE);
  authorize.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: origin(env) + CALLBACK_PATH,
    response_type: "code",
    scope: "openid email profile",
    state: flow.state,
    nonce: flow.nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  }).toString();

  const cookieValue = base64url(new TextEncoder().encode(JSON.stringify(flow)));
  return redirect(authorize.toString(), [oauthCookie(cookieValue, OAUTH_COOKIE_MAX_AGE_S)]);
}

/**
 * Verify a Google ID token and return the email it vouches for.
 * @throws GoogleAuthError for any token this sign-in must not accept
 */
export async function verifyGoogleIdToken(
  idToken: string,
  clientId: string,
  expectedNonce: string,
): Promise<{ sub: string; email: string }> {
  let payload;
  try {
    ({ payload } = await jwtVerify(idToken, jwks(), { issuer: GOOGLE_ISSUERS, audience: clientId }));
  } catch (err) {
    throw new GoogleAuthError("ID token rejected: " + (err instanceof Error ? err.message : String(err)));
  }
  if (typeof payload.nonce !== "string" || !constantTimeEqual(payload.nonce, expectedNonce)) {
    throw new GoogleAuthError("ID token nonce does not match this sign-in");
  }
  if (typeof payload.sub !== "string" || !payload.sub) throw new GoogleAuthError("ID token has no subject");
  if (typeof payload.email !== "string" || !payload.email) throw new GoogleAuthError("ID token has no email");
  if (payload.email_verified !== true) throw new GoogleAuthError("Google has not verified this email address");
  return { sub: payload.sub, email: payload.email };
}

async function exchangeCode(env: Env, code: string, verifier: string): Promise<string> {
  const clientSecret = env.GOOGLE_CLIENT_SECRET;
  if (!clientSecret) throw new GoogleAuthError("GOOGLE_CLIENT_SECRET is not configured");

  const res = await fetch(GOOGLE_TOKEN, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: clientSecret,
      redirect_uri: origin(env) + CALLBACK_PATH,
      grant_type: "authorization_code",
      code_verifier: verifier,
    }).toString(),
  });
  if (!res.ok) {
    throw new GoogleAuthError(`token exchange failed (${res.status}): ${(await res.text()).slice(0, 300)}`);
  }
  const body = (await res.json()) as { id_token?: unknown };
  if (typeof body.id_token !== "string") throw new GoogleAuthError("token response has no id_token");
  return body.id_token;
}

/** GET /auth/google/callback */
export async function handleGoogleCallback(
  request: Request,
  env: Env,
  store: SessionStore,
  now = Date.now(),
): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405, headers: { allow: "GET" } });
  }

  const clearFlow = oauthCookie("", 0);
  const failed = (reason: string) => {
    console.warn("google-oidc: sign-in failed: " + reason);
    return redirect(`${HOME}?signin=failed`, [clearFlow]);
  };

  const params = new URL(request.url).searchParams;
  const flow = readOAuthState(request);
  if (!flow) return failed("no sign-in in progress (flow cookie missing or expired)");

  if (params.get("error") === "access_denied") {
    return redirect(`${HOME}?signin=cancelled`, [clearFlow]);
  }

  const state = params.get("state");
  if (!state || !constantTimeEqual(state, flow.state)) return failed("state mismatch");
  const code = params.get("code");
  if (!code) return failed(`no code (error=${params.get("error") ?? "none"})`);

  let email: string;
  try {
    const idToken = await exchangeCode(env, code, flow.verifier);
    ({ email } = await verifyGoogleIdToken(idToken, env.GOOGLE_CLIENT_ID, flow.nonce));
  } catch (err) {
    return failed(err instanceof Error ? err.message : String(err));
  }

  // Deny-by-default: a verified Google account still needs an allowlist entry.
  if (!isAllowedEmail(email, parseAllowlist(env.AEGIS_ALLOWED_EMAILS))) {
    return failed("email is not on the operator allowlist");
  }

  const sessionCookie = await startSession(store, email, now);
  return redirect(safeNext(flow.next), [clearFlow, sessionCookie]);
}

/**
 * GET /auth/logout — a same-site navigation only. A cross-site <img> or link
 * must not be able to sign the operator out (Sec-Fetch-Site: cross-site).
 */
export async function handleLogout(request: Request, store: SessionStore): Promise<Response> {
  const site = request.headers.get("sec-fetch-site");
  if (site === "cross-site") {
    return new Response("Cross-site logout refused", { status: 403 });
  }
  await endSession(request, store);
  return redirect(HOME, [clearedSessionCookie()]);
}

/** GET /auth/me — public sign-in state for the dashboard shell. */
export async function handleMe(request: Request, store: SessionStore): Promise<Response> {
  const session = await currentSession(request, store);
  return json(session ? { authenticated: true, email: session.email } : { authenticated: false });
}