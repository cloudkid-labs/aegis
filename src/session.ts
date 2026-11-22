import { sha256Hex } from "./auth";
import type { Session, SessionStore } from "./session-store";

/**
 * The dashboard's own login session, set after Google sign-in.
 *
 * The cookie carries 32 random bytes and nothing else: no identity, no expiry,
 * nothing to decode. The server keeps only its SHA-256 (./session-store), so
 * signing out is a row delete that takes effect on the next request.
 *
 * `__Host-` pins the cookie to this exact origin: Secure, Path=/, no Domain,
 * so no other cloudkid.link subdomain can set or read it. SameSite=Lax keeps
 * it off cross-site subrequests; the state-changing API additionally rides on
 * the JSON content-type check (./http), which a cross-site form cannot set.
 */
export const SESSION_COOKIE = "__Host-aegis_session";

/** Fixed, not sliding: a stolen token stops working within this window. */
export const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** `bytes` of CSPRNG output, base64url-encoded. */
export function randomToken(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function sessionCookie(token: string): string {
  return `${SESSION_COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`;
}

export function clearedSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}

/** Create a session for this email and return the Set-Cookie value for it. */
export async function startSession(store: SessionStore, email: string, now: number): Promise<string> {
  const token = randomToken();
  await store.create(await sha256Hex(token), email, now, now + SESSION_TTL_MS);
  return sessionCookie(token);
}

/** The signed-in session, or null. Never throws for a missing or junk cookie. */
export async function currentSession(
  request: Request,
  store: SessionStore,
  now = Date.now(),
): Promise<Session | null> {
  const token = readCookie(request, SESSION_COOKIE);
  // 43 chars is 32 bytes of base64url. Anything else was never issued here,
  // so it is refused without a database round trip.
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  return store.get(await sha256Hex(token), now);
}

/** Delete this request's session, if it has one. Idempotent. */
export async function endSession(request: Request, store: SessionStore): Promise<void> {
  const token = readCookie(request, SESSION_COOKIE);
  if (token) await store.delete(await sha256Hex(token));
}