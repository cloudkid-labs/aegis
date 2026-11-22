import { constantTimeEqual } from "./auth";

const encoder = new TextEncoder();

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return [...new Uint8Array(signature)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Short-lived, scan-bound token handed to the executor and returned on the
 * callback. Format: `v1.<expiresAtMs>.<hex hmac of "scanId.expiresAtMs">`.
 * Possession allows exactly one callback for that scan (the DO records use).
 */
export async function signCallbackToken(secret: string, scanId: string, expiresAtMs: number): Promise<string> {
  return `v1.${expiresAtMs}.${await hmacHex(secret, `${scanId}.${expiresAtMs}`)}`;
}

export async function verifyCallbackToken(
  secret: string,
  scanId: string,
  token: string,
  nowMs: number,
): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return false;
  if (!/^\d+$/.test(parts[1]!)) return false;
  const expiresAt = Number(parts[1]);
  if (!Number.isSafeInteger(expiresAt) || expiresAt < nowMs) return false;
  const expected = await hmacHex(secret, `${scanId}.${expiresAt}`);
  return constantTimeEqual(expected, parts[2]!);
}