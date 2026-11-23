const encoder = new TextEncoder();

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Compare fixed-length hex digests, not raw secrets: equal-length inputs make
 * the XOR loop constant-time regardless of where the first difference is.
 * A length mismatch is itself public (the digest length is fixed), so the
 * early return leaks nothing.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Bearer-token check for the dashboard API. Hashing both sides first means
 * the comparison runs over 64 hex chars whatever the supplied key's length.
 * An unset expected key always fails, so a missing secret locks the API
 * rather than opening it.
 */
export async function isAuthorized(req: Request, expectedKey: string): Promise<boolean> {
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token || !expectedKey) return false;
  const [supplied, expected] = await Promise.all([sha256Hex(token), sha256Hex(expectedKey)]);
  return constantTimeEqual(supplied, expected);
}