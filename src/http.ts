/** Scan-create bodies are small; anything larger is a client bug or an attack. */
export const JSON_BODY_LIMIT = 8 * 1024;

export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export function jsonError(message: string, status: number): Response {
  return json({ error: message }, status);
}

export type BodyResult =
  | { ok: true; value: unknown }
  | { ok: false; response: Response };

/**
 * Enforces the content type before reading (a cross-site form POST is not
 * accepted as JSON), then the size limit, then parses. Callers get either a
 * value or a ready-made error response.
 */
export async function readJsonBody(req: Request, limit = JSON_BODY_LIMIT): Promise<BodyResult> {
  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return { ok: false, response: jsonError("Expected application/json", 415) };
  }
  const text = await req.text();
  if (text.length > limit) {
    return { ok: false, response: jsonError("Body too large", 413) };
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, response: jsonError("Invalid JSON", 400) };
  }
}