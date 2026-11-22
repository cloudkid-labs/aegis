import { verifyCallbackToken } from "./callback-token";
import type { Env } from "./env";

/** A scan cannot outlive a day, whatever the caller asks for. */
const MAX_TIMEOUT_SECONDS = 24 * 60 * 60;

/**
 * One instance per scan (`idFromName(scanId)`).
 *
 * D1 is the source of truth for scan status; this object owns only the two
 * things that need coordination: the timeout alarm, and the single-use
 * registry for callback tokens. It is reached only through the service
 * binding, never by a public route.
 */
export class ScanCoordinator implements DurableObject {
  constructor(
    private readonly state: DurableObjectState,
    private readonly env: Env,
  ) {}

  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

    switch (pathname) {
      case "/start":
        return this.start(request);
      case "/consume":
        return this.consume(request);
      case "/cancel":
        return this.cancel();
      default:
        return new Response("Not Found", { status: 404 });
    }
  }

  private async start(request: Request): Promise<Response> {
    const body = await parseBody(request);
    if (!body.ok) return body.response;

    const { scanId, timeoutSeconds } = body.value as { scanId?: unknown; timeoutSeconds?: unknown };
    if (typeof scanId !== "string" || scanId.length === 0 || scanId.length > 128) {
      return new Response("Invalid scanId", { status: 400 });
    }
    if (
      typeof timeoutSeconds !== "number" ||
      !Number.isInteger(timeoutSeconds) ||
      timeoutSeconds <= 0 ||
      timeoutSeconds > MAX_TIMEOUT_SECONDS
    ) {
      return new Response("Invalid timeoutSeconds", { status: 400 });
    }

    const deadline = Date.now() + timeoutSeconds * 1000;
    await this.state.storage.put("scanId", scanId);
    await this.state.storage.put("deadline", deadline);
    await this.state.storage.setAlarm(deadline);
    return new Response("ok");
  }

  private async consume(request: Request): Promise<Response> {
    const body = await parseBody(request);
    if (!body.ok) return body.response;

    const { scanId, token } = body.value as { scanId?: unknown; token?: unknown };
    if (typeof scanId !== "string" || typeof token !== "string") {
      return new Response("Invalid request", { status: 400 });
    }
    if (!(await verifyCallbackToken(this.env.CALLBACK_SECRET, scanId, token, Date.now()))) {
      return new Response("Invalid token", { status: 401 });
    }

    const key = `used:${token}`;
    if (await this.state.storage.get(key)) return new Response("Token already used", { status: 409 });
    await this.state.storage.put(key, true);
    return new Response("ok");
  }

  private async cancel(): Promise<Response> {
    await this.state.storage.deleteAlarm();
    return new Response("ok");
  }

  /**
   * The timeout path. The UPDATE is conditional on a nonterminal status, so a
   * late alarm cannot overwrite a scan the callback already completed (or a
   * cancel already closed). The event is written only if the UPDATE landed.
   */
  async alarm(): Promise<void> {
    const scanId = await this.state.storage.get<string>("scanId");
    if (!scanId) return;

    const now = new Date().toISOString();
    const res = await this.env.AEGIS_DB.prepare(
      "UPDATE scans SET status='failed', error='timeout', updated_at=?2 WHERE id=?1 AND status IN ('queued','running')",
    ).bind(scanId, now).run();
    if ((res.meta?.changes ?? 0) === 0) return;

    await this.env.AEGIS_DB.prepare(
      "INSERT INTO scan_events (scan_id, event, detail, created_at) VALUES (?1,'failed','timeout',?2)",
    ).bind(scanId, now).run();
  }
}

type ParsedBody = { ok: true; value: unknown } | { ok: false; response: Response };

async function parseBody(request: Request): Promise<ParsedBody> {
  try {
    const value = (await request.json()) as unknown;
    if (typeof value !== "object" || value === null) {
      return { ok: false, response: new Response("Invalid JSON", { status: 400 }) };
    }
    return { ok: true, value };
  } catch {
    return { ok: false, response: new Response("Invalid JSON", { status: 400 }) };
  }
}