/**
 * Invasion caps and timeouts. These live here and nowhere else so the create
 * handler, the Durable Object alarm and the executor all read one value; an
 * invasion timeout is derived from the selection (active iff zap-full), not
 * hard-coded at a call site. Explore keeps its own 900 seconds.
 */

/** Upper bound on URLs one invasion scan accepts, chained or standalone. */
export const INVASION_MAX_URLS = 8;

/** seconds; nuclei plus ZAP baseline. */
export const INVASION_TIMEOUT_BASELINE = 1800;

/** seconds; nuclei plus the opt-in ZAP full scan. */
export const INVASION_TIMEOUT_ACTIVE = 3600;