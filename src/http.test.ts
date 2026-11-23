import { describe, expect, it } from "vitest";
import { JSON_BODY_LIMIT, json, jsonError, readJsonBody } from "./http";

function post(body: string, contentType = "application/json"): Request {
  return new Request("https://aegis.test/api/scans", {
    method: "POST",
    headers: { "content-type": contentType },
    body,
  });
}

describe("readJsonBody", () => {
  it("parses valid JSON", async () => {
    const result = await readJsonBody(post('{"a":1}'));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toEqual({ a: 1 });
  });

  it("accepts a content type with a charset parameter", async () => {
    const result = await readJsonBody(post("{}", "application/json; charset=utf-8"));
    expect(result.ok).toBe(true);
  });

  it("rejects the wrong content type with 415", async () => {
    const result = await readJsonBody(post("{}", "text/plain"));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.response.status).toBe(415);
  });

  it("rejects a body over the limit with 413", async () => {
    const result = await readJsonBody(post("x".repeat(9000)), JSON_BODY_LIMIT);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.response.status).toBe(413);
  });

  it("accepts a body exactly at the limit", async () => {
    const body = `{"x":"${"a".repeat(50)}"}`;
    const result = await readJsonBody(post(body), body.length);
    expect(result.ok).toBe(true);
  });

  it("rejects invalid JSON with 400", async () => {
    const result = await readJsonBody(post("{nope"));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.response.status).toBe(400);
  });

  it("rejects an empty body with 400", async () => {
    const result = await readJsonBody(post(""));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.response.status).toBe(400);
  });
});

describe("json helpers", () => {
  it("json sets status, content type and body", async () => {
    const res = json({ x: 1 }, 201);
    expect(res.status).toBe(201);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ x: 1 });
  });

  it("json defaults to 200", () => {
    expect(json({}).status).toBe(200);
  });

  it("jsonError wraps the message", async () => {
    const res = jsonError("bad", 400);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "bad" });
  });
});