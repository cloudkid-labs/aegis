import { describe, expect, it } from "vitest";
import { matchesQuery } from "./search";

describe("matchesQuery", () => {
  it("matches every row when the query is empty", () => {
    expect(matchesQuery("", ["https://target.example", "explore"])).toBe(true);
  });

  it("matches every row when the query is only whitespace", () => {
    expect(matchesQuery("   ", ["https://target.example"])).toBe(true);
  });

  it("matches a case-insensitive substring of a field", () => {
    expect(matchesQuery("SINGULAR", ["https://www.singularfs.co.za/"])).toBe(true);
  });

  it("matches a value in any field, not just the first", () => {
    expect(matchesQuery("completed", ["https://target.example", "abc123", "explore", "completed"])).toBe(true);
  });

  it("requires every word to match, in any order", () => {
    expect(matchesQuery("completed singular", ["https://www.singularfs.co.za/", "explore", "completed"])).toBe(true);
  });

  it("rejects a row when one word is absent", () => {
    expect(matchesQuery("singular running", ["https://www.singularfs.co.za/", "explore", "completed"])).toBe(false);
  });

  it("does not match the literal text of a null field", () => {
    expect(matchesQuery("null", [null, undefined, "https://target.example"])).toBe(false);
  });

  it("matches a present field alongside null ones", () => {
    expect(matchesQuery("target", [null, undefined, "https://target.example"])).toBe(true);
  });

  it("trims the query before matching", () => {
    expect(matchesQuery("  target  ", ["https://target.example"])).toBe(true);
  });
});