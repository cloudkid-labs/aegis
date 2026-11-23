import { describe, expect, it } from "vitest";
import { selectInvasionTargets } from "./invasion-targets";
import type { Asset } from "./types";

const A = (id: string, type: Asset["type"], value: string, metadata: string | null): Asset =>
  ({ id, scanId: "s", type, value, metadata, createdAt: "2026-11-23T00:00:00.000Z" });

describe("selectInvasionTargets", () => {
  it("keeps live urls and endpoints in asset order", () => {
    const sel = selectInvasionTargets([
      A("1", "url", "https://x.example/", '{"status_code":200}'),
      A("2", "endpoint", "https://x.example/login", '{"status_code":302}'),
    ]);
    expect(sel.targets).toEqual([
      { url: "https://x.example/", type: "url", statusCode: 200 },
      { url: "https://x.example/login", type: "endpoint", statusCode: 302 },
    ]);
    expect(sel.excluded).toEqual([]);
  });

  it("excludes asset types that are not urls or endpoints", () => {
    const sel = selectInvasionTargets([
      A("a", "subdomain", "x.example", null),
      A("b", "host", "10.0.0.1", null),
      A("c", "ip", "10.0.0.1", null),
      A("d", "port", "https://x.example:8443/", '{"status_code":200}'),
      A("e", "technology", "nginx", null),
    ]);
    expect(sel.targets).toEqual([]);
    expect(sel.excluded.map((e) => e.reason)).toEqual(["not-url", "not-url", "not-url", "not-url", "not-url"]);
  });

  it("excludes unparseable, whitespace, markup, non-http and source-position values as malformed", () => {
    const sel = selectInvasionTargets([
      A("a", "url", "not a url", '{"status_code":200}'),
      A("b", "url", "https://x.example/a b", '{"status_code":200}'),
      A("c", "url", "https://x.example/<script>", '{"status_code":200}'),
      A("d", "url", "https://x.example/a.js:1:240", '{"status_code":200}'),
      A("e", "url", "https://x.example/a.js:12", '{"status_code":200}'),
      A("f", "url", "ftp://x.example/", '{"status_code":200}'),
    ]);
    expect(sel.targets).toEqual([]);
    expect(sel.excluded.map((e) => e.reason)).toEqual([
      "malformed", "malformed", "malformed", "malformed", "malformed", "malformed",
    ]);
  });

  it("keeps an explicit port on the origin instead of reading it as a source position", () => {
    const sel = selectInvasionTargets([
      A("a", "url", "https://x.example:8443", '{"status_code":200}'),
    ]);
    expect(sel.targets.map((t) => t.url)).toEqual(["https://x.example:8443"]);
    expect(sel.excluded).toEqual([]);
  });

  it("keeps a non-default port as its own service and folds host case with the port", () => {
    const sel = selectInvasionTargets([
      A("root", "url", "https://x.example/", '{"status_code":200}'),
      A("alt", "url", "https://x.example:8443/", '{"status_code":200}'),
      A("alt-upper", "url", "https://X.example:8443/", '{"status_code":200}'),
    ]);
    expect(sel.targets.map((t) => t.url)).toEqual(["https://x.example/", "https://x.example:8443/"]);
    expect(sel.excluded).toEqual([{ url: "https://X.example:8443/", reason: "duplicate" }]);
  });

  it("excludes assets without a live status code", () => {
    const sel = selectInvasionTargets([
      A("a", "url", "https://x.example/missing", null),
      A("b", "url", "https://x.example/not-json", "oops"),
      A("c", "url", "https://x.example/no-status", '{"title":"Home"}'),
      A("d", "url", "https://x.example/redirect", '{"status_code":301}'),
      A("e", "url", "https://x.example/client-error", '{"status_code":404}'),
      A("f", "url", "https://x.example/edge", '{"status_code":399}'),
    ]);
    expect(sel.targets.map((t) => t.url)).toEqual(["https://x.example/redirect", "https://x.example/edge"]);
    expect(sel.excluded.map((e) => e.reason)).toEqual([
      "not-live", "not-live", "not-live", "not-live",
    ]);
  });

  it("excludes Cloudflare cdn-cgi paths before the static-asset rule", () => {
    const sel = selectInvasionTargets([
      A("a", "url", "https://x.example/cdn-cgi/scripts/x.js", '{"status_code":200}'),
      A("b", "url", "https://x.example/cdn-cgi/trace", '{"status_code":200}'),
    ]);
    expect(sel.targets).toEqual([]);
    expect(sel.excluded.map((e) => e.reason)).toEqual(["cdn-cgi", "cdn-cgi"]);
  });

  it("excludes requests for static asset files", () => {
    const paths = [
      "/app.js", "/app.mjs", "/app.css", "/logo.png", "/photo.jpg", "/photo.jpeg", "/anim.gif",
      "/icon.svg", "/hero.webp", "/favicon.ico", "/font.woff", "/font.woff2", "/font.ttf", "/app.js.map",
    ];
    const sel = selectInvasionTargets(
      paths.map((p, i) => A(String(i), "url", `https://x.example${p}`, '{"status_code":200}')),
    );
    expect(sel.targets).toEqual([]);
    expect(sel.excluded.map((e) => e.reason)).toEqual(paths.map(() => "static-asset"));
  });

  it("excludes duplicates of an earlier kept target, folding host case and trailing slashes", () => {
    const sel = selectInvasionTargets([
      A("root", "url", "https://x.example/", '{"status_code":200}'),
      A("a", "subdomain", "x.example", null),
      A("b", "url", "https://x.example/a.js:1:240", '{"status_code":200}'),
      A("c", "url", "https://x.example/dead", '{"status_code":404}'),
      A("d", "url", "https://x.example/cdn-cgi/scripts/x.js", '{"status_code":200}'),
      A("e", "url", "https://x.example/app.css", '{"status_code":200}'),
      A("f", "url", "https://X.example/", '{"status_code":200}'),
      A("g", "url", "https://x.example", '{"status_code":200}'),
    ]);
    expect(sel.targets.map((t) => t.url)).toEqual(["https://x.example/"]);
    expect(sel.excluded.map((e) => e.reason)).toEqual([
      "not-url", "malformed", "not-live", "cdn-cgi", "static-asset", "duplicate", "duplicate",
    ]);
  });

  it("reports the earliest failing rule when an asset fails more than one", () => {
    // Every row below fails the rule named by its expected reason AND a later
    // rule, so swapping any adjacent pair of rules in selectInvasionTargets
    // changes a reason here and turns this test red.
    const sel = selectInvasionTargets([
      // not-url + malformed: "x.example" has no scheme.
      A("not-url", "subdomain", "x.example", '{"status_code":200}'),
      // malformed + not-live: a katana source position on a dead URL.
      A("malformed", "url", "https://x.example/a.js:1:240", '{"status_code":404}'),
      // not-live + cdn-cgi.
      A("cdn-cgi-dead", "url", "https://x.example/cdn-cgi/trace", '{"status_code":404}'),
      // not-live + static-asset.
      A("static-dead", "url", "https://x.example/app.css", '{"status_code":404}'),
      // Kept, and seeds the key "/app.js": the trailing slash defeats the
      // static-asset extension test, so the bare file below fails BOTH the
      // static-asset rule and the duplicate rule. Do not "tidy" this row away:
      // it is the only fixture that pins rule 5 ahead of rule 6.
      A("static-trailing-slash", "url", "https://x.example/app.js/", '{"status_code":200}'),
      // static-asset + duplicate.
      A("static-duplicate", "url", "https://x.example/app.js", '{"status_code":200}'),
      // cdn-cgi + static-asset.
      A("cdn-cgi-live", "url", "https://x.example/cdn-cgi/scripts/x.js", '{"status_code":200}'),
    ]);
    expect(sel.targets.map((t) => t.url)).toEqual(["https://x.example/app.js/"]);
    expect(sel.excluded.map((e) => e.reason)).toEqual([
      "not-url", "malformed", "not-live", "not-live", "static-asset", "cdn-cgi",
    ]);
  });

  it("keeps distinct search strings and path case, folding only trailing slashes", () => {
    const sel = selectInvasionTargets([
      A("a", "url", "https://x.example/login", '{"status_code":200}'),
      A("b", "url", "https://x.example/login/", '{"status_code":200}'),
      A("c", "url", "https://x.example/login?next=/a", '{"status_code":200}'),
      A("d", "endpoint", "https://x.example/Login", '{"status_code":200}'),
      A("e", "url", "https://x.example/login?a=1", '{"status_code":200}'),
      A("f", "url", "https://x.example/login?a=2", '{"status_code":200}'),
    ]);
    expect(sel.targets.map((t) => t.url)).toEqual([
      "https://x.example/login",
      "https://x.example/login?next=/a",
      "https://x.example/Login",
      "https://x.example/login?a=1",
      "https://x.example/login?a=2",
    ]);
    expect(sel.excluded).toEqual([{ url: "https://x.example/login/", reason: "duplicate" }]);
  });

  it("only an earlier kept target can make a later asset a duplicate", () => {
    const sel = selectInvasionTargets([
      A("a", "url", "https://x.example/dead", '{"status_code":404}'),
      A("b", "url", "https://x.example/dead", '{"status_code":200}'),
    ]);
    expect(sel.targets.map((t) => t.url)).toEqual(["https://x.example/dead"]);
    expect(sel.excluded).toEqual([{ url: "https://x.example/dead", reason: "not-live" }]);
  });
});