import { describe, expect, it, vi } from "vitest";
import { assertAllowedUrl, canonicalizeOllamaEndpoint, createLoopbackFetch } from "./endpoint";

describe("Ollama loopback endpoint", () => {
  it("canonicalizes only numeric ports", () => {
    expect(canonicalizeOllamaEndpoint(11_434)).toEqual({
      port: 11_434,
      origin: "http://127.0.0.1:11434",
      nativeApiUrl: "http://127.0.0.1:11434/api",
    });
    expect(() => canonicalizeOllamaEndpoint(0)).toThrow(/between 1 and 65535/);
    expect(() => canonicalizeOllamaEndpoint(11_434.5)).toThrow(/integer/);
  });

  it("rejects localhost aliases, LAN hosts, credentials, and other ports", () => {
    const endpoint = canonicalizeOllamaEndpoint(11_434);
    expect(() => assertAllowedUrl(endpoint, "http://localhost:11434/api/tags")).toThrow(/127\.0\.0\.1/);
    expect(() => assertAllowedUrl(endpoint, "http://192.168.1.2:11434/api/tags")).toThrow(/127\.0\.0\.1/);
    expect(() => assertAllowedUrl(endpoint, "http://127.0.0.1:11435/api/tags")).toThrow(/configured/);
    expect(() => assertAllowedUrl(endpoint, "http://user@127.0.0.1:11434/api/tags")).toThrow(/configured/);
  });

  it("disables redirects for every request", async () => {
    const nativeFetch = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit & { maxRedirections?: number; connectTimeout?: number },
    ) => new Response("{}", { status: 200 }));
    const fetch = createLoopbackFetch(canonicalizeOllamaEndpoint(11_434), nativeFetch);
    await fetch("http://127.0.0.1:11434/api/tags", { method: "GET" });
    expect(nativeFetch).toHaveBeenCalledWith(
      "http://127.0.0.1:11434/api/tags",
      expect.objectContaining({ redirect: "error", maxRedirections: 0, connectTimeout: 5_000 }),
    );
    const requestInit = nativeFetch.mock.calls[0]?.[1];
    expect(new Headers(requestInit?.headers).get("Origin")).toBe("");
  });
});
