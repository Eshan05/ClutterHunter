import { fetch as tauriFetch } from "@tauri-apps/plugin-http";
import { AgentRuntimeError, type OllamaEndpoint } from "./types";

export type AgentFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type NativeFetch = (
  input: RequestInfo | URL,
  init?: RequestInit & { maxRedirections?: number; connectTimeout?: number },
) => Promise<Response>;

export function canonicalizeOllamaEndpoint(port: number): OllamaEndpoint {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new AgentRuntimeError(
      "INVALID_ENDPOINT",
      "Ollama port must be an integer between 1 and 65535",
      false,
    );
  }
  const origin = `http://127.0.0.1:${port}`;
  return {
    port,
    origin,
    nativeApiUrl: `${origin}/api`,
  };
}

export function createLoopbackFetch(
  endpoint: OllamaEndpoint,
  nativeFetch: NativeFetch = tauriFetch as NativeFetch,
): AgentFetch {
  return async (input, init) => {
    assertAllowedUrl(endpoint, requestUrl(input));
    const headers = mergedHeaders(input, init?.headers);
    // Tauri's release webview origin is not accepted by Ollama. With the
    // plugin's unsafe-headers feature, an empty Origin removes it entirely.
    headers.set("Origin", "");
    const response = await nativeFetch(input, {
      ...init,
      headers,
      redirect: "error",
      maxRedirections: 0,
      connectTimeout: 5_000,
    });
    if (response.url) assertAllowedUrl(endpoint, response.url);
    return response;
  };
}

export function assertAllowedUrl(endpoint: OllamaEndpoint, value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AgentRuntimeError("INVALID_ENDPOINT", "Ollama request URL is invalid", false);
  }
  if (
    url.protocol !== "http:"
    || url.hostname !== "127.0.0.1"
    || url.port !== String(endpoint.port)
    || url.username !== ""
    || url.password !== ""
  ) {
    throw new AgentRuntimeError(
      "INVALID_ENDPOINT",
      "Ollama requests are restricted to the configured 127.0.0.1 port",
      false,
    );
  }
  return url;
}

function mergedHeaders(input: RequestInfo | URL, initHeaders?: HeadersInit): Headers {
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  new Headers(initHeaders).forEach((value, key) => headers.set(key, value));
  return headers;
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}
