import { describe, expect, it } from "vitest";
import { formatAgentError } from "./types";

describe("agent error formatting", () => {
  it("extracts a nested Tauri scan failure instead of rendering object text", () => {
    expect(formatAgentError({ error: { code: "STALE_SESSION", detail: "Scan changed" } }))
      .toBe("Scan changed");
  });
});
