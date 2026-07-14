import { describe, expect, it } from "vitest";
import { harnessAnswer } from "./harness";

describe("compatibility harness presentation", () => {
  it("accepts deterministic typed results when a small model emits no prose", () => {
    expect(harnessAnswer("", [{
      selected_candidate_bytes: "5000000000",
      review_potential_bytes: "2000000000",
    }])).toContain("5000000000");
  });

  it("presents an empty bounded query honestly", () => {
    expect(harnessAnswer("", [{ items: [], next_cursor: null }])).toBe(
      "No matching item was returned.",
    );
  });
});
