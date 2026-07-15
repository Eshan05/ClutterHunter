import { MODEL_HARNESS_VERSION } from "./harness";
import type { LocalModelPreflight, ModelHarnessResult } from "./types";

const CACHE_PREFIX = "clutterhunter:model-harness:";

export interface HarnessCache {
  get(preflight: LocalModelPreflight): ModelHarnessResult | null;
  set(result: ModelHarnessResult): void;
}

export class LocalHarnessCache implements HarnessCache {
  private readonly storage: Pick<Storage, "getItem" | "setItem"> | null;

  constructor(storage: Pick<Storage, "getItem" | "setItem"> | null = browserStorage()) {
    this.storage = storage;
  }

  get(preflight: LocalModelPreflight): ModelHarnessResult | null {
    let raw: string | null | undefined;
    try {
      raw = this.storage?.getItem(cacheKey(preflight));
    } catch {
      return null;
    }
    if (!raw) return null;
    try {
      const result = JSON.parse(raw) as ModelHarnessResult;
      if (
        !validHarnessShape(result)
        || result.harnessVersion !== MODEL_HARNESS_VERSION
        || result.digest !== preflight.model.digest
        || result.ollamaVersion !== preflight.ollamaVersion
        || result.model !== preflight.model.name
      ) return null;
      return result;
    } catch {
      return null;
    }
  }

  set(result: ModelHarnessResult): void {
    try {
      this.storage?.setItem(
        `${CACHE_PREFIX}${result.digest}:${result.ollamaVersion}:${result.harnessVersion}`,
        JSON.stringify(result),
      );
    } catch {
      // A storage quota/privacy setting may disable caching; rerunning is safer than bypassing.
    }
  }
}

function validHarnessShape(result: ModelHarnessResult): boolean {
  const expected = ["overview-query", "cleanup-plan", "empty-result", "bounded-retry"];
  return typeof result === "object"
    && typeof result.model === "string"
    && typeof result.digest === "string"
    && typeof result.ollamaVersion === "string"
    && typeof result.passed === "boolean"
    && Number.isFinite(result.totalElapsedMs)
    && Array.isArray(result.scenarios)
    && result.scenarios.length === expected.length
    && expected.every((id, index) => {
      const scenario = result.scenarios[index];
      return scenario?.id === id
        && typeof scenario.passed === "boolean"
        && (scenario.firstTokenMs === null || Number.isFinite(scenario.firstTokenMs))
        && Number.isFinite(scenario.elapsedMs)
        && typeof scenario.detail === "string";
    })
    && result.passed === result.scenarios.every((scenario) => scenario.passed);
}

function cacheKey(preflight: LocalModelPreflight): string {
  return `${CACHE_PREFIX}${preflight.model.digest}:${preflight.ollamaVersion}:${MODEL_HARNESS_VERSION}`;
}

function browserStorage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}
