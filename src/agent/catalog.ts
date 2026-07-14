import type {
  HardwareProfile,
  InstalledOllamaModel,
  ModelCatalogEntry,
  ModelHarnessResult,
} from "./types";

export const MODEL_CATALOG_VERSION = 1;

export const bundledModelCatalog: readonly ModelCatalogEntry[] = [
  {
    id: "lfm2.5-thinking:1.2b",
    label: "LFM 2.5 Thinking 1.2B",
    class: "light",
    expectedBytes: 900_000_000,
    minMemoryBytes: 3_000_000_000,
    recommendedContext: 8_192,
    qualityRank: 2,
    officialUrl: "https://ollama.com/library/lfm2.5-thinking",
  },
  {
    id: "granite4:1b-h",
    label: "Granite 4 1B Hybrid",
    class: "light",
    expectedBytes: 1_600_000_000,
    minMemoryBytes: 3_500_000_000,
    recommendedContext: 8_192,
    qualityRank: 3,
    officialUrl: "https://ollama.com/library/granite4:1b-h",
  },
  {
    id: "qwen3.5:0.8b",
    label: "Qwen 3.5 0.8B",
    class: "light",
    expectedBytes: 700_000_000,
    minMemoryBytes: 3_000_000_000,
    recommendedContext: 8_192,
    qualityRank: 1,
    officialUrl: "https://ollama.com/library/qwen3.5",
  },
  {
    id: "qwen3.5:2b",
    label: "Qwen 3.5 2B",
    class: "balanced",
    expectedBytes: 1_600_000_000,
    minMemoryBytes: 5_500_000_000,
    recommendedContext: 8_192,
    qualityRank: 3,
    officialUrl: "https://ollama.com/library/qwen3.5",
  },
  {
    id: "qwen3.5:4b",
    label: "Qwen 3.5 4B",
    class: "heavy",
    expectedBytes: 3_100_000_000,
    minMemoryBytes: 9_000_000_000,
    recommendedContext: 8_192,
    qualityRank: 4,
    officialUrl: "https://ollama.com/library/qwen3.5",
  },
] as const;

export interface RankedModel {
  catalog: ModelCatalogEntry | null;
  installed: InstalledOllamaModel;
  harness: ModelHarnessResult | null;
  memoryFit: boolean;
  headroomBytes: number;
}

export function rankInstalledModels(
  models: InstalledOllamaModel[],
  hardware: HardwareProfile,
  harnesses: ReadonlyMap<string, ModelHarnessResult>,
): RankedModel[] {
  return models
    .map((installed) => {
      const catalog = bundledModelCatalog.find((entry) => modelNamesMatch(entry.id, installed.name)) ?? null;
      const required = catalog?.minMemoryBytes ?? Math.max(installed.size * 2, 3_000_000_000);
      const totalHeadroom = hardware.totalMemoryBytes - required;
      const availableRequired = Math.max(installed.size + 256_000_000, 1_000_000_000);
      const availableHeadroom = hardware.availableMemoryBytes === undefined
        ? Number.MAX_SAFE_INTEGER
        : hardware.availableMemoryBytes - availableRequired;
      const alreadyResident = installed.loaded !== undefined;
      return {
        catalog,
        installed,
        harness: harnesses.get(installed.digest) ?? null,
        memoryFit: totalHeadroom >= 0 && (alreadyResident || availableHeadroom >= 0),
        headroomBytes: alreadyResident ? totalHeadroom : Math.min(totalHeadroom, availableHeadroom),
      };
    })
    .sort(compareRankedModels);
}

function compareRankedModels(left: RankedModel, right: RankedModel): number {
  return Number(right.harness?.passed === true) - Number(left.harness?.passed === true)
    || Number(right.memoryFit) - Number(left.memoryFit)
    || (right.harness?.scenarios.filter((scenario) => scenario.passed).length ?? 0)
      - (left.harness?.scenarios.filter((scenario) => scenario.passed).length ?? 0)
    || (left.harness?.totalElapsedMs ?? Number.MAX_SAFE_INTEGER)
      - (right.harness?.totalElapsedMs ?? Number.MAX_SAFE_INTEGER)
    || (right.catalog?.qualityRank ?? 0) - (left.catalog?.qualityRank ?? 0)
    || left.installed.name.localeCompare(right.installed.name);
}

function modelNamesMatch(catalogName: string, installedName: string): boolean {
  return normalizeModelName(catalogName) === normalizeModelName(installedName);
}

function normalizeModelName(value: string): string {
  return value.trim().toLocaleLowerCase().replace(/:latest$/, "");
}
