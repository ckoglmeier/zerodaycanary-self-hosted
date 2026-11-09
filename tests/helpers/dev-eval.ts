// Test helper: runs the developer evaluator's pure matching step against fixture advisories.
import { vi } from "vitest";
vi.mock("server-only", () => ({}));
vi.mock("../../lib/db", () => ({ q: async () => [], one: async () => null }));
const { evaluateComponents } = await import("../../lib/developer/evaluate");
const { NEXT_CACHE } = await import("../../intel/fixtures/advisories");
export const evaluateComponentsPure = (c: Parameters<typeof evaluateComponents>[0]) => evaluateComponents(c, [NEXT_CACHE], "2026-10-22T00:00:00Z");
