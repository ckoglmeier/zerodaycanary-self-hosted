// canary-evidence/1 bundles: validation and server-side packing. Ports the companion's
// validate_bundle(), inventory() and pack() rules (zero-day-canary-skill/scripts/canary.py)
// and reuses its pinned schemas and the unmodified Cloudflare findings validator.
import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020";
import evidenceSchema from "@/vendor/canary/canary-evidence-v1.schema.json";
import evidenceSchemaV2 from "@/skills/zero-day-canary-skill/schemas/canary-evidence-v2.schema.json";
import reportSchema from "@/vendor/canary/report-schema.json";
import { validateDocument } from "@/vendor/canary/validate-findings.cjs";
import { canonical, JsonRejected } from "./json";

export const PIN = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8";
export const SCHEMA_HASH = "6575c9de4a62255699ea052ebf9a49ebfb373a32891bcd89af6f55cc84b35519";
export const LIMITATIONS = [
  "Developer-supplied source inventory is not evidence of the deployed system.",
  "Lockfiles describe declared resolution; installed, bundled, runtime, OS and deployment components may differ or be absent.",
  "Source audit verdicts are separate from advisory matches and deployed-system verification.",
  "A clean audit or no matching advisory never proves absence of vulnerabilities.",
  "Inventory scope covers supplied lockfile entries, including development and optional packages; runtime reachability is unknown.",
  "Detailed findings are omitted unless individually selected; schema validity does not certify audit completion or independent verification.",
];
const NAME = /^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/;
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;
const TS = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;

export type Component = {
  ecosystem: string;
  public_registry?: boolean;
  name: string;
  version: string | null;
  purl: string | null;
  relationship: "direct" | "transitive" | "unknown";
  development: boolean | null;
  optional: boolean | null;
  source_id: string;
  instance: number;
};
export type Bundle = {
  schema_version: "canary-evidence/1" | "canary-evidence/2";
  created_at: string;
  repository: { id: string; commit: string | null; dirty: boolean | null; basis: "developer_supplied" };
  scope: string[];
  deployment: { identity: string; version: string; basis: "developer_supplied_unverified" } | null;
  audit: {
    context: { upstream_revision: string | null; source_commit: string | null; source_dirty: boolean | null; audited_at: string | null; scope: string[]; run_status: "completed" | "incomplete" | "unknown" };
    compatibility_revision: string;
    schema_sha256: string;
    report_sha256: string | null;
    total_records: number;
    verdict_counts: { confirmed: number; needs_validation: number; rejected: number };
    selected_findings: { verdict: string; fingerprint: string }[];
  };
  inventory: { format: "npm-lock-v2" | "npm-lock-v3" | "component-inventory" | "missing" | "unsupported"; components: Component[]; unknowns: { reason: string; entry: number | null }[] };
  sources: { id: string; kind: string; sha256: string }[];
  limitations: string[];
};

export const sha256 = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");
const need = (c: unknown, m: string) => {
  if (!c) throw new JsonRejected(m);
};

// Wrapper schema without the findings $ref; findings go through the pinned upstream validator.
const wrapper = structuredClone(evidenceSchema) as unknown as { properties: { audit: { properties: { selected_findings: unknown } } } };
wrapper.properties.audit.properties.selected_findings = { type: "array", maxItems: 1000 };
const ajv = new Ajv2020({ strict: false, allErrors: false });
const validateWrapper = ajv.compile(wrapper as object);
const wrapperV2 = structuredClone(evidenceSchemaV2) as unknown as typeof wrapper;
wrapperV2.properties.audit.properties.selected_findings = { type: "array", maxItems: 1000 };
const validateWrapperV2 = ajv.compile(wrapperV2 as object);

function timestamp(v: string) {
  need(TS.test(v), "Timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ.");
  const d = new Date(v);
  need(!Number.isNaN(d.getTime()) && d.toISOString().slice(0, 19) + "Z" === v, "Invalid calendar timestamp.");
  return d.getTime();
}

export function exactVersion(v: unknown): v is string {
  if (typeof v !== "string" || v.length > 128) return false;
  const m = VERSION.exec(v);
  if (!m) return false;
  for (const g of [m[4], m[5]]) if (g && g.split(".").some((p) => !p)) return false;
  return !(m[4] && m[4].split(".").some((p) => /^\d+$/.test(p) && p.length > 1 && p[0] === "0"));
}

// Python urllib.parse.quote(s, safe=...) for the characters NAME/VERSION allow.
const quote = (s: string, safe: string) =>
  [...Buffer.from(s, "utf8")].map((b) => {
    const ch = String.fromCharCode(b);
    return /[A-Za-z0-9_.~-]/.test(ch) || safe.includes(ch) ? ch : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }).join("");
export const purlFor = (name: string, version: string | null) => (version ? `pkg:npm/${quote(name, "/")}@${quote(version, "")}` : null);

function safeRelative(v: string) {
  need(typeof v === "string" && v.length > 0 && v.length <= 512, "Invalid relative path.");
  need(!v.startsWith("/") && !v.startsWith("\\") && !v.includes("\\") && !v.includes(":"), "Absolute or platform-ambiguous path rejected.");
  need(v.split("/").every((x) => x !== "" && x !== "." && x !== ".."), "Traversal or empty path component rejected.");
  need(!/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\ufeff]/.test(v), "Control character in path.");
}

export function validateBundle(value: unknown): Bundle {
  const v2 = (value as {schema_version?:string})?.schema_version === 'canary-evidence/2';
  need(v2 ? validateWrapperV2(value) : validateWrapper(value), "Bundle does not satisfy the declared evidence schema (values suppressed).");
  const b = value as Bundle;
  const created = timestamp(b.created_at);
  need(b.scope.length > 0, "Inventory scope must be explicit.");
  for (const p of [...b.scope, ...b.audit.context.scope]) if (p !== ".") safeRelative(p);
  for (const c of b.inventory.components) {
    if (!v2) {
      if (c.version !== null) need(exactVersion(c.version), "Non-exact inventory version.");
      need(c.purl === purlFor(c.name, c.version), "Component purl does not match identity/version.");
    } else {
      need(c.version === null || !/^(?:latest|unknown|any|HEAD|main|master)$/i.test(c.version), 'Inventory needs an exact version or null.');
      // PURLs are optional evidence only. OSV queries use the validated explicit
      // ecosystem/name/version, never an untrusted URL, registry or commit.
      need(c.purl === null || !/[\s\u0000-\u001f\u007f]/.test(c.purl), 'Invalid package URL.');
      need(c.ecosystem !== 'product' || c.public_registry === false, 'Vendor/runtime assets are not public registry packages.');
    }
  }
  const inv = b.inventory;
  if (inv.format === "missing" || inv.format === "unsupported") {
    need(inv.components.length === 0, "Missing/unsupported inventory cannot contain component claims.");
    const reason = inv.format === "missing" ? "missing_inventory" : "unsupported_inventory";
    need(inv.unknowns.some((u) => u.reason === reason), "Missing/unsupported inventory must retain its coverage unknown.");
  }
  const inst = inv.components.map((c) => c.instance);
  need(new Set(inst).size === inst.length, "Duplicate inventory instance.");
  if (b.audit.context.audited_at) need(timestamp(b.audit.context.audited_at) <= created, "Audit is later than packaging time.");
  const a = b.audit;
  need(a.verdict_counts.confirmed + a.verdict_counts.needs_validation + a.verdict_counts.rejected === a.total_records, "Audit counts disagree.");
  if (a.report_sha256 === null) need(a.total_records === 0 && a.selected_findings.length === 0, "Findings require report provenance.");
  need(validateDocument(a.selected_findings, reportSchema).length === 0, "Audit records failed the pinned upstream schema/semantic validator (values suppressed).");
  const counts: Record<string, number> = {};
  for (const f of a.selected_findings) counts[f.verdict] = (counts[f.verdict] ?? 0) + 1;
  need(Object.entries(counts).every(([v, n]) => n <= (a.verdict_counts as Record<string, number>)[v]), "Selected findings exceed report counts.");
  need(new Set(a.selected_findings.map((f) => f.fingerprint)).size === a.selected_findings.length, "Duplicate selected finding.");
  const sources = new Map(b.sources.map((s) => [s.id, s]));
  need(sources.size === b.sources.length, "Duplicate evidence source.");
  for (const c of inv.components) need(sources.get(c.source_id)?.kind === (v2 ? 'component_inventory' : "npm_lockfile"), "Missing inventory provenance.");
  if (v2 && inv.format === 'component-inventory') need(sources.get('inventory-1')?.kind === 'component_inventory', 'Inventory requires its source.');
  else if (inv.format.startsWith("npm-lock-")) need(sources.get("inventory-1")?.kind === "npm_lockfile", "Supported inventory requires its lockfile source.");
  else if (inv.format === "missing") need(!sources.has("inventory-1"), "Missing inventory cannot claim an inventory input.");
  else need(sources.get("inventory-1")?.kind === "unsupported_inventory", "Unsupported inventory requires its source.");
  if (a.report_sha256) need(sources.get("audit-1")?.sha256 === a.report_sha256, "Missing audit provenance.");
  need(JSON.stringify(b.limitations) === JSON.stringify(LIMITATIONS), "Coverage limitations must be retained unchanged.");
  return b;
}

// npm package-lock v2/v3 → components + unknowns (port of canary.py inventory()).
export function inventoryFromLock(lock: unknown): Bundle["inventory"] {
  if (lock === null || lock === undefined) return { format: "missing", components: [], unknowns: [{ reason: "missing_inventory", entry: null }] };
  const l = lock as { lockfileVersion?: unknown; packages?: unknown };
  if (typeof l !== "object" || !Number.isInteger(l.lockfileVersion) || ![2, 3].includes(l.lockfileVersion as number) || typeof l.packages !== "object" || l.packages === null || Array.isArray(l.packages))
    return { format: "unsupported", components: [], unknowns: [{ reason: "unsupported_inventory", entry: null }] };
  const packages = l.packages as Record<string, Record<string, unknown>>;
  need(Object.keys(packages).length <= 20000, "Lockfile exceeds 20000 entries.");
  const root = packages[""];
  const hasManifest = typeof root === "object" && root !== null && !Array.isArray(root);
  const direct = new Set<string>();
  const unknowns: Bundle["inventory"]["unknowns"] = [];
  if (hasManifest) {
    for (const k of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const vals = (root as Record<string, unknown>)[k] ?? {};
      need(typeof vals === "object" && vals !== null && !Array.isArray(vals), "Invalid root dependency map.");
      for (const n of Object.keys(vals as object)) direct.add(n);
    }
  } else unknowns.push({ reason: "missing_root_manifest", entry: null });
  const components: Component[] = [];
  // Python sorted() over keys = code-point order.
  const entries = Object.entries(packages).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  entries.forEach(([location, meta], i) => {
    const index = i + 1;
    if (location === "") return;
    safeRelative(location);
    need(typeof meta === "object" && meta !== null && !Array.isArray(meta), "Invalid lockfile entry.");
    if (meta.link || !location.startsWith("node_modules/")) {
      unknowns.push({ reason: "linked_or_workspace_component", entry: index });
      return;
    }
    const suffixes = location.split("node_modules/").slice(1);
    need(suffixes.slice(0, -1).every((x) => x.endsWith("/") && NAME.test(x.slice(0, -1))), "Invalid nested package locator.");
    const derived = suffixes[suffixes.length - 1];
    const candidate = meta.name ?? derived;
    if (typeof candidate !== "string" || candidate.length > 214 || !NAME.test(candidate) || !NAME.test(derived)) {
      unknowns.push({ reason: "ambiguous_identity", entry: index });
      return;
    }
    if (meta.resolved !== undefined && meta.resolved !== null) {
      need(typeof meta.resolved === "string", "Invalid resolution metadata.");
      let ok = false;
      try {
        const u = new URL(meta.resolved as string);
        ok = u.protocol === "https:" && u.hostname === "registry.npmjs.org" && !u.username && !u.password && !u.search && !u.hash;
      } catch {
        ok = false;
      }
      if (!ok) {
        unknowns.push({ reason: "non_registry_component", entry: index });
        return;
      }
    }
    const version = exactVersion(meta.version) ? (meta.version as string) : null;
    if (version === null) unknowns.push({ reason: "ambiguous_version", entry: index });
    const relationship = !hasManifest ? "unknown" : location === "node_modules/" + derived && direct.has(derived) ? "direct" : "transitive";
    components.push({
      ecosystem: "npm", name: candidate, version, purl: purlFor(candidate, version), relationship,
      development: typeof meta.dev === "boolean" ? meta.dev : null, optional: typeof meta.optional === "boolean" ? meta.optional : null,
      source_id: "inventory-1", instance: index,
    });
  });
  for (const name of [...direct].sort()) if (!(("node_modules/" + name) in packages)) unknowns.push({ reason: "missing_direct_entry", entry: null });
  return { format: `npm-lock-v${l.lockfileVersion}` as "npm-lock-v2" | "npm-lock-v3", components, unknowns };
}

// Builds a bundle from a web upload (lockfile and/or Cloudflare findings JSON). Detailed
// findings are included only when the owner opts in; otherwise only counts are kept.
export function packFromUpload(input: {
  repositoryId: string;
  lock: { value: unknown; bytes: Uint8Array } | null;
  findings: { value: unknown; bytes: Uint8Array } | null;
  includeFindings: boolean;
  now?: Date;
}): Bundle {
  const at = (input.now ?? new Date()).toISOString().slice(0, 19) + "Z";
  need(/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(input.repositoryId), "Repository name may use letters, digits, '.', '_', '/', '-' (max 200).");
  const sources: Bundle["sources"] = [];
  let inventory: Bundle["inventory"];
  if (input.lock) {
    inventory = inventoryFromLock(input.lock.value);
    sources.push({ id: "inventory-1", kind: inventory.format === "unsupported" ? "unsupported_inventory" : "npm_lockfile", sha256: sha256(input.lock.bytes) });
  } else inventory = inventoryFromLock(null);
  let findings: { verdict: string; fingerprint: string }[] = [];
  let report: string | null = null;
  if (input.findings) {
    need(Array.isArray(input.findings.value), "Audit findings must be a JSON array (Cloudflare findings.json).");
    findings = input.findings.value as typeof findings;
    need(findings.length <= 1000, "Audit has more than 1000 records.");
    need(validateDocument(findings, reportSchema).length === 0, "Audit records failed the pinned upstream schema/semantic validator (values suppressed).");
    report = sha256(input.findings.bytes);
    sources.push({ id: "audit-1", kind: "audit_findings", sha256: report });
  }
  const counts = { confirmed: 0, needs_validation: 0, rejected: 0 };
  for (const f of findings) counts[f.verdict as keyof typeof counts]++;
  const bundle: Bundle = {
    schema_version: "canary-evidence/1",
    created_at: at,
    repository: { id: input.repositoryId, commit: null, dirty: null, basis: "developer_supplied" },
    scope: ["."],
    deployment: null,
    audit: {
      context: { upstream_revision: null, source_commit: null, source_dirty: null, audited_at: null, scope: [], run_status: "unknown" },
      compatibility_revision: PIN,
      schema_sha256: SCHEMA_HASH,
      report_sha256: report,
      total_records: findings.length,
      verdict_counts: counts,
      selected_findings: input.includeFindings ? findings : [],
    },
    inventory,
    sources,
    limitations: LIMITATIONS,
  };
  return validateBundle(JSON.parse(canonical(bundle)));
}
