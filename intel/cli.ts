// Standalone intelligence-layer CLI. No hosted secrets, database, billing or telemetry:
// it reads files (or the public API) and writes JSON to stdout.
//
//   npm run intel -- fetch <base-url> > catalog.json        # all pages, one catalog revision
//   npm run intel -- validate catalog.json                   # schema-check every record
//   npm run intel -- match catalog.json evidence.json        # deterministic assessment
//
// evidence.json: { "techs": [{ "product": "php", "version": "8.2.10" }], "facts": {} }
import { readFileSync } from "node:fs";
import { AdvisoryRecord } from "./schema";
import { assessAll } from "./match";
import type { EvidenceSet, TechObservation } from "./evidence";

type Catalog = { schema_version: string; catalog_revision: number; data: unknown[] };

function load(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function fetchAll(base: string): Promise<Catalog> {
  let url: string | null = new URL("/api/v1/advisories?limit=200", base).href;
  const data: unknown[] = [];
  let rev: number | null = null;
  let schema = "";
  while (url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`HTTP ${r.status} from ${url}`);
    const page = (await r.json()) as Catalog & { next: string | null };
    if (rev !== null && page.catalog_revision !== rev) throw new Error("Catalog changed while paging; retry for a consistent snapshot.");
    rev = page.catalog_revision;
    schema = page.schema_version;
    data.push(...page.data);
    url = page.next ? new URL(page.next, base).href : null;
  }
  return { schema_version: schema, catalog_revision: rev ?? 0, data };
}

function records(c: Catalog) {
  return c.data.map((d, i) => {
    const r = AdvisoryRecord.safeParse(d);
    if (!r.success) throw new Error(`Record ${i} does not match the schema: ${r.error.issues[0]?.message}`);
    return r.data;
  });
}

async function main(argv: string[]) {
  const [cmd, a, b] = argv;
  if (cmd === "fetch" && a) return console.log(JSON.stringify(await fetchAll(a), null, 2));
  if (cmd === "validate" && a) {
    const recs = records(load(a) as Catalog);
    return console.log(JSON.stringify({ valid: recs.length }));
  }
  if (cmd === "match" && a && b) {
    const cat = load(a) as Catalog;
    const ev = load(b) as { techs: Partial<TechObservation>[]; facts?: Record<string, boolean> };
    const now = new Date().toISOString();
    const evidence: EvidenceSet = {
      techs: ev.techs.map((t) => ({
        product: String(t.product), name: t.name ?? String(t.product), version: t.version ?? null, version_basis: t.version ? (t.version_basis ?? "admin_supplied") : null,
        evidence_type: "administrator", location: "cli input", detail: "Supplied to the CLI", confidence: "medium", observed_at: now, limitations: [],
      })),
      facts: ev.facts ?? {},
      observed_at: now,
    };
    return console.log(JSON.stringify({ catalog_revision: cat.catalog_revision, results: assessAll(records(cat), evidence) }, null, 2));
  }
  console.error("usage: intel fetch <base-url> | validate <catalog.json> | match <catalog.json> <evidence.json>");
  process.exitCode = 2;
}

main(process.argv.slice(2)).catch((e) => {
  console.error((e as Error).message);
  process.exitCode = 1;
});
