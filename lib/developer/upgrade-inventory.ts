import type {Bundle} from './bundle';
// Retain legacy validation, then add explicit origin evidence for broad lookups.
// A missing resolved field does not establish that an npm name is public.
export function upgradeNpmInventory(bundle:Bundle,lock:unknown,allow=true):Bundle {
 const b=structuredClone(bundle);b.schema_version='canary-evidence/2';
 if(b.inventory.format.startsWith('npm-lock-'))b.inventory.format='component-inventory';
 const packages=(lock as {packages?:Record<string,{resolved?:unknown}>}|null)?.packages||{};
 const entries=Object.entries(packages).sort(([a],[b])=>a<b?-1:a>b?1:0);
 for(const c of b.inventory.components){const resolved=entries[c.instance-1]?.[1]?.resolved;let pub=false;
  if(allow&&typeof resolved==='string')try{const u=new URL(resolved);pub=u.protocol==='https:'&&u.hostname==='registry.npmjs.org'&&!u.username&&!u.password&&!u.search&&!u.hash;}catch{}
  c.public_registry=pub;
 }
 for(const s of b.sources)if(s.kind==='npm_lockfile')s.kind='component_inventory';
 return b;
}
