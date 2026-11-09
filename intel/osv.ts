// OSV performs ecosystem-specific matching. Canary never treats an empty response
// as proof of security or a lockfile as proof of production applicability.
import { z } from 'zod';
export const OSV_ECOSYSTEMS = ['npm','PyPI','Packagist','Go','Maven','NuGet','RubyGems','crates.io','Pub','Hex','SwiftURL','Hackage','ConanCenter','CRAN','Bioconductor','Alpine','Debian','Ubuntu','Rocky Linux','AlmaLinux','Red Hat','SUSE','Wolfi','Chainguard','Linux','OSS-Fuzz'] as const;
export const supportedEcosystem = (e:string) => OSV_ECOSYSTEMS.some(x=>e===x || ['Alpine','Debian','Ubuntu','Rocky Linux','AlmaLinux','Red Hat','SUSE'].includes(x) && e.startsWith(x+':'));
export const OsvRecordSchema = z.object({
 id:z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/), modified:z.string().datetime({offset:true}),
 aliases:z.array(z.string().max(200)).max(200).default([]), summary:z.string().max(10000).optional(), details:z.string().max(200000).optional(),
 withdrawn:z.string().datetime({offset:true}).optional(), published:z.string().optional(),
 references:z.array(z.object({type:z.string().optional(),url:z.string().url().max(2048)})).max(300).default([]),
 affected:z.array(z.object({package:z.object({name:z.string().max(512),ecosystem:z.string().max(100)}),ranges:z.array(z.unknown()).max(100).optional(),versions:z.array(z.string().max(128)).max(50000).optional()})).max(1000),
 database_specific:z.object({severity:z.string().max(100).optional()}).passthrough().optional(),
});
export type OsvRecord=z.infer<typeof OsvRecordSchema>;
export type PackageIdentity={ecosystem:string;name:string;version:string};
export type PackageCheck=PackageIdentity & {checked_at:string;records:OsvRecord[]};
export type InventoryComponent={instance:number;ecosystem:string;name:string;exact_version:string|null;relationship:string;development:boolean|null;public_registry?:boolean};
export const packageKey=(c:PackageIdentity)=>JSON.stringify([c.ecosystem,c.name,c.version]);
export const canQuery=(c:InventoryComponent)=>c.public_registry===true && supportedEcosystem(c.ecosystem) && !!c.exact_version && !/^(latest|unknown|any|HEAD|main|master)$/i.test(c.exact_version) && /^[A-Za-z0-9][A-Za-z0-9._+!~:-]{0,127}$/.test(c.exact_version) && /^[^\s\x00-\x1f\x7f]{1,512}$/.test(c.name);
export const freshCheck=(c:PackageCheck,now=Date.now())=>Number.isFinite(Date.parse(c.checked_at)) && Date.parse(c.checked_at)<=now+300000 && now-Date.parse(c.checked_at)<24*3600000;
export const osvHref=(id:string)=>id.startsWith('osv-')?`https://osv.dev/vulnerability/${encodeURIComponent(id.slice(4))}`:`/advisory/${encodeURIComponent(id)}`;
export function matchingRecords(check:PackageCheck) {
 const normalize=(e:string,n:string)=>e==='PyPI'?n.toLowerCase().replace(/[-_.]+/g,'-'):e==='NuGet'?n.toLowerCase():n;
 return check.records.filter(r=>!r.withdrawn&&r.affected.some(a=>a.package.ecosystem===check.ecosystem&&normalize(check.ecosystem,a.package.name)===normalize(check.ecosystem,check.name)));
}
