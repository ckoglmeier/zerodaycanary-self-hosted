import 'server-only';
import { q,tx } from '../db';
import { canQuery,packageKey,freshCheck,type InventoryComponent,type PackageCheck } from '@/intel/osv';
import { queryPackages } from './client';
export async function storedChecks(components:InventoryComponent[]):Promise<PackageCheck[]> {
 const wanted=[...new Map(components.filter(canQuery).map(c=>{const p={ecosystem:c.ecosystem,name:c.name,version:c.exact_version!};return [packageKey(p),p];})).values()];
 if(!wanted.length)return [];
 const rows=await q<PackageCheck & {checked_at:Date}>(`select p.* from package_checks p join jsonb_to_recordset($1::jsonb) as w(ecosystem text,name text,version text) using(ecosystem,name,version)`,[JSON.stringify(wanted)]);
 return rows.map(r=>({...r,checked_at:r.checked_at.toISOString()}));
}
// Called on authenticated intake and daily refresh, never public reads. Bound work;
// partial/error batches do not replace a previously complete result.
export async function refreshChecks(components:InventoryComponent[],deadline=Date.now()+35000) {
 const stored=await storedChecks(components),map=new Map(stored.map(r=>[packageKey(r),r]));
 const wanted=[...new Map(components.filter(canQuery).map(c=>{const p={ecosystem:c.ecosystem,name:c.name,version:c.exact_version!};return [packageKey(p),p];})).values()]
 .filter(p=>!map.has(packageKey(p))||!freshCheck(map.get(packageKey(p))!))
 .sort((a,b)=>Date.parse(map.get(packageKey(a))?.checked_at||'1970-01-01')-Date.parse(map.get(packageKey(b))?.checked_at||'1970-01-01')).slice(0,500);
 let failed=0,refreshed=0;
 for(let i=0;i<wanted.length&&Date.now()<deadline;i+=50){
  try{const checks=await queryPackages(wanted.slice(i,i+50),fetch,deadline);await tx(async db=>{
   const payload=JSON.stringify(checks);
   await db.query('insert into package_check_history(ecosystem,name,version,checked_at,records) select ecosystem,name,version,checked_at,records from jsonb_to_recordset($1::jsonb) as x(ecosystem text,name text,version text,checked_at timestamptz,records jsonb) where not exists(select 1 from package_check_history h where h.ecosystem=x.ecosystem and h.name=x.name and h.version=x.version and h.records=x.records)',[payload]);
   await db.query('insert into package_checks(ecosystem,name,version,checked_at,records) select ecosystem,name,version,checked_at,records from jsonb_to_recordset($1::jsonb) as x(ecosystem text,name text,version text,checked_at timestamptz,records jsonb) on conflict(ecosystem,name,version) do update set checked_at=excluded.checked_at,records=excluded.records where package_checks.checked_at<excluded.checked_at',[payload]);
  });refreshed+=checks.length;}catch{failed+=Math.min(50,wanted.length-i);}
 }
 return {refreshed,failed,pending:wanted.length-refreshed-failed};
}
