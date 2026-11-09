import {NextResponse} from 'next/server';
import {monitorAuthorized,monitoringHealth} from '@/lib/monitoring/server';
export const dynamic='force-dynamic';
export const maxDuration=15;
const headers={'cache-control':'private, no-store'};
export async function GET(req:Request){
  if(!monitorAuthorized(req))return NextResponse.json({error:'unauthorized'},{status:401,headers});
  try {const health=await monitoringHealth();return NextResponse.json(health,{status:health.ok?200:503,headers});}
  catch{return NextResponse.json({ok:false,issues:['health_unavailable']},{status:503,headers});}
}
