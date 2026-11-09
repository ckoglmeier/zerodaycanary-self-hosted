export const TEAM_SYSTEM_LIMIT=25;
export function monitoringState(sub:{status:string;quantity:number;billing_model:string}|null|undefined,index:number,previous:string){
  const good=['active','trialing'].includes(sub?.status??'');
  if(sub?.billing_model==='per_system'&&!['canceled','incomplete_expired'].includes(sub.status)){
    if(good)return index<sub.quantity?'active':'pending_payment';
    if(['canceled','incomplete_expired'].includes(sub.status))return 'none';
    return ['active','payment_issue'].includes(previous)?'payment_issue':'pending_payment';
  }
  if(index===0)return 'active';
  if(good&&sub?.quantity===1&&index<TEAM_SYSTEM_LIMIT)return 'active';
  return ['active','payment_issue'].includes(previous)?'payment_issue':'pending_payment';
}
