import {errorArea} from './policy';
let sent=0;
const seen=new Set<string>();
export function reportBrowserError(area=errorArea(window.location.pathname)) {
  if(sent>=3||seen.has(area))return;
  seen.add(area);sent++;
  void fetch('/api/monitor/errors',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({area}),keepalive:true}).catch(()=>{});
}
