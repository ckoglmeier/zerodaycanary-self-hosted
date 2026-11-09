import { notFound } from "next/navigation";
import { requireViewer,HttpError } from "@/lib/auth";
import { invitation } from "@/lib/review/requests";
import { Submit } from "@/components/submit";
export const dynamic='force-dynamic';
export const metadata={title:'App check invitation',robots:{index:false,follow:false}};
export default async function Invitation({params}:{params:Promise<{id:string}>}){
 const {id}=await params,v=await requireViewer(`/requests/${id}`);
 let i;try{i=await invitation(v,id);}catch(e){if(e instanceof HttpError&&e.status===404)notFound();if(e instanceof HttpError&&[403,410].includes(e.status))return <section className="panel stack"><h1 className="h-page">Invitation unavailable</h1><p>{e.message}</p><a href="/requests">Your requests</a></section>;throw e;}
 return <section className="panel stack prose"><p className="eyebrow">Invitation from {i.requester}</p><h1 className="h-page">Please check {i.label}</h1><p className="mono">{i.url}</p><p>Open the specific request, reply and share your answer here. You can give a quick confirmation; a full security report is optional.</p><p>Your free report page can also be shared with other clients. Their conversations stay separate.</p><p className="small muted">Signed in as {v.email}. Access is limited to this app’s conversation.</p><form method="post" action={`/api/app/reviews/${id}/accept`}><Submit busy="Opening…">Open request</Submit></form></section>;
}
