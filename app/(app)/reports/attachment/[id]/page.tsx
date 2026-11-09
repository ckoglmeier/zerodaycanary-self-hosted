import { redirect,notFound } from "next/navigation";
import { requireViewer } from "@/lib/auth";
import { sharedReportData } from "@/lib/review/reports";
import { one } from "@/lib/db";
export default async function Attachment({params}:{params:Promise<{id:string}>}){const {id}=await params,v=await requireViewer(`/reports/attachment/${id}`);if(!/^[0-9a-f-]{36}$/.test(id))notFound();const r=await one<{page_id:string}>('select page_id from shared_reports where id=$1',[id]);if(!r)notFound();await sharedReportData(v,r.page_id,id).catch(()=>notFound());redirect(`/reports/${r.page_id}?rev=${id}`);}
