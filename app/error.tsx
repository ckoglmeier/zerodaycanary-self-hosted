'use client';
import {useEffect} from 'react';
import {reportBrowserError} from '@/lib/monitoring/client';
export default function ErrorPage({error,reset}:{error:Error&{digest?:string};reset:()=>void}){
  useEffect(()=>{if(!error.digest)reportBrowserError();},[error]);
  return <main className="container section"><h1>We couldn’t load this page.</h1><p>Try loading the page again. If you were submitting something, check its status before retrying.</p><button className="btn btn-primary" onClick={reset}>Try again</button></main>;
}
