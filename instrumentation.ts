import type {Instrumentation} from 'next';
export const onRequestError:Instrumentation.onRequestError=async(_error,_request,context)=>{
  if(process.env.NEXT_RUNTIME==='nodejs'){
    const {recordError}=await import('./lib/monitoring/server');
    const {errorArea}=await import('./lib/monitoring/policy');
    await recordError(errorArea(context.routePath));
  }
};
