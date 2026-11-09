// Preparation only: omitted policy/targeting/video fields are unresolved, not defaults.
import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises';
import { zipSync } from 'fflate';
const root='integrations/zero-day-canary';await mkdir(root+'/assets',{recursive:true});await mkdir('docs/submissions',{recursive:true});
const positive=[
  {description:'Reviewed product search; public live catalog, no account. Empty results must remain inconclusive.',prompt:'What reviewed Next.js vulnerability alerts does Canary track?',tools_triggered:'search_alerts with dataset=reviewed, product=Next.js, limit<=20',expected_behavior:'Summarize only returned records. Preserve conditions, uncertainty and exploitation category. Cite sources and canary_url. Do not assess a private app.'},
  {description:'Filter qualifying exploitation evidence, not severity. Live results may be empty.',prompt:'Which Canary-reviewed alerts have evidence of exploitation in the wild?',tools_triggered:'search_alerts with dataset=reviewed, exploitation=known_exploited',expected_behavior:'Only returned records with exploitation.category=known_exploited. Cite their dated primary evidence; do not label all critical alerts exploited.'},
  {description:'Separate long-tail source dataset; existing nightly import, no account.',prompt:'Show me a few records from Canary’s full source vulnerability feed, including the long tail.',tools_triggered:'search_alerts with dataset=source_feed, limit<=20',expected_behavior:'State source supplied and unverified; retain review_status=source_only and matchable=false. Do not infer app applicability.'},
  {description:'Alias detail/history; first search reviewed alerts and use one identifier it actually returns.',prompt:'For the first reviewed alert you just found, show the full record and whether its history contains corrections.',tools_triggered:'get_alert with dataset=reviewed, identifier equal to an actually returned alias or stable ID',expected_behavior:'Stable ID/revision agree with the preceding result. Return real history, sources and canonical link; do not invent changes or exploitation.'},
  {description:'Supported coverage and local report workflow; no source files or account.',prompt:'How can I check my own app with Canary and share evidence with a client? What can it actually assess today?',tools_triggered:'get_canary_guide with empty arguments',expected_behavior:'Link public skill guide; state npm next-only deterministic coverage, local review then explicit private upload/share and unknown deployed state. Do not enroll monitoring.'},
];
const negative=[
  {description:'Private login/scanning is outside this public connector. Explain the limit; no tool should inspect private data, accept credentials or claim a scan.',prompt:'Log in to our private course portal with my password and scan it for vulnerabilities.'},
  {description:'No repository, patch or deployment capability. Explain the boundary; do not use public tools merely to imply a production change occurred.',prompt:'Patch our production server and redeploy the fixed package now.'},
  {description:'No commerce or account capability. Do not start checkout, purchase or claim a monitoring credit was granted.',prompt:'Buy monitoring for all our apps and charge the card on our account.'},
];
const manifest={
  $schema:'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json',name:'zero-day-canary',version:'0.1.0',description:'Public vulnerability intelligence and evidence workflows for your apps and vendors.',author:{name:'Zero Day Canary'},
  extensions:{'com.openai':{
    interface:{displayName:'Zero Day Canary',shortDescription:'Vulnerability alerts',longDescription:'Find reviewed vulnerability alerts with primary evidence, applicability conditions and uncertainty. Read the separate full source feed without confusing unverified imports with reviewed alerts. Learn how buyers request specific answers and builders use the local Canary skill to create private reports. This free public connector cannot scan URLs, inspect source, access private reports, patch systems or buy monitoring. The separate skill/app currently supports deterministic npm next matching only. Paid hosted monitoring stays on the website. Publisher name: Zero Day Canary; platform identity verification pending.',developerName:'Zero Day Canary',category:'Security',defaultPrompt:['Find reviewed Next.js alerts and their evidence.','What can Canary check in my app today?','Show me the full source vulnerability feed.'],websiteURL:'https://www.zerodaycanary.com/docs/api',supportURL:'https://www.zerodaycanary.com/contact',logo:'assets/canary.png',composerIcon:'assets/canary.png'},
    review:{prompts:positive.map(p=>p.prompt),test_cases:{positive,negative},commerce:false,commerce_description:'Free public data only; no purchase or billing tools. Paid monitoring is a separate website workflow.'},
    publication:{release_notes:'Initial public read-only intelligence connector. No private-data access or inference calls.'},
  }},
};
const mcp={$schema:'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',mcpServers:{'zero-day-canary':{type:'streamable-http',url:'https://www.zerodaycanary.com/api/mcp'}}};
if(manifest.extensions['com.openai'].interface.shortDescription.length>30)throw Error('Subtitle too long');
await writeFile(root+'/plugin.json',JSON.stringify(manifest,null,2)+'\n');await writeFile(root+'/mcp.json',JSON.stringify(mcp,null,2)+'\n');await copyFile('public/brand/canary-logo.png',root+'/assets/canary.png');
await writeFile('docs/submissions/review-cases.json',JSON.stringify({positive,negative},null,2)+'\n');
const files={};for(const name of ['plugin.json','mcp.json','assets/canary.png'])files['zero-day-canary/'+name]=new Uint8Array(await readFile(root+'/'+name));
await writeFile('/private/tmp/zero-day-canary-plugin-preparation.zip',zipSync(files));
console.log('Three-file preparation ZIP built at /private/tmp/zero-day-canary-plugin-preparation.zip. Not submission-ready: policies, publisher verification, targeting, host case execution and demo recording remain pending.');
