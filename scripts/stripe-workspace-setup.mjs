// Prepare the approved workspace prices in TEST mode only. Does not change legacy prices or live billing.
import Stripe from 'stripe';
if(!process.env.STRIPE_SECRET_KEY?.startsWith('sk_test_'))throw Error('Stripe TEST key required');
const stripe=new Stripe(process.env.STRIPE_SECRET_KEY),lookup='zdc_workspace_team_monthly';
const current=(await stripe.prices.list({lookup_keys:[lookup],active:true,limit:1})).data[0];
if(current){if(current.unit_amount!==4900||current.currency!=='usd'||current.recurring?.interval!=='month')throw Error('Existing test price differs; review before replacing');console.log('Workspace TEST price already configured');}
else{const product=await stripe.products.create({name:'Zero Day Canary Team workspace',metadata:{zdc:'workspace_team'}});await stripe.prices.create({product:product.id,unit_amount:4900,currency:'usd',recurring:{interval:'month'},lookup_key:lookup,nickname:'Team up to 25 systems — proposed TEST price'});console.log('Created $49 monthly workspace TEST price');}

const nonprofitLookup='zdc_nonprofit_workspace_team_monthly';
const nonprofit=(await stripe.prices.list({lookup_keys:[nonprofitLookup],active:true,limit:1})).data[0];
if(nonprofit){if(nonprofit.unit_amount!==2900||nonprofit.currency!=='usd'||nonprofit.recurring?.interval!=='month')throw Error('Existing nonprofit TEST price differs; do not replace automatically');console.log('Nonprofit workspace TEST price already configured');}
else{const standard=(await stripe.prices.list({lookup_keys:[lookup],active:true,limit:1})).data[0];await stripe.prices.create({product:typeof standard.product==='string'?standard.product:standard.product.id,unit_amount:2900,currency:'usd',recurring:{interval:'month'},lookup_key:nonprofitLookup,nickname:'Nonprofit Team up to 25 systems',metadata:{zdc_nonprofit:'true'}});console.log('Created $29/month nonprofit workspace TEST price');}

const {appendFile}=await import('node:fs/promises');
if(!process.env.STRIPE_WORKSPACE_PORTAL_CONFIGURATION){
 const config=await stripe.billingPortal.configurations.create({business_profile:{headline:'Zero Day Canary billing'},features:{payment_method_update:{enabled:true},invoice_history:{enabled:true},subscription_cancel:{enabled:true,mode:'at_period_end'},subscription_update:{enabled:false}},metadata:{zdc:'workspace_team_test'}});
 await appendFile('.env.local',`\nSTRIPE_WORKSPACE_PORTAL_CONFIGURATION=${config.id}\n`);console.log('Created TEST portal: period-end cancellation, no quantity edits');
}
