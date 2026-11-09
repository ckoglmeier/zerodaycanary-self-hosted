import Stripe from 'stripe';
const key=process.env.STRIPE_SECRET_KEY||'';
if(!/^(sk|rk)_test_/.test(key))throw Error('This setup only permits Stripe test keys.');
const stripe=new Stripe(key),lookup='zdc_nonprofit_monitored_system_monthly';
const prior=(await stripe.prices.list({lookup_keys:[lookup],active:true,limit:1})).data[0];
if(prior){if(prior.unit_amount!==1900||prior.currency!=='usd'||prior.recurring?.interval!=='month')throw Error('Existing nonprofit price is inconsistent; will not replace it.');console.log('Test nonprofit monthly price already configured.');}
else{const standard=(await stripe.prices.list({lookup_keys:['zdc_monitored_system_monthly'],active:true,limit:1})).data[0];if(!standard)throw Error('Configure the standard test price first.');await stripe.prices.create({product:typeof standard.product==='string'?standard.product:standard.product.id,currency:'usd',unit_amount:1900,recurring:{interval:'month'},lookup_key:lookup,nickname:'Self-reported nonprofit discount — $19 per monitored app/month',metadata:{zdc_nonprofit:'true'}});console.log('Configured $19 monthly nonprofit price in Stripe TEST mode. No charge or subscription created.');}
