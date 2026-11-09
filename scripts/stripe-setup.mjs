// Creates (once) the test-mode product and monthly per-system price used by checkout.
// The amount comes from STRIPE_PRICE_MONTHLY_CENTS. Refuses to run with a live key.
// Usage: node --env-file=.env.local scripts/stripe-setup.mjs
import Stripe from "stripe";

const key = process.env.STRIPE_SECRET_KEY ?? "";
if (!/^(sk|rk)_test_/.test(key)) throw new Error("Refusing to run without a test-mode Stripe key.");
const cents = Number(process.env.STRIPE_PRICE_MONTHLY_CENTS);
if (!Number.isInteger(cents) || cents <= 0) throw new Error("Set STRIPE_PRICE_MONTHLY_CENTS.");
const stripe = new Stripe(key);
const LOOKUP = "zdc_monitored_system_monthly";

const existing = (await stripe.prices.list({ lookup_keys: [LOOKUP], active: true, limit: 1 })).data[0];
if (existing && existing.unit_amount === cents) {
  console.log("price exists", existing.id, existing.unit_amount, existing.currency);
} else {
  const product =
    (await stripe.products.search({ query: "metadata['zdc']:'monitored_system'" })).data[0] ??
    (await stripe.products.create({ name: "Zero Day Canary monitored system", metadata: { zdc: "monitored_system" } }));
  const price = await stripe.prices.create({
    product: product.id,
    currency: "usd",
    unit_amount: cents,
    recurring: { interval: "month" },
    lookup_key: LOOKUP,
    transfer_lookup_key: true,
    nickname: "Per monitored system, monthly (placeholder price pending owner decision)",
  });
  console.log("price created", price.id, price.unit_amount, price.currency);
}
