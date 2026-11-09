# Reference snapshot verification

November 9, 2026. Source based on the last private application revision, exported without its Git history or operational data.

- 293 application tests passed; TypeScript passed.
- Production build passed without a production database or credentials. Database reads are deferred to request time.
- 54 companion tests passed.
- Actual packaged companion smoke passed: install, manifest hashes, supplied catalog, report validation and local API fixture; no production data uploaded.
- Secret-pattern and known-local-credential scans performed on the publication tree, including packaged ZIP content. No matching credentials found.

Not tested: a new Supabase project's full login/report-sharing journey, real email, live Stripe payments, or a new hosting provider's deployment. Existing tests do not make this a maintained or certified security product. Configure and validate your own instance before using real data.

Historical test fixtures and the sample Oracle record are examples, not a maintained advisory feed. No automatic scheduler is installed.
