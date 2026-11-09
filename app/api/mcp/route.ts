import { createCanaryMcp, mcpHosts } from '@/lib/mcp';
import { listAdvisories, getAdvisory, catalogMeta } from '@/lib/catalog';
import { listSources, getSource } from '@/lib/source-feed';
import { rateLimit } from '@/lib/rate';
export const runtime = 'nodejs';
export const maxDuration = 30;
const handle = createCanaryMcp({ listAdvisories, getAdvisory, catalogMeta, listSources, getSource }, {
  allowedHosts: mcpHosts(),
  rate: req => rateLimit(`mcp:${req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'anon'}`, 600, 3600),
});
export const POST = handle;
export const GET = handle;
export const DELETE = handle;
export const OPTIONS = handle;
