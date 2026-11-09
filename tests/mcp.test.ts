import { describe, it, expect, vi } from 'vitest';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createCanaryMcp, MCP_BODY_LIMIT, type McpData } from '@/lib/mcp';
import { jsonLd, publicMetadata, PUBLIC_PAGES } from '@/lib/discovery';

const fixture = { id: 'zdc-fixture', identifiers: ['CVE-2099-12345'], product: 'fixture-next', summary: '</script><script>untrusted</script>', status: 'published' };
const setup = (rate = vi.fn(async () => {})) => {
  const data = { listAdvisories: vi.fn(async () => ({ data: [fixture], next_cursor: null })), catalogMeta: vi.fn(async () => ({ catalog_revision: 4, catalog_updated_at: '2026-10-22T12:00:00Z' })), getAdvisory: vi.fn(async (id: string) => id === 'missing' ? null : ({ record: fixture, history: [] })), listSources: vi.fn(async () => ({ data: [{ id: 'src-fixture', review_status: 'source_only', matchable: false }], next_cursor: null, feed_revision: 3, sync_until: null })), getSource: vi.fn(async () => ({ record: { id: 'src-fixture', review_status: 'source_only' } })) };
  const raw = createCanaryMcp(data as unknown as McpData, { allowedHosts: ['canary.test'], rate });
  // A real HTTP adapter supplies Host; the in-memory Request constructor does not.
  const handle = (req: Request) => { if (!req.headers.has('host')) req.headers.set('host', new URL(req.url).host); return raw(req); };
  return { data, handle, fetch: (async (input: string | URL | Request, init?: RequestInit) => handle(new Request(input, init))) as typeof fetch };
};
async function clientFor(mode: 'legacy' | 'auto' = 'legacy') {
  const ctx = setup();
  const client = new Client({ name: 'canary-protocol-test', version: '1.0.0' }, { versionNegotiation: { mode } });
  await client.connect(new StreamableHTTPClientTransport(new URL('https://canary.test/api/mcp'), { fetch: ctx.fetch }));
  return { ...ctx, client };
}
const call = (client: Client, name: string, args: Record<string, unknown> = {}) => client.callTool({ name, arguments: args });
describe('public read-only MCP', () => {
  for (const mode of ['legacy','auto'] as const) it(`negotiates ${mode}, lists annotations, and calls all three tools`, async () => {
    const { client, data } = await clientFor(mode);
    try {
      const { tools } = await client.listTools();
      expect(tools.map(t => t.name)).toEqual(['search_alerts','get_alert','get_canary_guide']);
      tools.forEach(t => expect(t.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, openWorldHint: true }));
      const search = await call(client,'search_alerts',{ product: 'next', limit: 2 });
      expect(search.structuredContent).toMatchObject({ dataset: 'reviewed', catalog_revision: 4 });
      expect(data.listAdvisories).toHaveBeenCalledWith(expect.objectContaining({ product: 'next', limit: 2 }));
      const detail = await call(client,'get_alert',{identifier:'CVE-2099-12345'});
      expect(detail.structuredContent).toMatchObject({ record: fixture, canary_url: 'http://localhost:3000/advisory/zdc-fixture' });
      expect((await call(client,'get_canary_guide')).structuredContent).toHaveProperty('coverage', expect.stringContaining('supported OSV ecosystems'));
    } finally { await client.close(); }
  });
  it('preserves source-only status and uses the separate feed', async () => {
    const { client, data } = await clientFor();
    try {
      const r = await call(client,'search_alerts',{dataset:'source_feed',identifier:'CVE-2099-12345'});
      expect(r.structuredContent).toMatchObject({dataset:'source_feed',feed_revision:3,data:[{review_status:'source_only',matchable:false}]});
      expect(data.listAdvisories).not.toHaveBeenCalled();
      expect((await call(client,'get_alert',{dataset:'source_feed',identifier:'CVE-2099-12345'})).structuredContent).toHaveProperty('notice',expect.stringContaining('not independently verified'));
      expect((await call(client,'search_alerts',{dataset:'source_feed',exploitation:'known_exploited'})).isError).toBe(true);
    } finally { await client.close(); }
  });
  it('handles unknown records, invalid cursors and backend failure without fabricating safety', async () => {
    const { client, data } = await clientFor();
    try {
      expect((await call(client,'get_alert',{identifier:'missing'})).isError).toBe(true);
      expect((await call(client,'search_alerts',{cursor:'bad'})).isError).toBe(true);
      data.listAdvisories.mockRejectedValueOnce(new Error('private database connection secret'));
      const r = await call(client,'search_alerts');
      expect(r.isError).toBe(true); expect(JSON.stringify(r)).not.toContain('connection secret');
    } finally { await client.close(); }
  });
  it('rejects unsupported tools and strict-schema invalid arguments', async () => {
    const { client, data } = await clientFor();
    try {
      for (const [name,args] of [['scan_url',{url:'http://localhost'}],['search_alerts',{limit:21}],['get_alert',{identifier:'x',secret:'do not accept'}]] as const) {
        try { const r = await call(client,name,args); expect(r.isError).toBe(true); } catch (e) { expect(String(e)).toMatch(/tool|argument|valid/i); }
      }
      expect(data.listAdvisories).not.toHaveBeenCalled(); expect(data.getAdvisory).not.toHaveBeenCalled();
    } finally { await client.close(); }
  });
  it('checks origin and host before data access', async () => {
    const { handle, data } = setup();
    expect((await handle(new Request('https://evil.test/api/mcp',{method:'POST',body:'{}'}))).status).toBe(403);
    expect((await handle(new Request('https://canary.test/api/mcp',{method:'POST',headers:{origin:'https://evil.test'},body:'{}'}))).status).toBe(403);
    expect(data.listAdvisories).not.toHaveBeenCalled();
  });
  it('bounds body size, validates JSON and content type, and has no session endpoint', async () => {
    const { handle } = setup();
    const post = (body: string, type = 'application/json') => handle(new Request('https://canary.test/api/mcp',{method:'POST',headers:{'content-type':type,accept:'application/json, text/event-stream'},body}));
    expect((await post('x'.repeat(MCP_BODY_LIMIT+1))).status).toBe(413);
    expect((await post('{')).status).toBe(400);
    expect((await post('{}','text/plain')).status).toBe(415);
    for (const method of ['GET','DELETE']) expect((await handle(new Request('https://canary.test/api/mcp',{method}))).status).toBe(405);
    expect((await handle(new Request('https://canary.test/api/mcp',{method:'OPTIONS'}))).status).toBe(204);
  });
  it('enforces shared persistent limit and hides infrastructure errors', async () => {
    const limited = Object.assign(new Error('wait'),{status:429});
    const { handle } = setup(vi.fn(async () => { throw limited; }));
    const r = await handle(new Request('https://canary.test/api/mcp',{method:'POST'}));
    expect(r.status).toBe(429); expect(r.headers.get('retry-after')).toBe('3600');
  });
});
describe('public discovery metadata', () => {
  it('uses a stable public canonical without private URLs or fabricated dates', () => {
    expect(publicMetadata('/docs/skill','Skill','Description').alternates?.canonical).toBe('http://localhost:3000/docs/skill');
    expect(PUBLIC_PAGES.some(p=>p.startsWith('/reports')||p.startsWith('/reviews'))).toBe(false);
    expect(jsonLd({text:'</script><script>bad</script>'})).not.toContain('<');
  });
});
