import { readFile } from 'node:fs/promises';
export const runtime = 'nodejs';
export const revalidate = 3600;
export async function GET() {
  const bytes = await readFile(`${process.cwd()}/vendor/companion/zero-day-canary-skill.zip`);
  return new Response(bytes, { headers: { 'content-type': 'application/zip', 'content-disposition': 'attachment; filename="zero-day-canary-skill.zip"', 'cache-control': 'public, max-age=300', 'x-content-type-options': 'nosniff' } });
}
