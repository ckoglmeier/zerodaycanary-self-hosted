// Reviewed, exact package-identity → catalog product mapping. Product slugs alone do not
// carry ecosystem identity, so only pairs added here (with tests) are matched. No fuzzy
// matching on names or titles. Coverage shown to developers is derived from this table.
export const PACKAGE_PRODUCTS: Record<string, string> = {
  "npm:next": "nextjs",
};

export function productForPackage(ecosystem: string, name: string): string | null {
  return PACKAGE_PRODUCTS[`${ecosystem}:${name}`] ?? null;
}

export const PACKAGE_COVERAGE = Object.entries(PACKAGE_PRODUCTS).map(([k, product]) => {
  const [ecosystem, name] = k.split(":");
  return { ecosystem, name, product };
});

export function advisoryHref(id:string){
 if(id.startsWith('osv-'))return 'https://osv.dev/vulnerability/'+encodeURIComponent(id.slice(4));
 if(/^CVE-[0-9]{4}-[0-9]{4,}$/.test(id))return 'https://www.cve.org/CVERecord?id='+encodeURIComponent(id);
 return '/advisory/'+encodeURIComponent(id);
}
