// Deterministic version parsing and comparison. Anything we cannot parse is
// reported as unparseable so callers treat it as unknown instead of guessing.

export type ParsedVersion = {
  raw: string;
  nums: number[];
  pre: (string | number)[] | null; // prerelease identifiers, null for a release
  distro: string | null; // e.g. "1ubuntu0.2", "+deb12u1": vendor build that may carry backports
};

const VERSION_RE = /^v?(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.+~-]+))?$/;
const DISTRO_HINT = /(ubuntu|deb|el\d|fc\d|amzn|alpine|suse|centos|rhel|bpo)/i;

export function parseVersion(raw: string): ParsedVersion | null {
  const s = raw.trim();
  const m = VERSION_RE.exec(s);
  if (!m) {
    // Debian/Ubuntu style "8.2.20-1ubuntu0.2" or "8.1.2~deb12" fall through here only
    // if they contain characters outside the regex; try a tolerant split.
    const t = /^v?(\d+(?:\.\d+){0,3})[-~+](.+)$/.exec(s);
    if (!t) return null;
    return { raw: s, nums: t[1].split(".").map(Number), pre: null, distro: t[2] };
  }
  const nums = m[1].split(".").map(Number);
  let pre: ParsedVersion["pre"] = null;
  let distro: string | null = m[3] ?? null;
  if (m[2]) {
    if (DISTRO_HINT.test(m[2]) || /^\d+[a-z]/i.test(m[2])) distro = m[2];
    else pre = m[2].split(".").map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  }
  return { raw: s, nums, pre, distro };
}

function cmpNums(a: number[], b: number[]): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

function cmpPre(a: ParsedVersion["pre"], b: ParsedVersion["pre"]): number {
  if (!a && !b) return 0;
  if (!a) return 1; // release > prerelease
  if (!b) return -1;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x < y ? -1 : 1;
    if (typeof x === "number") return -1;
    if (typeof y === "number") return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

export function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  return cmpNums(a.nums, b.nums) || cmpPre(a.pre, b.pre);
}

export function cmp(a: string, b: string): number | null {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return null;
  return compareVersions(pa, pb);
}

// Major.minor branch key, used to tell whether a version falls on a branch an
// advisory explicitly covers.
export function branchOf(v: ParsedVersion, depth = 2): string {
  return v.nums.slice(0, depth).join(".");
}
