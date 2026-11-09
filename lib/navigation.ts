export type NavigationViewer = { email: string; organization: string; isOperator: boolean };
export type NavigationItem = { href: string; label: string };

// Used by all sign-in entry points. Preserve request/project query context, but
// never permit an external destination (including backslash URL variants).
export function safeReturnTo(value?: string | null, fallback = "/systems") {
  if (!value || !value.startsWith("/") || /^\/(?:\/|%2f|%5c)/i.test(value) || /[\\\u0000-\u0020\u007f]/.test(value)) return fallback;
  try {
    const url = new URL(value, "https://canary.invalid");
    return url.origin === "https://canary.invalid" ? `${url.pathname}${url.search}${url.hash}` : fallback;
  } catch { return fallback; }
}

export const WORKSPACE_NAV: NavigationItem[] = [
  { href: "/systems", label: "Systems" },
  { href: "/developer", label: "Developer projects" },
  { href: "/requests", label: "Requests" },
];
export const ADMIN_NAV: NavigationItem[] = [
  { href: "/operator/accounts", label: "Accounts" },
  { href: "/operator", label: "Vulnerability intake" },
  { href: "/operator/feed", label: "Source feed" },
  { href: "/operator/costs", label: "Costs" },
  { href: "/operator/contacts", label: "Contact requests" },
  { href: "/operator/communications", label: "Communications" },
];

export function sectionActive(path: string, href: string) {
  if (href === "/systems") return path === "/systems" || path.startsWith("/systems/");
  if (href === "/requests") return path === "/requests" || path.startsWith("/requests/");
  if (href === "/advisories") return path.startsWith("/advisories") || path.startsWith("/advisory/");
  if (href === "/operator") return path === "/operator" || path.startsWith("/operator/intake/");
  return path === href || path.startsWith(href + "/");
}

export function workspaceSection(path: string): boolean {
  return /^\/(systems|developer|requests|reviews|reports)(\/|$)/.test(path);
}
