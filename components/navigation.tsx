"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { ADMIN_NAV, WORKSPACE_NAV, sectionActive, workspaceSection, type NavigationViewer } from "@/lib/navigation";

export function Navigation({ initialViewer }: { initialViewer?: NavigationViewer }) {
  const path = usePathname() || "/";
  const [viewer, setViewer] = useState<NavigationViewer | null>(initialViewer ?? null);
  const [loading, setLoading] = useState(!initialViewer);
  const [open, setOpen] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    const refresh = () => fetch("/api/app/session", { cache: "no-store", signal: controller.signal })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(data => { setViewer(data.viewer); setLoading(false); })
      .catch(() => { if (!controller.signal.aborted) setLoading(false); });
    // Private pages have a server-validated identity. Public pages remain
    // shared-cacheable and obtain identity only in this browser boundary.
    if (!initialViewer) void refresh();
    window.addEventListener("focus", refresh);
    return () => { controller.abort(); window.removeEventListener("focus", refresh); };
  }, [path, initialViewer]);

  useEffect(() => { setOpen(false); }, [path]);
  useEffect(() => {
    if (!open) return;
    const escape = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); trigger.current?.focus(); } };
    const outside = (e: PointerEvent) => { if (!menu.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("keydown", escape);
    document.addEventListener("pointerdown", outside);
    return () => { document.removeEventListener("keydown", escape); document.removeEventListener("pointerdown", outside); };
  }, [open]);

  const workspace = workspaceSection(path);
  const admin = path === "/operator" || path.startsWith("/operator/");
  const links = [
    ...(viewer ? [{ href: "/systems", label: "Workspace", active: workspace }] : []),
    { href: "/advisories", label: "Alerts", active: sectionActive(path, "/advisories") },
    { href: "/docs/api", label: "API", active: sectionActive(path, "/docs/api") },
    ...(!viewer ? [{ href: "/pricing", label: "Pricing", active: path === "/pricing" }] : []),
    { href: viewer ? "/account" : "/login", label: viewer ? "Account" : loading ? "Account" : "Sign in", active: /^\/(account|billing|operator)(\/|$)/.test(path) || path === "/login" },
  ];

  return <>
    <div className="navigation" ref={menu}>
      <button ref={trigger} className="btn btn-secondary nav-toggle" aria-expanded={open} aria-controls="global-navigation" onClick={() => setOpen(!open)}>Menu</button>
      <nav id="global-navigation" className={`nav global-nav${open ? " is-open" : ""}`} aria-label="Main">
        {links.map(n => <Link key={n.href} href={n.href} prefetch={false} data-site-action={n.href==="/pricing"?"view_pricing":undefined} aria-current={n.active ? "page" : undefined} onClick={() => setOpen(false)}>{n.label}</Link>)}
      </nav>
    </div>
    {viewer && (workspace || admin || path === "/account" || path.startsWith("/billing")) ? <div className="workspace-bar">
      <div className="workspace-identity"><strong>{admin ? "Administration" : viewer.organization || "Your workspace"}</strong><span className="small muted">{viewer.email}</span></div>
      {workspace ? <nav className="nav workspace-nav" aria-label="Workspace">{WORKSPACE_NAV.map(n => <Link key={n.href} href={n.href} prefetch={false} aria-current={sectionActive(path,n.href) ? "page" : undefined}>{n.label}</Link>)}</nav> : null}
      {admin && viewer.isOperator ? <nav className="nav workspace-nav" aria-label="Administration">{ADMIN_NAV.map(n => <Link key={n.href} href={n.href} prefetch={false} aria-current={sectionActive(path,n.href) ? "page" : undefined}>{n.label}</Link>)}</nav> : null}
    </div> : null}
  </>;
}
