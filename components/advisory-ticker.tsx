"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import type { AdvisoryRecord } from "@/intel/schema";
import { disclosureDate } from "@/lib/recent-advisories";
import { abs } from "@/components/time";
import { EXPLOIT_LABEL } from "@/components/badges";

export type TickerAdvisory = Pick<AdvisoryRecord, "id" | "product" | "title" | "severity" | "published_at" | "exploitation">;

export function AdvisoryTicker({ records, reviewedAt, revision }: { records: TickerAdvisory[]; reviewedAt: string | null; revision: number }) {
  const [index, setIndex] = useState(0);
  const [paused, setPaused] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [announcement, setAnnouncement] = useState("");
  const held = useRef(false);
  const region = useRef<HTMLElement>(null);
  const currentIndex = index % Math.max(records.length, 1);
  const current = records[currentIndex];

  useEffect(() => {
    const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReducedMotion(preference.matches);
    update();
    preference.addEventListener("change", update);
    return () => preference.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    if (paused || reducedMotion || records.length < 2) return;
    const timer = window.setInterval(() => {
      if (document.hidden || held.current || region.current?.contains(document.activeElement)) return;
      setIndex((value) => (value + 1) % records.length);
    }, 8000);
    return () => window.clearInterval(timer);
  }, [paused, reducedMotion, records.length]);

  function next() {
    const nextIndex = (currentIndex + 1) % records.length;
    setIndex(nextIndex);
    setAnnouncement(`${nextIndex + 1} of ${records.length}: ${records[nextIndex].product}. ${records[nextIndex].title}.`);
  }

  return (
    <section className="advisory-ticker" aria-labelledby="ticker-h" ref={region} onMouseEnter={() => { held.current = true; }} onMouseLeave={() => { held.current = false; }}>
      <div className="ticker-header">
        <h2 id="ticker-h">Priority vulnerabilities</h2>
        <p className="ticker-meta">Catalog {revision} · Last reviewed {reviewedAt ? abs(reviewedAt) : "not yet"}</p>
        {records.length > 1 ? <div className="ticker-controls">
          {!reducedMotion ? <button type="button" onClick={() => setPaused((value) => !value)} aria-label={paused ? "Resume vulnerability ticker" : "Pause vulnerability ticker"}>{paused ? "Resume" : "Pause"}</button> : <span className="small">Automatic rotation off</span>}
          <button type="button" onClick={next} aria-label="Next vulnerability">Next <span aria-hidden="true">→</span></button>
        </div> : null}
      </div>
      {current ? <div className="ticker-item">
        <span className="ticker-severity">{current.severity === "unknown" ? "Severity unknown" : current.severity[0].toUpperCase() + current.severity.slice(1)}</span>
        <strong>{current.product}</strong>
        <Link prefetch={false} href={`/advisory/${current.id}`}>{current.title}</Link>
        <span className="ticker-meta">{disclosureDate(current.published_at) ? <>Disclosed {disclosureDate(current.published_at)}</> : "Disclosure date not provided"}</span>
        <span className="ticker-meta">{EXPLOIT_LABEL[current.exploitation.category]}</span>
      </div> : <p className="small">No reviewed alerts yet. <Link prefetch={false} href="/advisories">Browse the public feed</Link>.</p>}
      <span className="sr-only" role="status">{announcement}</span>
    </section>
  );
}
