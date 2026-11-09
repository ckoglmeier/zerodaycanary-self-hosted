"use client";
// Progressive enhancement: the full list renders without JavaScript; this narrows it in place.
import { useEffect, useRef, useState } from "react";

export function FeedFilter({ children }: { children: React.ReactNode }) {
  const [text, setText] = useState("");
  const [severity, setSeverity] = useState("");
  const [shown, setShown] = useState<number | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const items = ref.current?.querySelectorAll<HTMLLIElement>("[data-feed] > li") ?? [];
    let n = 0;
    const t = text.trim().toLowerCase();
    items.forEach((li) => {
      const ok = (!t || (li.dataset.search ?? "").includes(t)) && (!severity || li.dataset.severity === severity);
      li.hidden = !ok;
      if (ok) n++;
    });
    setShown(t || severity ? n : null);
  }, [text, severity]);

  return (
    <div className="stack">
      <div className="inline-form" style={{ gridTemplateColumns: "1fr 220px" }} role="search">
        <div>
          <label htmlFor="q">Search technology or alert</label>
          <input id="q" type="search" placeholder="e.g. PHP, GitLab, CVE-2026-…" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <div>
          <label htmlFor="sev">Severity</label>
          <select id="sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">Any</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>
      </div>
      <p className="small muted" aria-live="polite">
        {shown === null ? "" : shown === 0 ? "No reviewed records match these filters." : `${shown} matching record${shown === 1 ? "" : "s"}.`}
      </p>
      <div ref={ref}>{children}</div>
    </div>
  );
}
