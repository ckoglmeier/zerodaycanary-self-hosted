// Relative time in lists with an accessible absolute value; exports use explicit UTC.
export function abs(d: string | Date | null | undefined) {
  if (!d) return "—";
  const date = typeof d === "string" ? new Date(d) : d;
  return date.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

export function rel(d: string | Date, now = Date.now()) {
  const t = typeof d === "string" ? new Date(d).getTime() : d.getTime();
  const s = Math.round((now - t) / 1000);
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} hr ago`;
  return `${Math.round(h / 24)} days ago`;
}

export function When({ at, prefix }: { at: string | Date | null | undefined; prefix?: string }) {
  if (!at) return <span className="muted">never</span>;
  const iso = typeof at === "string" ? at : at.toISOString();
  return (
    <time dateTime={iso} title={abs(iso)}>
      {prefix}
      {rel(iso)}
      <span className="sr-only"> ({abs(iso)})</span>
    </time>
  );
}
