"use client";
import { useState } from "react";

export function CopyButton({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  const [error, setError] = useState(false);
  return (
    <div className="stack" style={{ ["--gap" as string]: "8px" }}>
      <button
        type="button"
        className="btn btn-secondary"
        onClick={async () => {
          setError(false);
          try {
            await navigator.clipboard.writeText(text);
            setDone(true);
            setTimeout(() => setDone(false), 2500);
          } catch {
            setDone(false);
            setError(true);
          }
        }}
      >
        {done ? "Copied" : label}
      </button>
      <span className="sr-only" aria-live="polite">
        {done ? "Copied to clipboard" : ""}
      </span>
      {error ? <p className="field-error" role="alert">Could not copy automatically. Open “Show text” below and copy the text manually.</p> : null}
      <details>
        <summary className="small">Show text</summary>
        <textarea readOnly value={text} className="small" rows={8} aria-label={label} />
      </details>
    </div>
  );
}
