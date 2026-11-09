"use client";
import { useEffect } from "react";

export function PrintButton() {
  useEffect(() => {
    const opened = new Set<HTMLDetailsElement>();
    const expand = () => document.querySelectorAll<HTMLDetailsElement>(".report-content details:not(.no-print)").forEach(detail => {
      if (!detail.open) { opened.add(detail); detail.open = true; }
    });
    const restore = () => { opened.forEach(detail => { detail.open = false; }); opened.clear(); };
    // Includes browser-menu/keyboard printing. Keep every finding in the printed
    // report, then restore the reader's own disclosure choices afterward.
    window.addEventListener("beforeprint", expand);
    window.addEventListener("afterprint", restore);
    return () => { window.removeEventListener("beforeprint", expand); window.removeEventListener("afterprint", restore); restore(); };
  }, []);
  return (
    <button type="button" className="btn btn-primary" onClick={() => window.print()}>
      Print or save as PDF
    </button>
  );
}
