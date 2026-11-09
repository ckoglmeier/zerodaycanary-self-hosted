"use client";
// Submit button that prevents duplicate submissions and announces progress politely.
import { useEffect, useRef, useState } from "react";

export function Submit({ children, busy, className = "btn btn-primary", name, value, confirm }: { children: React.ReactNode; busy: string; className?: string; name?: string; value?: string; confirm?: string }) {
  const [pending, setPending] = useState(false);
  const ref = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const form = ref.current?.form;
    if (!form) return;
    const onSubmit = (e: SubmitEvent) => {
      if (e.submitter !== ref.current) return;
      if (confirm && !window.confirm(confirm)) {
        e.preventDefault();
        return;
      }
      setPending(true);
    };
    form.addEventListener("submit", onSubmit);
    const reset = () => setPending(false);
    window.addEventListener("pageshow", reset);
    return () => {
      form.removeEventListener("submit", onSubmit);
      window.removeEventListener("pageshow", reset);
    };
  }, [confirm]);
  return (
    <>
      <button ref={ref} type="submit" className={className} name={name} value={value} aria-disabled={pending} onClick={(e) => pending && e.preventDefault()}>
        {pending ? busy : children}
      </button>
      <span className="sr-only" aria-live="polite">
        {pending ? busy : ""}
      </span>
    </>
  );
}
