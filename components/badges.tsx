import type { AssessmentStatus } from "@/intel/match";
import { STATUS_LABEL } from "@/intel/match";
import type { ExploitationCategory } from "@/intel/schema";

type Tone = "danger" | "warning" | "success" | "neutral" | "brand";

const ICONS: Record<Tone, React.ReactNode> = {
  danger: <path d="M8 1.5 15 14H1L8 1.5Zm0 4.5v4m0 2v.5" />,
  warning: <path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM8 4.5v4.5m0 2v.5" />,
  success: <path d="M2.5 8.5 6 12l7.5-8" />,
  neutral: <path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM5 8h6" />,
  brand: <path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13Z" />,
};

export function Badge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return (
    <span className={`badge b-${tone}`}>
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {ICONS[tone]}
      </svg>
      {children}
    </span>
  );
}

const STATUS_TONE: Record<AssessmentStatus, Tone> = {
  needs_verification: "warning",
  affected_version_matched: "danger",
  applicability_confirmed: "danger",
  fix_verified: "success",
  not_affected: "success",
  not_assessed: "neutral",
};

export function StatusBadge({ status }: { status: AssessmentStatus }) {
  return <Badge tone={STATUS_TONE[status]}>{STATUS_LABEL[status]}</Badge>;
}

export const EXPLOIT_LABEL: Record<ExploitationCategory, string> = {
  known_exploited: "Known exploited",
  public_poc: "Public exploit / PoC",
  none_confirmed: "No confirmed exploit evidence",
};

export function ExploitBadge({ category, withdrawn }: { category: ExploitationCategory; withdrawn?: string }) {
  if (withdrawn) return <Badge tone="neutral">{withdrawn === "superseded" ? "Superseded" : "Withdrawn"}</Badge>;
  return <Badge tone={category === "known_exploited" ? "danger" : category === "public_poc" ? "warning" : "neutral"}>{EXPLOIT_LABEL[category]}</Badge>;
}

export function SeverityText({ severity, score, source }: { severity: string; score: number | null; source: string | null }) {
  const s = severity === "unknown" ? "Severity unknown" : severity[0].toUpperCase() + severity.slice(1);
  return (
    <span>
      {s}
      {score != null ? ` ${score.toFixed(1)}` : ""}
      {source ? <span className="muted"> ({source})</span> : null}
    </span>
  );
}

export const MONITORING_LABEL: Record<string, { label: string; tone: Tone }> = {
  none: { label: "Not monitored", tone: "neutral" },
  pending_payment: { label: "Payment pending", tone: "warning" },
  active: { label: "Monitored", tone: "brand" },
  paused: { label: "Monitoring paused", tone: "neutral" },
  payment_issue: { label: "Payment problem", tone: "danger" },
};

export function MonitoringBadge({ state }: { state: string }) {
  const m = MONITORING_LABEL[state] ?? MONITORING_LABEL.none;
  return <Badge tone={m.tone}>{m.label}</Badge>;
}

export const CLAIM_LABEL: Record<string, { label: string; tone: Tone }> = {
  reported: { label: "Upgrade reported", tone: "neutral" },
  checking: { label: "Checking", tone: "neutral" },
  fix_verified: { label: "Fixed, confirmed by evidence", tone: "success" },
  no_finding: { label: "No affected finding", tone: "neutral" },
  still_affected: { label: "Still affected", tone: "danger" },
  unable_to_confirm: { label: "Unable to confirm", tone: "warning" },
  check_failed: { label: "Check could not complete", tone: "warning" },
};

export function ClaimBadge({ state }: { state: string }) {
  const c = CLAIM_LABEL[state] ?? CLAIM_LABEL.reported;
  return <Badge tone={c.tone}>{c.label}</Badge>;
}
