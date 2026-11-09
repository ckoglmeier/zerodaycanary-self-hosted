// Evidence about a system, as produced by a public scan, an administrator or (later)
// a local CLI. The basis of every version is explicit so an inference can never be
// displayed or matched as an observation.

// developer_supplied: from a developer's source inventory (lockfile); usable for matching,
// never evidence of the deployed system and never a verified fix.
export type VersionBasis = "observed" | "inferred" | "admin_supplied" | "developer_supplied";

export type TechObservation = {
  product: string; // product key matching AffectedProduct.product
  name: string; // display name
  version: string | null;
  version_basis: VersionBasis | null; // null when version is null
  evidence_type: "header" | "html" | "script" | "cookie" | "endpoint" | "administrator" | "inventory";
  location: string; // URL or "administrator-supplied"
  detail: string; // short human-readable description of the evidence
  confidence: "high" | "medium" | "low";
  observed_at: string;
  limitations: string[];
};

export type EvidenceGap = {
  kind:
    | "fetch_failed"
    | "timeout"
    | "access_denied"
    | "redirect_out_of_scope"
    | "not_html"
    | "too_large"
    | "version_hidden"
    | "unsupported"
    | "blocked_target"
    | "partial";
  detail: string;
  location?: string;
};

export type EvidenceSet = {
  techs: TechObservation[];
  facts: Record<string, boolean>; // e.g. { "nextjs.app_router": true }
  observed_at: string | null;
};
