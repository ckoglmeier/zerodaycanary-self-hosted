import "server-only";
// Host control verification and upgrade confirmation.
// Domain control (DNS TXT) is separate from patch verification: a verified host's claim is
// recorded as a claim, then a fresh public scan decides fix verified / still affected /
// unable to confirm. A claim never overwrites observed evidence.
import { randomBytes } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { q, one } from "./db";
import { analyze } from "./scanjobs";
import { canonicalize } from "./scan/canonical";
import { allAdvisories } from "./catalog";
import { assessAll, STATUS_LABEL } from "@/intel/match";
import { latestSuccessfulObservation, rematchScope } from "./assess";
import { HttpError } from "./auth";
import { rateLimit } from "./rate";

export const CHALLENGE_TTL_HOURS = 24;
export const CONTROL_FRESH_MINUTES = 60;
export const txtName = (host: string) => `_zerodaycanary-challenge.${host}`;
export const txtValue = (token: string) => `zdc-verify=${token}`;

export type TxtResolver = (name: string) => Promise<string[][]>;

export async function scopeForToken(token: string) {
  if (!/^[0-9a-f]{36}$/.test(token)) return null;
  return one<{ scope_id: string; url: string; host: string }>(
    "select s.scope_id, sc.url, sc.host from systems s join scan_scopes sc on sc.id = s.scope_id where s.host_request_token = $1 and s.removed_at is null",
    [token],
  );
}

export async function createChallenge(scopeId: string, host: string) {
  await rateLimit(`challenge:${scopeId}`, 10, 3600);
  const token = randomBytes(16).toString("hex");
  return one<{ id: string; token: string; expires_at: Date }>(
    `insert into host_challenges (scope_id, host, token, expires_at) values ($1,$2,$3, now() + ($4 || ' hours')::interval) returning id, token, expires_at`,
    [scopeId, host, token, String(CHALLENGE_TTL_HOURS)],
  );
}

type Challenge = { id: string; scope_id: string; host: string; token: string; expires_at: Date; verified_at: Date | null; consumed_at: Date | null; verify_attempts: number };

async function dnsHasToken(host: string, token: string, resolver: TxtResolver): Promise<boolean> {
  try {
    const recs = await resolver(txtName(host));
    return recs.some((parts) => parts.join("").trim() === txtValue(token));
  } catch {
    return false;
  }
}

// Checks control for exactly the challenge's host and scope.
export async function verifyChallenge(challengeId: string, scopeId: string, resolver: TxtResolver = resolveTxt) {
  await rateLimit(`verify:${challengeId}`, 20, 3600);
  const ch = await one<Challenge>("select * from host_challenges where id = $1", [challengeId]);
  if (!ch || ch.scope_id !== scopeId) throw new HttpError(404, "Challenge not found for this system.");
  if (ch.consumed_at) throw new HttpError(409, "This challenge was already used. Start a new verification.");
  if (ch.expires_at.getTime() < Date.now()) throw new HttpError(410, "This challenge expired. Start a new verification.");
  await q("update host_challenges set verify_attempts = verify_attempts + 1 where id = $1", [ch.id]);
  const ok = await dnsHasToken(ch.host, ch.token, resolver);
  if (ok) await q("update host_challenges set verified_at = now() where id = $1", [ch.id]);
  return { verified: ok };
}

export type UpgradeInput = { product: string; claimed_version: string; upgraded_at?: string | null; reference_url?: string | null };

export async function reportUpgrade(challengeId: string, scopeId: string, input: UpgradeInput, resolver: TxtResolver = resolveTxt, scanOpts: { forceRescan?: boolean } = {}) {
  await rateLimit(`upgrade:${scopeId}`, 6, 3600);
  const ch = await one<Challenge>("select * from host_challenges where id = $1", [challengeId]);
  if (!ch || ch.scope_id !== scopeId) throw new HttpError(404, "Challenge not found for this system.");
  if (!ch.verified_at) throw new HttpError(403, "Verify domain control first.");
  if (ch.consumed_at) throw new HttpError(409, "This verification was already used for an upgrade report.");
  if (ch.expires_at.getTime() < Date.now()) throw new HttpError(410, "This verification expired.");
  if (Date.now() - ch.verified_at.getTime() > CONTROL_FRESH_MINUTES * 60_000) throw new HttpError(403, "Domain control was verified too long ago. Verify again.");
  // Privileged update: re-check that the record is still in place right now.
  if (!(await dnsHasToken(ch.host, ch.token, resolver))) throw new HttpError(403, "The DNS record is no longer present. Domain control could not be re-confirmed.");
  const consumed = await one<{ id: string }>("update host_challenges set consumed_at = now() where id = $1 and consumed_at is null returning id", [ch.id]);
  if (!consumed) throw new HttpError(409, "This verification was already used.");

  const before = await latestSuccessfulObservation(scopeId);
  const claim = (await one<{ id: string }>(
    `insert into host_claims (scope_id, challenge_id, product, claimed_version, upgraded_at, reference_url, state, before_observation_id)
     values ($1,$2,$3,$4,$5,$6,'checking',$7) returning id`,
    [scopeId, ch.id, input.product, input.claimed_version, input.upgraded_at || null, input.reference_url || null, before?.id ?? null],
  ))!;
  await rematchScope(scopeId, "upgrade_reported");
  if (scanOpts.forceRescan === false) return claim.id;
  await checkClaim(claim.id);
  return claim.id;
}

// Runs the fresh analysis for a claim and records an evidence-based outcome. Safe to retry.
export async function checkClaim(claimId: string) {
  const claim = await one<{ id: string; scope_id: string; product: string; claimed_version: string; before_observation_id: string | null }>(
    "select * from host_claims where id = $1",
    [claimId],
  );
  if (!claim) throw new HttpError(404, "Claim not found.");
  await q("update host_claims set state = 'checking', updated_at = now() where id = $1", [claimId]);
  const scope = (await one<{ url: string }>("select url from scan_scopes where id = $1", [claim.scope_id]))!;
  const r = await analyze(canonicalize(scope.url), { force: true, trigger: "host_upgrade" });
  const after = r.observation;
  if (!after || after.outcome === "failed" || r.cached) {
    await q("update host_claims set state = 'check_failed', after_observation_id = $2, outcome_detail = $3, updated_at = now() where id = $1", [
      claimId, after?.id ?? null,
      after?.outcome === "failed" ? `Could not complete the check: ${after.gaps[0]?.detail ?? "fetch failed"}. The last successful evidence is retained. An unreachable site is not evidence of a fix.` : "The check did not finish. Retry shortly.",
    ]);
    await rematchScope(claim.scope_id, "upgrade_check_failed");
    return;
  }
  const advisories = (await allAdvisories()).filter((a) => a.affected.some((p) => p.product === claim.product));
  const before = claim.before_observation_id ? await one<{ evidence: { techs: never[]; facts: Record<string, boolean> }; observed_at: Date }>("select evidence, observed_at from observations where id = $1", [claim.before_observation_id]) : null;
  const beforeRes = before ? assessAll(advisories, { techs: before.evidence.techs, facts: before.evidence.facts, observed_at: before.observed_at.toISOString() }) : [];
  const prior = beforeRes.map((x) => ({ advisory_id: x.advisory_id, status: x.status, observed_at: before!.observed_at.toISOString() }));
  const afterRes = assessAll(advisories, { techs: after.evidence.techs, facts: after.evidence.facts, observed_at: after.observed_at.toISOString() }, prior).filter((x) =>
    advisories.some((a) => a.id === x.advisory_id),
  );
  const seen = after.evidence.techs.filter((t) => t.product === claim.product && t.version && t.version_basis === "observed");
  let state: string;
  let detail: string;
  if (seen.length === 0) {
    state = "unable_to_confirm";
    detail = `The fresh public check could not see the ${claim.product} version, so the upgrade to ${claim.claimed_version} cannot be confirmed from public evidence. A missing or changed version header is not evidence of a fix. Provide suitable version evidence (for example, an administrator-confirmed version or vendor build reference).`;
  } else {
    const observed = [...new Set(seen.map((t) => t.version))].join(", ");
    const affected = afterRes.filter((x) => x.status === "affected_version_matched" || x.status === "applicability_confirmed");
    const unknown = afterRes.filter((x) => x.status === "needs_verification");
    const mismatch = !seen.some((t) => t.version === claim.claimed_version) ? ` Observed version ${observed} differs from the claimed ${claim.claimed_version}.` : "";
    if (affected.length) {
      state = "still_affected";
      detail = `Fresh evidence shows ${claim.product} ${observed}, still within the affected range for ${affected.map((a) => a.primary_identifier).join(", ")}.${mismatch}`;
    } else if (unknown.length || afterRes.length === 0) {
      state = "unable_to_confirm";
      detail = `Fresh evidence shows ${claim.product} ${observed}, but ${afterRes.length === 0 ? "no reviewed alert covers this product" : `applicability remains unknown for ${unknown.map((a) => a.primary_identifier).join(", ")}`}.${mismatch}`;
    } else if (!beforeRes.some((x) => x.status !== "not_affected")) {
      // Nothing was affected before the claim, so there is no fix to verify.
      state = "no_finding";
      detail = `Fresh evidence shows ${claim.product} ${observed}, outside the affected ranges for: ${afterRes.map((a) => a.primary_identifier).join(", ")}. There was no affected finding before this report, so no fix is being verified.${mismatch}`;
    } else {
      state = "fix_verified";
      detail = `Fresh evidence shows ${claim.product} ${observed}, outside the affected ranges for: ${afterRes.map((a) => `${a.primary_identifier} (${STATUS_LABEL[a.status]})`).join("; ")}. This confirms the fix for these vulnerabilities only; it does not mean the system has no other vulnerabilities.${mismatch}`;
    }
  }
  await q("update host_claims set state = $2, after_observation_id = $3, outcome_detail = $4, updated_at = now() where id = $1", [claimId, state, after.id, detail]);
  await rematchScope(claim.scope_id, "upgrade_checked");
}

export async function claimsForScope(scopeId: string) {
  return q<{ id: string; product: string; claimed_version: string; upgraded_at: Date | null; reference_url: string | null; created_at: Date; state: string; outcome_detail: string | null; updated_at: Date }>(
    "select id, product, claimed_version, upgraded_at, reference_url, created_at, state, outcome_detail, updated_at from host_claims where scope_id = $1 order by created_at desc",
    [scopeId],
  );
}
