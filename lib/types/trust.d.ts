/**
 * Progressive grants: an in-memory record of which operation signatures have
 * earned auto-allow. State is written only from the post-execute observation
 * path, never persisted, and never consulted for redline calls.
 * @module @deepseek-ai/dsh-reversibility-gate/trust
 */
import type { RiskTier } from './types.ts';
/** Decision the ledger derives for one call. */
export type TrustDecision = 'allow' | 'ask';
/**
 * Per-instance progressive-grant ledger.
 *
 * `safe` calls always pass, `redline` calls always ask, and a `risky` call
 * passes only after `threshold` consecutive approved-and-successful outcomes
 * for the same signature.
 */
export declare class TrustLedger {
    readonly threshold: number;
    private readonly states;
    /**
     * @param threshold - consecutive successes required for auto-allow; also the number reported in audit reasons.
     * @throws Error when the threshold is not a positive integer.
     */
    constructor(threshold: number);
    /**
     * Approved count currently recorded for one signature.
     * @param signature - signature hash.
     * @returns the consecutive-success count, zero when absent.
     */
    approvedCount(signature: string): number;
    /**
     * Decide whether a call of this tier may proceed without asking.
     * @param tier - classification of the pending call.
     * @param signature - signature hash of the pending call.
     * @returns `allow` to proceed, `ask` to require approval.
     */
    decide(tier: RiskTier, signature: string): TrustDecision;
    /**
     * Record one approved-and-successful outcome for a signature.
     * @param signature - signature hash of the call that succeeded.
     */
    confirm(signature: string): void;
    /**
     * Revoke a signature's grants after one failure or denial.
     * @param signature - signature hash of the call that failed.
     */
    reset(signature: string): void;
}
//# sourceMappingURL=trust.d.ts.map