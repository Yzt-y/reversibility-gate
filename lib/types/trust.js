/**
 * Progressive grants: an in-memory record of which operation signatures have
 * earned auto-allow. State is written only from the post-execute observation
 * path, never persisted, and never consulted for redline calls.
 * @module @deepseek-ai/dsh-reversibility-gate/trust
 */
/**
 * Per-instance progressive-grant ledger.
 *
 * `safe` calls always pass, `redline` calls always ask, and a `risky` call
 * passes only after `threshold` consecutive approved-and-successful outcomes
 * for the same signature.
 */
export class TrustLedger {
    threshold;
    states = new Map();
    /**
     * @param threshold - consecutive successes required for auto-allow; also the number reported in audit reasons.
     * @throws Error when the threshold is not a positive integer.
     */
    constructor(threshold) {
        this.threshold = threshold;
        if (!Number.isInteger(threshold) || threshold < 1) {
            throw new Error(`reversibility-gate: trustThreshold must be a positive integer, got ${String(threshold)}`);
        }
    }
    /**
     * Approved count currently recorded for one signature.
     * @param signature - signature hash.
     * @returns the consecutive-success count, zero when absent.
     */
    approvedCount(signature) {
        return this.states.get(signature)?.approvedCount ?? 0;
    }
    /**
     * Decide whether a call of this tier may proceed without asking.
     * @param tier - classification of the pending call.
     * @param signature - signature hash of the pending call.
     * @returns `allow` to proceed, `ask` to require approval.
     */
    decide(tier, signature) {
        if (tier === 'safe')
            return 'allow';
        if (tier === 'redline')
            return 'ask';
        return this.approvedCount(signature) >= this.threshold ? 'allow' : 'ask';
    }
    /**
     * Record one approved-and-successful outcome for a signature.
     * @param signature - signature hash of the call that succeeded.
     */
    confirm(signature) {
        const current = this.states.get(signature);
        this.states.set(signature, { approvedCount: (current?.approvedCount ?? 0) + 1, lastOutcome: 'success' });
    }
    /**
     * Revoke a signature's grants after one failure or denial.
     * @param signature - signature hash of the call that failed.
     */
    reset(signature) {
        this.states.set(signature, { approvedCount: 0, lastOutcome: 'failure' });
    }
}
//# sourceMappingURL=trust.js.map