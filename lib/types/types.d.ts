/**
 * Vocabulary shared by the reversibility gate modules: risk tiers, the pure
 * classification input, extracted side effects, and the audit record.
 * @module @deepseek-ai/dsh-reversibility-gate/types
 */
/**
 * Side-effect reversibility of one tool call. `safe` has no durable effect,
 * `risky` changes state recoverable from the session workspace, and `redline`
 * reaches state this deployment cannot recover.
 */
export type RiskTier = 'safe' | 'risky' | 'redline';
/**
 * The pure inputs of classification: no agent, signal, or session log, so the
 * same value always classifies identically.
 */
export interface CallInput {
    /** Registered tool name as the model called it. */
    readonly toolName: string;
    /** Parsed call arguments; the effect extractor reads only known keys. */
    readonly args: unknown;
    /** Session workspace root; `undefined` when the caller has no workspace. */
    readonly workspace: string | undefined;
}
/** One classification result plus the rule that produced it. */
export interface Classification {
    readonly tier: RiskTier;
    /** Stable rule id recorded in the audit trail, e.g. `remote:remote-state`. */
    readonly rule: string;
}
/** Where one effect target sits relative to the session workspace. */
export type TargetScope = 'workspace' | 'outside' | 'unknown';
/** One path an effect reaches, with its resolved scope. */
export interface Target {
    /** The path exactly as the call spelled it; never written to the audit trail. */
    readonly path: string;
    readonly scope: TargetScope;
}
/** Remote effect families: durable state, an outbound message, or money. */
export type RemoteSurface = 'state' | 'message' | 'spend';
/** One side effect a call would have, independent of whether it may run. */
export type Effect = {
    readonly kind: 'read';
    readonly detail: string;
} | {
    readonly kind: 'delegate';
    readonly detail: string;
} | {
    readonly kind: 'mutate';
    readonly detail: string;
    readonly targets: readonly Target[];
} | {
    readonly kind: 'destroy';
    readonly detail: string;
    readonly targets: readonly Target[];
} | {
    readonly kind: 'remote';
    readonly detail: string;
    readonly surface: RemoteSurface;
} | {
    readonly kind: 'privilege';
    readonly detail: string;
} | {
    readonly kind: 'unknown';
    readonly detail: string;
    readonly severity: 'risky' | 'redline';
};
/** Progressive-grant bookkeeping for one signature. */
export interface SignatureState {
    /** Consecutive approved-and-successful outcomes; reset by one failure. */
    approvedCount: number;
    readonly lastOutcome: 'success' | 'failure' | 'denied';
}
/** One JSONL audit line. Optional fields distinguish a decision from its outcome. */
export interface AuditRecord {
    readonly timestamp: string;
    readonly callId: string;
    readonly toolName: string;
    readonly signatureHash: string;
    readonly riskTier: RiskTier;
    readonly decisionKind: 'allow' | 'deny' | 'ask';
    readonly decisionReason: string;
    /** `decision` is written before dispatch; `outcome` after the call settles. */
    readonly event: 'decision' | 'outcome';
    /** Approved-count at decision time, for risky calls only. */
    readonly trustCount?: number;
    /** Post-execute observation of the settled call. */
    readonly outcome?: 'success' | 'failure';
}
//# sourceMappingURL=types.d.ts.map