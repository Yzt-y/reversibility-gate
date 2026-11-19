/**
 * Reversibility gate: a pre-dispatch policy layer over `tools/pre-execute`,
 * `ctx.tools.guard()`, and `tools/post-execute`. It classifies every call by
 * side-effect reversibility, asks for approval while a risky signature is
 * untrusted, auto-allows once it has earned trust, never lets redline calls
 * inherit that trust, and records every decision in an append-only audit trail.
 * @module @deepseek-ai/dsh-reversibility-gate
 */
import { approvalPolicyOf } from "./approval-policy.js";
import { AuditSink, messageOf, resolveAuditFile } from "./audit.js";
import { classify } from "./classify.js";
import { compilePolicy, Config } from "./config.js";
import { selfProtectionReason } from "./guard.js";
import { signatureOf } from "./signature.js";
import { TrustLedger } from "./trust.js";
export { Config };
/** Stable Loader identity. */
export const name = 'reversibility-gate';
/** The policy layer reads and guards the tool registry. */
export const inject = ['tools'];
/**
 * Install the pre-execute policy, the post-execute observer, and the
 * self-protection guard. All three are effects of this plugin's context, so
 * unloading removes every listener and the in-memory ledger with it.
 * @param ctx - plugin context; effects and registrations are scoped to it.
 * @param config - validated configuration supplied by the Loader.
 */
export function apply(ctx, config) {
    const policy = compilePolicy(config);
    const trust = new TrustLedger(policy.trustThreshold);
    const pending = new Map();
    const sinks = new Map();
    /** Reuse one writable sink per resolved destination. */
    const sinkFor = (workspace) => {
        const file = resolveAuditFile(policy.auditFile, workspace);
        const existing = sinks.get(file);
        if (existing !== undefined)
            return existing;
        const created = new AuditSink(file);
        sinks.set(file, created);
        return created;
    };
    /** Pure classification inputs of one execution. */
    const callOf = (exec) => ({
        toolName: exec.name,
        args: exec.arguments,
        workspace: exec.agent?.session.header.cwd,
    });
    /** Audited reason for one decision, naming the rule or the earned trust count. */
    const reasonOf = (tier, signature, classification) => {
        if (tier === 'safe')
            return classification.rule;
        if (tier === 'redline')
            return `redline:${classification.rule}`;
        const approved = trust.approvedCount(signature);
        return approved >= policy.trustThreshold ? `signature:approved:${approved}` : `signature:untrusted:${classification.rule}`;
    };
    ctx.on('tools/pre-execute', async (exec, next) => {
        const call = callOf(exec);
        const callId = String(exec.callId);
        try {
            const classification = classify(call, policy);
            const signature = signatureOf(call, policy.signatureTruncateChars);
            const route = trust.decide(classification.tier, signature);
            // Delegate first: another policy's deny, cancel, or ask outranks ours. Only
            // a downstream allow can be raised to `ask`, never the other way around.
            const downstream = await next();
            let decision = downstream;
            let auditReason = reasonOf(classification.tier, signature, classification);
            if (downstream.kind === 'allow' && route === 'ask') {
                const session = exec.agent?.session;
                if (session !== undefined && approvalPolicyOf(ctx.get('approval'), session) === 'never') {
                    // A `never` deployment rejects the ask before any answerer sees it, so
                    // own the denial and say why instead of promising an impossible prompt.
                    decision = {
                        kind: 'deny',
                        reason: `reversibility-gate: ${auditReason} requires approval, but this session's approval policy is never; switch the permission preset to Standard (approval policy ask)`,
                    };
                    auditReason = `policy:never:${auditReason}`;
                }
                else {
                    decision = {
                        kind: 'ask',
                        reason: `reversibility-gate: ${auditReason}`,
                        displayReason: { en: `Approve this ${classification.tier} tool call? Reversibility gate rule: ${classification.rule}.` },
                    };
                }
            }
            sinkFor(call.workspace).write({
                timestamp: new Date().toISOString(),
                callId,
                toolName: exec.name,
                signatureHash: signature,
                riskTier: classification.tier,
                decisionKind: decision.kind === 'cancel' ? 'deny' : decision.kind,
                decisionReason: auditReason,
                event: 'decision',
                ...(classification.tier === 'risky' ? { trustCount: trust.approvedCount(signature) } : {}),
            });
            if (classification.tier === 'risky')
                pending.set(callId, { signature, tier: classification.tier });
            return decision;
        }
        catch (error) {
            // Fail closed: an unauditable or unclassifiable call never reaches the tool.
            ctx.logger.warn(`reversibility-gate: denying ${exec.name}: ${messageOf(error)}`);
            return { kind: 'deny', reason: `reversibility-gate: ${messageOf(error)}` };
        }
    });
    // Observation only: the outcome feeds the ledger and the audit trail, and the
    // decision is returned untouched so the model sees the real result (N2).
    ctx.on('tools/post-execute', async (exec, result, next) => {
        const downstream = await next();
        const callId = String(exec.callId);
        const recorded = pending.get(callId);
        if (recorded === undefined)
            return downstream;
        pending.delete(callId);
        try {
            if (result.isError)
                trust.reset(recorded.signature);
            else
                trust.confirm(recorded.signature);
            sinkFor(exec.agent?.session.header.cwd).write({
                timestamp: new Date().toISOString(),
                callId,
                toolName: exec.name,
                signatureHash: recorded.signature,
                riskTier: recorded.tier,
                decisionKind: result.isError ? 'deny' : 'allow',
                decisionReason: result.isError ? 'outcome:failure' : 'outcome:success',
                event: 'outcome',
                outcome: result.isError ? 'failure' : 'success',
            });
        }
        catch (error) {
            // Rethrowing would turn a settled tool result into an error and rewrite
            // the model-visible outcome, which this observer must never do.
            ctx.logger.warn(`reversibility-gate: observation failed for ${exec.name}: ${messageOf(error)}`);
        }
        return downstream;
    });
    // Monotonic invariants: a throwing guard fails closed through the registry.
    ctx.effect(() => ctx.tools.guard((exec) => {
        const reason = selfProtectionReason(callOf(exec), policy);
        return reason === undefined ? undefined : `reversibility-gate: ${reason}`;
    }));
}
//# sourceMappingURL=index.js.map