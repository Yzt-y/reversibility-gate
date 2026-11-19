/**
 * Deterministic risk classification: extract the call's side effects, take the
 * most severe of them, then apply the deployment's tool-level overrides.
 * @module @deepseek-ai/dsh-reversibility-gate/classify
 */
import { effectOf } from "./effects.js";
/** Severity order used to pick the worst effect of a call. */
const TIER_RANK = { safe: 0, risky: 1, redline: 2 };
/**
 * Tier of one effect. A workspace-scoped mutation or deletion is recoverable
 * from the session workspace; anything reaching outside it, or whose target
 * cannot be resolved, is not.
 * @param effect - one extracted side effect.
 * @returns the tier that effect implies on its own.
 */
function tierOf(effect) {
    if (effect.kind === 'read' || effect.kind === 'delegate')
        return 'safe';
    if (effect.kind === 'remote' || effect.kind === 'privilege')
        return 'redline';
    if (effect.kind === 'unknown')
        return effect.severity;
    // The remaining union is exactly mutate/destroy, so a new Effect kind that
    // carries no targets fails to compile here rather than classifying silently.
    return effect.targets.every(target => target.scope === 'workspace') ? 'risky' : 'redline';
}
/**
 * Classify one call by the reversibility of its side effects.
 * @param call - pure call inputs (name, arguments, workspace root).
 * @param policy - compiled deployment policy.
 * @returns the highest tier implied by the call's effects plus the rule that produced it.
 */
export function classify(call, policy) {
    const effects = effectOf(call, policy.extraRedlineHosts);
    // Ties keep the earlier effect, so a compound command reports its first
    // equally severe rule rather than the last one.
    const worst = effects.reduce((best, effect) => (TIER_RANK[tierOf(effect)] > TIER_RANK[tierOf(best)] ? effect : best));
    const tier = tierOf(worst);
    const override = policy.tierOverrides[call.toolName];
    if (override !== undefined && TIER_RANK[override] > TIER_RANK[tier]) {
        return { tier: override, rule: `override:${call.toolName}` };
    }
    return { tier, rule: worst.detail };
}
//# sourceMappingURL=classify.js.map