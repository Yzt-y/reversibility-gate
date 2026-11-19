/**
 * Deterministic risk classification: extract the call's side effects, take the
 * most severe of them, then apply the deployment's tool-level overrides.
 * @module @deepseek-ai/dsh-reversibility-gate/classify
 */
import type { Policy } from './config.ts';
import type { CallInput, Classification } from './types.ts';
/**
 * Classify one call by the reversibility of its side effects.
 * @param call - pure call inputs (name, arguments, workspace root).
 * @param policy - compiled deployment policy.
 * @returns the highest tier implied by the call's effects plus the rule that produced it.
 */
export declare function classify(call: CallInput, policy: Policy): Classification;
//# sourceMappingURL=classify.d.ts.map