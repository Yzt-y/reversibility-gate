/**
 * Monotonic self-protection invariants. These checks run after every
 * `tools/pre-execute` decision, so a human approval cannot turn them into a
 * permit: they are registered through `ctx.tools.guard()`, which has no
 * allow result. Ordinary tier policy stays in the waterfall instead.
 * @module @deepseek-ai/dsh-reversibility-gate/guard
 */
import type { Policy } from './config.ts';
import type { CallInput } from './types.ts';
/**
 * Check the invariants a session must never break, even with approval.
 * @param call - pure call inputs of the pending execution.
 * @param policy - compiled deployment policy.
 * @returns a denial reason, or undefined when the call breaks no invariant.
 */
export declare function selfProtectionReason(call: CallInput, policy: Policy): string | undefined;
//# sourceMappingURL=guard.d.ts.map