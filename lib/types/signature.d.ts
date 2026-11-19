/**
 * Operation signatures: one hash over the tool name plus normalization of its
 * arguments, so two calls with the same intent share progressive-grant state.
 * Normalization is deliberately approximate; the README records the tradeoff.
 * @module @deepseek-ai/dsh-reversibility-gate/signature
 */
import type { CallInput } from './types.ts';
/**
 * Compute the signature of one call.
 * @param call - pure call inputs.
 * @param truncateChars - characters retained per argument string.
 * @returns 16 lowercase hex characters derived from the tool name and normalized arguments.
 */
export declare function signatureOf(call: CallInput, truncateChars: number): string;
//# sourceMappingURL=signature.d.ts.map