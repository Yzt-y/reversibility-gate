/**
 * Reversibility gate: a pre-dispatch policy layer over `tools/pre-execute`,
 * `ctx.tools.guard()`, and `tools/post-execute`. It classifies every call by
 * side-effect reversibility, asks for approval while a risky signature is
 * untrusted, auto-allows once it has earned trust, never lets redline calls
 * inherit that trust, and records every decision in an append-only audit trail.
 * @module @deepseek-ai/dsh-reversibility-gate
 */
import type { Context } from '@deepseek-ai/cordis';
import { Config } from './config.ts';
export { Config };
/** Stable Loader identity. */
export declare const name = "reversibility-gate";
/** The policy layer reads and guards the tool registry. */
export declare const inject: string[];
/**
 * Install the pre-execute policy, the post-execute observer, and the
 * self-protection guard. All three are effects of this plugin's context, so
 * unloading removes every listener and the in-memory ledger with it.
 * @param ctx - plugin context; effects and registrations are scoped to it.
 * @param config - validated configuration supplied by the Loader.
 */
export declare function apply(ctx: Context, config: Config): void;
//# sourceMappingURL=index.d.ts.map