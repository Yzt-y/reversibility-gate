/**
 * Pure side-effect extraction. `effectOf` reads a call's name and arguments and
 * reports the effects it would have; it never reads the filesystem, spawns a
 * process, or consults the clock, so classification stays deterministic and
 * cheap enough for the pre-dispatch path.
 * @module @deepseek-ai/dsh-reversibility-gate/effects
 */
import type { CallInput, Effect } from './types.ts';
/** One shell redirection: `>` overwrites, `>>` appends. */
export interface Redirect {
    readonly op: '>' | '>>';
    readonly target: string;
}
/** One `&&`/`||`/`;`/`|`-separated command with its redirections removed. */
export interface ShellSegment {
    readonly words: readonly string[];
    readonly redirects: readonly Redirect[];
}
/** Structured view of one shell command string. */
export interface ShellAnalysis {
    readonly segments: readonly ShellSegment[];
    /** A pipeline feeds a shell interpreter, so remote content would execute locally. */
    readonly pipeToShell: boolean;
    /** URLs written literally in the command. */
    readonly urls: readonly string[];
    /** False when quoting, substitution, or a malformed construct makes the split unreliable. */
    readonly parsed: boolean;
}
/**
 * Analyze one shell command string.
 * @param command - the command text from the tool arguments.
 * @returns the parsed segments, pipeline-to-shell flag, literal URLs, and whether parsing succeeded.
 */
export declare function analyzeShell(command: string): ShellAnalysis;
/**
 * Extract the side effects one call would have.
 * @param call - pure call inputs (name, arguments, workspace root).
 * @param extraRedlineHosts - deployment-added hosts whose traffic counts as remote state.
 * @returns the effects in command order, never empty.
 */
export declare function effectOf(call: CallInput, extraRedlineHosts: readonly string[]): readonly Effect[];
//# sourceMappingURL=effects.d.ts.map