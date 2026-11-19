/**
 * Append-only JSONL audit trail. Every decision is written synchronously before
 * it is returned, and a write that fails makes the caller deny the call:
 * a decision without a traceable record never reaches the tool.
 * @module @deepseek-ai/dsh-reversibility-gate/audit
 */
import type { AuditRecord } from './types.ts';
/** Raised when the audit destination cannot be resolved or written. */
export declare class AuditUnavailableError extends Error {
    /**
     * @param message - why the trail is unavailable.
     */
    constructor(message: string);
}
/**
 * Best-effort message for an arbitrary thrown value.
 * @param error - the thrown value.
 * @returns a printable message.
 */
export declare function messageOf(error: unknown): string;
/**
 * Resolve the configured audit destination against the session workspace.
 * @param auditFile - configured destination, absolute or workspace-relative.
 * @param workspace - session workspace root, when the caller has one.
 * @returns the absolute destination path.
 * @throws AuditUnavailableError when a relative destination has no workspace to resolve against.
 */
export declare function resolveAuditFile(auditFile: string, workspace: string | undefined): string;
/** One writable JSONL destination. */
export declare class AuditSink {
    readonly file: string;
    /**
     * Create the destination's directory and verify it is writable before any
     * decision depends on it, so an unusable trail fails at the first call rather
     * than after an allowed one.
     * @param file - absolute audit file path.
     * @throws AuditUnavailableError when the directory cannot be created or the file cannot be opened.
     */
    constructor(file: string);
    /**
     * Append one record as a single JSONL line.
     * @param record - the record to persist.
     * @throws AuditUnavailableError when the write fails.
     */
    write(record: AuditRecord): void;
}
//# sourceMappingURL=audit.d.ts.map