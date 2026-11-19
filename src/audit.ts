/**
 * Append-only JSONL audit trail. Every decision is written synchronously before
 * it is returned, and a write that fails makes the caller deny the call:
 * a decision without a traceable record never reaches the tool.
 * @module @deepseek-ai/dsh-reversibility-gate/audit
 */

import { appendFileSync, closeSync, mkdirSync, openSync, statSync } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'
import type { AuditRecord } from './types.ts'

/** Raised when the audit destination cannot be resolved or written. */
export class AuditUnavailableError extends Error {
  /**
   * @param message - why the trail is unavailable.
   */
  constructor(message: string) {
    super(message)
    this.name = 'AuditUnavailableError'
  }
}

/**
 * Best-effort message for an arbitrary thrown value.
 * @param error - the thrown value.
 * @returns a printable message.
 */
export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Resolve the configured audit destination against the session workspace.
 * @param auditFile - configured destination, absolute or workspace-relative.
 * @param workspace - session workspace root, when the caller has one.
 * @returns the absolute destination path.
 * @throws AuditUnavailableError when a relative destination has no workspace to resolve against.
 */
export function resolveAuditFile(auditFile: string, workspace: string | undefined): string {
  if (isAbsolute(auditFile)) return auditFile
  if (workspace === undefined) {
    throw new AuditUnavailableError(`reversibility-gate: cannot resolve audit file "${auditFile}" without a session workspace`)
  }
  return resolve(workspace, auditFile)
}

/** One writable JSONL destination. */
export class AuditSink {
  /**
   * Create the destination's directory and verify it is writable before any
   * decision depends on it, so an unusable trail fails at the first call rather
   * than after an allowed one.
   * @param file - absolute audit file path.
   * @throws AuditUnavailableError when the directory cannot be created or the file cannot be opened.
   */
  constructor(readonly file: string) {
    try {
      mkdirSync(dirname(file), { recursive: true })
      if (statSync(file, { throwIfNoEntry: false })?.isDirectory() === true) {
        throw new AuditUnavailableError(`reversibility-gate: audit destination "${file}" is a directory`)
      }
      // Opening proves the destination is a writable file without appending a
      // placeholder line a reader would have to skip.
      closeSync(openSync(file, 'a'))
    } catch (error: unknown) {
      if (error instanceof AuditUnavailableError) throw error
      throw new AuditUnavailableError(`reversibility-gate: audit file "${file}" is not writable: ${messageOf(error)}`)
    }
  }

  /**
   * Append one record as a single JSONL line.
   * @param record - the record to persist.
   * @throws AuditUnavailableError when the write fails.
   */
  write(record: AuditRecord): void {
    try {
      appendFileSync(this.file, `${JSON.stringify(record)}\n`, 'utf8')
    } catch (error: unknown) {
      throw new AuditUnavailableError(`reversibility-gate: audit write failed for "${this.file}": ${messageOf(error)}`)
    }
  }
}
