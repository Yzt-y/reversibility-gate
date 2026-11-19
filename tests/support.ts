import { join, resolve } from 'node:path'
import type { Policy } from '../src/config.ts'
import type { CallInput } from '../src/types.ts'

/**
 * Workspace root used by unit cases. Built from the platform root so the same
 * expectations hold on POSIX and Windows: anything joined beneath it is inside,
 * anything joined to the sibling `outside` directory escapes it.
 */
export const WORKSPACE = join(resolve('/'), 'workspace')

/** One path inside {@link WORKSPACE}. */
export function inside(relativePath: string): string {
  return join(WORKSPACE, relativePath)
}

/** One path that resolves outside {@link WORKSPACE}. */
export function outside(relativePath: string): string {
  return join(resolve('/'), 'outside', relativePath)
}

/** Compiled policy with test defaults. */
export function policyOf(overrides: Partial<Policy> = {}): Policy {
  return {
    trustThreshold: 3,
    auditFile: '.dsh-reversibility/audit.jsonl',
    signatureTruncateChars: 500,
    tierOverrides: {},
    extraRedlineHosts: [],
    extraProtectedPaths: [],
    ...overrides,
  }
}

/** Pure classification input for one call. */
export function callOf(toolName: string, args: unknown, workspace: string = WORKSPACE): CallInput {
  return { toolName, args, workspace }
}

/** Classification input for a caller that has no session workspace (a direct registry caller). */
export function callWithoutWorkspace(toolName: string, args: unknown): CallInput {
  return { toolName, args, workspace: undefined }
}
