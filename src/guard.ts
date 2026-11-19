/**
 * Monotonic self-protection invariants. These checks run after every
 * `tools/pre-execute` decision, so a human approval cannot turn them into a
 * permit: they are registered through `ctx.tools.guard()`, which has no
 * allow result. Ordinary tier policy stays in the waterfall instead.
 * @module @deepseek-ai/dsh-reversibility-gate/guard
 */

import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { resolveAuditFile } from './audit.ts'
import type { Policy } from './config.ts'
import { effectOf } from './effects.ts'
import type { CallInput } from './types.ts'

/**
 * Whether one absolute path is the parent's own path or sits beneath it.
 * @param parent - absolute parent path.
 * @param child - absolute path to test.
 * @returns true when `child` is `parent` or nested inside it.
 */
function contains(parent: string, child: string): boolean {
  const nested = relative(parent, child)
  return nested === '' || (!nested.startsWith('..') && !isAbsolute(nested))
}

/**
 * Check the invariants a session must never break, even with approval.
 * @param call - pure call inputs of the pending execution.
 * @param policy - compiled deployment policy.
 * @returns a denial reason, or undefined when the call breaks no invariant.
 */
export function selfProtectionReason(call: CallInput, policy: Policy): string | undefined {
  if (call.workspace === undefined) return undefined
  const root = resolve(call.workspace)
  const auditFile = resolveAuditFile(policy.auditFile, root)
  const auditDir = dirname(auditFile)
  const gitDir = resolve(root, '.git')
  const protectedPaths = policy.extraProtectedPaths.map(path => resolve(root, path))
  for (const effect of effectOf(call, policy.extraRedlineHosts)) {
    if (effect.kind !== 'mutate' && effect.kind !== 'destroy') continue
    for (const target of effect.targets) {
      const absolute = resolve(root, target.path)
      if (contains(absolute, root)) return 'refusing to remove or replace the workspace root'
      if (contains(gitDir, absolute)) return 'refusing to touch repository metadata'
      if (contains(auditDir, absolute)) return 'refusing to touch the audit trail'
      if (protectedPaths.some(path => contains(path, absolute))) return 'refusing to touch a protected path'
    }
  }
  return undefined
}
