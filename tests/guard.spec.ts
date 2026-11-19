import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { selfProtectionReason } from '../src/guard.ts'
import { callOf, inside, policyOf, WORKSPACE } from './support.ts'

/**
 * Guard suite: the invariants that must survive an approval, because
 * `ctx.tools.guard()` is evaluated after the pre-execute decision and has no
 * allow result.
 */
describe('self-protection invariants', () => {
  it('refuses to remove the workspace root itself', () => {
    expect(selfProtectionReason(callOf('bash', { command: 'rm -rf .' }), policyOf())).toMatch(/workspace root/)
    expect(selfProtectionReason(callOf('write', { file_path: WORKSPACE }), policyOf())).toMatch(/workspace root/)
  })

  it('refuses to remove an ancestor of the workspace root', () => {
    expect(selfProtectionReason(callOf('bash', { command: `rm -rf ${resolve('/')}` }), policyOf())).toMatch(/workspace root/)
  })

  it('refuses to touch repository metadata', () => {
    expect(selfProtectionReason(callOf('write', { file_path: inside('.git/config') }), policyOf())).toMatch(/repository metadata/)
  })

  it('refuses to touch the audit trail that proves the decisions', () => {
    expect(selfProtectionReason(callOf('write', { file_path: inside('.dsh-reversibility/audit.jsonl') }), policyOf()))
      .toMatch(/audit trail/)
    expect(selfProtectionReason(callOf('bash', { command: 'rm -rf .dsh-reversibility' }), policyOf()))
      .toMatch(/audit trail/)
  })

  it('refuses to touch a deployment-protected path', () => {
    const policy = policyOf({ extraProtectedPaths: ['secrets'] })
    expect(selfProtectionReason(callOf('write', { file_path: inside('secrets/key.pem') }), policy)).toMatch(/protected path/)
    expect(selfProtectionReason(callOf('write', { file_path: inside('src/key.pem') }), policy)).toBeUndefined()
  })

  it('leaves ordinary calls and read-only effects alone', () => {
    expect(selfProtectionReason(callOf('write', { file_path: inside('src/app.ts') }), policyOf())).toBeUndefined()
    expect(selfProtectionReason(callOf('read', { file_path: inside('.git/config') }), policyOf())).toBeUndefined()
  })

  it('skips the check when the caller has no workspace', () => {
    expect(selfProtectionReason({ toolName: 'bash', args: { command: 'rm -rf .' }, workspace: undefined }, policyOf()))
      .toBeUndefined()
  })
})
