import { describe, expect, it } from 'vitest'
import { compilePolicy, Config } from '../src/config.ts'

/**
 * Configuration suite: schema defaults reach the policy, hosts are normalized,
 * copied tables stay detached, and the one invalid value the schema cannot
 * express fails plugin load.
 */
describe('compilePolicy', () => {
  it('applies the documented defaults', () => {
    expect(compilePolicy(Config({}))).toEqual({
      trustThreshold: 3,
      auditFile: '.dsh-reversibility/audit.jsonl',
      signatureTruncateChars: 500,
      tierOverrides: {},
      extraRedlineHosts: [],
      extraProtectedPaths: [],
    })
  })

  it('normalizes configured hosts and drops empty entries', () => {
    const policy = compilePolicy(Config({ extraRedlineHosts: [' Internal.CORP ', '', '   '] }))
    expect(policy.extraRedlineHosts).toEqual(['internal.corp'])
  })

  it('copies override and protected-path tables so later mutation cannot widen policy', () => {
    const tierOverrides: Record<string, 'redline'> = { write: 'redline' }
    const extraProtectedPaths = ['secrets']
    const policy = compilePolicy(Config({ tierOverrides, extraProtectedPaths }))
    tierOverrides['read'] = 'redline'
    extraProtectedPaths.push('src')
    expect(policy.tierOverrides).toEqual({ write: 'redline' })
    expect(policy.extraProtectedPaths).toEqual(['secrets'])
  })

  it('rejects a blank audit destination so decisions cannot go untraced', () => {
    expect(() => compilePolicy(Config({ auditFile: '   ' }))).toThrow(/non-empty/)
  })
})
