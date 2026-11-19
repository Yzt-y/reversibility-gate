import { describe, expect, it } from 'vitest'
import { TrustLedger } from '../src/trust.ts'

/**
 * Progressive-grant suite: the ask → allow → revoke cycle (readme AC-3) and the
 * rule that a redline signature never enters the ledger (AC-4).
 */
describe('TrustLedger', () => {
  it('rejects a threshold that cannot be reached by counting successes', () => {
    expect(() => new TrustLedger(0)).toThrow(/positive integer/)
    expect(() => new TrustLedger(1.5)).toThrow(/positive integer/)
  })

  it('allows safe calls and always asks for redline calls', () => {
    const ledger = new TrustLedger(3)
    expect(ledger.decide('safe', 'sig')).toBe('allow')
    expect(ledger.decide('redline', 'sig')).toBe('ask')
  })

  it('asks for an untrusted risky call, allows it after the threshold, and revokes on failure (AC-3)', () => {
    const ledger = new TrustLedger(3)
    expect(ledger.decide('risky', 'sig')).toBe('ask')
    expect(ledger.approvedCount('sig')).toBe(0)
    ledger.confirm('sig')
    ledger.confirm('sig')
    expect(ledger.decide('risky', 'sig')).toBe('ask')
    ledger.confirm('sig')
    expect(ledger.approvedCount('sig')).toBe(3)
    expect(ledger.decide('risky', 'sig')).toBe('allow')
    ledger.reset('sig')
    expect(ledger.approvedCount('sig')).toBe(0)
    expect(ledger.decide('risky', 'sig')).toBe('ask')
  })

  it('never lets a redline signature inherit trust, whatever its count (AC-4)', () => {
    const ledger = new TrustLedger(1)
    for (let count = 0; count < 5; count += 1) ledger.confirm('redline-sig')
    expect(ledger.approvedCount('redline-sig')).toBe(5)
    expect(ledger.decide('redline', 'redline-sig')).toBe('ask')
  })

  it('keeps signatures independent', () => {
    const ledger = new TrustLedger(2)
    ledger.confirm('a')
    ledger.confirm('a')
    expect(ledger.decide('risky', 'a')).toBe('allow')
    expect(ledger.decide('risky', 'b')).toBe('ask')
  })
})
