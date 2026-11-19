import { describe, expect, it } from 'vitest'
import { signatureOf } from '../src/signature.ts'
import type { CallInput } from '../src/types.ts'

/** Signature of one call with test defaults. */
function sig(toolName: string, args: unknown, truncateChars = 500): string {
  const call: CallInput = { toolName, args, workspace: undefined }
  return signatureOf(call, truncateChars)
}

/**
 * Signature suite: whitespace folding (readme AC-2), path normalization,
 * key-order independence, truncation, and the documented approximation.
 */
describe('signature', () => {
  it('treats insignificant command whitespace as the same operation (AC-2)', () => {
    expect(sig('bash', { command: 'ls   -la' })).toBe(sig('bash', { command: 'ls -la' }))
  })

  it('normalizes separators and trailing separators in path arguments', () => {
    expect(sig('read', { file_path: 'src/app/' })).toBe(sig('read', { file_path: 'src/app' }))
    expect(sig('read', { file_path: 'src\\app' })).toBe(sig('read', { file_path: 'src/app' }))
    expect(sig('read', { file_path: 'src/./app' })).toBe(sig('read', { file_path: 'src/app' }))
    expect(sig('write', { file_path: '/', content: 'x' })).toMatch(/^[0-9a-f]{16}$/)
  })

  it('separates different tools and different arguments', () => {
    expect(sig('read', { file_path: 'a' })).not.toBe(sig('write', { file_path: 'a' }))
    expect(sig('read', { file_path: 'a' })).not.toBe(sig('read', { file_path: 'b' }))
  })

  it('is independent of argument key order', () => {
    expect(sig('bash', { command: 'ls', workdir: 'src' })).toBe(sig('bash', { workdir: 'src', command: 'ls' }))
  })

  it('walks arrays and nested objects', () => {
    expect(sig('bash', { argv: ['a', 'b'], nested: { z: 1, y: 2 } }))
      .toBe(sig('bash', { nested: { y: 2, z: 1 }, argv: ['a', 'b'] }))
    expect(sig('bash', { argv: ['a', 'b'] })).not.toBe(sig('bash', { argv: ['b', 'a'] }))
  })

  it('keeps numbers, null, and booleans distinct', () => {
    expect(sig('bash', { n: 1 })).not.toBe(sig('bash', { n: 2 }))
    expect(sig('bash', { n: null })).not.toBe(sig('bash', { n: false }))
    expect(sig('bash', {})).toMatch(/^[0-9a-f]{16}$/)
  })

  it('truncates long text and marks the omitted count', () => {
    const body = 'x'.repeat(600)
    expect(sig('write', { content: body })).toBe(sig('write', { content: body }))
    // Two payloads sharing the retained prefix and length collapse into one
    // signature: the documented approximation that trust thresholds absorb.
    expect(sig('write', { content: `${'x'.repeat(500)}AAAA` })).toBe(sig('write', { content: `${'x'.repeat(500)}BBBB` }))
    expect(sig('write', { content: 'AAAA' })).not.toBe(sig('write', { content: 'BBBB' }))
  })

  it('honors a custom truncation length', () => {
    expect(sig('write', { content: 'y'.repeat(200) }, 64)).not.toBe(sig('write', { content: 'z'.repeat(200) }, 64))
  })
})
