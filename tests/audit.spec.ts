import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { AuditSink, AuditUnavailableError, messageOf, resolveAuditFile } from '../src/audit.ts'
import type { AuditRecord } from '../src/types.ts'

const created: string[] = []

/** One fresh temporary directory owned by the current case. */
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'reversibility-gate-'))
  created.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const record: AuditRecord = {
  timestamp: '2026-01-01T00:00:00.000Z',
  callId: 'call-1',
  toolName: 'write',
  signatureHash: '0123456789abcdef',
  riskTier: 'risky',
  decisionKind: 'ask',
  decisionReason: 'signature:untrusted:file:mutate',
  event: 'decision',
  trustCount: 0,
}

/**
 * Audit suite: destination resolution, the created-before-first-decision probe,
 * JSONL shape, and the fail-closed errors the plugin turns into a denial.
 */
describe('resolveAuditFile', () => {
  it('keeps an absolute destination as given', () => {
    expect(resolveAuditFile('/abs/audit.jsonl', '/ws')).toBe('/abs/audit.jsonl')
  })

  it('resolves a relative destination against the session workspace', () => {
    expect(resolveAuditFile('.dsh-reversibility/audit.jsonl', '/ws'))
      .toBe(resolve('/ws', '.dsh-reversibility/audit.jsonl'))
  })

  it('refuses a relative destination with no workspace to resolve it against', () => {
    expect(() => resolveAuditFile('audit.jsonl', undefined)).toThrow(AuditUnavailableError)
  })
})

describe('AuditSink', () => {
  it('creates missing directories and appends one JSON line per record', () => {
    const file = join(tempDir(), 'nested', 'audit.jsonl')
    const sink = new AuditSink(file)
    sink.write(record)
    sink.write({ ...record, event: 'outcome', outcome: 'success', decisionKind: 'allow' })
    const lines = readFileSync(file, 'utf8').split('\n').filter(line => line.length > 0)
    expect(lines).toHaveLength(2)
    expect(JSON.parse(lines[0] ?? '') as AuditRecord).toEqual(record)
    expect(JSON.parse(lines[1] ?? '') as AuditRecord).toMatchObject({ event: 'outcome', outcome: 'success' })
  })

  it('fails before any decision when the destination is not a writable file', () => {
    const dir = tempDir()
    const file = join(dir, 'audit.jsonl')
    mkdirSync(file)
    expect(() => new AuditSink(file)).toThrow(/is a directory/)
  })

  it('wraps a filesystem refusal as an unavailable trail', () => {
    const dir = tempDir()
    const blocker = join(dir, 'blocker')
    mkdirSync(blocker)
    const nested = join(blocker, 'audit.jsonl')
    writeFileSync(nested, '')
    expect(() => new AuditSink(join(nested, 'audit.jsonl'))).toThrow(/is not writable/)
  })

  it('fails the write when the destination stops being writable', () => {
    const dir = tempDir()
    const file = join(dir, 'audit.jsonl')
    const sink = new AuditSink(file)
    rmSync(file)
    mkdirSync(file)
    expect(() => { sink.write(record) }).toThrow(/audit write failed/)
  })
})

describe('messageOf', () => {
  it('reads an Error message and stringifies anything else', () => {
    expect(messageOf(new Error('boom'))).toBe('boom')
    expect(messageOf('plain')).toBe('plain')
  })
})
