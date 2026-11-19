import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import AgentLoop from '@deepseek-ai/dsh-agent-loop'
import { mountAgentLoopTestDependencies } from '@deepseek-ai/dsh-agent-loop-testkit'
import type { ApprovalOutcome } from '@deepseek-ai/dsh-user-approval'
import ApprovalService, { setApprovalPolicy } from '@deepseek-ai/dsh-user-approval'
import * as ReversibilityGate from '@deepseek-ai/dsh-reversibility-gate'
import { MockAdapter, textResponse, toolCallResponse } from '../../../core/agent-loop/tests/mock-adapter.ts'
import type { AuditRecord } from '../src/types.ts'

/** One scripted model response. */
type Response = ReturnType<typeof toolCallResponse>

const workspaces: string[] = []

afterEach(() => {
  for (const dir of workspaces.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** One fresh session workspace owned by the current case. */
function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), 'reversibility-gate-ws-'))
  workspaces.push(dir)
  return dir
}

/** Mounted composition under test plus the observations a case asserts on. */
interface Harness {
  readonly ctx: Context
  readonly workspace: string
  readonly auditPath: string
  readonly executed: string[]
  readonly plugin: { dispose(): Promise<void> }
}

/** Options for one mounted composition. */
interface HarnessOptions {
  /** Scripted model responses, consumed in order across turns. */
  readonly responses: readonly Response[]
  /**
   * Approval channel: `true` mounts a service whose answerer always grants one
   * shot, `'never'` mounts the deployment default `never` (the Web "Full
   * access" policy), and omission mounts none.
   */
  readonly approval?: boolean | 'never'
  /** Audit destination override; defaults to the case workspace. */
  readonly auditFile?: string
  /** Hook that runs inside the write fixture's body. */
  readonly afterWrite?: () => void
}

/**
 * Boot the core spine, an optional approval channel, the gate, and three named
 * fixture tools whose bodies only record that they ran: the effect is what the
 * policy classifies, so the bodies never touch the filesystem.
 * @param options - responses, approval channel, audit destination, and the write-body hook.
 * @returns the mounted composition and its observation points.
 */
async function harness(options: HarnessOptions): Promise<Harness> {
  const dir = workspace()
  const auditPath = join(dir, '.dsh-reversibility', 'audit.jsonl')
  const executed: string[] = []
  const ctx = new Context()
  await mountAgentLoopTestDependencies(ctx)
  if (options.approval !== undefined && options.approval !== false) {
    await ctx.plugin(ApprovalService, options.approval === 'never' ? { policy: 'never' } : {})
    if (options.approval === true) ctx.on('approval/request', () => Promise.resolve<ApprovalOutcome>('allowed-once'))
  }
  await ctx.plugin(AgentLoop, { agents: [] })
  const plugin = await ctx.plugin(ReversibilityGate, {
    auditFile: options.auditFile ?? auditPath,
    trustThreshold: 3,
  })
  ctx.llm.registerAdapter(['mock'], new MockAdapter([...options.responses]))
  ctx.tools.register(defineContentToolFixture({
    name: 'read', description: 'read fixture', parameters: {},
    async execute() { executed.push('read'); return [{ type: 'text', text: 'read-ok' }] },
  }))
  ctx.tools.register(defineContentToolFixture({
    name: 'write', description: 'write fixture', parameters: {},
    async execute() {
      executed.push('write')
      options.afterWrite?.()
      return [{ type: 'text', text: 'write-ok' }]
    },
  }))
  ctx.tools.register(defineContentToolFixture({
    name: 'bash', description: 'shell fixture', parameters: {},
    async execute() { executed.push('bash'); return [{ type: 'text', text: 'bash-ok' }] },
  }))
  return { ctx, workspace: dir, auditPath, executed, plugin }
}

/** Create one agent bound to the case workspace. */
async function agentOf(h: Harness, id: string): Promise<Agent> {
  return h.ctx.agentLoop.create(SessionId(id), { provider: 'mock', model: 'mock' }, { cwd: h.workspace })
}

/** Admit one user turn and wait until the agent reports idle. */
async function turn(ctx: Context, agent: Agent): Promise<void> {
  agent.followup(createUserMessage({ content: [{ type: 'text', text: 'go' }], source: { kind: 'user' } }))
  await new Promise<void>((resolve) => {
    const dispose = ctx.on('agent/status', ({ agent: subject, status }) => {
      if (subject !== agent || status !== 'idle') return
      dispose()
      resolve()
    })
  })
}

/** Audit records written so far, or an empty list when no line exists yet. */
function auditOf(h: Harness): AuditRecord[] {
  try {
    return readFileSync(h.auditPath, 'utf8')
      .split('\n')
      .filter(line => line.length > 0)
      .map(line => JSON.parse(line) as AuditRecord)
  } catch (_absentAuditFile) {
    return []
  }
}

/** Decisions recorded for one tool name, in order. */
function decisionsOf(h: Harness, toolName: string): AuditRecord[] {
  return auditOf(h).filter(record => record.event === 'decision' && record.toolName === toolName)
}

describe('reversibility gate: mounted behavior', () => {
  it('runs a safe call and records an allow decision (AC-7)', async () => {
    const h = await harness({ responses: [toolCallResponse('c1', 'read', { file_path: 'a.txt' }), textResponse('done')] })
    await turn(h.ctx, await agentOf(h, 'safe'))

    expect(h.executed).toEqual(['read'])
    expect(decisionsOf(h, 'read')).toMatchObject([
      { riskTier: 'safe', decisionKind: 'allow', decisionReason: 'read-only' },
    ])
    // Only risky calls carry grant state, so a safe call settles with one line.
    expect(auditOf(h)).toHaveLength(1)
  })

  it('denies a risky call when the deployment composes no approval channel (AC-8)', async () => {
    const h = await harness({ responses: [toolCallResponse('c1', 'write', { file_path: 'a.txt' }), textResponse('done')] })
    await turn(h.ctx, await agentOf(h, 'risky-no-approval'))

    expect(h.executed).toEqual([])
    expect(decisionsOf(h, 'write')).toMatchObject([{ riskTier: 'risky', decisionKind: 'ask' }])
  })

  it('denies a risky call under the never approval policy and says why (Full access preset)', async () => {
    const h = await harness({
      approval: 'never',
      responses: [toolCallResponse('c1', 'write', { file_path: 'a.txt' }), textResponse('done')],
    })
    await turn(h.ctx, await agentOf(h, 'never-policy'))

    expect(h.executed).toEqual([])
    expect(decisionsOf(h, 'write')).toMatchObject([{
      riskTier: 'risky',
      decisionKind: 'deny',
      decisionReason: 'policy:never:signature:untrusted:file:mutate',
    }])
  })

  it('honors a session-level never override, not only the deployment default', async () => {
    const h = await harness({
      approval: true,
      responses: [toolCallResponse('c1', 'write', { file_path: 'a.txt' }), textResponse('done')],
    })
    const agent = await agentOf(h, 'never-override')
    setApprovalPolicy(agent.session, 'never')
    await turn(h.ctx, agent)

    expect(h.executed).toEqual([])
    expect(decisionsOf(h, 'write')[0]?.decisionKind).toBe('deny')
  })

  it('auto-allows a risky signature after three approved successes (AC-3)', async () => {
    const h = await harness({
      approval: true,
      responses: [
        toolCallResponse('c1', 'write', { file_path: 'a.txt' }),
        toolCallResponse('c2', 'write', { file_path: 'a.txt' }),
        toolCallResponse('c3', 'write', { file_path: 'a.txt' }),
        toolCallResponse('c4', 'write', { file_path: 'a.txt' }),
        textResponse('done'),
      ],
    })
    await turn(h.ctx, await agentOf(h, 'risky-trusted'))

    expect(h.executed).toEqual(['write', 'write', 'write', 'write'])
    expect(decisionsOf(h, 'write').map(record => record.decisionKind)).toEqual(['ask', 'ask', 'ask', 'allow'])
    expect(decisionsOf(h, 'write').map(record => record.decisionReason)).toEqual([
      'signature:untrusted:file:mutate',
      'signature:untrusted:file:mutate',
      'signature:untrusted:file:mutate',
      'signature:approved:3',
    ])
  })

  it('asks again for every redline call, however many were approved (AC-9)', async () => {
    const outside = join(tmpdir(), 'reversibility-gate-outside.txt')
    const h = await harness({
      approval: true,
      responses: [
        toolCallResponse('c1', 'bash', { command: `rm ${outside}` }),
        toolCallResponse('c2', 'bash', { command: `rm ${outside}` }),
        textResponse('done'),
      ],
    })
    await turn(h.ctx, await agentOf(h, 'redline'))

    expect(h.executed).toEqual(['bash', 'bash'])
    expect(decisionsOf(h, 'bash').map(record => record.decisionKind)).toEqual(['ask', 'ask'])
    expect(decisionsOf(h, 'bash')[0]).toMatchObject({ decisionReason: 'redline:shell:destroy', riskTier: 'redline' })
  })

  it('lets the self-protection guard reject an approved call that would remove the workspace root', async () => {
    const h = await harness({
      approval: true,
      responses: [toolCallResponse('c1', 'bash', { command: 'rm -rf .' }), textResponse('done')],
    })
    await turn(h.ctx, await agentOf(h, 'guard'))

    expect(h.executed).toEqual([])
    expect(decisionsOf(h, 'bash')).toMatchObject([{ decisionKind: 'ask', riskTier: 'risky' }])
  })

  it('denies when the audit destination is unusable (AC-5)', async () => {
    const dir = workspace()
    const blocked = join(dir, 'blocked')
    mkdirSync(blocked)
    const h = await harness({
      approval: true,
      auditFile: blocked,
      responses: [toolCallResponse('c1', 'write', { file_path: 'a.txt' }), textResponse('done')],
    })
    await turn(h.ctx, await agentOf(h, 'audit-denied'))

    expect(h.executed).toEqual([])
    expect(auditOf(h)).toEqual([])
  })

  it('keeps a settled result when the outcome audit line cannot be written', async () => {
    const dir = workspace()
    const auditPath = join(dir, '.dsh-reversibility', 'audit.jsonl')
    const h = await harness({
      approval: true,
      auditFile: auditPath,
      afterWrite: () => {
        // Replace the destination with a directory between the decision and its outcome.
        rmSync(auditPath)
        mkdirSync(auditPath)
      },
      responses: [toolCallResponse('c1', 'write', { file_path: 'a.txt' }), textResponse('done')],
    })
    await turn(h.ctx, await agentOf(h, 'outcome-write-failed'))

    expect(h.executed).toEqual(['write'])
  })

  it('records a downstream cancellation as a denial without dispatching the tool', async () => {
    const h = await harness({ responses: [toolCallResponse('c1', 'read', { file_path: 'a.txt' }), textResponse('done')] })
    h.ctx.on('tools/pre-execute', () => Promise.resolve({ kind: 'cancel' as const }))
    await turn(h.ctx, await agentOf(h, 'cancelled'))

    expect(h.executed).toEqual([])
    expect(decisionsOf(h, 'read')).toMatchObject([{ decisionKind: 'deny' }])
  })

  it('restores native behavior when the plugin is unloaded (AC-10)', async () => {
    const h = await harness({
      responses: [
        toolCallResponse('c1', 'write', { file_path: 'a.txt' }),
        textResponse('first'),
        toolCallResponse('c2', 'write', { file_path: 'a.txt' }),
        textResponse('second'),
      ],
    })
    const agent = await agentOf(h, 'unloaded')
    await turn(h.ctx, agent)
    expect(h.executed).toEqual([])

    await h.plugin.dispose()
    await turn(h.ctx, agent)
    expect(h.executed).toEqual(['write'])
  })
})
