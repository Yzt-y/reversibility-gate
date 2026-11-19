/**
 * REAL-composition proof: the shipped YAML rows boot through the vendored
 * Loader, the plugin's `inject: ['tools']` and Config schema resolve, and one
 * dispatch decision lands in the workspace-relative audit file.
 */
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import Include from '@deepseek-ai/cordis-plugin-include'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import SessionStore, { SessionId } from '@deepseek-ai/dsh-session'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import * as ReversibilityGate from '@deepseek-ai/dsh-reversibility-gate'

let root: string | undefined
let context: Context | undefined

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
})

describe('real Loader composition', () => {
  it('mounts the package and audits one decision at the workspace path', async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-reversibility-gate-loader-'))
    const cwd = join(root, 'ws')
    await writeFile(join(root, 'cordis.yml'), [
      "- name: '@deepseek-ai/dsh-session'",
      "- name: '@deepseek-ai/dsh-system-prompt'",
      "- name: '@deepseek-ai/dsh-tools'",
      "- name: '@deepseek-ai/dsh-reversibility-gate'",
      '  config:',
      '    trustThreshold: 2',
      '',
    ].join('\n'))
    context = new Context()
    context.baseUrl = `${pathToFileURL(root).href}/`
    await context.plugin(Loader)
    context.loader.builtins.include = Include
    const modules = new Map<string, unknown>([
      ['@deepseek-ai/dsh-session', SessionStore],
      ['@deepseek-ai/dsh-system-prompt', SystemPrompt],
      ['@deepseek-ai/dsh-tools', ToolRuntime],
      ['@deepseek-ai/dsh-reversibility-gate', ReversibilityGate],
    ])
    // Swap in a stub for the Loader's module hook. Node keeps the original
    // object, so vitest's own dynamic imports stay on the real loader.
    Reflect.set(context.loader, 'internal', {
      version: 'v2',
      async import(specifier: string) {
        if (!modules.has(specifier)) throw new Error(`unexpected Loader import: ${specifier}`)
        return modules.get(specifier)
      },
    })
    await context.loader.create({ name: 'cordis:include', config: { path: pathToFileURL(join(root, 'cordis.yml')).href } })
    await context.loader.await()

    const unloaded = [...context.loader.entries()]
      .filter(entry => entry.fiber === undefined && !entry.disabled)
      .map(entry => entry.options.name)
    expect(unloaded).toEqual([])

    const session = context.sessions.create(SessionId('composed'), { meta: { cwd } })
    const exec = {
      callId: ToolCallId('composed-call'),
      name: 'read',
      arguments: { file_path: 'a.txt' },
      agent: { session },
      signal: new AbortController().signal,
    }
    const decision = await context.waterfall('tools/pre-execute', exec as never, () => Promise.resolve({ kind: 'allow' } as never))
    expect(decision).toEqual({ kind: 'allow' })

    const lines = (await readFile(join(cwd, '.dsh-reversibility', 'audit.jsonl'), 'utf8'))
      .split('\n')
      .filter(line => line.length > 0)
    expect(lines).toHaveLength(1)
    expect(JSON.parse(lines[0] ?? '') as Record<string, unknown>).toMatchObject({
      callId: 'composed-call',
      toolName: 'read',
      riskTier: 'safe',
      decisionKind: 'allow',
    })

    // A direct registry caller has no agent and no workspace: the gate must fail
    // closed instead of allowing an unauditable call.
    const direct = await context.waterfall('tools/pre-execute', {
      callId: ToolCallId('direct-call'),
      name: 'write',
      arguments: { file_path: 'a.txt' },
      signal: new AbortController().signal,
    } as never, () => Promise.resolve({ kind: 'allow' } as never))
    expect(direct).toMatchObject({ kind: 'deny' })
  })
})
