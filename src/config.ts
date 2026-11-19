/**
 * Plugin configuration and its compiled policy. The schemastery schema rejects
 * malformed deployments at load time; `compilePolicy` only normalizes the
 * validated values and rejects the one case the schema cannot express.
 * @module @deepseek-ai/dsh-reversibility-gate/config
 */

import z from '@deepseek-ai/schemastery'
import type { RiskTier } from './types.ts'

/** Deployment-varying policy choices; every default is overridable from cordis.yml. */
export interface Config {
  /**
   * Consecutive approved-and-successful outcomes after which a risky signature
   * auto-allows (default 3). One failure resets it to zero.
   */
  trustThreshold?: number
  /**
   * JSONL audit destination: absolute, or relative to the session workspace
   * (default `.dsh-reversibility/audit.jsonl`).
   */
  auditFile?: string
  /** Characters of one argument string retained in a signature (default 500). */
  signatureTruncateChars?: number
  /** Tool-name to tier overrides; they can only raise a tier, never lower it. */
  tierOverrides?: Record<string, RiskTier>
  /** Extra hosts whose traffic counts as remote state even for a read-only verb. */
  extraRedlineHosts?: string[]
  /** Extra workspace-relative paths a guard refuses to mutate or remove. */
  extraProtectedPaths?: string[]
}

/** Schemastery validation for {@link Config}. */
export const Config: z<Config> = z.object({
  trustThreshold: z.natural().min(1).default(3),
  auditFile: z.string().default('.dsh-reversibility/audit.jsonl'),
  signatureTruncateChars: z.natural().min(64).default(500),
  tierOverrides: z.dict(z.union(['safe', 'risky', 'redline'] as const)).default({}),
  extraRedlineHosts: z.array(z.string()).default([]),
  extraProtectedPaths: z.array(z.string()).default([]),
})

/** Validated, normalized configuration the decision path reads. */
export interface Policy {
  readonly trustThreshold: number
  readonly auditFile: string
  readonly signatureTruncateChars: number
  readonly tierOverrides: Readonly<Record<string, RiskTier>>
  readonly extraRedlineHosts: readonly string[]
  readonly extraProtectedPaths: readonly string[]
}

/**
 * Normalize validated configuration into the policy the decision path reads.
 * @param config - configuration already validated by the {@link Config} schema.
 * @returns the frozen policy with normalized hosts and copied tables.
 * @throws Error when the audit destination is empty, which would leave decisions unauditable.
 */
export function compilePolicy(config: Config): Policy {
  // schemastery's .default() guarantees these fields after validation.
  const auditFile = (config.auditFile as string).trim()
  if (auditFile.length === 0) {
    throw new Error('reversibility-gate: auditFile must be a non-empty path')
  }
  return {
    trustThreshold: config.trustThreshold as number,
    auditFile,
    signatureTruncateChars: config.signatureTruncateChars as number,
    tierOverrides: { ...config.tierOverrides },
    extraRedlineHosts: (config.extraRedlineHosts as string[])
      .map(host => host.trim().toLowerCase())
      .filter(host => host.length > 0),
    extraProtectedPaths: [...config.extraProtectedPaths as string[]],
  }
}
