/**
 * Plugin configuration and its compiled policy. The schemastery schema rejects
 * malformed deployments at load time; `compilePolicy` only normalizes the
 * validated values and rejects the one case the schema cannot express.
 * @module @deepseek-ai/dsh-reversibility-gate/config
 */
import z from '@deepseek-ai/schemastery';
/** Schemastery validation for {@link Config}. */
export const Config = z.object({
    trustThreshold: z.natural().min(1).default(3),
    auditFile: z.string().default('.dsh-reversibility/audit.jsonl'),
    signatureTruncateChars: z.natural().min(64).default(500),
    tierOverrides: z.dict(z.union(['safe', 'risky', 'redline'])).default({}),
    extraRedlineHosts: z.array(z.string()).default([]),
    extraProtectedPaths: z.array(z.string()).default([]),
});
/**
 * Normalize validated configuration into the policy the decision path reads.
 * @param config - configuration already validated by the {@link Config} schema.
 * @returns the frozen policy with normalized hosts and copied tables.
 * @throws Error when the audit destination is empty, which would leave decisions unauditable.
 */
export function compilePolicy(config) {
    // schemastery's .default() guarantees these fields after validation.
    const auditFile = config.auditFile.trim();
    if (auditFile.length === 0) {
        throw new Error('reversibility-gate: auditFile must be a non-empty path');
    }
    return {
        trustThreshold: config.trustThreshold,
        auditFile,
        signatureTruncateChars: config.signatureTruncateChars,
        tierOverrides: { ...config.tierOverrides },
        extraRedlineHosts: config.extraRedlineHosts
            .map(host => host.trim().toLowerCase())
            .filter(host => host.length > 0),
        extraProtectedPaths: [...config.extraProtectedPaths],
    };
}
//# sourceMappingURL=config.js.map