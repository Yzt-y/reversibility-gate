/**
 * The approval policy one `ask` would run under. A deployment that sets
 * `approval: never` — the Web "Full access" preset — rejects every ask before
 * any answerer sees it, so the gate must report a denial with the real reason
 * instead of promising a prompt that never appears.
 * @module @deepseek-ai/dsh-reversibility-gate/approval-policy
 */
/**
 * Resolve the policy an ask would resolve under.
 * @param source - the composed approval service, or undefined when the deployment mounts none.
 * @param session - the calling agent's session.
 * @returns `never` when the ask would be rejected before any answerer sees it.
 */
export function approvalPolicyOf(source, session) {
    // No approval service at all: the registry denies the ask with this plugin's
    // reason, so the call still cannot run.
    if (source === undefined)
        return 'ask';
    const override = source.overrideOf(session);
    if (override !== undefined)
        return override;
    return source.config.policy === 'never' ? 'never' : 'ask';
}
//# sourceMappingURL=approval-policy.js.map