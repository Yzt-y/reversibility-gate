/**
 * Operation signatures: one hash over the tool name plus normalization of its
 * arguments, so two calls with the same intent share progressive-grant state.
 * Normalization is deliberately approximate; the README records the tradeoff.
 * @module @deepseek-ai/dsh-reversibility-gate/signature
 */
import { createHash } from 'node:crypto';
/** Argument keys whose values are filesystem paths and get path normalization. */
const PATH_KEYS = new Set(['file_path', 'path', 'file', 'directory', 'target', 'workdir', 'cwd']);
/** Argument keys whose whitespace is insignificant. */
const COMMAND_KEYS = new Set(['command', 'script']);
/**
 * Unify one path spelling: separator, doubled separators, embedded `./`, and a
 * trailing separator. `resolve` is not used because it depends on the process
 * working directory, which would make the signature host-dependent.
 * @param value - the path as written.
 * @returns the normalized spelling.
 */
function normalizePath(value) {
    const unified = value.replaceAll('\\', '/').replace(/\/{2,}/g, '/').replace(/\/\.\//g, '/');
    if (unified.length > 1 && unified.endsWith('/'))
        return unified.slice(0, -1);
    return unified;
}
/**
 * Normalize one argument value recursively.
 * @param value - parsed argument value.
 * @param key - the property name holding this value, when there is one.
 * @param truncateChars - characters retained per string before an omitted-count marker.
 * @returns a JSON-normalized copy with sorted keys.
 */
function normalizeValue(value, key, truncateChars) {
    if (typeof value === 'string') {
        const collapsed = key !== undefined && COMMAND_KEYS.has(key) ? value.replace(/\s+/g, ' ').trim() : value;
        const normalized = key !== undefined && PATH_KEYS.has(key) ? normalizePath(collapsed) : collapsed;
        if (normalized.length <= truncateChars)
            return normalized;
        return `${normalized.slice(0, truncateChars)}…+${normalized.length - truncateChars}`;
    }
    if (Array.isArray(value))
        return value.map(item => normalizeValue(item, key, truncateChars));
    if (typeof value === 'object' && value !== null) {
        const record = value;
        const sorted = {};
        for (const child of Object.keys(record).sort()) {
            sorted[child] = normalizeValue(record[child], child, truncateChars);
        }
        return sorted;
    }
    return value;
}
/**
 * Compute the signature of one call.
 * @param call - pure call inputs.
 * @param truncateChars - characters retained per argument string.
 * @returns 16 lowercase hex characters derived from the tool name and normalized arguments.
 */
export function signatureOf(call, truncateChars) {
    const normalized = normalizeValue(call.args, undefined, truncateChars);
    return createHash('sha256')
        .update(`${call.toolName}\u0000${JSON.stringify(normalized)}`)
        .digest('hex')
        .slice(0, 16);
}
//# sourceMappingURL=signature.js.map