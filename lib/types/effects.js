/**
 * Pure side-effect extraction. `effectOf` reads a call's name and arguments and
 * reports the effects it would have; it never reads the filesystem, spawns a
 * process, or consults the clock, so classification stays deterministic and
 * cheap enough for the pre-dispatch path.
 * @module @deepseek-ai/dsh-reversibility-gate/effects
 */
import { isAbsolute, relative, resolve } from 'node:path';
/** Tools with no durable effect at all. */
const READ_TOOLS = new Set([
    'read', 'read_image', 'glob', 'grep', 'web_search', 'web_fetch', 'lsp',
]);
/** Tools whose own call is transport, not effect: their inner calls are gated separately. */
const DELEGATE_TOOLS = new Set(['run_code', 'workflow']);
/** Tools that cannot bound their effects and never reach the filesystem directly. */
const UNBOUNDED_TOOLS = new Map([
    ['subagent', 'delegation'],
    ['terminal', 'terminal-input'],
    ['job_start', 'job-control'],
    ['job_kill', 'job-control'],
]);
/** Tools that replace or create file content at one argument path. */
const FILE_MUTATION_TOOLS = new Set([
    'write', 'edit', 'write_file', 'str_replace_editor', 'apply_patch',
]);
/** Tools whose `command` argument is analyzed as a shell program. */
const SHELL_TOOLS = new Set(['bash', 'pwsh']);
/** Argument keys that carry a filesystem path across the tool catalog. */
const PATH_KEYS = ['file_path', 'path', 'file', 'directory', 'target', 'workdir', 'cwd'];
/** Leading wrapper commands that do not name the effect themselves. */
const COMMAND_WRAPPERS = new Set(['sudo', 'doas', 'su', 'env', 'time', 'nohup', 'command', 'exec']);
/** Wrappers that raise the call's privilege outside the workspace sandbox. */
const PRIVILEGE_WRAPPERS = new Set(['sudo', 'doas', 'su']);
/** Shell interpreters whose appearance downstream of a pipe means remote code execution. */
const SHELL_INTERPRETERS = new Set(['sh', 'bash', 'zsh', 'fish', 'pwsh', 'powershell', 'cmd']);
/** Verbs that only observe state. */
const READ_VERBS = new Set([
    'ls', 'cat', 'head', 'tail', 'less', 'more', 'pwd', 'echo', 'printf', 'grep', 'rg', 'ag', 'find',
    'wc', 'sort', 'uniq', 'cut', 'awk', 'jq', 'which', 'whereis', 'whoami', 'id', 'date', 'uname',
    'ps', 'top', 'df', 'du', 'stat', 'file', 'tree', 'get-childitem', 'get-content', 'write-output',
]);
/** Verbs that remove content or overwrite it irrecoverably. */
const DESTROY_VERBS = new Set([
    'rm', 'rmdir', 'del', 'erase', 'rd', 'shred', 'truncate', 'remove-item',
]);
/** Verbs that create or change content in place. */
const MUTATE_VERBS = new Set([
    'mkdir', 'touch', 'cp', 'copy', 'mv', 'move', 'sed', 'tee', 'ln', 'new-item', 'set-content',
    'add-content', 'copy-item', 'move-item', 'out-file',
]);
/** Verbs that change access control or host services. */
const PRIVILEGE_VERBS = new Set([
    'chmod', 'chown', 'chgrp', 'systemctl', 'service', 'sc', 'netsh', 'reg', 'launchctl', 'sudo',
]);
/** Package managers: installs mutate the workspace, publishes reach a registry. */
const PACKAGE_VERBS = new Set(['npm', 'pnpm', 'yarn', 'bun', 'npx']);
/** Package-manager actions that only report. */
const PACKAGE_READ_ACTIONS = new Set(['ls', 'list', 'view', 'why', 'outdated', 'info']);
/** Package-manager actions that reach a registry or account. */
const PACKAGE_REMOTE_ACTIONS = new Set(['publish', 'login', 'logout', 'deprecate', 'unpublish']);
/** HTTP clients: the method decides whether the call reads or writes remotely. */
const HTTP_VERBS = new Set(['curl', 'wget', 'invoke-webrequest', 'invoke-restmethod']);
/** Clients that execute a command on another host. */
const REMOTE_VERBS = new Set(['ssh', 'scp', 'rsync', 'telnet']);
/** Container runtimes. */
const CONTAINER_VERBS = new Set(['docker', 'podman']);
/** Kubernetes and infrastructure CLIs whose mutations act on remote state. */
const CLOUD_VERBS = new Set(['kubectl', 'terraform', 'aws', 'gcloud', 'az']);
/** Container and cloud actions that only report. */
const REMOTE_READ_ACTIONS = new Set(['get', 'describe', 'logs', 'ps', 'images', 'version', 'info', 'plan', 'show', 'validate']);
/** `git` subcommands that only observe. */
const GIT_READ_SUBCOMMANDS = new Set([
    'status', 'log', 'diff', 'show', 'branch', 'remote', 'rev-parse', 'describe', 'blame',
    'ls-files', 'ls-tree', 'shortlog', 'reflog', 'tag',
]);
/** `git` subcommands that destroy uncommitted work. */
const GIT_DESTROY_SUBCOMMANDS = new Set(['reset', 'clean', 'prune']);
/** `gh` actions that only observe. */
const GH_READ_ACTIONS = new Set(['view', 'list', 'status', 'diff', 'checks', 'download']);
/** `gh` actions that change remote state or post a message. */
const GH_REMOTE_ACTIONS = new Set([
    'create', 'merge', 'close', 'reopen', 'edit', 'delete', 'comment', 'review', 'approve',
    'ready', 'run', 'cancel', 'upload', 'deploy',
]);
/** Flags that carry an HTTP request body, which makes even a default method a write. */
const BODY_FLAGS = new Set([
    '-d', '--data', '--data-raw', '--data-binary', '-f', '--form', '-t', '--upload-file', '--post-data',
]);
/** URL scheme prefix recognized inside a command. */
const URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;
/** Read one field off an unknown arguments value. */
function recordOf(args) {
    return typeof args === 'object' && args !== null ? args : undefined;
}
/** Read one string field off an unknown arguments value. */
function stringField(record, key) {
    const value = record?.[key];
    return typeof value === 'string' ? value : undefined;
}
/** First path-valued argument key present on the call. */
function pathArgument(args) {
    const record = recordOf(args);
    for (const key of PATH_KEYS) {
        const value = stringField(record, key);
        if (value !== undefined && value.length > 0)
            return value;
    }
    return undefined;
}
/**
 * Resolve the directories a call's targets are measured against.
 * @param args - parsed tool arguments, read only for a shell `workdir`.
 * @param workspace - session workspace root, when the caller has one.
 * @returns the resolved pair, or undefined when the caller has no workspace.
 */
function pathsOf(args, workspace) {
    if (workspace === undefined)
        return undefined;
    const root = resolve(workspace);
    const workdir = stringField(recordOf(args), 'workdir');
    return { root, base: workdir === undefined ? root : resolve(root, workdir) };
}
/**
 * Compare one spelled path to the workspace root lexically — `resolve` and
 * `relative` never touch the disk.
 * @param pathText - path exactly as the call spelled it.
 * @param paths - resolved workspace directories, or undefined without a workspace.
 * @returns whether the target sits inside the workspace, outside it, or cannot be resolved.
 */
function scopeOfPath(pathText, paths) {
    if (pathText.length === 0)
        return 'unknown';
    if (/[*?]/.test(pathText))
        return 'unknown';
    if (pathText.startsWith('~'))
        return 'outside';
    if (paths === undefined)
        return 'unknown';
    const nested = relative(paths.root, resolve(paths.base, pathText));
    if (nested === '')
        return 'workspace';
    return !nested.startsWith('..') && !isAbsolute(nested) ? 'workspace' : 'outside';
}
/** Build one target from a spelled path. */
function targetOf(pathText, paths) {
    return { path: pathText, scope: scopeOfPath(pathText, paths) };
}
/** Non-flag words of one command, treated as its path operands. */
function pathWords(argv) {
    return argv.filter(word => word.length > 0 && !word.startsWith('-'));
}
/** Effects of redirections regardless of the verb that owns them. */
function redirectEffects(redirects, paths) {
    return redirects.map((redirect) => redirect.op === '>'
        ? { kind: 'destroy', detail: 'shell:overwrite', targets: [targetOf(redirect.target, paths)] }
        : { kind: 'mutate', detail: 'shell:append', targets: [targetOf(redirect.target, paths)] });
}
/** The workspace itself as a target, used by verbs whose effects cannot be read from arguments. */
function workspaceTargets(paths) {
    return [targetOf('.', paths)];
}
/** Whether `word` matches the URL scheme prefix. */
function isUrl(word) {
    return URL_PATTERN.test(word);
}
/**
 * Host of one URL, or undefined when it does not parse.
 * @param url - literal URL from a command.
 * @returns lowercase hostname, or undefined for an unparsable URL.
 */
function hostOf(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    }
    catch (_invalidUrl) {
        return undefined;
    }
}
/**
 * Split one command string into segments, tracked quotes, and pipeline links.
 * @param command - the shell command text.
 * @returns raw segments plus whether a `|` follows each of them, or undefined for an unparsable command.
 */
function splitSegments(command) {
    const raw = [];
    const piped = [];
    const chars = command.split('');
    let current = '';
    let quote;
    let skip = false;
    const push = (pipedIntoNext) => {
        if (current.trim().length === 0)
            return;
        raw.push(current);
        piped.push(pipedIntoNext);
        current = '';
    };
    for (const [index, char] of chars.entries()) {
        if (skip) {
            skip = false;
            continue;
        }
        if (quote !== undefined) {
            current += char;
            if (char === quote)
                quote = undefined;
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            current += char;
            continue;
        }
        if (char === '`')
            return undefined;
        if (char === '$' && chars.at(index + 1) === '(')
            return undefined;
        if (char === '|') {
            push(chars.at(index + 1) !== '|');
            skip = chars.at(index + 1) === '|';
            continue;
        }
        if (char === '&' && chars.at(index + 1) === '&') {
            push(false);
            skip = true;
            continue;
        }
        if (char === ';' || char === '\n') {
            push(false);
            continue;
        }
        current += char;
    }
    if (quote !== undefined)
        return undefined;
    push(false);
    return { raw, piped };
}
/**
 * Split one segment into words with quotes removed. Callers pass segments that
 * `splitSegments` accepted, so quoting is balanced here by construction.
 * @param segment - raw segment text without separators.
 * @returns the words, in order, with quoted runs kept whole.
 */
function tokenize(segment) {
    const words = [];
    let current = '';
    let started = false;
    let quote;
    for (const char of segment) {
        if (quote !== undefined) {
            if (char === quote) {
                quote = undefined;
                continue;
            }
            current += char;
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            started = true;
            continue;
        }
        if (char === ' ' || char === '\t' || char === '\r') {
            if (started) {
                words.push(current);
                current = '';
                started = false;
            }
            continue;
        }
        current += char;
        started = true;
    }
    if (started)
        words.push(current);
    return words;
}
/**
 * Recognize one redirection word, including an attached target (`>out.txt`) and
 * a leading file-descriptor digit (`2>`).
 * @param word - one tokenized word.
 * @returns the operator and attached target text, or undefined when the word is not a redirection.
 */
function redirectOf(word) {
    const body = word.replace(/^[12&]/, '');
    if (body.startsWith('>>'))
        return { op: '>>', attached: body.slice(2) };
    if (body.startsWith('>'))
        return { op: '>', attached: body.slice(1) };
    return undefined;
}
/**
 * Separate redirections from a segment's words.
 * @param words - tokenized words of one segment.
 * @returns remaining words plus the redirections in order.
 */
function takeRedirects(words) {
    const rest = [];
    const redirects = [];
    let consumed = -1;
    for (const [index, word] of words.entries()) {
        if (index <= consumed)
            continue;
        const redirect = redirectOf(word);
        if (redirect === undefined) {
            rest.push(word);
            continue;
        }
        if (redirect.attached.length > 0) {
            redirects.push({ op: redirect.op, target: redirect.attached });
            continue;
        }
        const target = words[index + 1];
        if (target === undefined) {
            rest.push(word);
            continue;
        }
        redirects.push({ op: redirect.op, target });
        consumed = index + 1;
    }
    return { words: rest, redirects };
}
/**
 * Analyze one shell command string.
 * @param command - the command text from the tool arguments.
 * @returns the parsed segments, pipeline-to-shell flag, literal URLs, and whether parsing succeeded.
 */
export function analyzeShell(command) {
    const split = splitSegments(command);
    if (split === undefined)
        return { segments: [], pipeToShell: false, urls: [], parsed: false };
    const segments = [];
    const urls = [];
    let pipeToShell = false;
    for (const [index, raw] of split.raw.entries()) {
        const words = tokenize(raw);
        for (const word of words)
            if (isUrl(word))
                urls.push(word);
        segments.push(takeRedirects(words));
        const next = split.raw[index + 1];
        if (split.piped[index] === true && next !== undefined && SHELL_INTERPRETERS.has(verbOf(tokenize(next)))) {
            pipeToShell = true;
        }
    }
    return { segments, pipeToShell, urls, parsed: true };
}
/**
 * Index of the word that names the command's effect, skipping assignments and wrappers.
 * @param words - tokenized words of one segment.
 * @returns the verb index, or `words.length` when the segment holds only wrappers.
 */
function realVerbIndex(words) {
    for (const [index, word] of words.entries()) {
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word))
            continue;
        if (COMMAND_WRAPPERS.has(word.toLowerCase()))
            continue;
        return index;
    }
    return words.length;
}
/**
 * The verb naming one segment's effect.
 * @param words - tokenized words of one segment.
 * @returns the lowercase verb, or an empty string when the segment holds only wrappers.
 */
function verbOf(words) {
    return (words[realVerbIndex(words)] ?? '').toLowerCase();
}
/** Effects contributed by the verb and its operands. */
function verbEffects(verb, argv, redirects, paths) {
    if (DESTROY_VERBS.has(verb))
        return rebuildTargets('destroy', 'shell:destroy', argv, redirects, paths);
    if (MUTATE_VERBS.has(verb))
        return rebuildTargets('mutate', 'shell:mutate', argv, redirects, paths);
    if (READ_VERBS.has(verb))
        return redirectEffects(redirects, paths);
    if (PRIVILEGE_VERBS.has(verb))
        return [{ kind: 'privilege', detail: 'shell:privilege' }];
    if (PACKAGE_VERBS.has(verb))
        return [packageEffect(argv, paths)];
    if (HTTP_VERBS.has(verb))
        return [httpEffect(argv)];
    if (REMOTE_VERBS.has(verb))
        return [{ kind: 'remote', detail: 'remote:shell', surface: 'state' }];
    if (CONTAINER_VERBS.has(verb))
        return [containerEffect(argv, paths)];
    if (CLOUD_VERBS.has(verb))
        return [cloudEffect(argv)];
    if (verb === 'git')
        return [gitEffect(argv, paths)];
    if (verb === 'gh')
        return [ghEffect(argv)];
    return [{ kind: 'unknown', detail: 'shell:unknown-verb', severity: 'risky' }];
}
/** Build mutate/destroy effects from path operands plus redirections. */
function rebuildTargets(kind, detail, argv, redirects, paths) {
    const operands = pathWords(argv);
    const effects = [];
    if (operands.length > 0) {
        effects.push({ kind, detail, targets: operands.map(path => targetOf(path, paths)) });
    }
    effects.push(...redirectEffects(redirects, paths));
    if (effects.length === 0)
        return [{ kind: 'unknown', detail: `${detail}-no-target`, severity: 'redline' }];
    return effects;
}
/** Package-manager action: report, mutate the workspace, or reach a registry. */
function packageEffect(argv, paths) {
    const action = (argv[0] ?? '').toLowerCase();
    if (PACKAGE_REMOTE_ACTIONS.has(action))
        return { kind: 'remote', detail: 'remote:package', surface: 'state' };
    if (PACKAGE_READ_ACTIONS.has(action))
        return { kind: 'read', detail: 'read-only' };
    return { kind: 'mutate', detail: 'shell:package', targets: workspaceTargets(paths) };
}
/**
 * HTTP method the client was asked to use.
 * @param argv - client arguments.
 * @returns the uppercase method, or undefined when the client sends no body and requests none.
 */
function httpMethod(argv) {
    for (const [index, flag] of argv.entries()) {
        const word = flag.toLowerCase();
        if (word === '-x' || word === '--request' || word === '--method') {
            return (argv[index + 1] ?? '').toUpperCase();
        }
        if (BODY_FLAGS.has(word))
            return 'POST';
    }
    return undefined;
}
/** HTTP client effect: a body-carrying method writes remotely, everything else reads. */
function httpEffect(argv) {
    const method = httpMethod(argv);
    if (method === undefined || method === 'GET' || method === 'HEAD')
        return { kind: 'read', detail: 'read-only' };
    return { kind: 'remote', detail: 'remote:http', surface: method === 'DELETE' ? 'state' : 'message' };
}
/** Container CLI: push and login reach a registry, read actions report, the rest mutates locally. */
function containerEffect(argv, paths) {
    const action = (argv[0] ?? '').toLowerCase();
    if (action === 'push' || action === 'login')
        return { kind: 'remote', detail: 'remote:container', surface: 'state' };
    if (REMOTE_READ_ACTIONS.has(action))
        return { kind: 'read', detail: 'read-only' };
    return { kind: 'mutate', detail: 'shell:container', targets: workspaceTargets(paths) };
}
/** Cluster and cloud CLI: read actions report, everything else changes remote state. */
function cloudEffect(argv) {
    const action = (argv[0] ?? '').toLowerCase();
    if (REMOTE_READ_ACTIONS.has(action))
        return { kind: 'read', detail: 'read-only' };
    return { kind: 'remote', detail: 'remote:cloud', surface: 'state' };
}
/** `git` subcommand effect. */
function gitEffect(argv, paths) {
    const subcommand = (argv[0] ?? '').toLowerCase();
    if (subcommand === 'push')
        return { kind: 'remote', detail: 'remote:git-push', surface: 'state' };
    if (GIT_READ_SUBCOMMANDS.has(subcommand) && !argv.includes('--force'))
        return { kind: 'read', detail: 'read-only' };
    if (GIT_DESTROY_SUBCOMMANDS.has(subcommand))
        return { kind: 'unknown', detail: 'shell:git-destroy', severity: 'redline' };
    return { kind: 'mutate', detail: 'shell:git', targets: workspaceTargets(paths) };
}
/** `gh` subcommand effect. */
function ghEffect(argv) {
    const group = (argv[0] ?? '').toLowerCase();
    if (group === 'api') {
        const method = httpMethod(argv.slice(1));
        if (method === undefined || method === 'GET' || method === 'HEAD')
            return { kind: 'read', detail: 'read-only' };
        return { kind: 'remote', detail: 'remote:gh-api', surface: 'state' };
    }
    const action = (argv[1] ?? '').toLowerCase();
    if (GH_READ_ACTIONS.has(action))
        return { kind: 'read', detail: 'read-only' };
    if (GH_REMOTE_ACTIONS.has(action)) {
        return { kind: 'remote', detail: 'remote:gh', surface: action === 'comment' ? 'message' : 'state' };
    }
    return { kind: 'unknown', detail: 'shell:gh', severity: 'risky' };
}
/** Effects of one analyzed segment. */
function segmentEffects(segment, paths) {
    const verbIndex = realVerbIndex(segment.words);
    const verb = verbOf(segment.words);
    if (verb.length === 0)
        return redirectEffects(segment.redirects, paths);
    const argv = segment.words.slice(verbIndex + 1);
    const wrappers = segment.words.slice(0, verbIndex).map(word => word.toLowerCase());
    const effects = [];
    if (wrappers.some(wrapper => PRIVILEGE_WRAPPERS.has(wrapper))) {
        effects.push({ kind: 'privilege', detail: 'shell:privilege' });
    }
    effects.push(...verbEffects(verb, argv, segment.redirects, paths));
    return effects;
}
/** Effects of one shell tool call. */
function shellEffects(call, extraRedlineHosts) {
    const args = recordOf(call.args);
    const command = stringField(args, 'command');
    if (command === undefined)
        return [{ kind: 'unknown', detail: 'shell:missing-command', severity: 'redline' }];
    const analysis = analyzeShell(command);
    if (!analysis.parsed)
        return [{ kind: 'unknown', detail: 'shell:unparsed', severity: 'redline' }];
    const paths = pathsOf(call.args, call.workspace);
    const effects = [];
    for (const segment of analysis.segments)
        effects.push(...segmentEffects(segment, paths));
    if (analysis.pipeToShell)
        effects.push({ kind: 'remote', detail: 'remote:pipe-to-shell', surface: 'state' });
    if (analysis.urls.some(url => extraRedlineHosts.includes(hostOf(url) ?? ''))) {
        effects.push({ kind: 'remote', detail: 'remote:redline-host', surface: 'state' });
    }
    return effects.length > 0 ? effects : [{ kind: 'read', detail: 'read-only' }];
}
/**
 * Extract the side effects one call would have.
 * @param call - pure call inputs (name, arguments, workspace root).
 * @param extraRedlineHosts - deployment-added hosts whose traffic counts as remote state.
 * @returns the effects in command order, never empty.
 */
export function effectOf(call, extraRedlineHosts) {
    if (SHELL_TOOLS.has(call.toolName))
        return shellEffects(call, extraRedlineHosts);
    if (FILE_MUTATION_TOOLS.has(call.toolName)) {
        const path = pathArgument(call.args);
        if (path === undefined)
            return [{ kind: 'unknown', detail: 'file-mutation-no-path', severity: 'risky' }];
        return [{ kind: 'mutate', detail: 'file:mutate', targets: [targetOf(path, pathsOf(call.args, call.workspace))] }];
    }
    if (READ_TOOLS.has(call.toolName))
        return [{ kind: 'read', detail: 'read-only' }];
    if (DELEGATE_TOOLS.has(call.toolName))
        return [{ kind: 'delegate', detail: 'delegated-transport' }];
    const unbounded = UNBOUNDED_TOOLS.get(call.toolName);
    if (unbounded !== undefined)
        return [{ kind: 'unknown', detail: `tool:${unbounded}`, severity: 'risky' }];
    return [{ kind: 'unknown', detail: 'tool:unknown', severity: 'risky' }];
}
//# sourceMappingURL=effects.js.map