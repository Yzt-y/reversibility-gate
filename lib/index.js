import { appendFileSync, closeSync, mkdirSync, openSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import z from "@deepseek-ai/schemastery";
import { createHash } from "node:crypto";
//#region lib/types/approval-policy.js
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
function approvalPolicyOf(source, session) {
	if (source === void 0) return "ask";
	const override = source.overrideOf(session);
	if (override !== void 0) return override;
	return source.config.policy === "never" ? "never" : "ask";
}
//#endregion
//#region lib/types/audit.js
/**
* Append-only JSONL audit trail. Every decision is written synchronously before
* it is returned, and a write that fails makes the caller deny the call:
* a decision without a traceable record never reaches the tool.
* @module @deepseek-ai/dsh-reversibility-gate/audit
*/
/** Raised when the audit destination cannot be resolved or written. */
var AuditUnavailableError = class extends Error {
	/**
	* @param message - why the trail is unavailable.
	*/
	constructor(message) {
		super(message);
		this.name = "AuditUnavailableError";
	}
};
/**
* Best-effort message for an arbitrary thrown value.
* @param error - the thrown value.
* @returns a printable message.
*/
function messageOf(error) {
	return error instanceof Error ? error.message : String(error);
}
/**
* Resolve the configured audit destination against the session workspace.
* @param auditFile - configured destination, absolute or workspace-relative.
* @param workspace - session workspace root, when the caller has one.
* @returns the absolute destination path.
* @throws AuditUnavailableError when a relative destination has no workspace to resolve against.
*/
function resolveAuditFile(auditFile, workspace) {
	if (isAbsolute(auditFile)) return auditFile;
	if (workspace === void 0) throw new AuditUnavailableError(`reversibility-gate: cannot resolve audit file "${auditFile}" without a session workspace`);
	return resolve(workspace, auditFile);
}
/** One writable JSONL destination. */
var AuditSink = class {
	file;
	/**
	* Create the destination's directory and verify it is writable before any
	* decision depends on it, so an unusable trail fails at the first call rather
	* than after an allowed one.
	* @param file - absolute audit file path.
	* @throws AuditUnavailableError when the directory cannot be created or the file cannot be opened.
	*/
	constructor(file) {
		this.file = file;
		try {
			mkdirSync(dirname(file), { recursive: true });
			if (statSync(file, { throwIfNoEntry: false })?.isDirectory() === true) throw new AuditUnavailableError(`reversibility-gate: audit destination "${file}" is a directory`);
			closeSync(openSync(file, "a"));
		} catch (error) {
			if (error instanceof AuditUnavailableError) throw error;
			throw new AuditUnavailableError(`reversibility-gate: audit file "${file}" is not writable: ${messageOf(error)}`);
		}
	}
	/**
	* Append one record as a single JSONL line.
	* @param record - the record to persist.
	* @throws AuditUnavailableError when the write fails.
	*/
	write(record) {
		try {
			appendFileSync(this.file, `${JSON.stringify(record)}\n`, "utf8");
		} catch (error) {
			throw new AuditUnavailableError(`reversibility-gate: audit write failed for "${this.file}": ${messageOf(error)}`);
		}
	}
};
//#endregion
//#region lib/types/effects.js
/**
* Pure side-effect extraction. `effectOf` reads a call's name and arguments and
* reports the effects it would have; it never reads the filesystem, spawns a
* process, or consults the clock, so classification stays deterministic and
* cheap enough for the pre-dispatch path.
* @module @deepseek-ai/dsh-reversibility-gate/effects
*/
/** Tools with no durable effect at all. */
const READ_TOOLS = new Set([
	"read",
	"read_image",
	"glob",
	"grep",
	"web_search",
	"web_fetch",
	"lsp"
]);
/** Tools whose own call is transport, not effect: their inner calls are gated separately. */
const DELEGATE_TOOLS = new Set(["run_code", "workflow"]);
/** Tools that cannot bound their effects and never reach the filesystem directly. */
const UNBOUNDED_TOOLS = new Map([
	["subagent", "delegation"],
	["terminal", "terminal-input"],
	["job_start", "job-control"],
	["job_kill", "job-control"]
]);
/** Tools that replace or create file content at one argument path. */
const FILE_MUTATION_TOOLS = new Set([
	"write",
	"edit",
	"write_file",
	"str_replace_editor",
	"apply_patch"
]);
/** Tools whose `command` argument is analyzed as a shell program. */
const SHELL_TOOLS = new Set(["bash", "pwsh"]);
/** Argument keys that carry a filesystem path across the tool catalog. */
const PATH_KEYS$1 = [
	"file_path",
	"path",
	"file",
	"directory",
	"target",
	"workdir",
	"cwd"
];
/** Leading wrapper commands that do not name the effect themselves. */
const COMMAND_WRAPPERS = new Set([
	"sudo",
	"doas",
	"su",
	"env",
	"time",
	"nohup",
	"command",
	"exec"
]);
/** Wrappers that raise the call's privilege outside the workspace sandbox. */
const PRIVILEGE_WRAPPERS = new Set([
	"sudo",
	"doas",
	"su"
]);
/** Shell interpreters whose appearance downstream of a pipe means remote code execution. */
const SHELL_INTERPRETERS = new Set([
	"sh",
	"bash",
	"zsh",
	"fish",
	"pwsh",
	"powershell",
	"cmd"
]);
/** Verbs that only observe state. */
const READ_VERBS = new Set([
	"ls",
	"cat",
	"head",
	"tail",
	"less",
	"more",
	"pwd",
	"echo",
	"printf",
	"grep",
	"rg",
	"ag",
	"find",
	"wc",
	"sort",
	"uniq",
	"cut",
	"awk",
	"jq",
	"which",
	"whereis",
	"whoami",
	"id",
	"date",
	"uname",
	"ps",
	"top",
	"df",
	"du",
	"stat",
	"file",
	"tree",
	"get-childitem",
	"get-content",
	"write-output"
]);
/** Verbs that remove content or overwrite it irrecoverably. */
const DESTROY_VERBS = new Set([
	"rm",
	"rmdir",
	"del",
	"erase",
	"rd",
	"shred",
	"truncate",
	"remove-item"
]);
/** Verbs that create or change content in place. */
const MUTATE_VERBS = new Set([
	"mkdir",
	"touch",
	"cp",
	"copy",
	"mv",
	"move",
	"sed",
	"tee",
	"ln",
	"new-item",
	"set-content",
	"add-content",
	"copy-item",
	"move-item",
	"out-file"
]);
/** Verbs that change access control or host services. */
const PRIVILEGE_VERBS = new Set([
	"chmod",
	"chown",
	"chgrp",
	"systemctl",
	"service",
	"sc",
	"netsh",
	"reg",
	"launchctl",
	"sudo"
]);
/** Package managers: installs mutate the workspace, publishes reach a registry. */
const PACKAGE_VERBS = new Set([
	"npm",
	"pnpm",
	"yarn",
	"bun",
	"npx"
]);
/** Package-manager actions that only report. */
const PACKAGE_READ_ACTIONS = new Set([
	"ls",
	"list",
	"view",
	"why",
	"outdated",
	"info"
]);
/** Package-manager actions that reach a registry or account. */
const PACKAGE_REMOTE_ACTIONS = new Set([
	"publish",
	"login",
	"logout",
	"deprecate",
	"unpublish"
]);
/** HTTP clients: the method decides whether the call reads or writes remotely. */
const HTTP_VERBS = new Set([
	"curl",
	"wget",
	"invoke-webrequest",
	"invoke-restmethod"
]);
/** Clients that execute a command on another host. */
const REMOTE_VERBS = new Set([
	"ssh",
	"scp",
	"rsync",
	"telnet"
]);
/** Container runtimes. */
const CONTAINER_VERBS = new Set(["docker", "podman"]);
/** Kubernetes and infrastructure CLIs whose mutations act on remote state. */
const CLOUD_VERBS = new Set([
	"kubectl",
	"terraform",
	"aws",
	"gcloud",
	"az"
]);
/** Container and cloud actions that only report. */
const REMOTE_READ_ACTIONS = new Set([
	"get",
	"describe",
	"logs",
	"ps",
	"images",
	"version",
	"info",
	"plan",
	"show",
	"validate"
]);
/** `git` subcommands that only observe. */
const GIT_READ_SUBCOMMANDS = new Set([
	"status",
	"log",
	"diff",
	"show",
	"branch",
	"remote",
	"rev-parse",
	"describe",
	"blame",
	"ls-files",
	"ls-tree",
	"shortlog",
	"reflog",
	"tag"
]);
/** `git` subcommands that destroy uncommitted work. */
const GIT_DESTROY_SUBCOMMANDS = new Set([
	"reset",
	"clean",
	"prune"
]);
/** `gh` actions that only observe. */
const GH_READ_ACTIONS = new Set([
	"view",
	"list",
	"status",
	"diff",
	"checks",
	"download"
]);
/** `gh` actions that change remote state or post a message. */
const GH_REMOTE_ACTIONS = new Set([
	"create",
	"merge",
	"close",
	"reopen",
	"edit",
	"delete",
	"comment",
	"review",
	"approve",
	"ready",
	"run",
	"cancel",
	"upload",
	"deploy"
]);
/** Flags that carry an HTTP request body, which makes even a default method a write. */
const BODY_FLAGS = new Set([
	"-d",
	"--data",
	"--data-raw",
	"--data-binary",
	"-f",
	"--form",
	"-t",
	"--upload-file",
	"--post-data"
]);
/** URL scheme prefix recognized inside a command. */
const URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;
/** Read one field off an unknown arguments value. */
function recordOf(args) {
	return typeof args === "object" && args !== null ? args : void 0;
}
/** Read one string field off an unknown arguments value. */
function stringField(record, key) {
	const value = record?.[key];
	return typeof value === "string" ? value : void 0;
}
/** First path-valued argument key present on the call. */
function pathArgument(args) {
	const record = recordOf(args);
	for (const key of PATH_KEYS$1) {
		const value = stringField(record, key);
		if (value !== void 0 && value.length > 0) return value;
	}
}
/**
* Resolve the directories a call's targets are measured against.
* @param args - parsed tool arguments, read only for a shell `workdir`.
* @param workspace - session workspace root, when the caller has one.
* @returns the resolved pair, or undefined when the caller has no workspace.
*/
function pathsOf(args, workspace) {
	if (workspace === void 0) return void 0;
	const root = resolve(workspace);
	const workdir = stringField(recordOf(args), "workdir");
	return {
		root,
		base: workdir === void 0 ? root : resolve(root, workdir)
	};
}
/**
* Compare one spelled path to the workspace root lexically — `resolve` and
* `relative` never touch the disk.
* @param pathText - path exactly as the call spelled it.
* @param paths - resolved workspace directories, or undefined without a workspace.
* @returns whether the target sits inside the workspace, outside it, or cannot be resolved.
*/
function scopeOfPath(pathText, paths) {
	if (pathText.length === 0) return "unknown";
	if (/[*?]/.test(pathText)) return "unknown";
	if (pathText.startsWith("~")) return "outside";
	if (paths === void 0) return "unknown";
	const nested = relative(paths.root, resolve(paths.base, pathText));
	if (nested === "") return "workspace";
	return !nested.startsWith("..") && !isAbsolute(nested) ? "workspace" : "outside";
}
/** Build one target from a spelled path. */
function targetOf(pathText, paths) {
	return {
		path: pathText,
		scope: scopeOfPath(pathText, paths)
	};
}
/** Non-flag words of one command, treated as its path operands. */
function pathWords(argv) {
	return argv.filter((word) => word.length > 0 && !word.startsWith("-"));
}
/** Effects of redirections regardless of the verb that owns them. */
function redirectEffects(redirects, paths) {
	return redirects.map((redirect) => redirect.op === ">" ? {
		kind: "destroy",
		detail: "shell:overwrite",
		targets: [targetOf(redirect.target, paths)]
	} : {
		kind: "mutate",
		detail: "shell:append",
		targets: [targetOf(redirect.target, paths)]
	});
}
/** The workspace itself as a target, used by verbs whose effects cannot be read from arguments. */
function workspaceTargets(paths) {
	return [targetOf(".", paths)];
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
	} catch (_invalidUrl) {
		return;
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
	const chars = command.split("");
	let current = "";
	let quote;
	let skip = false;
	const push = (pipedIntoNext) => {
		if (current.trim().length === 0) return;
		raw.push(current);
		piped.push(pipedIntoNext);
		current = "";
	};
	for (const [index, char] of chars.entries()) {
		if (skip) {
			skip = false;
			continue;
		}
		if (quote !== void 0) {
			current += char;
			if (char === quote) quote = void 0;
			continue;
		}
		if (char === "\"" || char === "'") {
			quote = char;
			current += char;
			continue;
		}
		if (char === "`") return void 0;
		if (char === "$" && chars.at(index + 1) === "(") return void 0;
		if (char === "|") {
			push(chars.at(index + 1) !== "|");
			skip = chars.at(index + 1) === "|";
			continue;
		}
		if (char === "&" && chars.at(index + 1) === "&") {
			push(false);
			skip = true;
			continue;
		}
		if (char === ";" || char === "\n") {
			push(false);
			continue;
		}
		current += char;
	}
	if (quote !== void 0) return void 0;
	push(false);
	return {
		raw,
		piped
	};
}
/**
* Split one segment into words with quotes removed. Callers pass segments that
* `splitSegments` accepted, so quoting is balanced here by construction.
* @param segment - raw segment text without separators.
* @returns the words, in order, with quoted runs kept whole.
*/
function tokenize(segment) {
	const words = [];
	let current = "";
	let started = false;
	let quote;
	for (const char of segment) {
		if (quote !== void 0) {
			if (char === quote) {
				quote = void 0;
				continue;
			}
			current += char;
			continue;
		}
		if (char === "\"" || char === "'") {
			quote = char;
			started = true;
			continue;
		}
		if (char === " " || char === "	" || char === "\r") {
			if (started) {
				words.push(current);
				current = "";
				started = false;
			}
			continue;
		}
		current += char;
		started = true;
	}
	if (started) words.push(current);
	return words;
}
/**
* Recognize one redirection word, including an attached target (`>out.txt`) and
* a leading file-descriptor digit (`2>`).
* @param word - one tokenized word.
* @returns the operator and attached target text, or undefined when the word is not a redirection.
*/
function redirectOf(word) {
	const body = word.replace(/^[12&]/, "");
	if (body.startsWith(">>")) return {
		op: ">>",
		attached: body.slice(2)
	};
	if (body.startsWith(">")) return {
		op: ">",
		attached: body.slice(1)
	};
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
		if (index <= consumed) continue;
		const redirect = redirectOf(word);
		if (redirect === void 0) {
			rest.push(word);
			continue;
		}
		if (redirect.attached.length > 0) {
			redirects.push({
				op: redirect.op,
				target: redirect.attached
			});
			continue;
		}
		const target = words[index + 1];
		if (target === void 0) {
			rest.push(word);
			continue;
		}
		redirects.push({
			op: redirect.op,
			target
		});
		consumed = index + 1;
	}
	return {
		words: rest,
		redirects
	};
}
/**
* Analyze one shell command string.
* @param command - the command text from the tool arguments.
* @returns the parsed segments, pipeline-to-shell flag, literal URLs, and whether parsing succeeded.
*/
function analyzeShell(command) {
	const split = splitSegments(command);
	if (split === void 0) return {
		segments: [],
		pipeToShell: false,
		urls: [],
		parsed: false
	};
	const segments = [];
	const urls = [];
	let pipeToShell = false;
	for (const [index, raw] of split.raw.entries()) {
		const words = tokenize(raw);
		for (const word of words) if (isUrl(word)) urls.push(word);
		segments.push(takeRedirects(words));
		const next = split.raw[index + 1];
		if (split.piped[index] === true && next !== void 0 && SHELL_INTERPRETERS.has(verbOf(tokenize(next)))) pipeToShell = true;
	}
	return {
		segments,
		pipeToShell,
		urls,
		parsed: true
	};
}
/**
* Index of the word that names the command's effect, skipping assignments and wrappers.
* @param words - tokenized words of one segment.
* @returns the verb index, or `words.length` when the segment holds only wrappers.
*/
function realVerbIndex(words) {
	for (const [index, word] of words.entries()) {
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) continue;
		if (COMMAND_WRAPPERS.has(word.toLowerCase())) continue;
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
	return (words[realVerbIndex(words)] ?? "").toLowerCase();
}
/** Effects contributed by the verb and its operands. */
function verbEffects(verb, argv, redirects, paths) {
	if (DESTROY_VERBS.has(verb)) return rebuildTargets("destroy", "shell:destroy", argv, redirects, paths);
	if (MUTATE_VERBS.has(verb)) return rebuildTargets("mutate", "shell:mutate", argv, redirects, paths);
	if (READ_VERBS.has(verb)) return redirectEffects(redirects, paths);
	if (PRIVILEGE_VERBS.has(verb)) return [{
		kind: "privilege",
		detail: "shell:privilege"
	}];
	if (PACKAGE_VERBS.has(verb)) return [packageEffect(argv, paths)];
	if (HTTP_VERBS.has(verb)) return [httpEffect(argv)];
	if (REMOTE_VERBS.has(verb)) return [{
		kind: "remote",
		detail: "remote:shell",
		surface: "state"
	}];
	if (CONTAINER_VERBS.has(verb)) return [containerEffect(argv, paths)];
	if (CLOUD_VERBS.has(verb)) return [cloudEffect(argv)];
	if (verb === "git") return [gitEffect(argv, paths)];
	if (verb === "gh") return [ghEffect(argv)];
	return [{
		kind: "unknown",
		detail: "shell:unknown-verb",
		severity: "risky"
	}];
}
/** Build mutate/destroy effects from path operands plus redirections. */
function rebuildTargets(kind, detail, argv, redirects, paths) {
	const operands = pathWords(argv);
	const effects = [];
	if (operands.length > 0) effects.push({
		kind,
		detail,
		targets: operands.map((path) => targetOf(path, paths))
	});
	effects.push(...redirectEffects(redirects, paths));
	if (effects.length === 0) return [{
		kind: "unknown",
		detail: `${detail}-no-target`,
		severity: "redline"
	}];
	return effects;
}
/** Package-manager action: report, mutate the workspace, or reach a registry. */
function packageEffect(argv, paths) {
	const action = (argv[0] ?? "").toLowerCase();
	if (PACKAGE_REMOTE_ACTIONS.has(action)) return {
		kind: "remote",
		detail: "remote:package",
		surface: "state"
	};
	if (PACKAGE_READ_ACTIONS.has(action)) return {
		kind: "read",
		detail: "read-only"
	};
	return {
		kind: "mutate",
		detail: "shell:package",
		targets: workspaceTargets(paths)
	};
}
/**
* HTTP method the client was asked to use.
* @param argv - client arguments.
* @returns the uppercase method, or undefined when the client sends no body and requests none.
*/
function httpMethod(argv) {
	for (const [index, flag] of argv.entries()) {
		const word = flag.toLowerCase();
		if (word === "-x" || word === "--request" || word === "--method") return (argv[index + 1] ?? "").toUpperCase();
		if (BODY_FLAGS.has(word)) return "POST";
	}
}
/** HTTP client effect: a body-carrying method writes remotely, everything else reads. */
function httpEffect(argv) {
	const method = httpMethod(argv);
	if (method === void 0 || method === "GET" || method === "HEAD") return {
		kind: "read",
		detail: "read-only"
	};
	return {
		kind: "remote",
		detail: "remote:http",
		surface: method === "DELETE" ? "state" : "message"
	};
}
/** Container CLI: push and login reach a registry, read actions report, the rest mutates locally. */
function containerEffect(argv, paths) {
	const action = (argv[0] ?? "").toLowerCase();
	if (action === "push" || action === "login") return {
		kind: "remote",
		detail: "remote:container",
		surface: "state"
	};
	if (REMOTE_READ_ACTIONS.has(action)) return {
		kind: "read",
		detail: "read-only"
	};
	return {
		kind: "mutate",
		detail: "shell:container",
		targets: workspaceTargets(paths)
	};
}
/** Cluster and cloud CLI: read actions report, everything else changes remote state. */
function cloudEffect(argv) {
	const action = (argv[0] ?? "").toLowerCase();
	if (REMOTE_READ_ACTIONS.has(action)) return {
		kind: "read",
		detail: "read-only"
	};
	return {
		kind: "remote",
		detail: "remote:cloud",
		surface: "state"
	};
}
/** `git` subcommand effect. */
function gitEffect(argv, paths) {
	const subcommand = (argv[0] ?? "").toLowerCase();
	if (subcommand === "push") return {
		kind: "remote",
		detail: "remote:git-push",
		surface: "state"
	};
	if (GIT_READ_SUBCOMMANDS.has(subcommand) && !argv.includes("--force")) return {
		kind: "read",
		detail: "read-only"
	};
	if (GIT_DESTROY_SUBCOMMANDS.has(subcommand)) return {
		kind: "unknown",
		detail: "shell:git-destroy",
		severity: "redline"
	};
	return {
		kind: "mutate",
		detail: "shell:git",
		targets: workspaceTargets(paths)
	};
}
/** `gh` subcommand effect. */
function ghEffect(argv) {
	if ((argv[0] ?? "").toLowerCase() === "api") {
		const method = httpMethod(argv.slice(1));
		if (method === void 0 || method === "GET" || method === "HEAD") return {
			kind: "read",
			detail: "read-only"
		};
		return {
			kind: "remote",
			detail: "remote:gh-api",
			surface: "state"
		};
	}
	const action = (argv[1] ?? "").toLowerCase();
	if (GH_READ_ACTIONS.has(action)) return {
		kind: "read",
		detail: "read-only"
	};
	if (GH_REMOTE_ACTIONS.has(action)) return {
		kind: "remote",
		detail: "remote:gh",
		surface: action === "comment" ? "message" : "state"
	};
	return {
		kind: "unknown",
		detail: "shell:gh",
		severity: "risky"
	};
}
/** Effects of one analyzed segment. */
function segmentEffects(segment, paths) {
	const verbIndex = realVerbIndex(segment.words);
	const verb = verbOf(segment.words);
	if (verb.length === 0) return redirectEffects(segment.redirects, paths);
	const argv = segment.words.slice(verbIndex + 1);
	const wrappers = segment.words.slice(0, verbIndex).map((word) => word.toLowerCase());
	const effects = [];
	if (wrappers.some((wrapper) => PRIVILEGE_WRAPPERS.has(wrapper))) effects.push({
		kind: "privilege",
		detail: "shell:privilege"
	});
	effects.push(...verbEffects(verb, argv, segment.redirects, paths));
	return effects;
}
/** Effects of one shell tool call. */
function shellEffects(call, extraRedlineHosts) {
	const command = stringField(recordOf(call.args), "command");
	if (command === void 0) return [{
		kind: "unknown",
		detail: "shell:missing-command",
		severity: "redline"
	}];
	const analysis = analyzeShell(command);
	if (!analysis.parsed) return [{
		kind: "unknown",
		detail: "shell:unparsed",
		severity: "redline"
	}];
	const paths = pathsOf(call.args, call.workspace);
	const effects = [];
	for (const segment of analysis.segments) effects.push(...segmentEffects(segment, paths));
	if (analysis.pipeToShell) effects.push({
		kind: "remote",
		detail: "remote:pipe-to-shell",
		surface: "state"
	});
	if (analysis.urls.some((url) => extraRedlineHosts.includes(hostOf(url) ?? ""))) effects.push({
		kind: "remote",
		detail: "remote:redline-host",
		surface: "state"
	});
	return effects.length > 0 ? effects : [{
		kind: "read",
		detail: "read-only"
	}];
}
/**
* Extract the side effects one call would have.
* @param call - pure call inputs (name, arguments, workspace root).
* @param extraRedlineHosts - deployment-added hosts whose traffic counts as remote state.
* @returns the effects in command order, never empty.
*/
function effectOf(call, extraRedlineHosts) {
	if (SHELL_TOOLS.has(call.toolName)) return shellEffects(call, extraRedlineHosts);
	if (FILE_MUTATION_TOOLS.has(call.toolName)) {
		const path = pathArgument(call.args);
		if (path === void 0) return [{
			kind: "unknown",
			detail: "file-mutation-no-path",
			severity: "risky"
		}];
		return [{
			kind: "mutate",
			detail: "file:mutate",
			targets: [targetOf(path, pathsOf(call.args, call.workspace))]
		}];
	}
	if (READ_TOOLS.has(call.toolName)) return [{
		kind: "read",
		detail: "read-only"
	}];
	if (DELEGATE_TOOLS.has(call.toolName)) return [{
		kind: "delegate",
		detail: "delegated-transport"
	}];
	const unbounded = UNBOUNDED_TOOLS.get(call.toolName);
	if (unbounded !== void 0) return [{
		kind: "unknown",
		detail: `tool:${unbounded}`,
		severity: "risky"
	}];
	return [{
		kind: "unknown",
		detail: "tool:unknown",
		severity: "risky"
	}];
}
//#endregion
//#region lib/types/classify.js
/**
* Deterministic risk classification: extract the call's side effects, take the
* most severe of them, then apply the deployment's tool-level overrides.
* @module @deepseek-ai/dsh-reversibility-gate/classify
*/
/** Severity order used to pick the worst effect of a call. */
const TIER_RANK = {
	safe: 0,
	risky: 1,
	redline: 2
};
/**
* Tier of one effect. A workspace-scoped mutation or deletion is recoverable
* from the session workspace; anything reaching outside it, or whose target
* cannot be resolved, is not.
* @param effect - one extracted side effect.
* @returns the tier that effect implies on its own.
*/
function tierOf(effect) {
	if (effect.kind === "read" || effect.kind === "delegate") return "safe";
	if (effect.kind === "remote" || effect.kind === "privilege") return "redline";
	if (effect.kind === "unknown") return effect.severity;
	return effect.targets.every((target) => target.scope === "workspace") ? "risky" : "redline";
}
/**
* Classify one call by the reversibility of its side effects.
* @param call - pure call inputs (name, arguments, workspace root).
* @param policy - compiled deployment policy.
* @returns the highest tier implied by the call's effects plus the rule that produced it.
*/
function classify(call, policy) {
	const worst = effectOf(call, policy.extraRedlineHosts).reduce((best, effect) => TIER_RANK[tierOf(effect)] > TIER_RANK[tierOf(best)] ? effect : best);
	const tier = tierOf(worst);
	const override = policy.tierOverrides[call.toolName];
	if (override !== void 0 && TIER_RANK[override] > TIER_RANK[tier]) return {
		tier: override,
		rule: `override:${call.toolName}`
	};
	return {
		tier,
		rule: worst.detail
	};
}
//#endregion
//#region lib/types/config.js
/**
* Plugin configuration and its compiled policy. The schemastery schema rejects
* malformed deployments at load time; `compilePolicy` only normalizes the
* validated values and rejects the one case the schema cannot express.
* @module @deepseek-ai/dsh-reversibility-gate/config
*/
/** Schemastery validation for {@link Config}. */
const Config = z.object({
	trustThreshold: z.natural().min(1).default(3),
	auditFile: z.string().default(".dsh-reversibility/audit.jsonl"),
	signatureTruncateChars: z.natural().min(64).default(500),
	tierOverrides: z.dict(z.union([
		"safe",
		"risky",
		"redline"
	])).default({}),
	extraRedlineHosts: z.array(z.string()).default([]),
	extraProtectedPaths: z.array(z.string()).default([])
});
/**
* Normalize validated configuration into the policy the decision path reads.
* @param config - configuration already validated by the {@link Config} schema.
* @returns the frozen policy with normalized hosts and copied tables.
* @throws Error when the audit destination is empty, which would leave decisions unauditable.
*/
function compilePolicy(config) {
	const auditFile = config.auditFile.trim();
	if (auditFile.length === 0) throw new Error("reversibility-gate: auditFile must be a non-empty path");
	return {
		trustThreshold: config.trustThreshold,
		auditFile,
		signatureTruncateChars: config.signatureTruncateChars,
		tierOverrides: { ...config.tierOverrides },
		extraRedlineHosts: config.extraRedlineHosts.map((host) => host.trim().toLowerCase()).filter((host) => host.length > 0),
		extraProtectedPaths: [...config.extraProtectedPaths]
	};
}
//#endregion
//#region lib/types/guard.js
/**
* Monotonic self-protection invariants. These checks run after every
* `tools/pre-execute` decision, so a human approval cannot turn them into a
* permit: they are registered through `ctx.tools.guard()`, which has no
* allow result. Ordinary tier policy stays in the waterfall instead.
* @module @deepseek-ai/dsh-reversibility-gate/guard
*/
/**
* Whether one absolute path is the parent's own path or sits beneath it.
* @param parent - absolute parent path.
* @param child - absolute path to test.
* @returns true when `child` is `parent` or nested inside it.
*/
function contains(parent, child) {
	const nested = relative(parent, child);
	return nested === "" || !nested.startsWith("..") && !isAbsolute(nested);
}
/**
* Check the invariants a session must never break, even with approval.
* @param call - pure call inputs of the pending execution.
* @param policy - compiled deployment policy.
* @returns a denial reason, or undefined when the call breaks no invariant.
*/
function selfProtectionReason(call, policy) {
	if (call.workspace === void 0) return void 0;
	const root = resolve(call.workspace);
	const auditDir = dirname(resolveAuditFile(policy.auditFile, root));
	const gitDir = resolve(root, ".git");
	const protectedPaths = policy.extraProtectedPaths.map((path) => resolve(root, path));
	for (const effect of effectOf(call, policy.extraRedlineHosts)) {
		if (effect.kind !== "mutate" && effect.kind !== "destroy") continue;
		for (const target of effect.targets) {
			const absolute = resolve(root, target.path);
			if (contains(absolute, root)) return "refusing to remove or replace the workspace root";
			if (contains(gitDir, absolute)) return "refusing to touch repository metadata";
			if (contains(auditDir, absolute)) return "refusing to touch the audit trail";
			if (protectedPaths.some((path) => contains(path, absolute))) return "refusing to touch a protected path";
		}
	}
}
//#endregion
//#region lib/types/signature.js
/**
* Operation signatures: one hash over the tool name plus normalization of its
* arguments, so two calls with the same intent share progressive-grant state.
* Normalization is deliberately approximate; the README records the tradeoff.
* @module @deepseek-ai/dsh-reversibility-gate/signature
*/
/** Argument keys whose values are filesystem paths and get path normalization. */
const PATH_KEYS = new Set([
	"file_path",
	"path",
	"file",
	"directory",
	"target",
	"workdir",
	"cwd"
]);
/** Argument keys whose whitespace is insignificant. */
const COMMAND_KEYS = new Set(["command", "script"]);
/**
* Unify one path spelling: separator, doubled separators, embedded `./`, and a
* trailing separator. `resolve` is not used because it depends on the process
* working directory, which would make the signature host-dependent.
* @param value - the path as written.
* @returns the normalized spelling.
*/
function normalizePath(value) {
	const unified = value.replaceAll("\\", "/").replace(/\/{2,}/g, "/").replace(/\/\.\//g, "/");
	if (unified.length > 1 && unified.endsWith("/")) return unified.slice(0, -1);
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
	if (typeof value === "string") {
		const collapsed = key !== void 0 && COMMAND_KEYS.has(key) ? value.replace(/\s+/g, " ").trim() : value;
		const normalized = key !== void 0 && PATH_KEYS.has(key) ? normalizePath(collapsed) : collapsed;
		if (normalized.length <= truncateChars) return normalized;
		return `${normalized.slice(0, truncateChars)}…+${normalized.length - truncateChars}`;
	}
	if (Array.isArray(value)) return value.map((item) => normalizeValue(item, key, truncateChars));
	if (typeof value === "object" && value !== null) {
		const record = value;
		const sorted = {};
		for (const child of Object.keys(record).sort()) sorted[child] = normalizeValue(record[child], child, truncateChars);
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
function signatureOf(call, truncateChars) {
	const normalized = normalizeValue(call.args, void 0, truncateChars);
	return createHash("sha256").update(`${call.toolName}\u0000${JSON.stringify(normalized)}`).digest("hex").slice(0, 16);
}
//#endregion
//#region lib/types/trust.js
/**
* Progressive grants: an in-memory record of which operation signatures have
* earned auto-allow. State is written only from the post-execute observation
* path, never persisted, and never consulted for redline calls.
* @module @deepseek-ai/dsh-reversibility-gate/trust
*/
/**
* Per-instance progressive-grant ledger.
*
* `safe` calls always pass, `redline` calls always ask, and a `risky` call
* passes only after `threshold` consecutive approved-and-successful outcomes
* for the same signature.
*/
var TrustLedger = class {
	threshold;
	states = /* @__PURE__ */ new Map();
	/**
	* @param threshold - consecutive successes required for auto-allow; also the number reported in audit reasons.
	* @throws Error when the threshold is not a positive integer.
	*/
	constructor(threshold) {
		this.threshold = threshold;
		if (!Number.isInteger(threshold) || threshold < 1) throw new Error(`reversibility-gate: trustThreshold must be a positive integer, got ${String(threshold)}`);
	}
	/**
	* Approved count currently recorded for one signature.
	* @param signature - signature hash.
	* @returns the consecutive-success count, zero when absent.
	*/
	approvedCount(signature) {
		return this.states.get(signature)?.approvedCount ?? 0;
	}
	/**
	* Decide whether a call of this tier may proceed without asking.
	* @param tier - classification of the pending call.
	* @param signature - signature hash of the pending call.
	* @returns `allow` to proceed, `ask` to require approval.
	*/
	decide(tier, signature) {
		if (tier === "safe") return "allow";
		if (tier === "redline") return "ask";
		return this.approvedCount(signature) >= this.threshold ? "allow" : "ask";
	}
	/**
	* Record one approved-and-successful outcome for a signature.
	* @param signature - signature hash of the call that succeeded.
	*/
	confirm(signature) {
		const current = this.states.get(signature);
		this.states.set(signature, {
			approvedCount: (current?.approvedCount ?? 0) + 1,
			lastOutcome: "success"
		});
	}
	/**
	* Revoke a signature's grants after one failure or denial.
	* @param signature - signature hash of the call that failed.
	*/
	reset(signature) {
		this.states.set(signature, {
			approvedCount: 0,
			lastOutcome: "failure"
		});
	}
};
//#endregion
//#region lib/types/index.js
/**
* Reversibility gate: a pre-dispatch policy layer over `tools/pre-execute`,
* `ctx.tools.guard()`, and `tools/post-execute`. It classifies every call by
* side-effect reversibility, asks for approval while a risky signature is
* untrusted, auto-allows once it has earned trust, never lets redline calls
* inherit that trust, and records every decision in an append-only audit trail.
* @module @deepseek-ai/dsh-reversibility-gate
*/
/** Stable Loader identity. */
const name = "reversibility-gate";
/** The policy layer reads and guards the tool registry. */
const inject = ["tools"];
/**
* Install the pre-execute policy, the post-execute observer, and the
* self-protection guard. All three are effects of this plugin's context, so
* unloading removes every listener and the in-memory ledger with it.
* @param ctx - plugin context; effects and registrations are scoped to it.
* @param config - validated configuration supplied by the Loader.
*/
function apply(ctx, config) {
	const policy = compilePolicy(config);
	const trust = new TrustLedger(policy.trustThreshold);
	const pending = /* @__PURE__ */ new Map();
	const sinks = /* @__PURE__ */ new Map();
	/** Reuse one writable sink per resolved destination. */
	const sinkFor = (workspace) => {
		const file = resolveAuditFile(policy.auditFile, workspace);
		const existing = sinks.get(file);
		if (existing !== void 0) return existing;
		const created = new AuditSink(file);
		sinks.set(file, created);
		return created;
	};
	/** Pure classification inputs of one execution. */
	const callOf = (exec) => ({
		toolName: exec.name,
		args: exec.arguments,
		workspace: exec.agent?.session.header.cwd
	});
	/** Audited reason for one decision, naming the rule or the earned trust count. */
	const reasonOf = (tier, signature, classification) => {
		if (tier === "safe") return classification.rule;
		if (tier === "redline") return `redline:${classification.rule}`;
		const approved = trust.approvedCount(signature);
		return approved >= policy.trustThreshold ? `signature:approved:${approved}` : `signature:untrusted:${classification.rule}`;
	};
	ctx.on("tools/pre-execute", async (exec, next) => {
		const call = callOf(exec);
		const callId = String(exec.callId);
		try {
			const classification = classify(call, policy);
			const signature = signatureOf(call, policy.signatureTruncateChars);
			const route = trust.decide(classification.tier, signature);
			const downstream = await next();
			let decision = downstream;
			let auditReason = reasonOf(classification.tier, signature, classification);
			if (downstream.kind === "allow" && route === "ask") {
				const session = exec.agent?.session;
				if (session !== void 0 && approvalPolicyOf(ctx.get("approval"), session) === "never") {
					decision = {
						kind: "deny",
						reason: `reversibility-gate: ${auditReason} requires approval, but this session's approval policy is never; switch the permission preset to Standard (approval policy ask)`
					};
					auditReason = `policy:never:${auditReason}`;
				} else decision = {
					kind: "ask",
					reason: `reversibility-gate: ${auditReason}`,
					displayReason: { en: `Approve this ${classification.tier} tool call? Reversibility gate rule: ${classification.rule}.` }
				};
			}
			sinkFor(call.workspace).write({
				timestamp: (/* @__PURE__ */ new Date()).toISOString(),
				callId,
				toolName: exec.name,
				signatureHash: signature,
				riskTier: classification.tier,
				decisionKind: decision.kind === "cancel" ? "deny" : decision.kind,
				decisionReason: auditReason,
				event: "decision",
				...classification.tier === "risky" ? { trustCount: trust.approvedCount(signature) } : {}
			});
			if (classification.tier === "risky") pending.set(callId, {
				signature,
				tier: classification.tier
			});
			return decision;
		} catch (error) {
			ctx.logger.warn(`reversibility-gate: denying ${exec.name}: ${messageOf(error)}`);
			return {
				kind: "deny",
				reason: `reversibility-gate: ${messageOf(error)}`
			};
		}
	});
	ctx.on("tools/post-execute", async (exec, result, next) => {
		const downstream = await next();
		const callId = String(exec.callId);
		const recorded = pending.get(callId);
		if (recorded === void 0) return downstream;
		pending.delete(callId);
		try {
			if (result.isError) trust.reset(recorded.signature);
			else trust.confirm(recorded.signature);
			sinkFor(exec.agent?.session.header.cwd).write({
				timestamp: (/* @__PURE__ */ new Date()).toISOString(),
				callId,
				toolName: exec.name,
				signatureHash: recorded.signature,
				riskTier: recorded.tier,
				decisionKind: result.isError ? "deny" : "allow",
				decisionReason: result.isError ? "outcome:failure" : "outcome:success",
				event: "outcome",
				outcome: result.isError ? "failure" : "success"
			});
		} catch (error) {
			ctx.logger.warn(`reversibility-gate: observation failed for ${exec.name}: ${messageOf(error)}`);
		}
		return downstream;
	});
	ctx.effect(() => ctx.tools.guard((exec) => {
		const reason = selfProtectionReason(callOf(exec), policy);
		return reason === void 0 ? void 0 : `reversibility-gate: ${reason}`;
	}));
}
//#endregion
export { Config, apply, inject, name };
