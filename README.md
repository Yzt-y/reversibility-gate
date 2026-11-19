---
description: "Pre-dispatch policy plugin that classifies tool calls by side-effect reversibility, gates risky and redline calls through approval, accumulates progressive grants, and audits every decision for users and maintainers debugging why a call was allowed or asked."
kind: "package-reference"
---

# dsh-reversibility-gate

English | [中文](README.zh.md)

## Summary

This package adds a reversibility policy layer to the tool pipeline. Before dispatch, it classifies each call's side effects as `safe`, `risky`, or `redline` and routes it through one of three paths: pass, ask once while the operation signature is untrusted, or always ask. A risky signature that succeeds three times (configurable) auto-allows until one failure revokes it. Self-protection invariants are monotonic guards, so approval cannot permit deleting the workspace root. Every decision appends to a JSONL trail; an unwritable trail denies the call.

## Table of Contents

- [Use this package](#use-this-package)
- [Understand the implementation](#understand-the-implementation)
- [Repository layout](#repository-layout)
- [Further Exploration](#further-exploration)
- [Model Experience](#model-experience)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)
- [Dev Note](#dev-note)

-----

<a id="use-this-package"></a>
## Use this package

Install the package into the profile whose tool calls it should govern. Any install spec the plugin manager accepts works; a local clone, a tarball, or a published name:

```sh
pnpm dsh plugin --profile web add /absolute/path/to/dsh-reversibility-gate
```

Remove it with the same CLI (`... remove dsh-reversibility-gate`). Removing the layer restores native behavior: the pre-execute listener, the post-execute observer, the monotonic guard, and the in-memory grant ledger all unload together.

### When to choose it

Choose it when a profile runs autonomously enough that "did the model delete something it cannot restore, or write to a remote system?" is the question you want answered before the call runs, and when repeating an approved operation should stop asking. Avoid it when every call must be approved individually, because the progressive grant deliberately stops asking after three successes, and when the deployment already routes approvals through a text-pattern policy plugin that must stay the only decider.

### Configuration

```yaml
- name: 'dsh-reversibility-gate'
  config:
    trustThreshold: 3
    auditFile: .dsh-reversibility/audit.jsonl
    signatureTruncateChars: 500
    tierOverrides:
      subagent: redline
    extraRedlineHosts: [internal.corp]
    extraProtectedPaths: [secrets]
```

| Field | Default | Meaning |
|---|---|---|
| `trustThreshold` | `3` | Consecutive approved-and-successful outcomes after which a risky signature auto-allows |
| `auditFile` | `.dsh-reversibility/audit.jsonl` | JSONL destination; absolute, or relative to the session workspace |
| `signatureTruncateChars` | `500` | Characters of one argument string retained in a signature |
| `tierOverrides` | `{}` | Tool name to tier; can only raise a tier, never lower it |
| `extraRedlineHosts` | `[]` | Hosts whose appearance in a command counts as remote state |
| `extraProtectedPaths` | `[]` | Workspace-relative paths the guard refuses to mutate or remove |

An empty `auditFile` fails plugin load, and any schema violation fails load with the offending field; the plugin never falls back to an empty rule set. The harness [configuration catalog](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/config-catalog.md) documents every accepted value.

### What you get

A `read` runs immediately and leaves one `allow` audit line. A workspace `write` asks on its first call; after three approved successes the same signature runs without asking, and one failure drops it back to asking. A call that reaches outside the workspace — an absolute-path removal, a remote push, a publish, a cluster mutation, a privileged command, or a shell pipeline into an interpreter — asks on every call and never inherits trust. A call that would remove the workspace root, rewrite `.git`, or tamper with the audit trail is denied by the guard even when approval was granted.

When the session's approval policy is `never` — the pairing the Web "Full access" preset writes — the `ask` the runtime would reject is never sent: the gate denies the call itself and names both the policy and the preset to switch to. It does not pretend a prompt will appear.

Only legitimate-effect calls reach the guard: when another policy denies or cancels the call first, that decision stands, because the plugin delegates to later listeners before it considers raising a call to `ask`.

## Understand the implementation

<details>
<summary>Implementation internals — click to expand</summary>

### Design commitments

- **Delegation before escalation.** The pre-execute listener awaits `next()` first. A downstream deny, cancel, or ask outranks its own decision, so the plugin can only make the chain stricter.
- **Effects, not strings.** Classification extracts typed effects (read, mutate, destroy, remote, privilege, unknown) with resolved target scopes, then takes the most severe. A tool name or a command regex is never the sole input.
- **Monotonic invariants live in the guard.** `tools/pre-execute` is a waterfall, so a later listener could overturn an earlier deny. Self-protection therefore registers through `ctx.tools.guard()`, which has no allow result and is evaluated after the pre-execute decision — including after an approval.
- **Observation only in post-execute.** The listener returns the downstream decision untouched and only records the outcome. Trust is written nowhere else, and never to the session log or disk.

### Classification

`classify(call, policy)` is pure over its inputs (tool name, parsed arguments, workspace root) and returns a tier plus a stable rule id. A workspace-scoped mutation or deletion is `risky`: the workspace diff and git can recover it. A target that resolves outside the workspace, cannot be resolved (glob, home-relative, unknown workspace), or is reached by a remote, privileged, or unparsable effect is `redline`. Both a workspace `rm notes.txt` and an untracked `echo x > notes.txt` classify as `risky`, because neither is recoverable without the workspace; an absolute-path removal is `redline`.

`run_code` and `workflow` are transport: their inner calls traverse this same listener, so classifying them as effects would double-charge and double-count. Tools whose effects cannot be bounded (a subagent launch, terminal input, job control) stay `risky`, and an unknown tool is `risky` rather than a hard block.

### Progressive grants

The ledger maps a signature hash to a consecutive-success count. A `risky` signature asks while the count is below the threshold, auto-allows at or above it, and resets to zero on any failure, denial, or cancellation — the post-execute listener also sees denied calls, so a rejected approval revokes trust. `redline` and `safe` calls never enter the ledger.

The signature is `sha256(toolName + normalizedArguments)` truncated to 16 hex characters. Normalization sorts object keys, folds command whitespace, unifies path separators, and truncates long strings. It is an approximation of intent: two different 500-character payloads that share a prefix collapse into one signature, which is why redline calls never use trust and why one failure resets the count.

### Audit trail

Each decision appends one JSONL line before the decision is returned: `timestamp`, `callId`, `toolName`, `signatureHash`, `riskTier`, `decisionKind`, `decisionReason`, `event`, and — for risky calls — `trustCount`. A risky call that settles also appends an `outcome` line paired by `callId`. Argument text is never written; `decisionReason` carries the rule id (`redline:remote:git-push`, `signature:approved:3`) or the failure source.

Writing is synchronous and happens before the decision leaves the listener, so a missing trail denies the call instead of allowing it untraced. An unusable destination (a directory, a missing workspace for a relative path, an unwritable path) fails closed at the first decision.

### Source map

| File | Role |
|---|---|
| [`src/index.ts`](src/index.ts) | Plugin entry: `Config`, listener wiring, decision assembly, fail-closed denial |
| [`src/classify.ts`](src/classify.ts) | Pure tier decision over extracted effects and overrides |
| [`src/effects.ts`](src/effects.ts) | Argument and shell analysis producing typed effects and target scopes |
| [`src/signature.ts`](src/signature.ts) | Argument normalization and the 16-character signature hash |
| [`src/trust.ts`](src/trust.ts) | In-memory progressive-grant ledger |
| [`src/audit.ts`](src/audit.ts) | Destination resolution, writability probe, JSONL append |
| [`src/guard.ts`](src/guard.ts) | Self-protection invariants registered through `ctx.tools.guard()` |
| [`src/approval-policy.ts`](src/approval-policy.ts) | Whether an ask would be rejected by the `never` policy before any answerer sees it |
| [`src/config.ts`](src/config.ts) | Configuration schema and compiled policy |
| — | No runtime invariant companion is published; every contribution is a listener, a guard, or an in-memory table owned by one apply effect, with no independent observation that can diverge. |

</details>

-----

<a id="repository-layout"></a>
## Repository layout

- `src/` — TypeScript source; the only tree to edit.
- `lib/` — committed build output. `lib/index.js` is the module a profile loads; `lib/types/` carries the declarations.
- `tests/` — the behavior specs. They import the harness agent-loop testkit and its scripted model adapter, so they run inside a [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) checkout, not in this repository alone.
- `cordis.patch.yml` — the bundle row the plugin manager applies when the package is installed into a profile.

Regenerate the build with `pnpm install && pnpm build`. The `dsh` peer packages are only needed for type checking; at runtime the plugin resolves them through the hosting harness.

-----

<a id="further-exploration"></a>
## Further Exploration

- [Tools subsystem reference](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/tools.md) — `tools/pre-execute`, `tools/post-execute`, and `ctx.tools.guard()` semantics this policy consumes.
- [User approval](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/interaction/user-approval/README.md) — the answerer chain that resolves an `ask` decision and the fail-closed outcomes it returns.
- [Guard group map](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/guard/README.md) — sibling policy and loop-hygiene guards.

-----

<a id="model-experience"></a>
## Model Experience

### Approval request and denial

#### What the model sees

Nothing on a safe or already-trusted call: the tool result is the tool's own output. A call held for approval that the user rejects reaches the model as the ordinary denial text below, wrapped by the tools pipeline's `Error: ` prefix. Under the `never` approval policy the gate denies the call itself instead of sending an ask that no answerer would see, and the reason carries the policy and the preset to switch to.

##### Denial text

```markdown
reversibility-gate: signature:untrusted:file:mutate
```

##### Policy-denied text

```markdown
reversibility-gate: signature:untrusted:file:mutate requires approval, but this session's approval policy is never; switch the permission preset to Standard (approval policy ask)
```

#### Token effect

Zero direct tokens on allow. A denial contributes one ordinary error tool result; the reason is one short rule id, and the `displayReason` prompt text is user-facing and never persisted in the transcript.

#### KV Cache effect

Append-only. The plugin adds no runtime context and rewrites no earlier request content, so a reusable prefix stays reusable.

### Self-protection denial

#### What the model sees

A call the guard refuses settles as an error whose message names the invariant, regardless of the pre-execute decision or any approval.

##### Guard denial text

```markdown
reversibility-gate: refusing to remove or replace the workspace root
```

#### Token effect

One ordinary error tool result; no additional request.

#### KV Cache effect

Append-only; earlier context is untouched.

## Known Limitations and Deferred Work

<a id="known-limitations-and-deferred-work"></a>

- **Grants are in memory only** — a restart, a profile reload, or unloading the plugin clears every count, so the first call after a restart asks again. Persisting grants would need integrity, partitioning, expiry, and revocation before it could ship.
- **One ledger per plugin instance** — sessions and agents in the same process share it; per-workspace partitioning is not implemented.
- **Shell analysis is heuristic** — quoting, substitutions, and Windows path spelling are handled conservatively and unparsable commands escalate to `redline`; the analyzer does not implement full POSIX semantics, and an unrecognized verb is only `risky`.
- **Policy, not confinement** — the plugin never sandboxes a call. The native `sandbox/mode` and approval channel still own execution limits and the answerer.
- **Full access cannot prompt** — the `danger-full-access` preset pairs with `approval: never`, which rejects every ask before any answerer sees it. Untrusted risky calls and every redline call are denied rather than prompted; only signatures that already earned trust still run. Ask-based review needs the `ask` policy (the Standard preset).
- **Out-of-process subagents are not covered** — their inner calls never traverse this process's tool pipeline, so the delegation call itself is classified, not what the child does.
- **No path-level allowlist** — a protected path can only be added to the guard's refusal list; allowing a specific destructive command inside the workspace is not configurable.
- **The audit file is not rotated** — it grows for the life of the deployment, and its location inside the workspace makes it appear in workspace changes.
- **Concurrent identical calls can advance faster** — parallel calls sharing a signature each confirm on success, so a burst can cross the threshold in one turn.

<a id="dev-note"></a>
### Dev Note

<details>
<summary>Working context for maintainers — click to expand</summary>

None.

</details>
