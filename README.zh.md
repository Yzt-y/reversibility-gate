---
description: "按副作用可逆性对工具调用分级、对 risky 与 redline 调用走审批、累积渐进授权，并为每一次决策留下审计记录的分发前策略插件，面向使用者与需要排查为什么放行或为什么询问的维护者。"
kind: "package-reference"
---

# 工具调用可逆性治理插件

[English](README.md) | 中文

## 摘要

本包为工具管线增加一层可逆性策略。分发之前，它把每次调用的副作用分为 `safe`、`risky`、`redline` 三级，并让调用走三条路径之一：直接放行、在操作签名尚未建立信任时询问一次、每次询问。一个 risky 签名连续成功三次（可配置）后自动放行，一次失败即撤销。自保护不变量是单调守卫，因此审批无法允许删除工作区根。每一次决策都追加到 JSONL 审计；审计写不下去时该调用被拒绝。

## 目录

- [使用本包](#use-this-package)
- [实现说明](#understand-the-implementation)
- [仓库结构](#repository-layout)
- [延伸阅读](#further-exploration)
- [模型体验](#model-experience)
- [已知限制与暂缓事项](#known-limitations-and-deferred-work)
- [开发者注记](#dev-note)

-----

<a id="use-this-package"></a>
## 使用本包

把包安装进需要治理工具调用的 profile。凡是插件管理器接受的安装形式都可用——本地克隆、tarball 或已发布的名字：

```sh
pnpm dsh plugin --profile web add /绝对路径/dsh-reversibility-gate
```

用同一个 CLI 移除（`... remove dsh-reversibility-gate`）。移除该层即恢复原生行为：pre-execute 监听器、post-execute 观测器、单调守卫与内存中的授权账本一并卸载。

### 何时选用

当 profile 的自动化程度足够高，"模型是否删掉了无法恢复的东西、或写到了远端系统？"正是你希望在调用执行之前得到回答的问题，并且重复同一操作不该反复询问时，选它。当每次调用都必须单独审批时不要选它——渐进授权会在三次成功后刻意不再询问；当部署已经用文本模式策略插件作为唯一裁决者时也不要选它。

### 配置

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

| 字段 | 默认值 | 含义 |
|---|---|---|
| `trustThreshold` | `3` | 连续"批准且成功"多少次后同签名自动放行 |
| `auditFile` | `.dsh-reversibility/audit.jsonl` | JSONL 目标：绝对路径，或相对会话工作区 |
| `signatureTruncateChars` | `500` | 单个参数字符串进入签名时保留的字符数 |
| `tierOverrides` | `{}` | 工具名到等级的覆盖；只能调高，不能调低 |
| `extraRedlineHosts` | `[]` | 出现在命令里即视为远端状态的主机名 |
| `extraProtectedPaths` | `[]` | 守卫拒绝修改或删除的工作区相对路径 |

`auditFile` 为空会让插件加载失败；任何不符合 schema 的值同样在加载期失败并指出字段，插件不会退化成空规则集。harness 的[配置目录](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/config-catalog.zh.md)记录了所有可接受取值。

### 你会得到什么

`read` 立即执行，只留一条 `allow` 审计。工作区内的 `write` 首次询问；同一签名三次批准成功后不再询问，一次失败即回到询问。越出工作区的调用——绝对路径删除、远端推送、发布、集群变更、特权命令、把管道交给解释器——每次都询问，且永不计入信任。会删除工作区根、改写 `.git` 或篡改审计的调用由守卫拒绝，即使审批已经通过。若会话的审批策略是 `never`（Web 的"完全权限"预设就是这种组合），被拦下的调用会由本插件直接拒绝，并在理由里说明是策略禁止询问以及该切回哪个预设——它不会假装弹出一个实际上永远不会出现的审批。

只有正当的调用才会走到守卫：若别的策略先拒绝或取消，该决定生效——本插件先委派给后续监听器，再考虑把自己的一票升为 `ask`。

<a id="understand-the-implementation"></a>
## 实现说明

<details>
<summary>实现内幕——点击展开</summary>

### 设计承诺

- **先委派，再升级。** pre-execute 监听器先 `await next()`。下游的 deny、cancel、ask 优先于自己的决定，因此本插件只能让链条更严，不会更松。
- **看副作用，不看字符串。** 分级先抽取带类型的副作用（read、mutate、destroy、remote、privilege、unknown）与解析后的目标作用域，再取最严重者；工具名或命令正则从不作为唯一依据。
- **单调不变量放在守卫里。** `tools/pre-execute` 是 waterfall，后续监听器可能推翻先前的拒绝，因此自保护经 `ctx.tools.guard()` 注册：守卫没有 allow 结果，且在 pre-execute 决定之后判定——包括审批通过之后。
- **post-execute 只观测。** 监听器原样返回下游决定，只记录结果。信任不在此之外写入，也从不写进会话日志或磁盘。

### 分级

`classify(call, policy)` 对输入（工具名、解析后的参数、工作区根）是纯函数，返回等级与稳定的规则 id。工作区内的改动或删除是 `risky`：工作区 diff 与 git 都能回收。目标解析到工作区之外、无法解析（通配符、`~`、未知工作区），或命中远端、特权、不可解析的副作用，是 `redline`。工作区内的 `rm notes.txt` 与未经回收的 `echo x > notes.txt` 同为 `risky`（两者都只能靠工作区回收），而绝对路径删除是 `redline`。

`run_code` 与 `workflow` 是传输层：其内部调用会再走一遍本监听器，按副作用处理会重复计费与重复计数。效果无法界定的工具（启动子代理、终端输入、作业控制）保持 `risky`，未知工具也是 `risky` 而不是硬拒绝。

### 渐进授权

账本把签名哈希映射到连续成功次数。`risky` 签名在计数低于阈值时询问、达到阈值后自动放行，任何失败、拒绝或取消都归零——post-execute 也会收到被拒绝的调用，因此被驳回的审批同样撤销信任。`redline` 与 `safe` 从不进入账本。

签名是 `sha256(toolName + 归一化参数)` 截断到 16 位十六进制。归一化会排序对象键、折叠命令空白、统一路径分隔符并截断长字符串。它只是"意图"的近似：两段共享前缀的 500 字符载荷会塌缩成同一签名，这正是 redline 永不用信任、且一次失败即归零的原因。

### 审计记录

每次决策在返回之前追加一行 JSONL：`timestamp`、`callId`、`toolName`、`signatureHash`、`riskTier`、`decisionKind`、`decisionReason`、`event`，risky 调用另带 `trustCount`。risky 调用结算后还会追加一行 `outcome`，通过 `callId` 配对。参数原文永不写入；`decisionReason` 携带规则 id（`redline:remote:git-push`、`signature:approved:3`、`policy:never:…`）或失败来源。

写入是同步的，且发生在决定离开监听器之前，因此"没有记录"会拒绝调用，而不是无记录地放行。目标不可用（是目录、相对路径却没有工作区、路径不可写）在第一次决策时即 fail-closed。

### 源码地图

| 文件 | 职责 |
|---|---|
| [`src/index.ts`](src/index.ts) | 插件入口：`Config`、监听器接线、决定组装、fail-closed 拒绝 |
| [`src/classify.ts`](src/classify.ts) | 基于副作用与覆盖的纯分级 |
| [`src/effects.ts`](src/effects.ts) | 参数与 shell 分析，产出类型化副作用与目标作用域 |
| [`src/signature.ts`](src/signature.ts) | 参数归一化与 16 位签名哈希 |
| [`src/trust.ts`](src/trust.ts) | 内存中的渐进授权账本 |
| [`src/audit.ts`](src/audit.ts) | 目标解析、可写性探测、JSONL 追加 |
| [`src/guard.ts`](src/guard.ts) | 经 `ctx.tools.guard()` 注册的自保护不变量 |
| [`src/approval-policy.ts`](src/approval-policy.ts) | 判断一次询问会不会被 `never` 策略提前驳回 |
| [`src/config.ts`](src/config.ts) | 配置 schema 与编译后的策略 |
| — | 不发布运行时 invariant companion：所有贡献都是由一个 apply effect 拥有的监听器、守卫或内存表，不存在可独立观察且会与之背离的事实。 |

</details>

-----

<a id="repository-layout"></a>
## 仓库结构

- `src/` —— TypeScript 源码，唯一需要编辑的目录。
- `lib/` —— 已提交的构建产物。`lib/index.js` 是 profile 实际加载的模块，`lib/types/` 提供类型声明。
- `tests/` —— 行为用例。它们引用 harness 的 agent-loop testkit 与脚本化模型适配器，因此在 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的检出目录里运行，而不是在本仓库单独运行。
- `cordis.patch.yml` —— 包被安装进 profile 时插件管理器应用的那一行。

重新生成构建：`pnpm install && pnpm build`。`dsh` 的那几个 peer 包只在类型检查时需要；运行时插件由宿主 harness 解析它们。

-----

<a id="further-exploration"></a>
## 延伸阅读

- [Tools 子系统参考](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/tools.zh.md) —— 本策略消费的 `tools/pre-execute`、`tools/post-execute` 与 `ctx.tools.guard()` 语义。
- [用户审批](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/interaction/user-approval/README.zh.md) —— 解析 `ask` 决定的应答链与其 fail-closed 结果。
- [guard 组地图](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/guard/README.zh.md) —— 同组的策略与循环卫生守卫。

-----

<a id="model-experience"></a>
## 模型体验

### 审批请求与拒绝

#### 模型看到什么

安全或已获信任的调用看不到任何新增内容：工具结果就是工具自己的输出。需要审批而被拒绝的调用，模型收到下面这段普通拒绝文本，并由工具管线的 `Error: ` 前缀包裹。若会话审批策略是 `never`，本插件不会发出注定被驳回的询问，而是直接拒绝，并把策略与应切回的预设写进理由。

##### 拒绝文案

```markdown
reversibility-gate: signature:untrusted:file:mutate
```

##### 策略拒绝文案

```markdown
reversibility-gate: signature:untrusted:file:mutate requires approval, but this session's approval policy is never; switch the permission preset to Standard (approval policy ask)
```

#### 词元影响

放行时零额外 token。拒绝只贡献一条普通错误工具结果；原因是极短的规则 id，`displayReason` 的提示文案面向用户，且不会写进会话日志。

#### 键值缓存影响

仅追加。插件不添加运行时上下文，也不改写更早的请求内容，因此可复用的前缀仍然可复用。

### 自保护拒绝

#### 模型看到什么

被守卫拒绝的调用结算为错误，其消息指明违反的不变量，与 pre-execute 决定、以及任何审批结果无关。

##### 守卫拒绝文案

```markdown
reversibility-gate: refusing to remove or replace the workspace root
```

#### 词元影响

一条普通错误工具结果；不产生额外请求。

#### 键值缓存影响

仅追加；更早的上下文不受影响。

## 已知限制与暂缓事项

<a id="known-limitations-and-deferred-work"></a>

- **授权只在内存中** —— 重启、profile 重载或卸载插件都会清空计数，因此重启后的第一次调用会重新询问。要持久化授权，必须先补齐完整性、分区、过期与撤销。
- **一个插件实例一份账本** —— 同一进程内的多个 session 与 agent 共享；按工作区分片尚未实现。
- **shell 分析是启发式的** —— 引号、命令替换与 Windows 路径拼写按保守方式处理，无法解析的命令升级为 `redline`；分析器不实现完整 POSIX 语义，未识别的动词只是 `risky`。
- **是策略，不是隔离** —— 插件从不沙箱化调用；执行边界与应答通道仍由原生 `sandbox/mode` 与审批服务负责。
- **完全权限无法弹审批** —— `danger-full-access` 预设搭配的是 `approval: never`，它在任何应答者看到问题之前就驳回询问；因此未获信任的 risky 与所有 redline 调用被直接拒绝，只有已经累积信任的签名照常执行。想让人审批必须让会话策略是 `ask`（切回 Standard 预设）。
- **跨进程子代理不在覆盖范围** —— 它们的内部调用不经过本进程的工具管线，被分级的是委派调用本身，而不是子代理做了什么。
- **没有路径级放行白名单** —— 受保护路径只能加进守卫的拒绝清单；"允许在工作区内执行某条特定破坏性命令"不可配置。
- **审计文件不轮转** —— 它随部署一直增长；放在工作区内会让它出现在工作区变更里。
- **并发的同签名调用会推进得更快** —— 共享签名的并行调用各自在成功时确认，一次爆发可能在一轮内跨过阈值。

<a id="dev-note"></a>
### 开发者注记

<details>
<summary>供维护者的工作上下文——点击展开</summary>

无。

</details>
