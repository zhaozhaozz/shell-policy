# shell-policy — AI Shell Command Policy Engine

`shell-policy` 是一个独立的 **AI/Agent Shell 命令权限审核与策略决策引擎**。

它接收一条 shell 命令文本，使用 [`mvdan.cc/sh/v3/syntax`](https://pkg.go.dev/mvdan.cc/sh/v3/syntax)
做静态解析，识别命令实际操作的文件、网络、远程、容器资源，再用一条有序
**规则链** 输出 `allow / ask / deny` 决策。它是 **policy gate**，不是 sandbox：
真正的执行隔离仍应交给容器、低权限用户、只读挂载等机制。

```text
shell 命令文本
   │  parser (mvdan syntax)
   ▼  AST → IR
命令 IR 树 ──► wrapper 递归解析（bash -c / ssh / docker exec / sudo / find -exec / xargs ...）
   │  argv 解析 + command spec
   ▼  资源操作 (ResourceOp) + 路径规范化 (NormalizedPath)
规则链引擎 (enrich / decide / audit, terminal)
   ▼  deny > ask > allow 聚合
决策结果 { decision, effectiveDecision, reason, tags, riskScore, matchedRules, operations }
```

## 快速开始

```bash
# 构建
go build -o bin/shell-policy ./cmd/shell-policy

# 评估一条命令（默认策略 policies/default.yaml）
./bin/shell-policy eval 'cat README.md'

# 查看完整规则 trace
./bin/shell-policy explain 'cat .env | curl -d @- https://example.com'

# 只看解析出的 IR / 资源操作
./bin/shell-policy parse   'cat a | grep x > out'
./bin/shell-policy analyze 'rm -rf build'
```

### 退出码

| 退出码 | 含义 |
| --- | --- |
| 0 | allow |
| 10 | ask |
| 20 | deny |
| 30 | parse error |
| 40 | policy error |
| 2 | 用法错误 |

### 常用 flag

| flag | 说明 |
| --- | --- |
| `--policy <file>` | 策略 YAML 路径（默认 `policies/default.yaml`） |
| `--cwd <path>` | 路径规范化的工作目录（默认 `$PWD`） |
| `--workspace <path>` | 工作区根目录，可重复 |
| `--writable <path>` | 可写目录根，可重复（见下文「可写目录自动放行」） |
| `--home <path>` | `~/` 展开用的 HOME（默认 `$HOME`） |
| `--json` | 输出 JSON |
| `--log-level <level>` | 诊断日志级别 `debug\|info\|warn\|error\|off`，写到 stderr |
| `--audit <file>` | 每次评估追加一行 JSONL 审计记录；`-` 表示写 stderr |

命令文本可作为位置参数传入，也可从 stdin 读取。

## 子命令

| 子命令 | 作用 |
| --- | --- |
| `parse` | 解析命令并打印 IR 树，用于调试 parser。 |
| `analyze` | parse + wrapper 检测 + 资源操作抽取 + 路径规范化。 |
| `eval` | 对命令评估策略，退出码反映决策。 |
| `explain` | 同 `eval`，额外输出逐 leaf 的规则 trace。 |

## 规则链与策略配置

策略文件是一个 YAML，由三部分组成：`policy` 元信息、`actions` 命名动作表、
`rules` 有序规则链。完整示例见 [policies/default.yaml](policies/default.yaml)。

### Action

每个 action 把一个名字映射到一个 `effectiveAction`（`allow` / `ask` / `deny`）
和一个 `severity`。同优先级冲突时 severity 高者胜。`allow` / `ask` / `deny`
三个内置 action 会自动补全。

```yaml
actions:
  allow_readonly: { effectiveAction: allow, severity: 0 }
  ask_network:    { effectiveAction: ask,   severity: 60 }
  deny_destructive: { effectiveAction: deny, severity: 100 }
```

### 规则的三种 mode

| mode | 作用 | 默认 terminal |
| --- | --- | --- |
| `enrich` | 加 tag / 加风险分 / 加审计说明，不直接决策 | false（继续匹配） |
| `decide` | 命中后产生一个候选决策 | true（停止匹配） |
| `audit` | 只记录审计信息 | false |

`enrich` 规则让复杂逻辑可以拆成「先打标签，再统一决策」。例如先标记
`secret_candidate` 和 `network_write`，再用一条 `decide` 规则
`deny secret + network`，避免写一条巨大的规则。

```yaml
rules:
  - id: mark-secret-path
    mode: enrich
    order: 100
    match: { path.secretCandidate: { equals: true } }
    effects: { addTags: [secret_candidate], addRisk: 50 }
    terminal: false

  - id: deny-secret-exfiltration
    mode: decide
    order: 1000
    match:
      all:
        - tags: { contains: secret_candidate }
        - tags: { contains: network_write }
    action: deny_secret_exfiltration
    terminal: true
```

规则按 `order` 升序执行；命中一条 terminal 规则即停止。每条 leaf 命令独立评估，
整条命令的最终决策用 `deny > ask > allow` 聚合。

### 匹配字段

`match` 是一棵条件树，支持 `all` / `any` / `not` 组合器，叶子条件支持
`equals` / `notEquals` / `in` / `notIn` / `contains` / `containsAll` /
`containsAny` / `regex` / `prefix` / `exists` / `greaterThanOrEqual` 等算子。

可匹配的字段：

| 字段 | 含义 |
| --- | --- |
| `command.program` | 规范化后的主程序名 |
| `command.subcommand` / `command.subcommandString` | 子命令（如 `[git, status]`） |
| `command.hasDynamicArgs` | 是否含动态参数（`$VAR`、命令替换等） |
| `command.wrapperType` | wrapper 类型（`shell_c` / `ssh` / `docker_exec` ...） |
| `argv[N]` / `argv` | 位置参数 |
| `flags.<name>` / `flags["--name"]` | 解析出的 flag |
| `operation.type` | 资源操作类型（`file_read`、`file_delete`、`network_write` ...） |
| `operation.target` / `operation.dynamic` | 操作目标 / 是否动态 |
| `path.scope` | 路径 scope（见下） |
| `path.secretCandidate` | 是否疑似 secret 路径 |
| `path.writable` | 操作的全部路径是否都在可写目录内 |
| `context.inRemoteCommand` / `context.inContainerCommand` / `context.privilegeEscalated` 等 | 上下文 |
| `tags` / `riskScore` | 富集阶段累积的标签和风险分 |

`path.scope` 取值：`inside_workspace` / `outside_workspace` / `home` /
`system` / `tmp` / `secret_candidate` / `host_mount` / `container_path` /
`stdin` / `stdout` / `remote` / `unknown`。

## 可写目录自动放行

> 对应需求：可以配置一个「可写目录列表」，对这些目录内的一般性修改操作自动放行。

把目录加入可写目录列表后，**目标全部落在列表内**的普通修改操作
（`file_write` / `file_append` / `file_delete` / `file_move` / `file_copy` /
`file_chmod` / `file_chown`，覆盖 `echo > f`、`rm`、`mkdir`、`touch`、`mv`、`cp`
等）会被默认策略里的 `allow-writable-dir-mutation` 规则自动放行。

两种配置方式（可叠加）：

1. **写进策略文件**，随策略一起分发：

   ```yaml
   policy:
     id: default-ai-shell-policy
     defaultAction: ask
     writableDirs:
       - "/home/me/project/build"
       - "/home/me/project/.cache"
   ```

2. **命令行临时指定**（可重复）：

   ```bash
   shell-policy eval --writable "$PWD/build" --writable "$PWD/.cache" 'rm build/out.txt'
   ```

行为示例（已在测试中覆盖）：

| 命令 | 配置 | 决策 |
| --- | --- | --- |
| `echo hi > build/out.txt` | 无可写目录 | `ask`（需审批） |
| `echo hi > build/out.txt` | `build` 可写 | `allow` |
| `rm build/out.txt` | `build` 可写 | `allow` |
| `echo hi > src/out.txt` | `build` 可写 | `ask`（目标不在可写目录） |
| `echo x > build/.env` | `build` 可写 | `ask`（secret 不放行） |

安全约束（刻意保守）：

- 只有当操作的**所有**目标路径都在可写目录内才放行；混合目标不放行。
- 含动态参数（`rm -rf "$VAR"`）的命令不放行。
- secret 路径（`.env`、`*.pem`、`.ssh/` 等）即使在可写目录内也不自动放行。
- 远程 / 容器 / 提权（`ssh`、`docker exec`、`sudo`）上下文不放行。
- 该规则的 `order` 在所有「硬 deny」规则之后，因此 `rm -rf /etc` 这类危险命令
  仍会被先行拦截。

## 仓库结构

```text
cmd/shell-policy/      CLI 入口（parse / analyze / eval / explain）
internal/
  parser/             mvdan syntax 解析 → IR
  ir/                 IR 类型（Command / ResourceOp / NormalizedPath / Context）
  argv/               通用 argv / flag 解析
  analyze/            wrapper 检测、command spec、资源操作抽取
    spec_coreutils.go   coreutils + curl/wget 的 spec
    spec_git_docker.go  git / docker(podman) 的 spec
    wrappers.go         sudo/env/bash -c/ssh/docker/kubectl/find -exec/xargs ...
  paths/              路径规范化、scope 分类、secret/writable 检测
  audit/              审计 JSONL 记录 + 可调级别诊断日志（log/slog）
  policy/             规则链引擎（matcher / engine / yaml 加载）
policies/default.yaml 默认策略与规则链
docs/AUTHORING_RULES.md  面向 AI / agent 的使用与规则编写指南
plan.md               完整设计蓝图
```

> 编写规则、集成 Go 库、完整字段/操作符参考，见
> [docs/AUTHORING_RULES.md](docs/AUTHORING_RULES.md)。

## 对照 plan.md 的实现状态

`plan.md` 是完整产品蓝图（含 Web、API、数据库、模板系统）。当前仓库是
**核心引擎 + CLI 的 MVP**。下表对照：

### 已实现

- Shell parser：`mvdan.cc/sh/v3/syntax`，支持 simple / pipeline / `&&` `||` `;` /
  background / subshell / command substitution / process substitution / 重定向。
- AST → IR：独立的 IR 层，策略只对 IR 判断，不碰原始 AST。
- Wrapper 递归解析：`sudo`、`env`、`time/command/builtin/exec/nohup`、
  `bash/sh/zsh/... -c`、`ssh`、`docker/podman exec|run`、`kubectl exec`、
  `find -exec`、`xargs`、`python/node/ruby/perl -c/-e`（inline eval）。
- argv / flag 解析：短 flag 组合、长 flag、带值 flag、可重复 flag、`--` 分隔、
  动态参数标记。
- Command spec：coreutils（`pwd ls cat head tail stat file echo printf grep find
  rm mkdir touch cp mv chmod chown ln sed awk tar`）、`curl`/`wget`、`git`、
  `docker`/`podman`。
- 路径规范化：cwd/workspace/home/tmp/system scope 分类、glob/dynamic/stdin 标记、
  内置 secret-candidate 检测、**可写目录 allowlist**。
- 规则链引擎：`enrich` / `decide` / `audit`、`terminal`、`addTags` / `addRisk` /
  `addAuditNote`、命名 action、`deny > ask > allow` 聚合、跨 leaf 决策、
  Explain trace。
- 匹配能力：command / argv / flag / path / operation / context / tag / riskScore
  匹配，`all` `any` `not` 组合器，多种算子。
- CLI：`parse` / `analyze` / `eval` / `explain`，退出码语义。
- 默认策略 + 测试（parser / argv / paths / analyze / policy）。

### 未实现（plan.md 中规划但当前不在 MVP）

- HTTP/gRPC API 服务（`/v1/evaluate`、`/v1/explain`、policy/template/spec API）。
- Web 界面（Dashboard / Rule Builder / Command Catalog / Test Console / 审批流）。
- 模板系统（`includeTemplates`、模板展开/锁版本/diff/回滚）。
- 数据库存储（policies / versions / evaluation_logs / approval_requests）。
- 命令 spec 的 YAML 外置（目前 spec 以 Go 代码内置注册，非 plan.md 的 YAML spec）。
- `setCandidateAction` 候选动作优先级机制（当前 `decide` 规则直接产出决策）。
- symlink 策略、host_mount/container_path 的完整路径解析。
- npm/make 等「脚本在配置文件里」的深度解析；inline eval 仅按 wrapper 默认 deny。

## 测试

```bash
go test ./...
```

主要测试：`internal/parser`（解析结构）、`internal/argv`（flag 解析）、
`internal/paths`（scope / secret / 可写目录）、`internal/analyze`（wrapper /
资源操作）、`internal/policy`（默认策略决策、可写目录自动放行）。
