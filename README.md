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
| `claude-hook` | 作为 Claude Code `PreToolUse` hook 运行：从 stdin 读取 hook JSON，向 stdout 输出权限决策。 |
| `codex-hook` | 作为 Codex CLI `PermissionRequest` hook 运行：从 stdin 读取 hook JSON，向 stdout 输出自动审批决策。 |

## 在 Claude Code 中作为权限审核 hook

`claude-hook` 子命令把本引擎接到 [Claude Code 的 `PreToolUse` hook](https://docs.anthropic.com/en/docs/claude-code/hooks)
上，对 Agent 即将执行的 `Bash` 命令做规则审核。协议适配层在
[internal/hooks/claudehook](internal/hooks/claudehook/claudehook.go)，刻意与
`policy` / `analyze` 解耦：它只认 Claude Code 的输入输出格式和一个
与引擎无关的 `Decision` 类型，由 CLI 胶水层负责调用策略引擎并把
`policy.Result` 翻译成 `Decision`。

### 协议

- **输入**（stdin）：Claude Code 发来的 hook JSON，关键字段是
  `tool_name` 和 `tool_input.command`，可选 `cwd`、`session_id`。
- **输出**（stdout）：

  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "allow | deny | ask",
      "permissionDecisionReason": "[shell-policy] deny (rule: ...): ..."
    }
  }
  ```

决策映射：引擎的 `allow / ask / deny` 直接对应 Claude Code 的
`allow / ask / deny`。设计上**失败一律降级为 `ask`** 而非放行：

| 情况 | 行为 |
| --- | --- |
| `tool_name` 不是 `Bash` | 不输出任何内容，退出 0，交还 Claude Code 默认流程 |
| 命令为空 | 同上，不干预 |
| 解析失败 / 策略加载失败 / 评估出错 | 输出 `ask`，附带错误原因 |
| 正常评估 | 输出引擎决策 |

`claude-hook` 在已输出决策时**始终退出 0**：Claude Code 通过 stdout 的 JSON
读取决策，非零退出码会被当成 hook 执行失败。

### 配置示例

在 `~/.claude/settings.json`（或项目级 `.claude/settings.json`）里注册：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/bin/shell-policy claude-hook --policy /path/to/policies/default.yaml --writable \"$CLAUDE_PROJECT_DIR/build\""
          }
        ]
      }
    ]
  }
}
```

`claude-hook` 复用所有公共 flag（`--policy` / `--workspace` / `--writable` /
`--home` / `--log-level` / `--audit`）。未显式传 `--cwd` 时，会采用 hook
输入里的 `cwd` 做路径规范化。加上 `--audit <file>` 可把每次决策（含
`session_id`）追加为一行 JSONL 审计记录。

可先用管道在命令行手动验证：

```bash
echo '{"tool_name":"Bash","cwd":"'"$PWD"'","tool_input":{"command":"rm -rf /etc"}}' \
  | ./bin/shell-policy claude-hook
```

## 在 Codex CLI 中作为权限自动审批 hook

`codex-hook` 子命令把本引擎接到 Codex CLI 的 `PermissionRequest` hook 上。
Codex 会在自身需要用户审批前调用这个 hook；本工具只处理 Codex 归一化后的
`Bash` 权限请求，并评估 `tool_input.command`。

### 协议

- **输入**（stdin）：Codex `PermissionRequest` hook JSON，关键字段是
  `hook_event_name`、`tool_name`、`tool_input.command`，可选
  `tool_input.description`、`cwd`、`session_id`、`turn_id`。
- **输出**（stdout，自动放行）：

  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PermissionRequest",
      "decision": {
        "behavior": "allow"
      }
    }
  }
  ```

- **输出**（stdout，自动拒绝）：

  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PermissionRequest",
      "decision": {
        "behavior": "deny",
        "message": "[shell-policy] deny (rule: ...): ..."
      }
    }
  }
  ```

决策映射：

| shell-policy 决策 | Codex hook 行为 |
| --- | --- |
| `allow` | 输出 `behavior: "allow"`，Codex 自动批准该权限请求。 |
| `deny` | 输出 `behavior: "deny"`，Codex 拒绝该权限请求。 |
| `ask` | 不输出决策，交还 Codex 默认审批流程。 |
| 解析失败 / 策略加载失败 / 评估出错 | 输出 warning-only JSON，不批准、不拒绝，交还 Codex 默认审批流程。 |

`codex-hook` 在已输出决策或主动不决策时都退出 0；只有输入 JSON 无法解析、
flag 用法错误或 stdout 写入失败才返回非 0。

### 配置示例

在 `~/.codex/config.toml`（或项目级 `.codex/config.toml`）里注册：

```toml
[[hooks.PermissionRequest]]
matcher = "Bash"

[[hooks.PermissionRequest.hooks]]
type = "command"
command = "/path/to/bin/shell-policy codex-hook --policy /path/to/policies/default.yaml --writable \"/path/to/project/build\""
statusMessage = "checking shell policy"
timeout = 10
```

`codex-hook` 复用所有公共 flag（`--policy` / `--workspace` / `--writable` /
`--home` / `--log-level` / `--audit`）。未显式传 `--cwd` 时，会采用 hook
输入里的 `cwd` 做路径规范化。加上 `--audit <file>` 可把每次决策（含
`session_id`）追加为一行 JSONL 审计记录。

Codex 对新 hook 或变更后的 hook 有信任确认流程；注册后按 Codex UI 提示信任该
hook，或在受控自动化环境中使用 Codex 自身的 hook trust 选项。

可先用管道在命令行手动验证：

```bash
echo '{"hook_event_name":"PermissionRequest","tool_name":"Bash","cwd":"'"$PWD"'","tool_input":{"command":"cat README.md"}}' \
  | ./bin/shell-policy codex-hook
```

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

### 默认策略的类别

`policies/default.yaml` 把危险操作分成以下类别，每个类别对应一个具名 action。调用方可以只改 action 的效果（允许 / 询问 / 拒绝）而不改规则，例如 ShellGate 的「简单设置」。

| 类别 | action | 默认 | 覆盖的命令 |
| --- | --- | --- | --- |
| 提权 | `ask_privilege` | ask | `sudo` / `su` / `doas` / `pkexec` 及其内层命令 |
| 写、删、改权限：可写目录之外 | `ask_write_outside_writable` | ask | 可写目录外、目录未知、敏感文件或带动态参数的写 / 删 / 移动 / chmod / chown / git 写操作 |
| 破坏性操作 | `deny_destructive` | deny | `rm -r` 系统路径、`rm -rf "$X"`、`chmod -R` 系统路径、`git push -f`、`git clean -fdx`、写块设备、`mkfs` / `fdisk` 等、风险分 ≥ 100 |
| 读取敏感文件 | `ask_sensitive_read` | ask | `.env`、私钥、凭证等 |
| 敏感文件外传 | `deny_secret_exfiltration` | deny | 读敏感文件并发往网络 |
| 网络访问 | `ask_network` | ask | `curl` / `wget` / `git fetch` 等 |
| 远程或容器内执行 | `ask_remote` | ask | `ssh`、`docker exec` / `run`、`kubectl exec` |
| 包管理 | `ask_package_manager` | ask | `apt` / `pip` / `npm install` 等 |
| 内联脚本 | `deny_inline_eval` | deny | `python -c`、`node -e` 等 |
| 默认规则 | `default` | ask | 以上都没判定的命令（`defaultAction: default`） |

另有几条固定规则（使用内置 `ask`，不属于任何类别）：改变后续命令行为的 shell 状态（`export PATH=...`、`alias`、`trap`、函数定义，即 `shell_config` 操作和函数体内的命令）以及 `exit` / `logout` 需要询问；`cd`、`pwd`、`echo`、`true`、普通变量的 `export` 等无副作用的内建命令直接放行。

deny / ask 规则都是 `terminal: false`：同一条命令命中的所有类别都会记录，最终取最强的一条，所以把某个类别改成 ask 不会让另一个类别的 deny 失效。

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

- 同一 leaf 上命中多条 deny / ask 规则（前面的是 `terminal: false`）时取最强的一条：deny 优先于 ask，同级取 `severity` 高者；之后命中的 allow 不会削弱已有的 ask / deny。
- 规则链跑完仍没有决策的 leaf 使用 `defaultAction`，不会因为同一命令里另一个 leaf 被放行而被忽略：`cat a && make` 的 `make` 按默认动作处理。
- 跨 leaf 合并只重跑 deny / ask 规则，并跳过 `match: {}` 这类兜底规则，所以 `cat a && cat b` 这样每段都被放行的组合命令仍然是 allow。

leaf 内按「(操作, 路径) 单元」匹配：`enrich` / `audit` 规则和 deny / ask 决策
只要任一单元命中就生效；allow 规则只放行它命中的单元，其余单元继续往下匹配，
所有单元都被放行后 leaf 才是 allow。因此 `cat README.md > ~/.bashrc` 里对
README 的读不能替对 `~/.bashrc` 的写放行，`cat README.md /etc/passwd` 的第二个
路径也会单独判定。重定向到 `/dev/null`、`/dev/stdin`、`/dev/stdout`、
`/dev/stderr` 不记为文件操作。

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
| `path.absolute` / `path.normalized` / `path.raw` | 当前路径字符串，配合 `regex` 使用 |
| `context.inRemoteCommand` / `context.inContainerCommand` / `context.privilegeEscalated` / `context.inFunction` 等 | 上下文 |
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
     defaultAction: default
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

### 工作目录跟踪（`cd` / `pushd`）

相对路径按命令执行到该处时的工作目录解析，而不是固定按 `--cwd`：
`cd /etc && rm -f passwd` 里的 `passwd` 解析为 `/etc/passwd`，不会被当成可写目录内的删除放行。

- `cd dir && …` 之后按 `dir` 解析；`cd` 无参数或 `cd ~/x` 按 HOME 解析；`pushd dir` 同 `cd`，`pushd -n` 不切换目录。
- 目录无法静态确定时，之后的相对路径 scope 为 `unknown`、不可写，写操作不会自动放行：`cd "$X"`、`cd -`、`cd ~user`、`popd`、无参数或 `+N` 的 `pushd`、`source` / `.` / `eval`、动态程序名，以及可能失败的 `cd`（`cd dir; rm x` 中 cd 失败时 rm 仍在原目录执行）。
- 子 shell、管道（zsh 的管道最后一段除外）、后台任务、`bash -c` 等子进程里的 `cd` 不影响后续命令；`command cd`、`builtin cd` 会影响。
- 循环和条件语句内出现 `cd` 时，整个语句及其后的相对路径都按未知处理（循环体会在 `cd` 之后再次执行）。
- `sudo -D dir` / `env -C dir` 让内层命令从 `dir` 开始解析；`find -execdir`、`ssh`、`docker exec` 等的内层命令目录未知。
- 库调用方传入空的 `Resolver.Cwd` 表示工作目录未知，相对路径同样按 `unknown` 处理。
- 已知限制：`CDPATH` 会改变相对目标的解析，引擎不感知；会话里已定义的同名函数 / alias 也不在静态分析范围内。

## 仓库结构

```text
cmd/shell-policy/      CLI 入口（parse / analyze / eval / explain / hooks）
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
  hooks/
    claudehook/       Claude Code hook 协议适配
    codexhook/        Codex CLI hook 协议适配
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
- Wrapper 递归解析：`sudo` / `doas` / `pkexec` / `su -c`、`env`、`time/command/builtin/exec/nohup`、
  `bash/sh/zsh/... -c`、`eval`（静态文本）、`ssh`、`docker/podman exec|run`、`kubectl exec`、
  `find -exec`（`{}` 按搜索根目录下的文件分析）、`xargs`（来自 stdin 的参数视为动态）、
  `python/node/ruby/perl -c/-e`（inline eval）。
- 不会藏住命令的解析：`time cmd`、`coproc`、`export/declare/local X=$(cmd)`、
  `[[ ]]` / `(( ))` / `let` 里的命令替换、`${X:-$(cmd)}`、重定向目标里的 `$(cmd)`、
  shell 函数体（`context.inFunction`）都会展开成 leaf；单词里的反斜杠转义按 shell 语义去掉。
- argv / flag 解析：短 flag 组合、长 flag、带值 flag、可重复 flag、`--` 分隔、
  动态参数标记。
- Command spec：coreutils（`pwd ls cat head tail stat file echo printf grep find
  rm mkdir touch cp mv chmod chown ln sed awk tar dd`）、`curl`/`wget`、`git`、
  `docker`/`podman`、常见包管理器（`package_install`）、shell 内建与改变 shell
  状态的命令（`shell_config`）。
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
