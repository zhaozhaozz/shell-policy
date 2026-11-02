# shell-policy 使用与规则编写指南（面向 AI / Agent）

本指南面向需要集成或扩展 `shell-policy` 的 AI agent、自动化系统和规则作者。
读完后你应该能够：

1. 用命令行或 Go 库对一条 shell 命令做出 allow / ask / deny 判定。
2. 读懂判定结果（决策、风险分、标签、审计说明、规则 trace）。
3. 编写、调试自己的策略规则（包含完整的字段与操作符参考）。
4. 配置可写目录自动放行、日志与审计。
5. 避开常见陷阱（glob 路径、动态参数、嵌套包裹命令等）。

> 术语约定：下文把一条被解析出的“最内层简单命令”（例如 `rm -rf x`）称为
> **leaf（叶子命令）**；把 `sudo` / `bash -c` / `ssh` / `docker exec` 这类
> 改变执行上下文或目标的命令称为 **wrapper（包裹命令）**；把 leaf 对文件、
> 网络、进程等资源的具体动作称为 **operation（资源操作）**。

---

## 1. 工作原理（流水线）

```
shell 文本
   │  parser：用 mvdan.cc/sh 解析成 AST，再转成 IR（不做变量展开）
   ▼
   IR 命令树
   │  analyze：识别 wrapper、解析 argv/flags、套用命令 spec、
   │           提取 operation、归一化路径（scope / writable / secret）
   ▼
   带 operation 的 IR
   │  policy engine：对每个 leaf 跑规则链，再做跨 leaf 合并
   ▼
   决策结果（deny > ask > allow 聚合）
```

关键设计：**解析器不展开变量**。`rm $X` 中的 `$X` 是动态值，引擎会把它标成
`dynamic`，规则可以据此更保守地判定。引擎只对“能静态看清的部分”给出确定结论。

---

## 2. 命令行用法

构建：

```bash
make build        # 产出 bin/shell-policy
```

四个子命令：

| 子命令    | 作用                                                   |
| --------- | ------------------------------------------------------ |
| `parse`   | 只打印 IR 树（调试解析）                                |
| `analyze` | 解析 + wrapper 识别 + operation 提取，输出 JSON         |
| `eval`    | 跑策略，打印决策；**退出码反映决策**                    |
| `explain` | 同 `eval`，额外打印每条命中规则的 trace                 |

示例：

```bash
# 评估一条命令，看决策
./bin/shell-policy eval --cwd "$PWD" --workspace "$PWD" 'rm -rf /var/log/*'

# 带完整规则 trace
./bin/shell-policy explain --cwd "$PWD" 'git push --force'

# 从 stdin 读命令
echo 'cat /etc/passwd' | ./bin/shell-policy eval --cwd "$PWD"
```

常用 flag：

| flag           | 说明                                                                 |
| -------------- | -------------------------------------------------------------------- |
| `--policy`     | 策略 YAML 路径，默认找 `policies/default.yaml`                       |
| `--cwd`        | 路径归一化的工作目录，默认 `$PWD`                                    |
| `--workspace`  | 工作区根目录，可重复；决定 `inside_workspace` 判定                   |
| `--writable`   | 可写目录根，可重复；目录内一般修改可自动放行                         |
| `--home`       | `~/` 展开用的 HOME，默认 `$HOME`                                     |
| `--json`       | 输出 JSON                                                            |
| `--log-level`  | 诊断日志级别 `debug\|info\|warn\|error\|off`，写到 stderr            |
| `--audit`      | 把每次评估写成一行 JSONL 审计记录；`-` 表示写 stderr                 |

退出码（便于脚本/agent 直接判断）：

| 码 | 含义        |
| -- | ----------- |
| 0  | allow       |
| 10 | ask         |
| 20 | deny        |
| 30 | parse error |
| 40 | policy error |

---

## 3. 作为 Go 库使用

模块路径：`github.com/self/shell_permission`。

```go
import (
    "fmt"

    "github.com/self/shell_permission/internal/analyze"
    "github.com/self/shell_permission/internal/audit"
    "github.com/self/shell_permission/internal/paths"
    "github.com/self/shell_permission/internal/policy"
)

func decide(command, cwd string) error {
    // 1. 加载策略
    pol, err := policy.LoadFromFile("policies/default.yaml")
    if err != nil {
        return err
    }

    // 2. 配置路径解析器（决定 scope / writable）
    rsv := &paths.Resolver{
        Cwd:            cwd,
        WorkspaceRoots: []string{cwd},
        WritableRoots:  append([]string(nil), pol.WritableDirs...),
    }

    // 3. 解析 + 分析
    pr, err := analyze.AnalyzeText(command, rsv)
    if err != nil {
        return err // 解析失败：按你的策略当作 deny 处理
    }

    // 4. 评估（可选注入诊断日志）
    eng := policy.New(pol).WithLogger(audit.NewLogger(nil, "off"))
    res, err := eng.Evaluate(pr.Command)
    if err != nil {
        return err
    }

    fmt.Println(res.Decision, res.EffectiveDecision, res.RiskScore)
    return nil
}
```

要点：
- `analyze.AnalyzeText(command, resolver)` 一步完成解析与分析，返回 `*parser.ParseResult`。
- `policy.New(pol)` 得到引擎；`.WithLogger(...)` 可选，注入 `*slog.Logger`。
- `eng.Evaluate(root)` 返回 `*policy.Result`，关键字段：
  `Decision`（命中规则的动作名）、`EffectiveDecision`（`allow`/`ask`/`deny`）、
  `Reason`、`RiskScore`、`Tags`、`AuditNotes`、`MatchedRules`、`Operations`、`PerLeaf`。
- 想记录审计：构造 `audit.NewWriter(w)` 后调用 `Write(audit.Record{...})`。

---

## 4. 策略文件结构

策略 YAML 顶层包含 `actions`、`rules`，可选 `defaultAction`、`writableDirs`、`sensitivePaths`（追加的敏感路径模式，写法见 README「追加敏感路径」）：

```yaml
defaultAction: default    # 没有规则决定的 leaf 使用的 action
writableDirs: []          # 可写目录白名单（绝对或相对 cwd）

actions:
  allow:           { effectiveAction: allow, severity: 0 }
  ask:             { effectiveAction: ask,   severity: 50 }
  default:         { effectiveAction: ask,   severity: 50 }
  ask_write_outside_writable: { effectiveAction: ask, severity: 55 }
  deny_destructive:    { effectiveAction: deny, severity: 100 }

rules:
  - id: deny-rm-system-root
    mode: decide
    order: 1000
    match:
      all:
        - operation.type: { equals: file_delete }
        - path.scope:     { in: [system] }
        - flags.recursive: { equals: true }
    action: deny_destructive
    reason: Recursive removal targeting system path
```

### Action（动作）
每个动作定义两件事：
- `effectiveAction`：最终归类，只能是 `allow` / `ask` / `deny`。
- `severity`：同一 `effectiveAction` 内部排序用，越大越优先。

聚合规则：跨所有 leaf，先按 `deny > ask > allow`，同级再按 `severity` 取高者。同一 leaf 上命中多条非 terminal 的 deny / ask 规则时也按这个顺序取最强者，之后命中的 allow 不会覆盖它。规则链跑完仍无决策的 leaf 使用 `defaultAction`。

### Rule（规则）
| 字段       | 说明                                                                 |
| ---------- | -------------------------------------------------------------------- |
| `id`       | 唯一标识                                                             |
| `mode`     | `enrich` / `decide` / `audit`，见下                                  |
| `order`    | 规则链执行顺序，小的先执行                                           |
| `enabled`  | 默认 true                                                            |
| `match`    | 匹配树（见第 6 节）                                                  |
| `effects`  | `addTags` / `addRisk` / `addAuditNote`                               |
| `action`   | `decide` 模式下命中后采用的动作名                                    |
| `terminal` | 命中后是否停止本 leaf 的规则链；`decide` 默认 true，`enrich` 默认 false |
| `reason`   | 给人看的理由                                                        |

---

## 5. 三种规则模式

| 模式     | 用途                          | 默认 terminal | 能否产生决策 |
| -------- | ----------------------------- | ------------- | ------------ |
| `enrich` | 打标签、加风险分、加审计说明  | false         | 否           |
| `decide` | 产生 allow/ask/deny 候选决策  | true          | 是           |
| `audit`  | 只记录，永不终止              | 永远 false    | 否           |

典型流程：先用若干 `enrich` 规则给 leaf 打标签 / 累加风险分（例如标记
`recursive_force_delete`、`privilege_escalated`），随后的 `decide` 规则根据这些
标签、operation、path scope 给出决策。

`enrich` 累加的 `riskScore` 可被后续规则使用，例如默认策略的
`deny-high-risk`（`riskScore >= 100 → deny_destructive`）。

默认策略的 deny / ask 规则都写成 `terminal: false`：同一 leaf 命中的所有 deny / ask
都会记录并取最强者，allow 规则放在不可绕过的 deny / ask 之后。新增 deny / ask 规则时
建议同样不设 terminal，避免某个类别被改成 ask 后挡住后面另一个类别的 deny。
默认策略的类别与 action 对照见 README「默认策略的类别」。

---

## 6. 匹配语言完整参考

匹配树由**组合子**和**字段匹配**构成。一条规则匹配的语义是：
**leaf 的任意一个 operation 让匹配树为真，即视为命中**（没有 operation 时用一个
空伪 operation，使纯上下文规则仍能触发）。

### 组合子
```yaml
all: [ ... ]   # 全部为真
any: [ ... ]   # 任一为真
not: { ... }   # 取反
```

### 字段匹配
形式为 `字段名: { 操作符: 期望值 }`；简写 `字段名: 值` 等价于 `equals`。

可用字段：

| 字段                          | 类型     | 含义                                            |
| ----------------------------- | -------- | ----------------------------------------------- |
| `command.program`             | string   | 归一化后的程序名（剥掉 wrapper 后的真实命令）   |
| `command.subcommand`          | []string | 子命令，如 git 的 `["push"]`                    |
| `command.subcommandString`    | string   | 子命令拼接成空格串                              |
| `command.hasDynamicArgs`      | bool     | 是否含动态（变量/命令替换）参数                 |
| `command.wrapperType`         | string   | 最外层 wrapper 类型，如 `sudo`/`ssh`/`docker`   |
| `argv[N]`                     | string   | 第 N 个参数（argv[0] 是程序）                   |
| `argv`                        | []string | 全部参数值                                      |
| `flags.<name>`                | any      | 具名 flag 值，如 `flags.recursive`              |
| `flags["--name"]`             | any      | 带连字符的 flag                                 |
| `operation.type`              | string   | 操作类型，见第 7 节                             |
| `operation.target`            | string   | 操作目标原始 token                              |
| `operation.dynamic`           | bool     | 该操作目标是否动态                              |
| `path.scope`                  | string   | 当前匹配单元的路径范围，见第 7 节               |
| `path.secretCandidate`        | bool     | 是否疑似敏感文件（.env / id_rsa / 凭证等）      |
| `path.writable`               | bool     | 操作的**所有**路径是否都在可写白名单内          |
| `path.absolute`               | string   | 当前路径的绝对形式（工作目录未知或 glob 时不存在）|
| `path.normalized` / `path.raw` | string  | 规范化后的路径 / 命令里的原始写法，配合 `regex` |
| `context.inPipeline`          | bool     | 是否在管道中                                    |
| `context.inSubshell`          | bool     | 是否在子 shell 中                               |
| `context.inCommandSubstitution` | bool   | 是否在 `$(...)` / 反引号中                       |
| `context.inRemoteCommand`     | bool     | 是否在远程命令（ssh）中                         |
| `context.remoteHost`          | string   | 远程主机名                                      |
| `context.inContainerCommand`  | bool     | 是否在容器（docker/podman/kubectl）中           |
| `context.privilegeEscalated`  | bool     | 是否经 sudo 提权                                |
| `context.background`          | bool     | 是否后台执行                                    |
| `context.inFunction`          | bool     | 是否在 shell 函数体内（函数被调用时才执行）     |
| `tags`                        | []string | 已累加的标签                                    |
| `riskScore`                   | int      | 已累加的风险分                                  |

### 操作符

| 操作符               | 适用类型      | 含义                            |
| -------------------- | ------------- | ------------------------------- |
| `equals` / `notEquals` | 任意        | 相等 / 不等（支持数值与列表）   |
| `in` / `notIn`       | 标量          | 值在 / 不在给定列表             |
| `contains`           | 字符串/列表   | 包含某子串 / 某元素             |
| `containsAll`        | 列表          | 包含列表中的全部元素            |
| `containsAny`        | 列表          | 包含列表中任一元素              |
| `regex`              | 字符串        | 正则匹配                        |
| `prefix`             | 字符串/列表   | 前缀（列表则前缀子序列）        |
| `exists`             | 任意          | 字段是否存在（true/false）      |
| `greaterThan` / `greaterThanOrEqual` | 数值 | 数值比较                  |
| `lessThan` / `lessThanOrEqual`       | 数值 | 数值比较                  |

---

## 7. 枚举值参考

### operation.type
`file_read` `file_list` `file_read_metadata` `file_write` `file_append`
`file_delete` `file_move` `file_copy` `file_chmod` `file_chown`
`process_exec` `network_read` `network_write` `git_read` `git_write`
`container_read` `container_write` `remote_exec` `package_install`
`shell_config` `unknown`

- `package_install`：包管理器的安装 / 卸载 / 升级类子命令（`apt install`、`pip install`、`npm i`、`pacman -S`、`npx` 等）；`npm run`、`go build` 这类不算。
- `shell_config`：改变后续命令行为的 shell 状态：给 `PATH`、`CDPATH`、`HOME`、`PROMPT_COMMAND`、`PS1`、`LD_PRELOAD` 等变量赋值（`export`、`declare`、`unset`、`PATH=... cmd`、裸赋值），以及 `alias name=...`、`trap cmd SIG`、`hash -p`、`enable`、`bind`。`operation.target` 是变量名或命令名。
- `cd`、`pushd`、`popd`、`pwd`、`echo`、`true`、`:`、`test`、`exit` 等内建命令以及普通变量的 `export` 不产生任何操作。

### path.scope
`inside_workspace` `outside_workspace` `home` `system` `tmp`
`secret_candidate` `host_mount` `container_path` `stdin` `stdout`
`remote` `unknown`

---

## 8. 可写目录自动放行

目标：把“在指定目录内做一般性修改”自动放行，减少对 agent 的打扰，同时保持对
系统路径、敏感文件、远程/容器/提权场景的保守。

配置方式（二选一或叠加）：
- 命令行 `--writable /path/to/build`（可重复）。
- 策略文件 `writableDirs: [ build, dist ]`。

`allow-writable-dir-mutation` 规则的判定条件（默认策略）：
- 操作是 `file_write`/`file_append`/`file_delete`/`file_move`/`file_copy`/`file_chmod`/`file_chown`/`git_write`（git 写操作的路径是仓库目录，即 `-C` 目录或当前目录）；
- `path.writable == true`（操作的所有路径都在白名单内）；
- `path.secretCandidate == false`（不是敏感文件）；
- `command.hasDynamicArgs == false`（无动态参数）；
- 不在远程 / 容器 / 提权上下文。

只要有一个目标越界、命中敏感文件或带动态参数，就不会自动放行，回落到
`ask-write-outside-writable`（action `ask_write_outside_writable`）。

示例：

```bash
./bin/shell-policy eval --cwd "$PWD" --writable "$PWD/build" 'rm build/*.o'
# → allow（glob 也会按静态前缀 build/ 判定为可写）
```

---

## 9. 日志与审计

两套互补机制：

1. **诊断日志**（`--log-level`，基于 `log/slog`，写 stderr）：调试规则匹配过程。
   `debug` 会打印每条命中规则与最终决策。
2. **审计记录**（`--audit <file>`，JSONL，每行一条）：稳定、机器可读的决策留痕，
   含时间、命令、cwd、决策、风险分、标签、命中规则、审计说明等，便于安全复盘。

```bash
./bin/shell-policy eval --cwd "$PWD" --log-level debug --audit audit.jsonl 'rm -rf /tmp/x'
```

---

## 10. 常见陷阱（写规则前务必了解）

- **glob 路径**：`rm -rf /var/log/*` 的目标是 glob，展开集合未知，`path.scope`
  会按**静态前缀目录**（`/var/log`）判定。因此系统目录下的危险 glob 仍会被
  `system` scope 规则拦住。但 glob 的“精确文件级”信息是缺失的，规则应结合
  scope 而非依赖具体文件名。
- **动态参数**：`rm $TARGET`、`rm $(...)` 的目标是 `dynamic`，无法静态获知路径。
  对这类操作要保守（通常 ask），不要因为“看起来在工作区内”就放行。
- **嵌套 wrapper**：`ssh host "docker exec c sh -c '...'"` 会逐层解析，最内层的
  真实命令才是 leaf。上下文标志（`inRemoteCommand`/`inContainerCommand`/
  `privilegeEscalated`）会从外层传递到内层 leaf。
- **多 leaf 命令**：`a && b`、`a | b`、`a; b` 会产生多个 leaf。决策按
  `deny > ask > allow` 聚合；只要任一分支危险，整体就不会 allow。任一 leaf
  没有被规则决定时按 `defaultAction` 处理。跨 leaf 合并阶段（把所有 leaf 的
  tag 合在一起再跑一遍）只跑 deny / ask 规则，并跳过 `match: {}` 的兜底规则。
- **单个 leaf 有多个操作或路径**：规则按「(操作, 路径) 单元」匹配。deny / ask
  只要任一单元命中就生效；allow 只放行它命中的单元，剩下的单元继续匹配后续规则，
  全部放行后 leaf 才是 allow。写 allow 规则时不要指望「顺带」放行同一命令的其他
  操作：例如 `cp src/a build/` 的读源文件需要 `allow-writable-dir-mutation-source`
  这样的规则单独覆盖。`explain` 里标 `[partial]` 的就是只放行了部分单元的 allow。
- **路径正则**：对路径做正则匹配用 `path.absolute` / `path.normalized` /
  `path.raw` 加 `regex` 操作符，例如 `path.absolute: { regex: "^/dev/sd" }`。
  旧写法 `path.normalizedRegex` / `path.rawRegex` 分别等同于 `path.normalized` /
  `path.raw`。

---

## 11. 编写一条新规则：完整示例

需求：禁止把任意文件写入 `.git` 目录（防止破坏仓库元数据）。

```yaml
- id: deny-write-git-internals
  mode: decide
  order: 1200
  match:
    all:
      - operation.type: { in: [file_write, file_append, file_delete, file_move] }
      - operation.target: { regex: '(^|/)\.git(/|$)' }
  action: deny_destructive
  reason: Writing into .git internals is not allowed
```

调试：

```bash
./bin/shell-policy explain --cwd "$PWD" 'echo x > .git/config'
# 看 Trace 里是否命中 deny-write-git-internals
```

如果没有命中，按这个顺序排查：
1. 用 `analyze` 看 operation 是否被正确提取（`operation.type` / `target` 对不对）。
2. 确认 `order` 没有被更早的 `terminal` 规则截断。
3. 确认字段名与操作符拼写正确（错误字段会被当作“字段不存在”）。

---

## 12. 测试你的规则

仓库用 Go 测试驱动策略验证，模式见
[internal/policy/policy_test.go](internal/policy/policy_test.go)：构造命令字符串、
跑 `evalDefaultPolicy`、断言决策与风险分。新增规则时，建议同时补一条覆盖
“应命中”和“不应命中”的用例，避免回归。

```bash
make test   # 跑全部测试
make vet    # 静态检查
```
