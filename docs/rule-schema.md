# Rule Schema v1

Detection rules are strict JSON bundles. The built-in bundle is [`deploy/rules/default.json`](../deploy/rules/default.json), embedded in the binary. Operators add or override rules with more bundles in `rules.dir` (default `/etc/pisentry/rules.d`, env `PISENTRY_RULES_DIR`).

The agent runs as root and parses these files, so the loader is attack surface. It is `encoding/json` with unknown fields rejected, hard size limits, and RE2 regexes compiled at load time. There is no YAML parser in the agent.

## Bundle

```json
{
  "schema_version": 1,
  "catalog": { "stratum_ports": [3333, 4444] },
  "rules": [ { "id": "...", "...": "..." } ]
}
```

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | Must be `1`. |
| `rules` | one of the two | Up to 500 rules per file. |
| `catalog` | one of the two | Table-driven lists for detectors whose logic stays in Go: `stratum_ports`, `shell_names`, `backdoor_ports` (`{port, note}`), `fim_watches`, `gtfo_suid`, `pkg_managers`, `priv_groups`. A list in `rules.d` replaces the built-in list of the same name. |

## Rule

Field names follow Sigma where they map cleanly, so SigmaHQ Linux rules can be converted later.

```json
{
  "id": "PS04-SUDO-SETCAP",
  "title": "Sudo assignment of Linux file capabilities",
  "status": "stable",
  "category": "PS04",
  "level": "medium",
  "tags": ["attack.t1548.001"],
  "source": "log",
  "match": {
    "all": [
      { "field": "log.ident", "equals": ["sudo"] },
      { "field": "process.cmdline", "regex": ["\\bsetcap\\b"] }
    ]
  },
  "exceptions": [ { "users": ["ansible"] } ],
  "falsepositives": ["Configuration management granting cap_net_bind_service"],
  "response": "none"
}
```

| Field | Required | Notes |
|---|---|---|
| `id` | yes | `[A-Za-z0-9_.-]`, at most 128 bytes, unique across all loaded files. |
| `title` | yes | At most 256 bytes. Becomes `rule.title` on the event. |
| `category` | yes | `PS01`..`PS10`, see `pisentry categories`. |
| `level` | no | `info` (default), `low`, `medium`, `high`, `critical`. Becomes the event severity. |
| `source` | yes | Telemetry stream: `process`, `network`, `file`, `log`, `k3s`. |
| `match` | yes | See below. |
| `mitre` / `tags` | no | Technique IDs (`T1548.001`). Sigma tags of the form `attack.t1548.001` are added to `mitre`. |
| `status` | no | `stable`, `test`, `experimental`, `deprecated`. |
| `description`, `author`, `references`, `falsepositives` | no | Documentation only. |
| `exceptions` | no | Up to 32. See below. |
| `response` | no | `none` (default), `kill_tree`, `quarantine`. Recorded only; no response actions run in v0.2. |

### Match

`all` conditions must all hold. If `any` is present, at least one of its conditions must also hold. A condition tests one field and is satisfied by any one of its patterns:

| Operator | Kind |
|---|---|
| `equals`, `contains`, `startswith`, `endswith` | Literal. Kept apart from regex so a literal prefilter can be added without a schema change. |
| `regex` | RE2 (Go `regexp`), no backtracking. At most 512 bytes. |
| `case_insensitive` | Applies to every pattern in the condition. |

Limits per rule: 32 conditions, 64 patterns. Exceeding a limit rejects the file; nothing is truncated.

### Fields

Rules match on [Event Schema v1](event-schema.md) names: `process.pid`, `process.ppid`, `process.uid`, `process.comm`, `process.exe`, `process.cmdline`, `process.parent_comm`, `source.ip`, `source.port`, `source.proto`, `user.name`, `user.uid`, `file.path`, `file.change`, `file.content`, `container.id`, `container.pod`, `container.namespace`, `container.image`, `log.ident`, `log.msg`, `k3s.kind`, `k3s.spec`. Any other name is a load error.

Which fields a detector fills depends on the source. `log` rules on sudo see `log.ident`, `log.msg`, `user.name` and the command as `process.cmdline`. `process` rules see the `process.*` fields; `process.uid` and `process.parent_comm` cost extra `/proc` reads, which only happen for every process when some rule matches on them.

### Exceptions

An exception suppresses a match when every non-empty key in it matches. Several exceptions on a rule are ORed. Keys: `exe`, `exe_prefix`, `comm`, `parent_comm`, `uids`, `users`, `container_image` (glob), `cidrs` (CIDR or bare IP), `paths` (glob), `cmdline_contains`. An empty exception is rejected because it would silence the rule.

To add an exception to a built-in rule, copy the rule into `rules.d` with the same `id` and add `exceptions`. A rule in `rules.d` with a built-in `id` replaces the built-in rule. Two files in `rules.d` defining the same `id` is an error.

## Validating

```bash
pisentry check                       # built-in rules plus rules.dir from the config, as the agent loads them
pisentry check -rules /path/to/dir   # a file or directory on its own
```

Both exit 1 on the first error and name the file, rule and field. At startup, a broken `rules.d` is logged and the agent runs on the built-in rules rather than with none.

## Fixtures

Every built-in rule has recorded inputs under `internal/rules/testdata/rules/<rule-id>/`:

- `positive/*.json`: the rule must fire.
- `negative/*.json`: the rule must stay quiet. These come from normal activity on a Pi running k3s: apt upgrades, k3s restarts, backups, cron.

Each file is one normalized input with the same shape the detectors build:

```json
{
  "source": "log",
  "log_ident": "sudo",
  "log_msg": "    pi : TTY=pts/0 ; PWD=/home/pi ; USER=root ; COMMAND=/usr/sbin/setcap cap_setuid+ep /usr/bin/python3.13",
  "user": { "name": "pi" },
  "process": { "cmdline": "/usr/sbin/setcap cap_setuid+ep /usr/bin/python3.13" }
}
```

Input keys: `source`, `process` (`pid`, `ppid`, `uid`, `comm`, `exe`, `cmdline`), `parent_comm`, `network` (`ip`, `port`), `proto`, `user` (`name`, `uid`), `file` (`path`), `file_change`, `file_content`, `container` (`id`, `pod`, `namespace`), `container_image`, `log_ident`, `log_msg`, `k3s_kind`, `k3s_spec`. Unknown keys fail the test, so a typo cannot turn a positive fixture into a no-op.

`go test ./internal/rules/...` replays them with no root and no network. It fails when a rule lacks either kind, when a fixture directory names no rule, or when any fixture gives the wrong verdict. `make sim` stays the end-to-end check.
