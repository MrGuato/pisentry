# Event Schema v1 & SIEM Mapping (OCSF / ECS)

Every security finding emitted by `pisentry` on stdout, in `output.json_file`, over `/api/events`, and to generic JSON webhooks conforms to **Event Schema v1** ([`docs/event-schema.json`](event-schema.json)).

All attacker-influenced string fields (`summary`, typed entity strings, and `fields` values) pass through the central sanitizer (`engine.SanitizeEvent`) before serialization: C0/C1 control characters, DEL, Unicode bidi overrides, and invalid UTF-8 are neutralized, and strings are bounded on a UTF-8 rune boundary.

## Example Event (v1)

```json
{
  "id": "c4f1d2e8-7a3b-4c91-8e2f-19a0b3c4d5e6",
  "schema_version": 1,
  "time": "2026-10-15T05:14:02Z",
  "host": "kubepi",
  "category": "PS08",
  "category_name": "Reverse shell",
  "severity": "critical",
  "mitre": ["T1059.004"],
  "detector": "proc",
  "summary": "Reverse shell: bash (pid 5358) has fd 0 connected to 192.0.2.2:4445",
  "key": "5358:98112",
  "process": {
    "pid": 5358,
    "ppid": 1,
    "start_time": 98112,
    "uid": 0,
    "comm": "bash",
    "exe": "/usr/bin/bash",
    "cmdline": "bash -i"
  },
  "source": {
    "ip": "192.0.2.2",
    "port": 4445
  },
  "user": {
    "uid": 0
  },
  "fields": {
    "cmdline": "bash -i",
    "comm": "bash",
    "exe": "/usr/bin/bash",
    "fd": "0",
    "local": "192.0.2.10:51234",
    "parent": "systemd",
    "pid": "5358",
    "ppid": "1",
    "remote": "192.0.2.2:4445",
    "uid": "0"
  }
}
```

## Typed Entity Groups

| Entity | Field | Type | Description |
|---|---|---|---|
| `process` | `pid` | `integer` | Process ID |
| `process` | `ppid` | `integer` | Parent process ID |
| `process` | `start_time` | `integer` | Process start time in clock ticks since boot (`/proc/[pid]/stat` field 22) |
| `process` | `uid` | `integer` | Real user ID (`0` for root) |
| `process` | `comm` | `string` | Kernel task `comm` name |
| `process` | `exe` | `string` | Resolved `/proc/[pid]/exe` target |
| `process` | `cmdline` | `string` | Sanitized command line (`argv`) |
| `source` | `ip` | `string` | Source IP address (or bound/remote socket IP) |
| `source` | `port` | `integer` | Source or target port (`0–65535`) |
| `user` | `name` | `string` | Account username |
| `user` | `uid` | `integer` | Account numeric UID |
| `file` | `path` | `string` | Host file path |
| `file` | `hash_before` | `string` | Previous SHA-256 fingerprint prefix |
| `file` | `hash_after` | `string` | Current SHA-256 fingerprint prefix |
| `container` | `id` | `string` | Container runtime ID |
| `container` | `pod` | `string` | Kubernetes pod name |
| `container` | `namespace` | `string` | Kubernetes namespace |
| `rule` | `id` | `string` | Detection rule ID or posture check ID |
| `rule` | `title` | `string` | Human-readable rule or posture check title |

## Deprecated `fields` Keys (v0.1 Compatibility)

To avoid breaking existing jq scripts, alerts, or log pipelines, every `fields` key from `v0.1.0` continues to be emitted in `v0.2.0` alongside the new typed entity groups. The following keys in `fields` are **deprecated in v0.2.0** and scheduled for removal in **v0.3.0**:

| Deprecated `fields` key | Detector(s) | Schema v1 replacement |
|---|---|---|
| `fields.pid` | `proc`, `listeners` | `process.pid` (integer) |
| `fields.ppid` | `proc` | `process.ppid` (integer) |
| `fields.comm` | `proc`, `listeners` | `process.comm` |
| `fields.exe` | `proc`, `listeners` | `process.exe` |
| `fields.cmdline` | `proc` | `process.cmdline` |
| `fields.command` | `auth` (sudo) | `process.cmdline` |
| `fields.src_ip` | `auth`, `portscan` | `source.ip` |
| `fields.port` | `listeners` | `source.port` (integer) |
| `fields.user` | `auth`, `fim` | `user.name` |
| `fields.uid` | `proc`, `fim` | `process.uid` / `user.uid` (integer) |
| `fields.owner_uid` | `suid` | `user.uid` (integer) |
| `fields.path` | `fim`, `suid` | `file.path` |
| `fields.old_sha256` | `fim`, `suid` | `file.hash_before` |
| `fields.sha256` | `fim`, `suid` | `file.hash_after` |
| `fields.check` | `audit` | `rule.id` |

Detector-specific context keys (`failures`, `window`, `users`, `method`, `recent_failures`, `distinct_ports`, `ports`, `proto`, `change`, `mode`, `keys`, `package_manager_active`, `cpu_percent`, `reason`, `fd`, `local`, `remote`, `parent`, `bit`, `detail`, `fix`, `group`, `shell`, `old_shell`) remain in `fields`.

## Mapping to OCSF and ECS

For SIEM ingestion without custom guesswork, map Event Schema v1 fields directly to **OCSF v1.1+** (`Detection Finding`, class `2004`) or **Elastic Common Schema (ECS v8.x)**:

| pisentry v1 field | OCSF v1.1 (`Detection Finding` / `2004`) | Elastic Common Schema (ECS v8.x) |
|---|---|---|
| `id` | `metadata.uid` / `finding_info.uid` | `event.id` |
| `schema_version` | `metadata.version` | `ecs.version` (custom `pisentry.schema_version`) |
| `time` | `time` / `time_dt` | `@timestamp` |
| `host` | `device.hostname` | `host.hostname` / `host.name` |
| `category` | `finding_info.analytic.uid` | `rule.category` / `event.code` |
| `category_name` | `finding_info.analytic.name` | `event.action` |
| `severity` | `severity` (`info`=1, `low`=2, `medium`=3, `high`=4, `critical`=5) | `event.severity_name` (`event.severity`: 1–5) |
| `mitre[]` | `attacks[].technique.uid` | `threat.technique.id` |
| `detector` | `metadata.product.feature.name` | `event.module` / `event.dataset` |
| `summary` | `message` / `finding_info.title` | `message` |
| `key` | `finding_info.src_url` / `unmapped.key` | `event.Action` / `pisentry.key` |
| `process.pid` | `evidences[].process.pid` | `process.pid` |
| `process.ppid` | `evidences[].process.parent_process.pid` | `process.parent.pid` |
| `process.start_time` | `evidences[].process.created_time` | `process.start` |
| `process.uid` | `evidences[].process.user.uid` | `process.user.id` |
| `process.comm` | `evidences[].process.name` | `process.name` |
| `process.exe` | `evidences[].process.file.path` | `process.executable` |
| `process.cmdline` | `evidences[].process.cmd_line` | `process.command_line` |
| `source.ip` | `evidences[].src_endpoint.ip` | `source.ip` |
| `source.port` | `evidences[].src_endpoint.port` | `source.port` |
| `user.name` | `evidences[].actor.user.name` | `user.name` |
| `user.uid` | `evidences[].actor.user.uid` | `user.id` |
| `file.path` | `evidences[].file.path` | `file.path` |
| `file.hash_before` | `evidences[].file.hashes[0].value` | `file.hash.sha256` (previous) |
| `file.hash_after` | `evidences[].file.hashes[1].value` | `file.hash.sha256` |
| `container.id` | `evidences[].container.uid` | `container.id` |
| `container.pod` | `evidences[].pod_uid` | `kubernetes.pod.name` |
| `container.namespace` | `evidences[].namespace` | `kubernetes.namespace` |
| `rule.id` | `finding_info.uid` | `rule.id` |
| `rule.title` | `finding_info.title` | `rule.name` |
| `fields.*` | `unmapped.*` | `labels.*` |
