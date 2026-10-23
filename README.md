# support-log-analyzer

A second pair of eyes for your log files.

A small Python tool that reads a plain-text log and reports what a support
engineer needs before writing up an incident: severity breakdown, the errors
that repeat most, when they happened, and a short list of findings.

The way I use it: while I review a log by hand during an incident, the
analyzer runs over the same file in the background. When I finish, I compare
its findings against my own notes. It catches the patterns a tired human
misses — the error that repeated 40 times at the bottom of the file, or the
hour where everything actually started.

## Features

- Severity counts (DEBUG / INFO / WARNING / ERROR / CRITICAL) and error rate
- Repeated-error clustering: messages are normalized (IPs, UUIDs, ids and
  numbers are masked) so the same failure groups together instead of
  appearing as dozens of unique lines
- Errors per hour, plus first and last timestamps seen
- HTTP 5xx counts and the source IPs most frequent in error lines
- A findings section written for comparison against a manual review
- Text report by default, JSON with `--json`, report file with `--output`
- Standard library only — no dependencies, no installation step

## Usage

```bash
python3 log_analyzer.py <logfile> [--top N] [--json] [--output report.md]
```

Try it on the bundled sample log (a database failover incident):

```bash
python3 log_analyzer.py sample_logs/app.log
```

## Sample output

```text
Log analysis: sample_logs/app.log
============================================================
Lines read:        47
Lines with a level: 47
Time range:        2026-10-23 09:00:01 to 2026-10-23 11:58:03

Severity breakdown
------------------------------------------------------------
  INFO           22
  WARNING         7
  ERROR          17
  CRITICAL        1
  Error rate: 38.3% of parsed lines

Top repeated errors (normalized, top 5)
------------------------------------------------------------
    10x  database connection timeout host=db-primary:<n> attempt=<n> request_id=<id>
     3x  failed to authenticate user session expired user_id=<n> client=<ip>
     2x  api request failed status=<n> method=GET path=/api/accounts client=<ip>

Findings to compare against your own review
------------------------------------------------------------
  - The dominant failure is 'database connection timeout ...' with 10 occurrences
    (56% of all errors). Start the RCA there.
  - Errors concentrate at 2026-10-23 10:00 (17 errors). Correlate that hour with
    deploys, jobs and traffic before anything else.
  - 4 HTTP 5xx responses: the failure was visible to clients, not only internal.
```

(The full report also lists errors per hour, 5xx counts, IPs, and findings.)

## Log format

The analyzer expects lines that contain an ISO-style timestamp and a level
word, for example:

```text
2026-10-23 10:15:08 ERROR database connection timeout host=db-primary:5432 attempt=1
```

`WARN` and `FATAL` are accepted and mapped to `WARNING` and `CRITICAL`.
Lines without a level are counted in the total but skipped for severity
statistics.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Why this exists

In production support roles I have repeatedly written small scripts like
this one to watch telemetry and application logs while I investigated
incidents manually. This is a cleaned-up, public version of that idea:
deliberately simple, readable, and easy to extend during a real incident.

## Limitations

- Single file, processed in one pass in memory order — it is a triage tool,
  not a log platform. For volume, use your observability stack.
- Timestamp support is ISO-style (`YYYY-MM-DD HH:MM:SS`). Syslog and epoch
  formats are not parsed yet.

## License

MIT
