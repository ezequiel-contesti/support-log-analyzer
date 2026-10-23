#!/usr/bin/env python3
"""support-log-analyzer: a second pair of eyes for your log files.

Reads a plain-text log file, then reports what a support engineer wants to
know before writing up an incident:

  * How many lines per severity level, and what share are errors.
  * Which errors repeat most often (messages are normalized so the same
    failure with different ids, IPs or numbers clusters together).
  * When things happened: first/last timestamps and errors per hour.
  * HTTP 5xx responses and the source IPs seen most often in errors.

Typical use: run it in the background while you review the log by hand,
then compare its findings against your own notes.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LEVEL_ALIASES = {"WARN": "WARNING", "FATAL": "CRITICAL", "TRACE": "DEBUG"}

LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\b")
TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HTTP_5XX_RE = re.compile(r"\b(5\d{2})\b")

# Pieces of a message that change between occurrences of the same failure.
# Replacing them with a placeholder lets repeated errors cluster together.
NORMALIZE_PATTERNS = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"0x[0-9a-fA-F]+"), "<hex>"),
    (re.compile(r"\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{6,}\b"), "<id>"),
    (re.compile(r"\b\d+\b"), "<n>"),
]


def detect_level(line: str) -> str | None:
    match = LEVEL_RE.search(line)
    if not match:
        return None
    raw = match.group(1)
    return LEVEL_ALIASES.get(raw, raw)


def parse_timestamp(line: str) -> datetime | None:
    match = TIMESTAMP_RE.search(line)
    if not match:
        return None
    try:
        return datetime.strptime(
            f"{match.group(1)} {match.group(2)}:{match.group(3)}:{match.group(4)}",
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError:
        return None


def normalize_message(line: str) -> str:
    """Strip the timestamp and level, then mask ids/ips/numbers."""
    message = TIMESTAMP_RE.sub("", line)
    message = LEVEL_RE.sub("", message, count=1)
    message = message.strip(" -[]|:")
    for pattern, replacement in NORMALIZE_PATTERNS:
        message = pattern.sub(replacement, message)
    return re.sub(r"\s+", " ", message).strip()


@dataclass
class LogReport:
    total_lines: int = 0
    parsed_lines: int = 0
    level_counts: Counter = field(default_factory=Counter)
    error_clusters: Counter = field(default_factory=Counter)
    errors_per_hour: Counter = field(default_factory=Counter)
    http_5xx: Counter = field(default_factory=Counter)
    error_ips: Counter = field(default_factory=Counter)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def error_lines(self) -> int:
        return self.level_counts["ERROR"] + self.level_counts["CRITICAL"]

    @property
    def error_rate(self) -> float:
        if self.parsed_lines == 0:
            return 0.0
        return 100.0 * self.error_lines / self.parsed_lines


def analyze_lines(lines) -> LogReport:
    report = LogReport()
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        report.total_lines += 1

        timestamp = parse_timestamp(line)
        if timestamp is not None:
            if report.first_seen is None or timestamp < report.first_seen:
                report.first_seen = timestamp
            if report.last_seen is None or timestamp > report.last_seen:
                report.last_seen = timestamp

        level = detect_level(line)
        if level is None:
            continue
        report.parsed_lines += 1
        report.level_counts[level] += 1

        lowered = line.lower()
        if "http" in lowered or "status" in lowered or "response" in lowered:
            status_match = HTTP_5XX_RE.search(line)
            if status_match:
                report.http_5xx[status_match.group(1)] += 1

        if level in ("ERROR", "CRITICAL"):
            report.error_clusters[normalize_message(line)] += 1
            if timestamp is not None:
                report.errors_per_hour[timestamp.strftime("%Y-%m-%d %H:00")] += 1
            for ip in IP_RE.findall(line):
                report.error_ips[ip] += 1
    return report


def analyze_file(path: Path) -> LogReport:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return analyze_lines(handle)


def render_text(report: LogReport, source: str, top: int = 5) -> str:
    out = []
    out.append(f"Log analysis: {source}")
    out.append("=" * 60)
    out.append(f"Lines read:        {report.total_lines}")
    out.append(f"Lines with a level: {report.parsed_lines}")
    if report.first_seen and report.last_seen:
        out.append(f"Time range:        {report.first_seen} to {report.last_seen}")
    out.append("")
    out.append("Severity breakdown")
    out.append("-" * 60)
    for level in LEVELS:
        count = report.level_counts.get(level, 0)
        if count:
            out.append(f"  {level:<9} {count:>6}")
    out.append(f"  Error rate: {report.error_rate:.1f}% of parsed lines")
    out.append("")
    out.append(f"Top repeated errors (normalized, top {top})")
    out.append("-" * 60)
    if report.error_clusters:
        for message, count in report.error_clusters.most_common(top):
            out.append(f"  {count:>4}x  {message}")
    else:
        out.append("  No ERROR or CRITICAL lines found.")
    out.append("")
    out.append("Errors per hour")
    out.append("-" * 60)
    if report.errors_per_hour:
        for hour, count in sorted(report.errors_per_hour.items()):
            out.append(f"  {hour}  {'#' * min(count, 50)} ({count})")
    else:
        out.append("  No timestamped errors found.")
    if report.http_5xx:
        out.append("")
        out.append("HTTP 5xx responses")
        out.append("-" * 60)
        for status, count in report.http_5xx.most_common():
            out.append(f"  {status}  {count}")
    if report.error_ips:
        out.append("")
        out.append("Most frequent IPs in error lines")
        out.append("-" * 60)
        for ip, count in report.error_ips.most_common(top):
            out.append(f"  {ip:<16} {count}")
    out.append("")
    out.append("Findings to compare against your own review")
    out.append("-" * 60)
    findings = build_findings(report, top)
    for finding in findings:
        out.append(f"  - {finding}")
    return "\n".join(out) + "\n"


def build_findings(report: LogReport, top: int = 5) -> list[str]:
    findings = []
    if report.error_lines == 0:
        findings.append("No errors found. If the incident is real, check the log level and time window you exported.")
        return findings
    top_message, top_count = report.error_clusters.most_common(1)[0]
    share = 100.0 * top_count / report.error_lines if report.error_lines else 0.0
    findings.append(
        f"The dominant failure is '{top_message}' with {top_count} occurrences "
        f"({share:.0f}% of all errors). Start the RCA there."
    )
    if report.errors_per_hour:
        busiest_hour, busiest_count = report.errors_per_hour.most_common(1)[0]
        findings.append(
            f"Errors concentrate at {busiest_hour} ({busiest_count} errors). "
            "Correlate that hour with deploys, jobs and traffic before anything else."
        )
    if report.http_5xx:
        total_5xx = sum(report.http_5xx.values())
        findings.append(f"{total_5xx} HTTP 5xx responses: the failure was visible to clients, not only internal.")
    if report.error_rate >= 10:
        findings.append(f"Error rate is high ({report.error_rate:.1f}%). Treat as a sustained incident, not noise.")
    return findings


def report_to_dict(report: LogReport, top: int = 5) -> dict:
    return {
        "total_lines": report.total_lines,
        "parsed_lines": report.parsed_lines,
        "level_counts": {level: report.level_counts.get(level, 0) for level in LEVELS},
        "error_lines": report.error_lines,
        "error_rate_percent": round(report.error_rate, 1),
        "first_seen": str(report.first_seen) if report.first_seen else None,
        "last_seen": str(report.last_seen) if report.last_seen else None,
        "top_errors": [
            {"count": count, "message": message}
            for message, count in report.error_clusters.most_common(top)
        ],
        "errors_per_hour": dict(sorted(report.errors_per_hour.items())),
        "http_5xx": dict(report.http_5xx.most_common()),
        "top_error_ips": [
            {"ip": ip, "count": count} for ip, count in report.error_ips.most_common(top)
        ],
        "findings": build_findings(report, top),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a log file: severity counts, repeated errors, timeline and findings."
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--top", type=int, default=5, help="How many repeated errors / IPs to show (default: 5)")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON instead of text")
    parser.add_argument("--output", help="Also write the report to this file (Markdown if it ends in .md)")
    args = parser.parse_args(argv)

    path = Path(args.logfile)
    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    report = analyze_file(path)

    if args.json:
        text = json.dumps(report_to_dict(report, args.top), indent=2)
    else:
        text = render_text(report, str(path), args.top)
    print(text)

    if args.output:
        output_path = Path(args.output)
        if output_path.suffix == ".md" and not args.json:
            output_path.write_text(f"# Log analysis: {path.name}\n\n```\n{text}```\n", encoding="utf-8")
        else:
            output_path.write_text(text, encoding="utf-8")
        print(f"Report written to {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
