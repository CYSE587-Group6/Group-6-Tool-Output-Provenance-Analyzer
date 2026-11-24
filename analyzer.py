import json
import re
import argparse
from pathlib import Path, PureWindowsPath
import posixpath
from collections import defaultdict

# Group 6: Tool Output Provenance & Injection Risk Analyzer

INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "ignore the system prompt",
    "reveal secrets",
    "exfiltrate",
    "send credentials",
    "upload the contents",
    "execute the following",
]

TRAVERSAL_PATTERN = re.compile(
    r"(?:^|[/\\])\.\.(?:[/\\]|$)|\.\.[/\\]"
)

GIT_OUTPUT_PATTERN = re.compile(
    r"(?:^|\s)--output(?:=|\s|$)"
)

SHELL_OUTPUT_PATTERN = re.compile(
    r"(?:^|\s)(?:>>|>)\s*\S"
)

SOURCE_TOOL_NAMES = ("fetch", "browser", "web", "search", "retrieve")


def load_logs(file_path):
    """Load JSON arrays, JSON objects, or JSON Lines files."""
    text = Path(file_path).read_text(encoding="utf-8")

    try:
        data = json.loads(text)

        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]

        if isinstance(data, dict):
            for key in ("events", "records", "logs", "data"):
                if isinstance(data.get(key), list):
                    return [
                        item for item in data[key]
                        if isinstance(item, dict)
                    ]
            return [data]

        raise ValueError("JSON must contain an object or list.")

    except json.JSONDecodeError:
        records = []

        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {error.msg}"
                ) from error

            if isinstance(record, dict):
                records.append(record)

        return records

def sanitize_record(record):
    """Remove scenario labels and debugging metadata."""
    excluded_fields = {
        "scenario_tag",
        "annotations",
        "expected_alert",
        "ground_truth",
        "debug",
    }

    def clean(value):
        if isinstance(value, dict):
            return {
                key: clean(item)
                for key, item in value.items()
                if key not in excluded_fields
            }

        if isinstance(value, list):
            return [clean(item) for item in value]

        return value

    return clean(record)
    
def flatten_record(value, prefix=""):
    """Make nested log fields searchable."""
    fields = []

    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            fields.extend(flatten_record(item, name))

    elif isinstance(value, list):
        for index, item in enumerate(value):
            fields.extend(
                flatten_record(item, f"{prefix}[{index}]")
            )

    elif value is not None:
        fields.append((prefix, str(value)))

    return fields


def get_fetch_content(record):
    
    """Extract the content preview from an ADOP Fetch event.
    Do not treat filenames, paths, or metadata as injection text. """
    tool_name = str(
        get_value(record, "tool_name", "tool", "name", "method")
        or ""
    ).lower()

    if "fetch" not in tool_name:
        return ""

    content = record.get("result_summary")

    if not isinstance(content, str):
        return ""

    return content[:200]


def get_value(record, *keys):
    """Return the first available field from a log record."""
    for key in keys:
        value = record.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return None


def get_identity(record, index):
    return {
        "record_index": index,
        "event_id": get_value(
            record, "event_id", "id", "record_id", "request_id"
        ),
        "task_id": get_value(
            record, "task_id", "session_id",
            "trace_id", "conversation_id"
        ),
        "timestamp": get_value(
            record, "timestamp", "time", "created_at"
        ),
        "tool_name": get_value(
            record, "tool_name", "tool", "name", "method"
        ) or "unknown",
        "result_status": get_value(
            record, "result_status", "status"
        ),
    }
def check_path_containment(path, base_dir, allowed_root):
    """Check lexical containment within an authorized root."""

    path = path.strip()

    if not path:
        return False

    # Detect Windows absolute and drive-relative paths.
    windows_path = PureWindowsPath(path)

    if windows_path.drive or windows_path.root == "\\":
        return True

    # Normalize path separators and parent directories.
    path = path.replace("\\", "/")

    resolved_path = posixpath.normpath(
        posixpath.join(base_dir, path)
    )

    allowed_root = posixpath.normpath(allowed_root)

    return posixpath.commonpath(
        [resolved_path, allowed_root]
    ) != allowed_root

def analyze_record(record, index):
    """Flag suspicious patterns and preserve supporting evidence."""
   fields = flatten_record(record)

    tool_name = (
        get_value(record, "tool_name", "tool", "name", "method")
        or "unknown"
    ).lower()

    findings = []
    score = 0



    
        # Check whether requested paths escape the repository.
    allowed_root = "/testbed/testbed-repo"

    # Assumed testbed layout; use verified server metadata
    # when available.
    base_dir = (
        "/testbed"
        if tool_name == "git_init"
        else allowed_root
    )

    path_fields = {
        "path", "paths", "pathspec", "filename",
        "directory", "target_resource"
    }

    candidates = flatten_record(
        record.get("arguments", {})
    )

    target = record.get("target_resource")

    if isinstance(target, str):
        candidates.append(("target_resource", target))

    traversal_detected = False

    for field_name, value in candidates:
        root_field = re.split(
            r"[.\[]", field_name
        )[0].lower()

        if root_field not in path_fields:
            continue

        # Extract paths from Git output options.
        if root_field == "pathspec":
            match = re.search(
                r"--output(?:=|\s+)([^\s]+)", value
            )

            if match:
                value = match.group(1)

        # Ignore URLs and non-filesystem resources.
        if "://" in value:
            continue

        if check_path_containment(
            value, base_dir, allowed_root
        ):
            findings.append({
                "category": "path_containment_violation",
                "evidence": (
                    "The requested path resolves outside "
                    "the assumed authorized repository."
                ),
                "evidence_field": field_name,
                "evidence_record_index": index,
            })

            if not traversal_detected:
                score += 45
                traversal_detected = True



        # Check command arguments, not file content or results.
    arguments = record.get("arguments", {})
    argument_fields = flatten_record(arguments)

    git_argument_names = {
        "pathspec", "args", "argv", "options",
        "flags", "ref", "command"
    }

    shell_argument_names = {
        "command", "cmd", "args", "argv", "script"
    }

    for field_name, value in argument_fields:
        root_field = re.split(
            r"[.\[]", field_name
        )[0].lower()

        suspicious = False

        if tool_name.startswith("git_"):
            if root_field in git_argument_names:
                suspicious = bool(
                    GIT_OUTPUT_PATTERN.search(value)
                )

        elif tool_name.startswith(("shell", "exec")):
            if root_field in shell_argument_names:
                suspicious = bool(
                    SHELL_OUTPUT_PATTERN.search(value)
                )

        if suspicious:
            findings.append({
                "category": "suspicious_tool_argument",
                "evidence": (
                    "A potentially unsafe output option "
                    "was detected in a command argument."
                ),
                "evidence_field": (
                    f"arguments.{field_name}"
                ),
                "evidence_record_index": index,
            })

            score += 25
            break



    # Check retrieved Fetch content for possible prompt injection.
    # Do not search filenames, paths, or debugging metadata.
    fetch_content = get_fetch_content(record).lower()

    matched_phrases = [
        phrase for phrase in INJECTION_PHRASES
        if phrase in fetch_content
    ]

    if matched_phrases:
        findings.append({
            "category": "prompt_injection_like_text",
            "evidence": (
                "Possible instruction-override language detected "
                "in the Fetch result_summary content preview."
            ),
            "matched_rule_count": len(matched_phrases),
        })
        score += 20



    
       if not findings:
        return None

    # Adjust risk based on the observed operation outcome.
    base_score = score

    result_status = str(
        get_value(record, "result_status", "status") or ""
    ).strip().lower()

    result_summary = str(
        record.get("result_summary") or ""
    ).strip().lower()

    outcome_adjustment = 0
    outcome_reason = "No additional outcome evidence."

    has_path_violation = any(
        finding["category"] == "path_containment_violation"
        for finding in findings
    )

    if result_status in {"error", "failed", "failure", "denied"}:
        outcome_adjustment = -20
        outcome_reason = (
            "The suspicious operation reported failure. "
            "The attempted action still requires review."
        )

    elif result_status == "success":

        if tool_name == "git_diff" and result_summary in {
            "(no changes)", "no changes"
        }:
            outcome_adjustment = -20
            outcome_reason = (
                "No changes were reported. "
                "The suspected output write remains unverified."
            )

        elif (
            tool_name in {"git_show_worktree", "read_text_file"}
            and has_path_violation
            and result_summary
        ):
            outcome_adjustment = 30
            outcome_reason = (
                "The operation returned content from a path "
                "flagged as outside the authorized repository."
            )

    score = max(0, min(score + outcome_adjustment, 100))


    if score >= 60:
        risk = "HIGH"
    elif score >= 35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        **get_identity(record, index),
        "risk": risk,
        "heuristic_score": score,
        "base_score": base_score,
        "outcome_adjustment": outcome_adjustment,
        "outcome_reason": outcome_reason,
        "findings": findings,
        "review_recommendation": (
            "Human review recommended; verify the source event, "
            "tool arguments, and intended target."
        ),
        "evidence_reference": {
            "record_index": index,
            "session_id": get_value(record, "session_id"),
            "task_id": get_value(record, "task_id"),
            "seq": record.get("seq"),
    },
 }

    
def correlate_events(records, alerts):
    """ Correlate suspicious actions with earlier Fetch events
    in the same task/session.

    Correlation is not proof of causation."""
   
    events_by_task = defaultdict(list)
    events_by_session = defaultdict(list)

    for index, record in enumerate(records):

        task_id = get_value(
            record, "task_id", "session_id",
            "trace_id", "conversation_id"
        )

        if task_id:
            events_by_task[task_id].append((index, record))
            
        session_id = get_value(record, "session_id")

        if session_id:
            events_by_session[session_id].append((index, record))


    for alert in alerts:
        task_id = alert.get("task_id")
        alert_index = alert.get("record_index")

        
        if not task_id or alert_index is None:
            alert["correlation"] = {
                "status": "insufficient_identifiers",
                "note": "Cannot establish an event relationship."
            }
            continue

        # Find earlier Fetch events from the same session.
        session_id = get_value(records[alert_index], "session_id")
        session_sources = []

        if session_id:
            for index, record in events_by_session.get(session_id, []):
                # Use ADOP sequence numbers when available.
                alert_seq = records[alert_index].get("seq")
                source_seq = record.get("seq")

                if alert_seq is not None and source_seq is not None:
                    try:
                        if int(source_seq) >= int(alert_seq):
                            continue
                    except (ValueError, TypeError):
                        if index >= alert_index:
                            continue
                elif index >= alert_index:
                    continue

                source_tool = (
                    get_value(record, "tool_name", "tool", "name", "method")
                    or ""
                ).lower()

                if "fetch" not in source_tool:
                    continue

                # Keep same-task evidence separate from session context.
                source_task = get_value(record, "task_id")
                alert_task = get_value(records[alert_index], "task_id")

                if source_task == alert_task:
                    continue

                session_sources.append({
                    "record_index": index,
                    "tool_name": source_tool,
                    "seq": record.get("seq"),
                    "relationship": "same_session_different_task",
                })


        related_events = events_by_task.get(task_id, [])

        earlier_sources = []

       
        for index, record in related_events:
            # Prefer ADOP sequence numbers when available.
            alert_seq = records[alert_index].get("seq")
            source_seq = record.get("seq")

            if alert_seq is not None and source_seq is not None:
                try:
                    if int(source_seq) >= int(alert_seq):
                        continue
                except (ValueError, TypeError):
                    # Fall back to input order if sequence values are invalid.
                    if index >= alert_index:
                        continue
            elif index >= alert_index:
                continue


            tool_name = (
                get_value(
                    record, "tool_name", "tool", "name", "method"
                ) or ""
            ).lower()

            if not any(
                name in tool_name for name in SOURCE_TOOL_NAMES
            ):
                continue

            fetch_content = get_fetch_content(record).lower()

            matched_phrases = [
                phrase for phrase in INJECTION_PHRASES
                if phrase in fetch_content
            ]

            earlier_sources.append({
                "record_index": index,
                "tool_name": tool_name,
                "suspicious_content_detected": bool(matched_phrases),
                "matched_rule_count": len(matched_phrases),
            })

        suspicious_sources = [
            source for source in earlier_sources
            if source["suspicious_content_detected"]
        ]

        if suspicious_sources:
            status = "suspicious_prior_source_found"
            note = (
                "A prior Fetch/source event contained suspicious "
                "instruction-like content. A later action occurred "
                "in the same task. This is a candidate relationship, "
                "not proof of causation."
            )
        elif earlier_sources:
            status = "prior_source_found"
            note = (
                "Earlier source events were found, but no "
                "injection phrases were detected in their "
                "available content previews."
            )
        else:
            status = "no_prior_source_found"
            note = (
                "No earlier source event could be identified "
                "from the available records."
            )

        alert["correlation"] = {
            "status": status,
            "related_record_count": len(related_events),
            "possible_source_events": earlier_sources,
            "same_session_source_events": session_sources,
            "same_session_source_count": len(session_sources),
            "note": note,

        }



def analyze_logs(records):
    clean_records = [
        sanitize_record(record) for record in records
    ]
    
    alerts = []

    for index, record in enumerate(clean_records):
        alert = analyze_record(record, index)

        if alert:
            alerts.append(alert)

       correlate_events(clean_records, alerts)

    # Rank alerts by final risk score, highest first.
    # Use record index as a consistent tie-breaker.
    alerts.sort(
        key=lambda alert: (
            -alert["heuristic_score"],
            alert["record_index"]
        )
    )

    return {
        "tool_name": (
            "Group 6 Tool Output Provenance "
            "& Injection Risk Analyzer"
        ),
        "version": "0.5",
        "analysis_mode": "passive_only",
        "records_analyzed": len(records),
        "alerts_found": len(alerts),
        "alerts": alerts,
        "limitations": [
            "Scores are heuristic indicators, not probabilities.",
            "A suspicious pattern is not proof of an attack.",
            "Shared task IDs do not prove causation.",
            "Detection depends on the fields present in the logs.",
            "This prototype does not modify ADOP or block actions.",
            "Source-to-action correlation uses available task IDs "
            "and sequence numbers, with input-order fallback; "
            "it does not prove causation.",

        ],
    }


def create_review_summary(report):
    """Create a readable security review summary."""
    lines = [
        "GROUP 6 - SECURITY-LEAD REVIEW",
        "=" * 40,
        f"Records analyzed: {report['records_analyzed']}",
        f"Alerts found: {report['alerts_found']}",
        f"Analysis mode: {report['analysis_mode']}",
        "",
    ]

    if not report["alerts"]:
        lines.append("No suspicious activity detected by current rules.")
    else:
        for number, alert in enumerate(report["alerts"], 1):
            correlation = alert.get("correlation", {})

            lines.extend([
                f"ALERT {number}",
                f"Tool: {alert['tool_name']}",
                f"Risk: {alert['risk']}",
                f"Heuristic score: {alert['heuristic_score']}",
                f"Record index: {alert['record_index']}",
                f"Task ID: {alert.get('task_id') or 'Unavailable'}",
                f"Timestamp: {alert.get('timestamp') or 'Unavailable'}",
                f"Correlation: {correlation.get('status', 'Unknown')}",
                "Findings:",
            ])

            for finding in alert["findings"]:
                lines.append(
                    f"  - {finding['category']}: {finding['evidence']}"
                )

            lines.extend([
                f"Same-task sources: "
                f"{len(correlation.get('possible_source_events', []))}",
                f"Cross-task session sources: "
                f"{correlation.get('same_session_source_count', 0)}",
                f"Recommendation: {alert['review_recommendation']}",
                "-" * 40,
            ])

    lines.extend([
        "",
        "LIMITATIONS",
        "Correlation does not prove causation.",
        "Scores are heuristic, not attack probabilities.",
    ])

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(
        description="Passively analyze structured tool logs."
    )
    parser.add_argument(
        "input",
        help="Path to the input JSON or JSONL log file"
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional path for the JSON results"
    )
    
    parser.add_argument(
        "--review",
        help="Optional path for the human-readable security review report"
    )

    args = parser.parse_args()

    try:
        records = load_logs(args.input)
        report = analyze_logs(records)
        output = json.dumps(report, indent=2)

        if args.review:
            review_text = create_review_summary(report)
            Path(args.review).write_text(
                review_text + "\n", encoding="utf-8"
            )
            print(f"Security review saved to: {args.review}")

        if args.output:
            Path(args.output).write_text(
                output + "\n", encoding="utf-8"
            )
            print(f"Records analyzed: {len(records)}")
            print(f"Alerts found: {report['alerts_found']}")
            print(f"Results saved to: {args.output}")
        else:
            print(output)

    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
