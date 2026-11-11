import json
import re
import argparse
from pathlib import Path
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

OUTPUT_PATTERN = re.compile(
    r"(?:^|\s)--output(?:=|\s)|(?:^|\s)>\s*\S",
    re.IGNORECASE,
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


def analyze_record(record, index):
    """Flag suspicious patterns and preserve supporting evidence."""
    fields = flatten_record(record)
    searchable_text = "\n".join(
        f"{name}: {value}" for name, value in fields
    )

    tool_name = (
        get_value(record, "tool_name", "tool", "name", "method")
        or "unknown"
    ).lower()

    findings = []
    score = 0

   
    # Check path-like fields for parent-directory traversal.
transversal_detected = False

    for field_name, value in fields:
        path_field = any(
            word in field_name.lower()
            for word in (
                "path", "pathspec", "target_resource",
                "filename", "directory"
            )
        )

        if path_field and TRAVERSAL_PATTERN.search(value):

            findings.append({
                "category": "path_traversal_pattern",
                "evidence": (
                    "A parent-directory traversal pattern "
                    "was detected in a path-related field."
                ),
                "evidence_field": field_name,
                "evidence_record_index": index,
            })


            if not traversal_detected:
                score += 45
                traversal_detected = True



    # Check for potentially unsafe output arguments.
    tool_related = any(
        word in tool_name
        for word in ("git", "file", "filesystem", "shell", "exec")
    )

    if tool_related and OUTPUT_PATTERN.search(searchable_text):
        findings.append({
            "category": "suspicious_tool_argument",
            "evidence": (
                "A command/output-redirection-style argument "
                "appears in a tool-related record."
            ),
        })
        score += 25

    
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


    score = min(score, 100)

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

    for index, record in enumerate(records):
        task_id = get_value(
            record, "task_id", "session_id",
            "trace_id", "conversation_id"
        )

        if task_id:
            events_by_task[task_id].append((index, record))

    for alert in alerts:
        task_id = alert.get("task_id")
        alert_index = alert.get("record_index")

        if not task_id or alert_index is None:
            alert["correlation"] = {
                "status": "insufficient_identifiers",
                "note": "Cannot establish an event relationship."
            }
            continue

        related_events = events_by_task.get(task_id, [])

        earlier_sources = []

        for index, record in related_events:
            # Only consider events preceding the flagged action.
            if index >= alert_index:
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

    return {
        "tool_name": (
            "Group 6 Tool Output Provenance "
            "& Injection Risk Analyzer"
        ),
        "version": "0.1",
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
        ],
    }


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
    args = parser.parse_args()

    try:
        records = load_logs(args.input)
        report = analyze_logs(records)
        output = json.dumps(report, indent=2)

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
