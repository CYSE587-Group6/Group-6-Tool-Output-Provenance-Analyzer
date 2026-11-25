import json
import re
import argparse
import hashlib
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


def parse_logs(text):
    """Parse JSON objects, arrays, or JSON Lines."""

    text = text.lstrip("\ufeff")

    if not text.strip():
        raise ValueError("The log file is empty.")

    try:
        data = json.loads(text)

    except json.JSONDecodeError:
        records = []

        for line_number, line in enumerate(
            text.splitlines(), 1
        ):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: "
                    f"{error.msg}"
                ) from error

            if not isinstance(record, dict):
                raise ValueError(
                    f"Record on line {line_number} "
                    "must be a JSON object."
                )

            records.append(record)

        return records

    if isinstance(data, dict):
        for key in ("events", "records", "logs", "data"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            return [data]

    if isinstance(data, list):
        if not all(isinstance(item, dict) for item in data):
            raise ValueError(
                "Every log record must be a JSON object."
            )

        return data

    raise ValueError("Expected a JSON object or list.")


def load_logs(file_path):
    """Load log files using the shared parser."""

    text = Path(file_path).read_text(encoding="utf-8-sig")

    return parse_logs(text)



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


def assess_behavioral_injection(records, alerts):
    """Assess suspicious actions following external retrieval."""

    for alert in alerts:
        index = alert["record_index"]
        action = records[index]

        task_id = get_value(action, "task_id")
        session_id = get_value(action, "session_id")

        if not task_id or not session_id:
            continue

        suspicious_action = any(
            finding["category"] in {
                "path_containment_violation",
                "suspicious_tool_argument"
            }
            for finding in alert["findings"]
        )

        if not suspicious_action:
            continue

        for source_index, source in enumerate(records):

            if get_value(source, "task_id") != task_id:
                continue

            if get_value(source, "session_id") != session_id:
                continue

            try:
                earlier = int(source["seq"]) < int(action["seq"])
            except (KeyError, ValueError, TypeError):
                earlier = source_index < index

            if not earlier:
                continue

            if not get_fetch_content(source):
                continue

            if get_value(source, "result_status") != "success":
                continue

            alert["findings"].append({
                "category": "behavioral_injection_risk",
                "evidence": (
                    "A suspicious tool action followed external "
                    "content retrieval within the same task. "
                    "This indicates possible indirect prompt "
                    "injection risk, not confirmed causation."
                ),
                "source_record_index": source_index,
                "source_seq": source.get("seq"),
                "evidence_record_index": index,
                "evidence_field": "event_sequence"
            })

            alert["behavioral_adjustment"] = 15

            score = min(
                alert["heuristic_score"] + 15, 100
            )

            alert["heuristic_score"] = score

            if score >= 60:
                alert["risk"] = "HIGH"
            elif score >= 35:
                alert["risk"] = "MEDIUM"
            else:
                alert["risk"] = "LOW"

            break


def correlate_content_provenance(records, alerts):
    """Compare Fetch previews with later tool arguments."""

    for alert in alerts:
        index = alert["record_index"]
        action = records[index]

        task_id = get_value(action, "task_id")
        session_id = get_value(action, "session_id")

        if not task_id or not session_id:
            continue

        argument_fields = flatten_record(
            action.get("arguments", {})
        )

        for source_index, source in enumerate(records):

            if get_value(source, "task_id") != task_id:
                continue

            if get_value(source, "session_id") != session_id:
                continue

            try:
                earlier = int(source["seq"]) < int(action["seq"])
            except (KeyError, ValueError, TypeError):
                earlier = source_index < index

            if not earlier:
                continue

            if get_value(source, "result_status") != "success":
                continue

            preview = get_fetch_content(source)

            if not preview:
                continue

            normalized_preview = " ".join(
                preview.split()
            ).lower()

            for field_name, value in argument_fields:

                normalized_value = " ".join(
                    value.split()
                ).lower()

                # Require meaningful overlap rather than
                # matching common words or short flags.
                if len(normalized_value) < 12:
                    continue

                if normalized_value not in normalized_preview:
                    continue

                alert["findings"].append({
                    "category": "content_provenance_overlap",
                    "evidence": (
                        "A later tool argument matches content "
                        "in an earlier Fetch preview within "
                        "the same task and session. "
                        "This supports a possible provenance "
                        "relationship, not confirmed causation."
                    ),
                    "source_record_index": source_index,
                    "source_seq": source.get("seq"),
                    "evidence_record_index": index,
                    "evidence_field": f"arguments.{field_name}",
                    "matched_length": len(normalized_value)
                })

                alert["content_provenance_match"] = True
                break

            if alert.get("content_provenance_match"):
                break


def detect_unvetted_dependencies(records, alerts):
    """Detect dependency declarations linked to unvetted sources."""

    for index, record in enumerate(records):

        if get_value(record, "tool_name") != "write_file":
            continue

        arguments = record.get("arguments", {})

        path = str(arguments.get("path", ""))

        if posixpath.basename(path) != "package.json":
            continue

        try:
            manifest = json.loads(
                arguments.get("content", "")
            )
        except (ValueError, TypeError):
            continue

        if not isinstance(manifest, dict):
            continue

        dependencies = {}

        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies"
        ):
            entries = manifest.get(section, {})

            if isinstance(entries, dict):
                dependencies.update(entries)

        task_id = get_value(record, "task_id")
        session_id = get_value(record, "session_id")

        if not task_id or not session_id:
            continue

        for source_index, source in enumerate(records):

            if get_value(source, "task_id") != task_id:
                continue

            if get_value(source, "session_id") != session_id:
                continue

            try:
                earlier = int(source["seq"]) < int(record["seq"])
            except (KeyError, ValueError, TypeError):
                earlier = source_index < index

            if not earlier:
                continue

            if get_value(source, "result_status") != "success":
                continue

            preview = get_fetch_content(source).lower()

            if not preview:
                continue

            if not re.search(
                r"not present in|not listed in|not approved|unvetted",
                preview
            ):
                continue

            for dependency in dependencies:

                if not re.search(
                    r"(?<![\w-])"
                    + re.escape(dependency.lower())
                    + r"(?![\w-])",
                    preview
                ):
                    continue

                finding = {
                    "category": "unvetted_dependency_risk",
                    "evidence": (
                        f"Dependency '{dependency}' appears in "
                        "package.json and in an earlier Fetch "
                        "preview indicating an unvetted source."
                    ),
                    "source_record_index": source_index,
                    "source_seq": source.get("seq"),
                    "evidence_record_index": index,
                    "evidence_field": "arguments.content"
                }

                status = get_value(record, "result_status")
                score = 65 if status == "success" else 45

                existing = next(
                    (
                        alert for alert in alerts
                        if alert["record_index"] == index
                    ),
                    None
                )

                if existing:
                    existing["findings"].append(finding)
                    existing["heuristic_score"] = max(
                        existing["heuristic_score"], score
                    )
                    existing["risk"] = (
                        "HIGH"
                        if existing["heuristic_score"] >= 60
                        else "MEDIUM"
                    )
                else:
                    alerts.append({
                        **get_identity(record, index),
                        "risk": (
                            "HIGH" if score >= 60 else "MEDIUM"
                        ),
                        "heuristic_score": score,
                        "findings": [finding],
                        "review_recommendation": (
                            "Verify dependency approval against "
                            "the organization's trusted registry."
                        ),
                        "evidence_reference": {
                            "record_index": index,
                            "session_id": session_id,
                            "task_id": task_id,
                            "seq": record.get("seq")
                        }
                    })


def detect_suspicious_memory(records, alerts):
    """Detect Memory writes following out-of-scope reads."""

    for index, record in enumerate(records):

        if get_value(record, "tool_name") != "memory_set":
            continue

        task_id = get_value(record, "task_id")
        session_id = get_value(record, "session_id")

        if not task_id or not session_id:
            continue

        for source_alert in list(alerts):

            source_index = source_alert["record_index"]
            source = records[source_index]

            if get_value(source, "task_id") != task_id:
                continue

            if get_value(source, "session_id") != session_id:
                continue

            if get_value(source, "tool_name") not in {
                "git_show_worktree",
                "read_text_file",
                "read_file"
            }:
                continue

            if get_value(source, "result_status") != "success":
                continue

            try:
                earlier = int(source["seq"]) < int(record["seq"])
            except (KeyError, ValueError, TypeError):
                earlier = source_index < index

            if not earlier:
                continue

            if not any(
                finding["category"] == "path_containment_violation"
                for finding in source_alert["findings"]
            ):
                continue

            finding = {
                "category": "suspicious_memory_activity",
                "evidence": (
                    "A Memory write followed a successful "
                    "out-of-scope read within the same task "
                    "and session. Potential sensitive-data "
                    "retention requires investigation."
                ),
                "source_record_index": source_index,
                "source_seq": source.get("seq"),
                "evidence_record_index": index,
                "evidence_field": "event_sequence"
            }

            status = get_value(record, "result_status")
            score = 80 if status == "success" else 50

            existing = next(
                (
                    alert for alert in alerts
                    if alert["record_index"] == index
                ),
                None
            )

            if existing:
                existing["findings"].append(finding)
                existing["heuristic_score"] = max(
                    existing["heuristic_score"], score
                )
                existing["risk"] = (
                    "HIGH"
                    if existing["heuristic_score"] >= 60
                    else "MEDIUM"
                )
            else:
                alerts.append({
                    **get_identity(record, index),
                    "risk": (
                        "HIGH" if score >= 60 else "MEDIUM"
                    ),
                    "heuristic_score": score,
                    "findings": [finding],
                    "review_recommendation": (
                        "Investigate whether sensitive data "
                        "was retained in agent Memory."
                    ),
                    "evidence_reference": {
                        "record_index": index,
                        "session_id": session_id,
                        "task_id": task_id,
                        "seq": record.get("seq")
                    }
                })

            break
            
def redact_sensitive_data(value):
    """Redact common credential patterns from analysis outputs."""

    sensitive_keys = {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization",
        "client_secret",
        "private_key",
        "credentials"
    }

    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if str(key).lower().replace("-", "_")
                in sensitive_keys
                else redact_sensitive_data(item)
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            redact_sensitive_data(item)
            for item in value
        ]

    if isinstance(value, str):

        # Redact labeled credentials.
        value = re.sub(
            r"""(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)""",
            r"\1=[REDACTED]",
            value
        )

        # Redact Bearer authentication tokens.
        value = re.sub(
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
            "Bearer [REDACTED]",
            value
        )

        # Redact credentials embedded in connection URLs.
        value = re.sub(
            r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@",
            r"\1[REDACTED]@",
            value
        )

        # Redact private key blocks.
        value = re.sub(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z ]*PRIVATE KEY-----",
            "[REDACTED PRIVATE KEY]",
            value,
            flags=re.DOTALL
        )

    return value


def calculate_log_hash(records):
    """Generate a SHA-256 fingerprint of parsed log records."""

    serialized = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()

def analyze_logs(records):
    log_hash = calculate_log_hash(records)
    clean_records = [
        sanitize_record(record) for record in records
    ]
    
    alerts = []

    for index, record in enumerate(clean_records):
        alert = analyze_record(record, index)

        if alert:
            alerts.append(alert)

    detect_unvetted_dependencies(clean_records, alerts)

    detect_suspicious_memory(clean_records, alerts)

    correlate_events(clean_records, alerts)

    assess_behavioral_injection(clean_records, alerts)

    correlate_content_provenance(clean_records, alerts)

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
        "alerts": redact_sensitive_data(alerts),
         "log_integrity": {
            "algorithm": "SHA-256",
            "log_hash": log_hash,
            "hash_scope": "original_parsed_records"
        },
        "privacy_controls": {
            "redaction_enabled": True,
            "redaction_scope": "alert_outputs",
            "raw_logs_modified": False
        },
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
