
import json
import streamlit as st

from analyzer import analyze_logs

st.set_page_config(
    page_title="Group 6 Security Review",
    page_icon="🛡️",
    layout="wide",
)

st.title("Tool Output Provenance & Injection Risk Analyzer")
st.caption("Group 6 | PoC v0.5 | Passive Static Analysis")

st.info(
    "Decision-support only. This tool does not block "
    "or modify ADOP operations."
)

uploaded_file = st.file_uploader(
    "Upload an ADOP-derived JSON or JSONL log",
    type=["json", "jsonl"],
)


def parse_uploaded_logs(file):
    text = file.getvalue().decode("utf-8-sig")

    try:
        data = json.loads(text)
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
            if not isinstance(record, dict):
                raise ValueError("Each JSONL record must be an object.")
            records.append(record)
        return records

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

    raise ValueError("Expected a JSON object or list.")


if uploaded_file is not None:
    try:
        records = parse_uploaded_logs(uploaded_file)
        report = analyze_logs(records)
    except (ValueError, UnicodeDecodeError) as error:
        st.error(f"Unable to analyze file: {error}")
        st.stop()

    alerts = sorted(
        report["alerts"],
        key=lambda item: item["heuristic_score"],
        reverse=True,
    )

    high_count = sum(a["risk"] == "HIGH" for a in alerts)

    st.subheader("Analysis Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Records Analyzed", report["records_analyzed"])
    col2.metric("Alerts Found", report["alerts_found"])
    col3.metric("High-Risk Alerts", high_count)

    if not alerts:
        st.success("No suspicious activity detected by current rules.")
    else:
        st.subheader("Ranked Security Alerts")

        for rank, alert in enumerate(alerts, 1):
            score = alert["heuristic_score"]
            risk = alert["risk"]
            tool = alert["tool_name"]
            record_index = alert["record_index"]
            correlation = alert.get("correlation", {})

            with st.expander(
                f"#{rank} | {tool} | {risk} | Score: {score}",
                expanded=(rank == 1),
            ):
                st.write(f"**Risk level:** {risk}")
                st.write(f"**Heuristic score:** {score}/100")
                st.write(f"**Record index:** {record_index}")
                st.write(
                    f"**Task ID:** {alert.get('task_id') or 'Unavailable'}"
                )
                st.write(
                    f"**Timestamp:** "
                    f"{alert.get('timestamp') or 'Unavailable'}"
                )

                st.markdown("#### Detection Evidence")
                for finding in alert.get("findings", []):
                    st.write(
                        f"**{finding['category']}** — "
                        f"{finding['evidence']}"
                    )

                st.markdown("#### Provenance Assessment")
                status = correlation.get("status", "unknown")
                st.write(f"**Correlation status:** {status}")
                st.write(correlation.get("note", "No context available."))

                source_events = correlation.get(
                    "possible_source_events", []
                )
                st.write(
                    f"**Earlier same-task source events:** "
                    f"{len(source_events)}"
                )

                for source in source_events:
                    st.write(
                        f"- Record {source['record_index']}: "
                        f"{source['tool_name']} | "
                        f"Suspicious preview: "
                        f"{source['suspicious_content_detected']}"
                    )

                st.write(
                    "**Earlier cross-task session sources:** "
                    f"{correlation.get('same_session_source_count', 0)}"
                )

                st.warning(
                    "Correlation does not establish causation. "
                    "Risk scores are heuristic indicators."
                )

                st.markdown("#### Security Lead Decision")

                decision_key = f"decision_{record_index}"
                notes_key = f"notes_{record_index}"

                decision = st.selectbox(
                    "Review decision",
                    ["Pending", "Approve", "Investigate", "Hold"],
                    key=decision_key,
                )

                notes = st.text_area(
                    "Reviewer notes",
                    key=notes_key,
                    placeholder="Document the reason for this decision.",
                )

                if "decisions" not in st.session_state:
                    st.session_state.decisions = {}

                st.session_state.decisions[str(record_index)] = {
                    "tool_name": tool,
                    "risk": risk,
                    "score": score,
                    "decision": decision,
                    "reviewer_notes": notes,
                }

    st.subheader("Export Results")

    st.download_button(
        "Download Analysis JSON",
        data=json.dumps(report, indent=2),
        file_name="analysis_results.json",
        mime="application/json",
    )

    if alerts:
        decisions = {
            str(alert["record_index"]): st.session_state.get(
                "decisions", {}
            ).get(str(alert["record_index"]), {})
            for alert in alerts
        }

        st.download_button(
            "Download Security Review Decisions",
            data=json.dumps(decisions, indent=2),
            file_name="security_review_decisions.json",
            mime="application/json",
        )

    st.caption(
        "Review decisions are recorded in the current session "
        "and can be exported. They are not sent to ADOP."
    )
else:
    st.write("Upload a log file to begin security analysis.")
