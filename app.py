
import json
import streamlit as st
from datetime import datetime, timezone

from analyzer import (
    analyze_logs,
    redact_sensitive_data,
    parse_logs
)

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
    """Parse uploaded logs using the shared analyzer parser."""

    text = file.getvalue().decode("utf-8-sig")

    return parse_logs(text)

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
        log_hash = report["log_integrity"]["log_hash"]

    if "decisions" not in st.session_state:
        st.session_state.decisions = {}

    st.sidebar.header("Review Governance")

    reviewer_id = st.sidebar.text_input(
        "Reviewer ID",
        placeholder="Enter reviewer identifier",
        key=f"reviewer_{log_hash}",
    )

    st.sidebar.caption("SHA-256 Log Fingerprint")
    st.sidebar.code(log_hash, language=None)

    st.sidebar.caption(
        "Reviewer identifiers are self-reported."
    )

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

                                review_key = f"{log_hash}_{record_index}"

                decision_key = f"decision_{review_key}"
                notes_key = f"notes_{review_key}"

                saved_review = st.session_state.decisions.get(
                    review_key, {}
                )

                decision_options = [
                    "Pending", "Approve", "Investigate", "Hold"
                ]

                decision = st.selectbox(
                    "Review decision",
                    decision_options,
                    index=decision_options.index(
                        saved_review.get("decision", "Pending")
                    ),
                    key=decision_key,
                )

                notes = st.text_area(
                    "Reviewer notes",
                    value=saved_review.get("reviewer_notes", ""),
                    key=notes_key,
                    placeholder="Document the reason for this decision.",
                )

                if st.button(
                    "Save Review Decision",
                    key=f"save_{review_key}",
                ):
                    if not reviewer_id.strip():
                        st.error("Enter a reviewer ID before saving.")

                    elif decision == "Pending":
                        st.error("Select a review decision before saving.")

                    elif not notes.strip():
                        st.error("Document the reason for your decision.")

                    else:
                        st.session_state.decisions[review_key] = {
                            "log_hash": log_hash,
                            "record_index": record_index,
                            "evidence_reference": alert.get(
                                "evidence_reference", {}
                            ),
                            "tool_name": tool,
                            "risk": risk,
                            "score": score,
                            "decision": decision,
                            "reviewer_id": reviewer_id.strip(),
                            "reviewed_at_utc": datetime.now(
                                timezone.utc
                            ).isoformat(),
                            "reviewer_notes": redact_sensitive_data(
                                notes.strip()
                            ),
                        }

                        st.success("Review decision saved.")

                saved_review = st.session_state.decisions.get(
                    review_key, {}
                )

                if saved_review:
                    st.caption(
                        f"Saved decision: "
                        f"{saved_review['decision']} | "
                        f"Reviewer: "
                        f"{saved_review['reviewer_id']} | "
                        f"UTC: "
                        f"{saved_review['reviewed_at_utc']}"
                    )

    st.subheader("Export Results")

    st.download_button(
        "Download Analysis JSON",
        data=json.dumps(report, indent=2),
        file_name="analysis_results.json",
        mime="application/json",
    )

       if alerts:
        decisions = [
            st.session_state.decisions[
                f"{log_hash}_{alert['record_index']}"
            ]
            for alert in alerts
            if f"{log_hash}_{alert['record_index']}"
            in st.session_state.decisions
        ]

        review_report = {
            "log_hash": log_hash,
            "hash_algorithm": "SHA-256",
            "records_analyzed": report["records_analyzed"],
            "alerts_found": report["alerts_found"],
            "reviews_completed": len(decisions),
            "reviews_pending": len(alerts) - len(decisions),
            "review_decisions": decisions,
        }

        st.download_button(
            "Download Security Review Decisions",
            data=json.dumps(
                redact_sensitive_data(review_report),
                indent=2
            ),
            file_name="security_review_decisions.json",
            mime="application/json",
            disabled=not decisions,
        )

       st.caption(
        "Saved review decisions are associated with the "
        "analyzed log fingerprint, reviewer identifier, "
        "and UTC timestamp. Decisions remain in the current "
        "application session and can be exported. "
        "Reviewer identity is self-reported. "
        "No decisions are sent to ADOP."
    )
else:
    st.write("Upload a log file to begin security analysis.")
