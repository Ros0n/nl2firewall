"""Structural linter for CanonicalRule — advisory checks only."""

from __future__ import annotations
import logging
from app.models.ir import CanonicalRule, Protocol, LintResult, LintIssue, LintSeverity
from app.snmt.loader import get_active_snmt

logger = logging.getLogger(__name__)


def run_linter(rule: CanonicalRule | None) -> LintResult:
    if rule is None:
        return LintResult(issues=[LintIssue(
            severity=LintSeverity.ERROR, code="NULL_RULE", message="No rule provided"
        )])

    issues: list[LintIssue] = []
    snmt = get_active_snmt()

    # Sources / destinations
    if not rule.source_is_any and len(rule.sources) == 0:
        issues.append(LintIssue(severity=LintSeverity.ERROR, code="EMPTY_SOURCE",
                                message="sources[] is empty and source_is_any=False", field="sources"))
    if not rule.destination_is_any and len(rule.destinations) == 0:
        issues.append(LintIssue(severity=LintSeverity.ERROR, code="EMPTY_DESTINATION",
                                message="destinations[] empty and destination_is_any=False", field="destinations"))

    # Entity validation against SNMT
    if snmt:
        for ep in rule.sources:
            if not (snmt.get_entity(ep.entity_name) or snmt.get_entity_fuzzy(ep.entity_name)):
                issues.append(LintIssue(severity=LintSeverity.WARNING, code="UNKNOWN_SOURCE_ENTITY",
                                        message=f"'{ep.entity_name}' not found in loaded network context",
                                        field="sources"))
        for ep in rule.destinations:
            if not (snmt.get_entity(ep.entity_name) or snmt.get_entity_fuzzy(ep.entity_name)):
                issues.append(LintIssue(severity=LintSeverity.WARNING, code="UNKNOWN_DEST_ENTITY",
                                        message=f"'{ep.entity_name}' not found in loaded network context",
                                        field="destinations"))

    # Protocol consistency
    if rule.protocol == Protocol.ICMP and rule.dst_ports:
        issues.append(LintIssue(severity=LintSeverity.ERROR, code="ICMP_WITH_PORTS",
                                message="ICMP rules must not have dst_ports. Use icmp_type/icmp_code instead.",
                                field="dst_ports"))
    if rule.protocol == Protocol.IP and (rule.dst_ports or rule.src_ports):
        issues.append(LintIssue(severity=LintSeverity.ERROR, code="IP_WITH_PORTS",
                                message="Protocol 'ip' matches all traffic — cannot restrict ports. Use tcp or udp.",
                                field="protocol"))
    if rule.tcp_established and rule.protocol != Protocol.TCP:
        issues.append(LintIssue(severity=LintSeverity.ERROR, code="ESTABLISHED_NON_TCP",
                                message="tcp_established is only valid for TCP protocol", field="tcp_established"))

    # Port range validation
    seen_ports: set = set()
    for i, ps in enumerate(rule.dst_ports):
        if ps.port is not None and not (1 <= ps.port <= 65535):
            issues.append(LintIssue(severity=LintSeverity.ERROR, code="INVALID_PORT",
                                    message=f"dst_ports[{i}]: port {ps.port} out of range", field=f"dst_ports[{i}]"))
        key = (ps.operator, ps.port, ps.port_high)
        if key in seen_ports:
            issues.append(LintIssue(severity=LintSeverity.WARNING, code="DUPLICATE_PORT",
                                    message=f"dst_ports[{i}]: duplicate port spec", field=f"dst_ports[{i}]"))
        seen_ports.add(key)

    # Deployment interface
    if len(rule.interfaces) == 0:
        issues.append(LintIssue(severity=LintSeverity.WARNING, code="NO_INTERFACE",
                                message="interfaces[] is empty — compiler cannot deploy without a target interface",
                                field="interfaces"))

    # Confidence
    if rule.confidence < 0.7:
        issues.append(LintIssue(severity=LintSeverity.WARNING, code="LOW_CONFIDENCE",
                                message=f"LLM confidence {rule.confidence:.2f} below 0.7 — review carefully",
                                field="confidence"))

    # LLM-flagged ambiguities
    for a in rule.ambiguities:
        issues.append(LintIssue(severity=LintSeverity.WARNING, code="LLM_AMBIGUITY",
                                message=f"LLM flagged: {a}", field="ambiguities"))

    # Rule name format
    if not rule.rule_name or rule.rule_name.strip() == "":
        issues.append(LintIssue(severity=LintSeverity.WARNING, code="EMPTY_RULE_NAME",
                                message="rule_name is empty", field="rule_name"))

    # Rule count sanity
    count = rule.estimated_line_count()
    if count > 20:
        issues.append(LintIssue(severity=LintSeverity.WARNING, code="HIGH_LINE_COUNT",
                                message=f"Will generate {count} ACL lines — consider simplifying", field="dst_ports"))

    return LintResult(issues=issues)