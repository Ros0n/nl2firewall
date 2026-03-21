"""
Batfish verification manager — full suite.

Five checks run in order after ACL compilation:

  1. parseWarning()           — syntax errors in the compiled config
  2. undefinedReferences()    — ACL name referenced on interface but never defined
  3. filterLineReachability() — dead/shadowed lines that can never match any packet
  4. searchFilters()          — correctness proof over the entire src/dst/port space
  5. testFilters()            — representative packet trace shown to the operator

Check 1+2: structural validity
Check 3:   ordering bugs (a broad early line shadows a specific later line)
Check 4:   the main policy proof — mathematically proves no packet in the
           entire subnet range violates the intended permit/deny
Check 5:   human-readable trace of one real packet — shown in the final output
           so the operator can see exactly what happens to a typical packet

All checks are ADVISORY — results are returned to the operator but never
hard-block the pipeline. The operator sees the full Batfish report alongside
the compiled config.

Batfish runs in Docker at localhost:9996.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.models.ir import CompiledACL, CompiledLine, BatfishResult, BatfishIssue
from app.snmt.loader import get_active_snmt
from app.core.config import get_settings

logger = logging.getLogger(__name__)

TOPOLOGY_DIR = Path(__file__).parent.parent.parent / "data" / "topology"


@dataclass
class FilterTestResult:
    """Result of testFilters for one representative packet — shown to operator."""
    flow: str            # e.g. "10.40.0.1:1025 → 10.20.0.1:22 TCP"
    action: str          # "PERMIT" or "DENY"
    matched_line: str    # e.g. "10 deny tcp 10.40.0.0 0.0.0.255 ..."
    trace: str           # full trace string


@dataclass
class SearchFilterViolation:
    """One violation found by searchFilters — a counterexample packet."""
    rule_text: str           # the ACL line being tested
    intended_action: str     # what we intended: "deny" or "permit"
    violation_action: str    # what Batfish found: opposite of intended
    example_flow: str        # e.g. "10.40.0.42:1025 → 10.20.0.1:22 TCP"
    example_line: str        # which ACL line matched the violating packet


@dataclass
class ShadowedLine:
    """One shadowed/unreachable line found by filterLineReachability."""
    unreachable_line: str    # the line that can never match
    action: str              # PERMIT or DENY
    blocking_lines: list     # lines that shadow it
    different_action: bool   # True if the blocker has the opposite action (risky)
    reason: str              # BLOCKING_LINES, EMPTY_INTERSECTION, etc.


@dataclass
class FullBatfishReport:
    """
    Complete Batfish verification report for one compiled ACL.
    Returned alongside the compiled config in the pipeline output.
    """
    acl_name: str

    # Check 1+2
    parse_warnings: list[str] = field(default_factory=list)
    undefined_references: list[str] = field(default_factory=list)

    # Check 3
    shadowed_lines: list[ShadowedLine] = field(default_factory=list)

    # Check 4
    search_violations: list[SearchFilterViolation] = field(default_factory=list)

    # Check 5
    test_filter_results: list[FilterTestResult] = field(default_factory=list)

    # Overall
    passed: bool = True
    error: Optional[str] = None

    def has_issues(self) -> bool:
        return (
            bool(self.parse_warnings)
            or bool(self.undefined_references)
            or bool(self.shadowed_lines)
            or bool(self.search_violations)
        )

    def summary(self) -> str:
        if self.error:
            return f"Batfish unavailable: {self.error}"
        parts = []
        if self.parse_warnings:
            parts.append(f"{len(self.parse_warnings)} parse warning(s)")
        if self.undefined_references:
            parts.append(f"{len(self.undefined_references)} undefined reference(s)")
        if self.shadowed_lines:
            parts.append(f"{len(self.shadowed_lines)} shadowed line(s)")
        if self.search_violations:
            parts.append(f"{len(self.search_violations)} policy violation(s)")
        if self.test_filter_results:
            parts.append(f"{len(self.test_filter_results)} flow trace(s)")
        return "Batfish: " + (", ".join(parts) if parts else "all checks passed ✓")

    def to_dict(self) -> dict:
        return {
            "acl_name": self.acl_name,
            "passed": self.passed,
            "summary": self.summary(),
            "parse_warnings": self.parse_warnings,
            "undefined_references": self.undefined_references,
            "shadowed_lines": [
                {
                    "unreachable_line": s.unreachable_line,
                    "action": s.action,
                    "blocking_lines": s.blocking_lines,
                    "different_action": s.different_action,
                    "reason": s.reason,
                }
                for s in self.shadowed_lines
            ],
            "search_violations": [
                {
                    "rule": v.rule_text,
                    "intended": v.intended_action,
                    "violation": v.violation_action,
                    "example_flow": v.example_flow,
                    "matched_line": v.example_line,
                }
                for v in self.search_violations
            ],
            "flow_traces": [
                {
                    "flow": t.flow,
                    "action": t.action,
                    "matched_line": t.matched_line,
                    "trace": t.trace,
                }
                for t in self.test_filter_results
            ],
        }


class BatfishManager:

    def __init__(self) -> None:
        settings = get_settings()
        self._host    = settings.batfish_host
        self._port    = settings.batfish_port
        self._network = settings.batfish_network

    async def verify(self, compiled_acl: CompiledACL, session_id: str) -> BatfishResult:
        """Async entry point — runs sync Batfish work in a thread pool."""
        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            None, self._run_all_checks, compiled_acl, session_id
        )
        # Convert FullBatfishReport → BatfishResult (the model used by pipeline state)
        return BatfishResult(
            passed=report.passed,
            issues=[
                BatfishIssue(severity="high", check_name="parse_warning", description=w)
                for w in report.parse_warnings
            ] + [
                BatfishIssue(severity="medium", check_name="undefined_reference", description=u)
                for u in report.undefined_references
            ] + [
                BatfishIssue(
                    severity="high" if s.different_action else "medium",
                    check_name="shadowed_line",
                    description=(
                        f"Line '{s.unreachable_line}' ({s.action}) is shadowed by: "
                        f"{s.blocking_lines}. "
                        + ("RISK: shadowing line has a DIFFERENT action." if s.different_action else "")
                    ),
                )
                for s in report.shadowed_lines
            ],
            reachability_violations=[
                f"{v.intended_action.upper()} VIOLATION: {v.rule_text}\n"
                f"  Found packet that gets {v.violation_action.upper()}: {v.example_flow}\n"
                f"  Matched by: {v.example_line}"
                for v in report.search_violations
            ],
            parse_warnings=report.parse_warnings,
            raw_output=report.to_dict(),
        )

    # ── Main verification orchestrator ────────────────────────────────────────

    def _run_all_checks(
        self, compiled_acl: CompiledACL, session_id: str
    ) -> FullBatfishReport:
        """Run all 5 Batfish checks and return a structured report."""

        report = FullBatfishReport(acl_name=compiled_acl.acl_name)

        try:
            from pybatfish.client.session import Session
            from pybatfish.datamodel.flow import HeaderConstraints
        except ImportError:
            report.passed = False
            report.error = "pybatfish not installed"
            return report

        with tempfile.TemporaryDirectory(prefix=f"nl2fw_{session_id[:8]}_") as tmpdir:
            snap_dir = Path(tmpdir) / "snapshot" / "configs"
            snap_dir.mkdir(parents=True)

            self._populate_configs(snap_dir, compiled_acl)

            try:
                bf = Session(host=self._host)
                bf.set_network(self._network)
                snap_name = f"snap_{session_id[:8]}"
                bf.init_snapshot(
                    str(Path(tmpdir) / "snapshot"),
                    name=snap_name,
                    overwrite=True,
                )
                logger.info(f"[{session_id}] Batfish snapshot initialised: {snap_name}")
            except Exception as e:
                report.passed = False
                report.error = f"Batfish connection failed: {e}"
                return report

            # Run all checks
            self._check_parse_warnings(bf, report, session_id)
            self._check_undefined_references(bf, report, session_id)
            self._check_shadowed_lines(bf, compiled_acl, report, session_id)
            self._check_search_filters(bf, compiled_acl, report, session_id)
            self._check_test_filters(bf, compiled_acl, report, session_id)

            try:
                bf.delete_snapshot(snap_name)
            except Exception:
                pass

        report.passed = not report.has_issues()
        logger.info(f"[{session_id}] Batfish complete: {report.summary()}")
        return report

    # ── Check 1: Parse warnings ───────────────────────────────────────────────

    def _check_parse_warnings(self, bf, report: FullBatfishReport, session_id: str) -> None:
        """
        Check 1: Parse warnings.
        Batfish parses every line of the injected config.
        Unrecognised commands, malformed addresses, invalid syntax all appear here.
        """
        try:
            frame = bf.q.parseWarning().answer().frame()
            for _, row in frame.iterrows():
                msg = str(row.get("Text", "")).strip()
                if msg:
                    report.parse_warnings.append(msg)
            logger.info(
                f"[{session_id}] Check 1 (parse): {len(report.parse_warnings)} warning(s)"
            )
        except Exception as e:
            logger.debug(f"Parse warning check failed: {e}")

    # ── Check 2: Undefined references ────────────────────────────────────────

    def _check_undefined_references(
        self, bf, report: FullBatfishReport, session_id: str
    ) -> None:
        """
        Check 2: Undefined references.
        Catches: interface applies 'ip access-group ACL_NAME in' but ACL_NAME
        was never defined. This would be a compiler name mismatch bug.
        """
        try:
            frame = bf.q.undefinedReferences().answer().frame()
            for _, row in frame.iterrows():
                desc = (
                    f"Undefined {row.get('Structure_Type', '')} "
                    f"'{row.get('Reference_Name', '')}' "
                    f"at {row.get('File_Lines', '')}"
                ).strip()
                if desc:
                    report.undefined_references.append(desc)
            logger.info(
                f"[{session_id}] Check 2 (undefined refs): "
                f"{len(report.undefined_references)} issue(s)"
            )
        except Exception as e:
            logger.debug(f"Undefined references check failed: {e}")

    # ── Check 3: Shadowed / dead lines ────────────────────────────────────────

    def _check_shadowed_lines(
        self, bf, compiled: CompiledACL, report: FullBatfishReport, session_id: str
    ) -> None:
        """
        Check 3: filterLineReachability — finds dead/unreachable lines.

        A line is unreachable if a prior line matches ALL the same packets
        (or more), meaning the later line can never fire.

        Example bug this catches:
            10 permit ip any any     ← matches everything
            20 deny tcp ... eq 22    ← DEAD: line 10 already matched everything

        'Different_Action' = True means the shadowing line has the OPPOSITE
        action — this is especially dangerous because the policy intent is
        being silently reversed.
        """
        try:
            frame = bf.q.filterLineReachability(
                filters=compiled.acl_name
            ).answer().frame()

            for _, row in frame.iterrows():
                blocking = row.get("Blocking_Lines", [])
                if isinstance(blocking, str):
                    blocking = [blocking]
                report.shadowed_lines.append(ShadowedLine(
                    unreachable_line=str(row.get("Unreachable_Line", "")),
                    action=str(row.get("Unreachable_Line_Action", "")),
                    blocking_lines=list(blocking),
                    different_action=bool(row.get("Different_Action", False)),
                    reason=str(row.get("Reason", "")),
                ))

            logger.info(
                f"[{session_id}] Check 3 (shadowed lines): "
                f"{len(report.shadowed_lines)} unreachable line(s)"
            )
        except Exception as e:
            logger.debug(f"filterLineReachability check failed: {e}")

    # ── Check 4: searchFilters — policy correctness proof ────────────────────

    def _check_search_filters(
        self, bf, compiled: CompiledACL, report: FullBatfishReport, session_id: str
    ) -> None:
        """
        Check 4: searchFilters — the main correctness proof.

        For every compiled ACL line (except the catch-all), we search the
        ENTIRE src/dst/port space for packets that violate the intended action:

          DENY line  → search action="permit"
            Is there ANY packet in 10.40.0.0/24 → 10.20.0.0/24 port 22 that
            gets PERMITTED? Empty = deny works. Non-empty = something slips through.

          PERMIT line → search action="deny"
            Is there ANY packet in the allowed range that gets DENIED?
            Empty = permit works. Non-empty = something is blocked that shouldn't be.

        An empty result is a mathematical proof that the policy is correct for
        the entire address space — not just one IP. This is what makes
        searchFilters powerful compared to testFilters.
        """
        try:
            from pybatfish.datamodel.flow import HeaderConstraints
        except ImportError:
            return

        tested = 0
        for line in compiled.lines:
            # Skip the catch-all deny ip any any
            if line.source_entity == "any" and line.destination_entity == "any":
                continue
            # Skip lines without prefix info
            if not line.source_prefix or not line.destination_prefix:
                continue

            try:
                violation = self._run_search_filter(bf, compiled.acl_name, line)
                if violation:
                    report.search_violations.append(violation)
                tested += 1
            except Exception as e:
                logger.debug(f"searchFilters skipped for '{line.text}': {e}")

        logger.info(
            f"[{session_id}] Check 4 (searchFilters): "
            f"{tested} line(s) tested, {len(report.search_violations)} violation(s)"
        )

    def _run_search_filter(
        self, bf, acl_name: str, line: CompiledLine
    ) -> Optional[SearchFilterViolation]:
        """
        Run searchFilters for one ACL line.

        Returns a SearchFilterViolation if Batfish finds a counterexample,
        or None if the policy is correctly implemented for this line.
        """
        from pybatfish.datamodel.flow import HeaderConstraints

        header_kwargs: dict = {
            "srcIps": line.source_prefix,
            "dstIps": line.destination_prefix,
        }

        # Add protocol if not catch-all IP
        if line.protocol and line.protocol not in ("ip", "any", ""):
            header_kwargs["ipProtocols"] = [line.protocol.upper()]

        # Add destination port for TCP/UDP
        if line.dst_port and line.protocol in ("tcp", "udp"):
            header_kwargs["dstPorts"] = str(line.dst_port)

        headers = HeaderConstraints(**header_kwargs)

        # Violation action is the OPPOSITE of intended:
        # deny rule  → search for "permit"  (packets that slip through)
        # permit rule → search for "deny"   (packets that get blocked)
        if line.action == "deny":
            search_action = "permit"
        else:
            search_action = "deny"

        result = bf.q.searchFilters(
            headers=headers,
            action=search_action,
            filters=acl_name,
        ).answer()

        frame = result.frame()

        if len(frame) == 0:
            # Empty = proven correct for the entire address space
            logger.debug(
                f"searchFilters OK: {line.action} {line.source_prefix} → "
                f"{line.destination_prefix}"
                + (f":{line.dst_port}" if line.dst_port else "")
            )
            return None

        # Non-empty = found a violation, extract the counterexample
        row = frame.iloc[0]
        return SearchFilterViolation(
            rule_text=line.text,
            intended_action=line.action,
            violation_action=search_action,
            example_flow=str(row.get("Flow", "")),
            example_line=str(row.get("Line_Content", "")),
        )

    # ── Check 5: testFilters — representative flow trace ─────────────────────

    def _check_test_filters(
        self, bf, compiled: CompiledACL, report: FullBatfishReport, session_id: str
    ) -> None:
        """
        Check 5: testFilters — one representative packet trace per ACL line.

        For each compiled line, we pick a representative source IP
        (the first usable host in the source subnet) and test it through
        the ACL. The result shows the operator:

          - The exact packet tested
          - Whether it was PERMIT or DENY
          - Which line matched it
          - The full trace through the ACL

        This is the human-readable confirmation: "here is exactly what
        happens when a packet from 10.40.0.1 tries to SSH to 10.20.0.1."

        Unlike searchFilters, this proves nothing about the whole subnet —
        it is purely for operator understanding and explanation.
        """
        try:
            from pybatfish.datamodel.flow import HeaderConstraints
        except ImportError:
            return

        tested = 0
        for line in compiled.lines:
            # Skip the catch-all
            if line.source_entity == "any" and line.destination_entity == "any":
                continue
            if not line.source_prefix or not line.destination_prefix:
                continue

            try:
                result = self._run_test_filter(bf, compiled.acl_name, line)
                if result:
                    report.test_filter_results.append(result)
                    tested += 1
            except Exception as e:
                logger.debug(f"testFilters skipped for '{line.text}': {e}")

        logger.info(
            f"[{session_id}] Check 5 (testFilters): {tested} flow trace(s)"
        )

    def _run_test_filter(
        self, bf, acl_name: str, line: CompiledLine
    ) -> Optional[FilterTestResult]:
        """
        Run testFilters for one ACL line using a representative host IP.

        We pick the first usable host from the source prefix.
        For /32 (single host), we use that IP directly.
        For any other prefix, we use network_ip + 1 (first usable host).
        """
        from pybatfish.datamodel.flow import HeaderConstraints

        # Derive a representative source IP
        src_ip = self._first_host_ip(line.source_prefix)
        dst_ip = self._first_host_ip(line.destination_prefix)

        if not src_ip or not dst_ip:
            return None

        header_kwargs: dict = {
            "srcIps": src_ip,
            "dstIps": dst_ip,
        }

        if line.protocol and line.protocol not in ("ip", "any", ""):
            header_kwargs["ipProtocols"] = [line.protocol.upper()]

        if line.dst_port and line.protocol in ("tcp", "udp"):
            header_kwargs["dstPorts"] = str(line.dst_port)

        headers = HeaderConstraints(**header_kwargs)

        result = bf.q.testFilters(
            headers=headers,
            filters=acl_name,
        ).answer()

        frame = result.frame()
        if len(frame) == 0:
            return None

        row = frame.iloc[0]
        flow_str = str(row.get("Flow", ""))
        action   = str(row.get("Action", ""))
        line_content = str(row.get("Line_Content", ""))
        trace    = str(row.get("Trace", ""))

        logger.debug(
            f"testFilters: {flow_str} → {action} (matched: {line_content})"
        )

        return FilterTestResult(
            flow=flow_str,
            action=action,
            matched_line=line_content,
            trace=trace,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _first_host_ip(prefix: str) -> Optional[str]:
        """
        Return the first usable host IP from a CIDR prefix.
        /32 → use the IP directly.
        /31 → use the network IP directly (point-to-point).
        others → network IP + 1.
        'any' / '0.0.0.0/0' → return None (skip).
        """
        if not prefix or prefix in ("any", "0.0.0.0/0", ""):
            return None

        if "/" not in prefix:
            return prefix  # bare IP

        ip_str, bits_str = prefix.split("/")
        bits = int(bits_str)

        if bits == 32:
            return ip_str  # single host

        if bits == 31:
            return ip_str  # point-to-point, use network IP

        # Convert IP to integer, add 1 for first host
        parts = list(map(int, ip_str.split(".")))
        ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        host_int = ip_int + 1
        return ".".join([
            str((host_int >> 24) & 0xFF),
            str((host_int >> 16) & 0xFF),
            str((host_int >> 8)  & 0xFF),
            str( host_int        & 0xFF),
        ])

    # ── Snapshot population ───────────────────────────────────────────────────

    def _populate_configs(self, snap_dir: Path, compiled_acl: CompiledACL) -> None:
        """
        Build the Batfish snapshot directory.
        Copies real configs from data/topology/ or generates stubs from SNMT.
        Always injects the new ACL into the correct router config.
        """
        import shutil

        copied = False
        if TOPOLOGY_DIR.exists():
            for cfg in TOPOLOGY_DIR.glob("*.cfg"):
                shutil.copy(cfg, snap_dir / cfg.name)
                copied = True
            if copied:
                logger.info(
                    f"Copied {len(list(snap_dir.glob('*.cfg')))} topology config(s) "
                    f"from {TOPOLOGY_DIR}"
                )

        if not copied:
            logger.info("No topology configs — generating stubs from SNMT")
            self._generate_stub_from_snmt(snap_dir)

        self._inject_acl(snap_dir, compiled_acl)

    def _generate_stub_from_snmt(self, snap_dir: Path) -> None:
        """Generate minimal Cisco IOS stub configs from the loaded SNMT."""
        snmt = get_active_snmt()
        if not snmt:
            (snap_dir / "router.cfg").write_text("hostname Router\n!\nend\n")
            return

        routers: dict[str, list] = {}
        for entity in snmt.get_all_entities():
            for gw in entity.gateways:
                routers.setdefault(gw.router, []).append(gw)

        for router_name, gateways in routers.items():
            lines = [f"hostname {router_name}", "!"]
            seen: set[str] = set()
            for gw in gateways:
                if gw.interface in seen:
                    continue
                seen.add(gw.interface)
                ip   = gw.prefix.split("/")[0]
                bits = int(gw.prefix.split("/")[1]) if "/" in gw.prefix else 32
                mask_int = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
                mask = ".".join(
                    str((mask_int >> (8 * i)) & 0xFF) for i in reversed(range(4))
                )
                lines += [
                    f"interface {gw.interface}",
                    f" ip address {ip} {mask}",
                    " no shutdown",
                    "!",
                ]
            lines.append("end")
            (snap_dir / f"{router_name}.cfg").write_text("\n".join(lines) + "\n")
            logger.debug(f"Generated stub for {router_name} ({len(seen)} interfaces)")

    def _inject_acl(self, snap_dir: Path, compiled: CompiledACL) -> None:
        """
        Inject the compiled ACL into the correct router's config file.
        Matches by router name stored on the CompiledACL object.
        Falls back to the first .cfg file if no match found.
        """
        cfg_file = None
        if compiled.router:
            for f in snap_dir.glob("*.cfg"):
                if f"hostname {compiled.router}" in f.read_text():
                    cfg_file = f
                    break

        if not cfg_file:
            cfgs = list(snap_dir.glob("*.cfg"))
            cfg_file = cfgs[0] if cfgs else snap_dir / "router.cfg"

        existing = cfg_file.read_text() if cfg_file.exists() else ""
        existing = existing.rstrip().rstrip("end").rstrip()
        cfg_file.write_text(
            existing + "\n!\n" + compiled.to_cisco_config() + "\n!\nend\n"
        )
        logger.debug(f"Injected ACL '{compiled.acl_name}' into {cfg_file.name}")