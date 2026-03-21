"""
Cisco IOS Extended ACL Compiler.

Implements BaseCompiler for Cisco IOS / IOS-XE using Named ACLs
(ip access-list extended NAME) — the preferred modern style.

Enumeration: src[] × dst[] × dst_ports[] → N individual ACL lines.
Wildcard masks computed arithmetically from CIDR prefix length.
REJECT action mapped to 'deny' (IOS has no reject; ASA compiler would differ).

Designed to be one concrete implementation of BaseCompiler.
Adding Juniper/PaloAlto means adding a new subclass — IR never changes.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod

from app.models.ir import (
    CanonicalRule, Action, Protocol, Direction, PortOperator,
    CompiledACL, CompiledLine, InterfaceTarget, TimeRange,
)
from app.snmt.loader import SNMTLoader

logger = logging.getLogger(__name__)


# ─── Base compiler (abstract) ─────────────────────────────────────────────────

class BaseCompiler(ABC):
    """
    Abstract base for all vendor compilers.
    Subclasses receive a CanonicalRule and produce vendor-specific config text.
    The IR is never modified — only the output format changes per vendor.
    """

    def __init__(self, snmt: SNMTLoader) -> None:
        self._snmt = snmt

    @abstractmethod
    def compile(self, rule: CanonicalRule) -> CompiledACL:
        """Compile a CanonicalRule → vendor-specific CompiledACL."""
        ...

    @abstractmethod
    def vendor_name(self) -> str:
        """Return the vendor/platform name, e.g. 'cisco_ios'."""
        ...


# ─── Cisco IOS helpers ────────────────────────────────────────────────────────

def _prefix_to_wildcard(prefix: str) -> str:
    """
    Arithmetically derive a Cisco wildcard mask from a CIDR prefix.
    Works for any network — no hardcoded addresses.
    """
    if "/" not in prefix:
        return "0.0.0.0"
    bits = int(prefix.split("/")[1])
    if bits == 32: return "0.0.0.0"
    if bits == 0:  return "255.255.255.255"
    mask = (0xFFFFFFFF >> bits) & 0xFFFFFFFF
    return ".".join(str((mask >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def _fmt_addr(prefix: str) -> str:
    """
    Format any address/prefix for Cisco IOS ACL syntax.
      any / 0.0.0.0/0  → 'any'
      /32              → 'host X.X.X.X'
      other CIDR       → 'X.X.X.X <wildcard>'
    """
    if prefix in ("any", "0.0.0.0/0", ""):
        return "any"
    ip, bits = (prefix.split("/")[0], int(prefix.split("/")[1])) \
               if "/" in prefix else (prefix, 32)
    if bits == 0:  return "any"
    if bits == 32: return f"host {ip}"
    return f"{ip} {_prefix_to_wildcard(prefix)}"


def _fmt_port(port_specs: list, side: str = "dst") -> str:
    """
    Format a list of PortSpec into Cisco IOS port qualifier string.
    Called separately for source and destination ports.
    Returns empty string when no restriction (any).
    Single spec: returns 'eq 80', 'range 1024 65535', 'gt 1023', etc.
    Multiple specs: not directly supported in one ACL line — caller must enumerate.
    """
    if not port_specs:
        return ""
    ps = port_specs[0]
    if ps.is_any or ps.operator == PortOperator.ANY:
        return ""
    op = ps.operator.value
    if ps.operator == PortOperator.RANGE:
        return f"{op} {ps.port} {ps.port_high}"
    return f"{op} {ps.port}"


def _acl_name_for_interface(interface: str, direction: str) -> str:
    """
    Generate a clean ACL name from an interface name and direction.
    e.g. 'GigabitEthernet0/0/1.40' + 'in' → 'ACL_Gi0_0_1_40_IN'
    Deterministic — same interface always gets same name.
    """
    # Shorten common interface prefixes
    short = interface
    for long, abbr in [
        ("GigabitEthernet", "Gi"),
        ("FastEthernet",    "Fa"),
        ("TenGigabitEthernet", "Te"),
        ("Ethernet",        "Et"),
        ("Loopback",        "Lo"),
        ("Vlan",            "Vl"),
        ("Port-channel",    "Po"),
    ]:
        short = short.replace(long, abbr)

    # Replace non-alphanumeric chars with underscores
    clean = re.sub(r"[^a-zA-Z0-9]", "_", short).strip("_")
    return f"ACL_{clean}_{direction.upper()}"


def _build_time_range_block(tr: TimeRange) -> str:
    """Render a Cisco IOS time-range config block."""
    lines = [f"time-range {tr.name}"]
    if tr.type == "absolute":
        start = f"start {tr.time_start}" if tr.time_start else ""
        end   = f"end {tr.time_end}"     if tr.time_end   else ""
        lines.append(f" absolute {start} {end}".strip())
    else:  # periodic
        days_str = " ".join(tr.days) if tr.days else "daily"
        time_str = ""
        if tr.time_start and tr.time_end:
            time_str = f" {tr.time_start} to {tr.time_end}"
        lines.append(f" periodic {days_str}{time_str}")
    return "\n".join(lines)


# ─── Cisco IOS compiler ───────────────────────────────────────────────────────

class CiscoIOSCompiler(BaseCompiler):
    """
    Compiles CanonicalRule → Cisco IOS named extended ACL config.

    Output style:
        ip access-list extended ACL_Gi0_0_1_40_IN
         permit tcp 192.168.10.0 0.0.0.255 10.0.1.0 0.0.0.255 eq 443
         deny   ip any any
        !
        interface GigabitEthernet0/0/1.40
         ip access-group ACL_Gi0_0_1_40_IN in

    Named ACLs are used exclusively (modern Cisco best practice).
    REJECT is mapped to 'deny' (IOS has no reject primitive).
    """

    def vendor_name(self) -> str:
        return "cisco_ios"

    def compile(self, rule: CanonicalRule) -> CompiledACL:
        """Main compilation entry point."""

        # Determine deployment interface(s)
        # Use the first InterfaceTarget from the rule
        # (pipeline ensures at least one is present)
        if not rule.interfaces:
            raise ValueError(
                f"Rule '{rule.rule_name}' has no interfaces defined. "
                "The LLM must fill interfaces[] from the SNMT before compilation."
            )

        target = rule.interfaces[0]
        iface  = target.interface
        router = target.router
        dir_str = "in" if target.direction == Direction.INBOUND else "out"
        acl_name = _acl_name_for_interface(iface, dir_str)

        # Map action — REJECT → deny on IOS
        action_str = "deny" if rule.action in (Action.DENY, Action.REJECT) else "permit"

        # Build time-range block if needed
        time_range_block = None
        time_range_suffix = ""
        if rule.time_range:
            time_range_block = _build_time_range_block(rule.time_range)
            time_range_suffix = f" time-range {rule.time_range.name}"

        # Logging suffix
        log_suffix = " log" if rule.logging else ""

        # Enumerate src × dst × dst_port
        sources = [("any", "any")] if rule.source_is_any \
                  else [(ep.entity_name, ep.prefix) for ep in rule.sources]
        dests   = [("any", "any")] if rule.destination_is_any \
                  else [(ep.entity_name, ep.prefix) for ep in rule.destinations]

        # Effective destination port list (empty → single pass with no port qualifier)
        dst_port_list = rule.dst_ports if rule.dst_ports else [None]
        src_port_list = rule.src_ports if rule.src_ports else [None]

        lines: list[CompiledLine] = []
        seq = 10  # IOS sequence numbers start at 10, increment by 10

        for src_name, src_prefix in sources:
            for dst_name, dst_prefix in dests:
                for dst_ps in dst_port_list:
                    for src_ps in src_port_list:

                        parts = [action_str, rule.protocol.value]

                        # Source address + optional source port
                        parts.append(_fmt_addr(src_prefix))
                        if src_ps and not src_ps.is_any:
                            parts.append(_fmt_port([src_ps], "src"))

                        # Destination address + optional destination port
                        parts.append(_fmt_addr(dst_prefix))
                        if dst_ps and not dst_ps.is_any:
                            parts.append(_fmt_port([dst_ps], "dst"))

                        # ICMP type/code
                        if rule.protocol == Protocol.ICMP:
                            if rule.icmp_type:
                                parts.append(rule.icmp_type)
                            if rule.icmp_code is not None:
                                parts.append(str(rule.icmp_code))

                        # TCP established
                        if rule.tcp_established:
                            parts.append("established")

                        # Time range + logging
                        line_text = " ".join(parts) + time_range_suffix + log_suffix

                        # Determine port for this line (first dst_port if present)
                        dst_port_num = dst_ps.port if dst_ps and not dst_ps.is_any else None

                        lines.append(CompiledLine(
                            text=line_text,
                            source_entity=src_name,
                            destination_entity=dst_name,
                            source_prefix=src_prefix,
                            destination_prefix=dst_prefix,
                            action=action_str,
                            protocol=rule.protocol.value,
                            dst_port=dst_port_num,
                            sequence_number=seq,
                        ))
                        seq += 10

        # No catch-all added.
        # We generate rules only for what the intent specifies.
        # The operator's existing ACL or router config handles all other traffic.
        # Adding permit/deny ip any any here would be making a policy decision
        # that belongs to the operator, not to us.

        logger.info(
            f"Compiled '{rule.rule_name}': {len(lines)} line(s) → "
            f"ACL '{acl_name}' {dir_str} on {iface} ({router})"
        )

        return CompiledACL(
            acl_name=acl_name,
            interface=iface,
            router=router,
            direction=dir_str,
            lines=lines,
            interface_command=f"ip access-group {acl_name} {dir_str}",
            time_range_block=time_range_block,
        )