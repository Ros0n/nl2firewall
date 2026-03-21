"""
Universal Canonical Rule — Intermediate Representation.

Vendor-agnostic firewall rule model. The same IR is used regardless of
the target platform. Vendor-specific compilers (CiscoIOS, Juniper, PaloAlto)
each consume this IR and produce their own syntax.

Design principles:
  - Lists for sources/destinations/ports → compiler enumerates combinations
  - All topology values (interfaces, prefixes) come from the SNMT, never hardcoded
  - Matching extras (tcp_established, icmp_type, time_range) are optional — null = not specified
  - No protect/Xumi-style action — plain PERMIT | DENY | REJECT
  - Lean operational section: logging, confidence, ambiguities only
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, model_validator


# ─── Enums ────────────────────────────────────────────────────────────────────

class Protocol(str, Enum):
    TCP   = "tcp"
    UDP   = "udp"
    ICMP  = "icmp"
    IP    = "ip"       # matches all traffic
    GRE   = "gre"
    ESP   = "esp"
    ANY   = "ip"       # alias — treated as IP

class PortOperator(str, Enum):
    EQ    = "eq"       # equal (single port)
    NEQ   = "neq"      # not equal
    LT    = "lt"       # less than
    GT    = "gt"       # greater than
    RANGE = "range"    # port range (requires port_high)
    ANY   = "any"      # no port restriction

class Action(str, Enum):
    PERMIT = "permit"
    DENY   = "deny"
    REJECT = "reject"  # send TCP RST / ICMP unreachable; compiled to 'deny' on IOS

class Direction(str, Enum):
    INBOUND  = "inbound"
    OUTBOUND = "outbound"


# ─── Sub-models ───────────────────────────────────────────────────────────────

class Endpoint(BaseModel):
    """
    One resolved network entity.
    All values copied exactly from the loaded SNMT — never invented.
    zone is optional: used by zone-based vendors (Palo Alto, Fortigate).
    """
    entity_name : str           = Field(description="Exact entity name from SNMT")
    router      : str           = Field(description="Router/device name from SNMT")
    interface   : str           = Field(description="Interface name from SNMT")
    prefix      : str           = Field(description="CIDR prefix, e.g. '192.168.1.0/24'")
    zone        : Optional[str] = Field(None, description="Security zone (future vendors)")


class PortSpec(BaseModel):
    """
    A port specification. Supports all Cisco operators plus range.
    For 'any' ports, use operator=ANY and leave port null.
    """
    operator  : PortOperator      = Field(PortOperator.ANY)
    port      : Optional[int]     = Field(None, description="Port number (or low end of range)")
    port_high : Optional[int]     = Field(None, description="High end of range (RANGE only)")

    @model_validator(mode="after")
    def validate_ports(self) -> "PortSpec":
        if self.operator == PortOperator.RANGE:
            if self.port is None or self.port_high is None:
                raise ValueError("RANGE operator requires both port and port_high")
            if self.port >= self.port_high:
                raise ValueError("port must be less than port_high for RANGE")
        if self.operator == PortOperator.ANY:
            if self.port is not None:
                raise ValueError("ANY operator must have port=null")
        if self.operator != PortOperator.RANGE and self.port_high is not None:
            raise ValueError("port_high is only used with RANGE operator")
        if self.operator != PortOperator.ANY and self.port is not None:
            if not (1 <= self.port <= 65535):
                raise ValueError(f"Port {self.port} out of valid range 1-65535")
        return self

    @property
    def is_any(self) -> bool:
        return self.operator == PortOperator.ANY


class InterfaceTarget(BaseModel):
    """
    Where to deploy the ACL. LLM infers this from SNMT + intent reasoning.
    Cisco: interface + direction (in/out).
    Future zone-based vendors: zone field used instead of interface.
    """
    router    : str           = Field(description="Router/device name")
    interface : str           = Field(description="Interface name")
    direction : Direction     = Field(description="inbound or outbound")
    zone      : Optional[str] = Field(None, description="Zone name (future vendors)")


class TimeRange(BaseModel):
    """
    Time-based filtering. Compiles to Cisco 'time-range' config block.
    Maps to equivalent constructs on other vendors.
    """
    name       : str            = Field(description="Name for the time range, e.g. 'BUSINESS_HOURS'")
    type       : str            = Field("periodic", description="'periodic' or 'absolute'")
    days       : list[str]      = Field(
        default_factory=list,
        description="Days: ['Monday','Tuesday',...] or keywords ['weekdays','weekends','daily']"
    )
    time_start : Optional[str]  = Field(None, description="Start time HH:MM, e.g. '08:00'")
    time_end   : Optional[str]  = Field(None, description="End time HH:MM, e.g. '17:00'")


# ─── Canonical Rule ───────────────────────────────────────────────────────────

class CanonicalRule(BaseModel):
    """
    Universal Intermediate Representation for one firewall policy intent.

    Vendor-agnostic. The compiler receives this and produces vendor-specific syntax.
    Lists are intentional: compiler enumerates src × dst × port → N individual rules.

    Example:
        sources      = [Finance(192.168.10.0/24)]
        destinations = [Servers(10.0.1.0/24), DMZ(10.0.2.0/24)]
        dst_ports    = [PortSpec(EQ,22), PortSpec(EQ,443)]
        action       = DENY
        → 4 compiled ACL lines (1 × 2 × 2)
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    rule_name    : str  = Field(description="Short machine-friendly name, e.g. 'Block_SSH_Finance'")
    description  : str  = Field(description="Human-readable explanation of what this rule does")
    intent_text  : str  = Field(description="Original natural language intent verbatim")

    # ── 5-Tuple ───────────────────────────────────────────────────────────────
    sources      : list[Endpoint] = Field(default_factory=list)
    destinations : list[Endpoint] = Field(default_factory=list)
    protocol     : Protocol       = Field(description="Traffic protocol")
    src_ports    : list[PortSpec] = Field(
        default_factory=list,
        description="Source ports (usually empty = any). Most rules leave this empty."
    )
    dst_ports    : list[PortSpec] = Field(
        default_factory=list,
        description="Destination ports. Empty list means any port."
    )

    # ── Source / destination any flags ───────────────────────────────────────
    source_is_any      : bool = Field(False, description="True when source is literally 'any'")
    destination_is_any : bool = Field(False, description="True when destination is 'any'")

    # ── Action & direction ────────────────────────────────────────────────────
    action    : Action    = Field(description="permit, deny, or reject")
    direction : Direction = Field(Direction.INBOUND, description="inbound or outbound on the interface")

    # ── Deployment ────────────────────────────────────────────────────────────
    interfaces : list[InterfaceTarget] = Field(
        default_factory=list,
        description="Where to apply this ACL. LLM infers from SNMT gateway + direction reasoning."
    )

    # ── Matching extras ───────────────────────────────────────────────────────
    tcp_established : bool           = Field(
        False,
        description=(
            "True to match only established TCP sessions (ACK/RST set). "
            "Use for permitting return traffic of outbound connections. "
            "Example: 'allow replies to internal web browsing' → tcp_established=true"
        )
    )
    icmp_type : Optional[str] = Field(
        None,
        description=(
            "ICMP message type name or number. "
            "Common: 'echo' (ping request), 'echo-reply', 'unreachable', 'time-exceeded'. "
            "Only set when protocol=ICMP."
        )
    )
    icmp_code : Optional[int] = Field(
        None,
        description="ICMP code (sub-type). Usually null — only needed for specific ICMP filtering."
    )
    time_range : Optional[TimeRange] = Field(
        None,
        description=(
            "Time-based filtering. Set when intent mentions time: "
            "'during business hours', 'on weekends', 'after 18:00'. "
            "Null means the rule applies at all times."
        )
    )

    # ── Operational ───────────────────────────────────────────────────────────
    logging      : bool        = Field(False, description="Log matched packets")
    confidence   : float       = Field(1.0, ge=0.0, le=1.0)
    ambiguities  : list[str]   = Field(default_factory=list)
    incomplete   : bool        = Field(False, description="True when any entity is Not Found or confidence < 0.5")

    # ── Validators ────────────────────────────────────────────────────────────
    @model_validator(mode="after")
    def validate_rule(self) -> "CanonicalRule":
        if not self.source_is_any and len(self.sources) == 0:
            raise ValueError("sources must be non-empty, or source_is_any=True")
        if not self.destination_is_any and len(self.destinations) == 0:
            raise ValueError("destinations must be non-empty, or destination_is_any=True")
        if self.protocol == Protocol.ICMP:
            if self.dst_ports:
                raise ValueError("ICMP rules use icmp_type/icmp_code, not dst_ports")
        if self.tcp_established and self.protocol != Protocol.TCP:
            raise ValueError("tcp_established is only valid for TCP protocol")
        if (self.icmp_type or self.icmp_code) and self.protocol != Protocol.ICMP:
            raise ValueError("icmp_type/icmp_code are only valid for ICMP protocol")
        return self

    def estimated_line_count(self) -> int:
        """How many individual ACL lines the compiler will generate."""
        s = 1 if self.source_is_any else len(self.sources)
        d = 1 if self.destination_is_any else len(self.destinations)
        p = max(len(self.dst_ports), 1)  # at least 1 (any)
        return s * d * p


# ─── Compiled output models ───────────────────────────────────────────────────

class CompiledLine(BaseModel):
    """One rendered ACL line plus its metadata."""
    text              : str
    source_entity     : str
    destination_entity: str
    source_prefix     : str = ""    # CIDR prefix e.g. "10.40.0.0/24" — used by Batfish
    destination_prefix: str = ""    # CIDR prefix e.g. "10.20.0.0/24" — used by Batfish
    action            : str = ""    # "permit" or "deny" — used by Batfish searchFilters
    protocol          : str = ""    # "tcp", "udp", "icmp", "ip" — used by Batfish
    dst_port          : Optional[int] = None   # destination port number — used by Batfish
    sequence_number   : Optional[int] = None


class CompiledACL(BaseModel):
    """
    Full compiled output for one CanonicalRule.
    Named ACL style — works on all modern Cisco IOS/NX-OS platforms.
    """
    acl_name          : str
    interface         : str
    router            : str
    direction         : str
    lines             : list[CompiledLine]
    interface_command : str
    time_range_block  : Optional[str] = None   # Cisco time-range config if needed

    def to_cisco_config(self) -> str:
        """Render the complete deployable Cisco IOS config block."""
        parts = []

        # Time range block (must be defined before the ACL that references it)
        if self.time_range_block:
            parts.append(self.time_range_block)
            parts.append("!")

        # Named ACL block
        parts.append(f"ip access-list extended {self.acl_name}")
        for line in self.lines:
            prefix = f" {line.sequence_number}" if line.sequence_number else " "
            parts.append(f"{prefix} {line.text}")
        parts.append("!")

        # Interface application
        parts.append(f"interface {self.interface}")
        parts.append(f" {self.interface_command}")

        return "\n".join(parts)


# ─── Pipeline state ───────────────────────────────────────────────────────────

class PipelineStatus(str, Enum):
    PENDING        = "pending"
    RESOLVING      = "resolving"
    BUILDING_IR    = "building_ir"
    AWAITING_REVIEW= "awaiting_review"
    LINTING        = "linting"
    SAFETY_CHECK   = "safety_check"
    COMPILING      = "compiling"
    VERIFYING      = "verifying"
    COMPLETE       = "complete"
    FAILED         = "failed"
    BLOCKED        = "blocked"


class LintSeverity(str, Enum):
    WARNING = "warning"
    ERROR   = "error"


class LintIssue(BaseModel):
    severity : LintSeverity
    code     : str
    message  : str
    field    : Optional[str] = None


class LintResult(BaseModel):
    issues: list[LintIssue] = Field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(i.severity == LintSeverity.ERROR for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == LintSeverity.WARNING for i in self.issues)

    def summary(self) -> str:
        e = sum(1 for i in self.issues if i.severity == LintSeverity.ERROR)
        w = sum(1 for i in self.issues if i.severity == LintSeverity.WARNING)
        return f"{e} error(s), {w} warning(s)"


class SafetyResult(BaseModel):
    safe    : bool
    errors  : list[str] = Field(default_factory=list)
    message : str = ""


class BatfishIssue(BaseModel):
    severity   : str
    check_name : str
    description: str
    affected_lines: list[str] = Field(default_factory=list)


class BatfishResult(BaseModel):
    passed                  : bool
    issues                  : list[BatfishIssue] = Field(default_factory=list)
    reachability_violations : list[str]          = Field(default_factory=list)
    shadowed_rules          : list[str]          = Field(default_factory=list)
    parse_warnings          : list[str]          = Field(default_factory=list)
    raw_output              : dict               = Field(default_factory=dict)

    def summary(self) -> str:
        if self.raw_output and "summary" in self.raw_output:
            return self.raw_output["summary"]
        if self.passed:
            return "Batfish: all checks passed ✓"
        return (
            f"Batfish: {len(self.issues)} issue(s), "
            f"{len(self.shadowed_rules)} shadowed line(s), "
            f"{len(self.reachability_violations)} policy violation(s)"
        )

    def flow_traces(self) -> list:
        """Return testFilters results for display to operator."""
        if self.raw_output and "flow_traces" in self.raw_output:
            return self.raw_output["flow_traces"]
        return []


class PipelineState(BaseModel):
    """Complete mutable state threaded through the LangGraph pipeline."""
    intent_text    : str
    session_id     : str
    status         : PipelineStatus = PipelineStatus.PENDING
    current_step   : str = ""
    error          : Optional[str] = None

    # LLM interaction
    llm_messages    : list[dict] = Field(default_factory=list)
    feedback_rounds : int = 0
    max_feedback_rounds: int = 3
    human_feedback  : Optional[str] = None

    # Stage outputs
    resolved_rule   : Optional[CanonicalRule] = None
    lint_result     : Optional[LintResult]    = None
    safety_result   : Optional[SafetyResult]  = None
    compiled_acl    : Optional[CompiledACL]   = None
    batfish_result  : Optional[BatfishResult] = None

    # Final output
    final_config    : Optional[str] = None
    explanation     : Optional[str] = None

    class Config:
        use_enum_values = False