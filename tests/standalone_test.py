"""
Standalone NL2Firewall test suite — stdlib + PyYAML only.
Tests the new CanonicalRule IR and CiscoIOSCompiler.
Run: python3 tests/standalone_test.py
"""

from __future__ import annotations
import sys, traceback, re
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import yaml

GREEN="\033[92m"; RED="\033[91m"; CYAN="\033[96m"; RESET="\033[0m"; BOLD="\033[1m"
def ok(m):   print(f"  {GREEN}✓{RESET} {m}")
def fail(m): print(f"  {RED}✗{RESET} {m}")

# ─── Inline models (mirror app/models/ir.py without Pydantic) ────────────────

class Protocol(str, Enum):
    TCP="tcp"; UDP="udp"; ICMP="icmp"; IP="ip"; GRE="gre"; ESP="esp"

class PortOperator(str, Enum):
    EQ="eq"; NEQ="neq"; LT="lt"; GT="gt"; RANGE="range"; ANY="any"

class Action(str, Enum):
    PERMIT="permit"; DENY="deny"; REJECT="reject"

class Direction(str, Enum):
    INBOUND="inbound"; OUTBOUND="outbound"

@dataclass
class Endpoint:
    entity_name: str
    router: str
    interface: str
    prefix: str
    zone: Optional[str] = None

@dataclass
class PortSpec:
    operator: PortOperator = PortOperator.ANY
    port: Optional[int] = None
    port_high: Optional[int] = None

    def __post_init__(self):
        if self.operator == PortOperator.RANGE:
            assert self.port and self.port_high and self.port < self.port_high
        if self.operator == PortOperator.ANY:
            assert self.port is None

    @property
    def is_any(self): return self.operator == PortOperator.ANY

@dataclass
class InterfaceTarget:
    router: str
    interface: str
    direction: Direction
    zone: Optional[str] = None

@dataclass
class TimeRange:
    name: str
    type: str = "periodic"
    days: list = field(default_factory=list)
    time_start: Optional[str] = None
    time_end: Optional[str] = None

@dataclass
class CanonicalRule:
    rule_name: str
    description: str
    intent_text: str
    sources: list = field(default_factory=list)
    destinations: list = field(default_factory=list)
    protocol: Protocol = Protocol.TCP
    src_ports: list = field(default_factory=list)
    dst_ports: list = field(default_factory=list)
    source_is_any: bool = False
    destination_is_any: bool = False
    action: Action = Action.DENY
    direction: Direction = Direction.INBOUND
    interfaces: list = field(default_factory=list)
    tcp_established: bool = False
    icmp_type: Optional[str] = None
    icmp_code: Optional[int] = None
    time_range: Optional[TimeRange] = None
    logging: bool = False
    confidence: float = 1.0
    ambiguities: list = field(default_factory=list)

    def estimated_line_count(self) -> int:
        s = 1 if self.source_is_any else len(self.sources)
        d = 1 if self.destination_is_any else len(self.destinations)
        p = max(len(self.dst_ports), 1)
        return s * d * p

# ─── Inline SNMT loader ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class GatewayTuple:
    router: str; interface: str; prefix: str

    @property
    def wildcard(self):
        if "/" not in self.prefix: return "0.0.0.0"
        bits = int(self.prefix.split("/")[1])
        if bits == 32: return "0.0.0.0"
        if bits == 0: return "255.255.255.255"
        mask = (0xFFFFFFFF >> bits) & 0xFFFFFFFF
        return ".".join(str((mask >> (8*i)) & 0xFF) for i in reversed(range(4)))

@dataclass
class SNMTEntity:
    name: str
    gateways: list = field(default_factory=list)

    @property
    def primary_gateway(self): return self.gateways[0] if self.gateways else None

class SNMTLoader:
    def __init__(self, nw, desc, entities):
        self.network_name = nw; self.description = desc; self._entities = entities

    @classmethod
    def from_file(cls, path):
        raw = yaml.safe_load(open(path).read())
        entities = {}
        for name, data in raw.get("entities", {}).items():
            gws = [GatewayTuple(g["router"], g["interface"], g["prefix"])
                   for g in data.get("gateways", [])]
            entities[name] = SNMTEntity(name=name, gateways=gws)
        return cls(raw.get("network_name",""), raw.get("description",""), entities)

    def get_entity(self, name): return self._entities.get(name)
    def get_entity_fuzzy(self, name):
        nl = name.lower()
        for n, e in self._entities.items():
            if n.lower() == nl: return e
        return None
    def get_all_entities(self): return list(self._entities.values())
    def get_deployment_gateway(self, name):
        e = self.get_entity(name) or self.get_entity_fuzzy(name)
        return e.primary_gateway if e else None

    def to_prompt_block(self):
        lines = [f"=== NETWORK CONTEXT: {self.network_name} ==="]
        for entity in self._entities.values():
            for i, gw in enumerate(entity.gateways):
                name_col = entity.name if i == 0 else ""
                lines.append(f"  {name_col:<25} {gw.router:<8} {gw.interface:<35} {gw.prefix}")
        lines.append("=== END ===")
        return "\n".join(lines)

# ─── Inline compiler ─────────────────────────────────────────────────────────

def _wc(prefix):
    if "/" not in prefix: return "0.0.0.0"
    bits = int(prefix.split("/")[1])
    if bits == 32: return "0.0.0.0"
    if bits == 0: return "255.255.255.255"
    mask = (0xFFFFFFFF >> bits) & 0xFFFFFFFF
    return ".".join(str((mask >> (8*i)) & 0xFF) for i in reversed(range(4)))

def _fmt(prefix):
    if prefix in ("any","0.0.0.0/0",""): return "any"
    ip, bits = (prefix.split("/")[0], int(prefix.split("/")[1])) if "/" in prefix else (prefix,32)
    if bits == 0: return "any"
    if bits == 32: return f"host {ip}"
    return f"{ip} {_wc(prefix)}"

def _fmt_port(ps):
    if ps is None or ps.is_any: return ""
    if ps.operator == PortOperator.RANGE: return f"range {ps.port} {ps.port_high}"
    return f"{ps.operator.value} {ps.port}"

def _acl_name(iface, direction):
    short = iface
    for l,a in [("GigabitEthernet","Gi"),("FastEthernet","Fa"),
                ("Ethernet","Et"),("Loopback","Lo"),("Vlan","Vl")]:
        short = short.replace(l,a)
    clean = re.sub(r"[^a-zA-Z0-9]","_",short).strip("_")
    return f"ACL_{clean}_{direction.upper()}"

@dataclass
class CompiledLine:
    text: str; source_entity: str; destination_entity: str
    source_prefix: str = ""; destination_prefix: str = ""
    action: str = ""; protocol: str = ""; dst_port: object = None; seq: int = 0

@dataclass
class CompiledACL:
    acl_name: str; interface: str; router: str; direction: str
    lines: list; interface_command: str; time_range_block: Optional[str] = None

    def to_cisco_config(self):
        parts = []
        if self.time_range_block:
            parts += [self.time_range_block, "!"]
        parts.append(f"ip access-list extended {self.acl_name}")
        for l in self.lines: parts.append(f" {l.seq} {l.text}")
        parts += ["!", f"interface {self.interface}", f" {self.interface_command}"]
        return "\n".join(parts)

def compile_rule(rule: CanonicalRule) -> CompiledACL:
    assert rule.interfaces, "No interfaces defined"
    target = rule.interfaces[0]
    iface = target.interface; router = target.router
    dir_str = "in" if target.direction == Direction.INBOUND else "out"
    acl_name = _acl_name(iface, dir_str)
    action_str = "deny" if rule.action in (Action.DENY, Action.REJECT) else "permit"

    tr_block = None; tr_suffix = ""
    if rule.time_range:
        tr = rule.time_range
        days_s = " ".join(tr.days) if tr.days else "daily"
        time_s = f" {tr.time_start} to {tr.time_end}" if tr.time_start else ""
        tr_block = f"time-range {tr.name}\n periodic {days_s}{time_s}"
        tr_suffix = f" time-range {tr.name}"

    log_suffix = " log" if rule.logging else ""

    sources = [("any","any")] if rule.source_is_any else [(e.entity_name,e.prefix) for e in rule.sources]
    dests   = [("any","any")] if rule.destination_is_any else [(e.entity_name,e.prefix) for e in rule.destinations]
    dp_list = rule.dst_ports if rule.dst_ports else [None]
    sp_list = rule.src_ports if rule.src_ports else [None]

    lines = []; seq = 10
    for sn,sp in sources:
        for dn,dp in dests:
            for dps in dp_list:
                for sps in sp_list:
                    parts = [action_str, rule.protocol.value, _fmt(sp)]
                    sp_str = _fmt_port(sps)
                    if sp_str: parts.append(sp_str)
                    parts.append(_fmt(dp))
                    dp_str = _fmt_port(dps)
                    if dp_str: parts.append(dp_str)
                    if rule.protocol == Protocol.ICMP and rule.icmp_type:
                        parts.append(rule.icmp_type)
                        if rule.icmp_code is not None: parts.append(str(rule.icmp_code))
                    if rule.tcp_established: parts.append("established")
                    dst_port_num = dps.port if dps and not dps.is_any else None
                    lines.append(CompiledLine(
                        text=" ".join(parts)+tr_suffix+log_suffix,
                        source_entity=sn, destination_entity=dn,
                        source_prefix=sp, destination_prefix=dp,
                        action=action_str, protocol=rule.protocol.value,
                        dst_port=dst_port_num, seq=seq))
                    seq += 10

    lines.append(CompiledLine(
        text="deny ip any any", source_entity="any", destination_entity="any",
        source_prefix="0.0.0.0/0", destination_prefix="0.0.0.0/0",
        action="deny", protocol="ip", dst_port=None, seq=seq))
    return CompiledACL(acl_name=acl_name, interface=iface, router=router,
                       direction=dir_str, lines=lines,
                       interface_command=f"ip access-group {acl_name} {dir_str}",
                       time_range_block=tr_block)

# ─── Inline linter/gate ───────────────────────────────────────────────────────

@dataclass
class LintIssue:
    severity: str; code: str; message: str

@dataclass
class LintResult:
    issues: list = field(default_factory=list)
    @property
    def has_errors(self): return any(i.severity=="error" for i in self.issues)
    @property
    def has_warnings(self): return any(i.severity=="warning" for i in self.issues)

def run_linter(rule, snmt=None):
    issues = []
    if rule is None:
        return LintResult([LintIssue("error","NULL_RULE","No rule")])
    if not rule.source_is_any and not rule.sources:
        issues.append(LintIssue("error","EMPTY_SOURCE","sources empty"))
    if not rule.destination_is_any and not rule.destinations:
        issues.append(LintIssue("error","EMPTY_DEST","destinations empty"))
    if rule.protocol == Protocol.ICMP and rule.dst_ports:
        issues.append(LintIssue("error","ICMP_WITH_PORTS","ICMP+dst_ports"))
    if rule.protocol == Protocol.IP and (rule.dst_ports or rule.src_ports):
        issues.append(LintIssue("error","IP_WITH_PORTS","ip+ports"))
    if rule.tcp_established and rule.protocol != Protocol.TCP:
        issues.append(LintIssue("error","ESTABLISHED_NON_TCP","established+non-tcp"))
    if not rule.interfaces:
        issues.append(LintIssue("warning","NO_INTERFACE","interfaces[] empty"))
    if rule.confidence < 0.7:
        issues.append(LintIssue("warning","LOW_CONFIDENCE",f"conf={rule.confidence:.2f}"))
    if snmt:
        for ep in rule.sources:
            if not (snmt.get_entity(ep.entity_name) or snmt.get_entity_fuzzy(ep.entity_name)):
                issues.append(LintIssue("warning","UNKNOWN_SRC",f"'{ep.entity_name}' not in SNMT"))
        for ep in rule.destinations:
            if not (snmt.get_entity(ep.entity_name) or snmt.get_entity_fuzzy(ep.entity_name)):
                issues.append(LintIssue("warning","UNKNOWN_DST",f"'{ep.entity_name}' not in SNMT"))
    for a in rule.ambiguities:
        issues.append(LintIssue("warning","LLM_AMBIGUITY",a))
    return LintResult(issues)

def run_safety_gate(rule):
    if rule is None: return (False, ["No rule"])
    errors = []
    if (rule.action == Action.PERMIT and rule.source_is_any
            and rule.destination_is_any and rule.protocol == Protocol.IP and not rule.dst_ports):
        errors.append("SAFETY_ANY_TO_ANY_PERMIT")
    if rule.action == Action.PERMIT:
        if rule.protocol == Protocol.IP and not rule.dst_ports:
            if rule.source_is_any or rule.destination_is_any:
                errors.append("SAFETY_BROAD_PERMIT")
    if rule.action == Action.PERMIT and rule.confidence < 0.5:
        errors.append("SAFETY_LOW_CONFIDENCE_PERMIT")
    if not rule.interfaces:
        errors.append("SAFETY_NO_INTERFACE")
    return (len(errors)==0, errors)

# ═════════════════════════════════════════════════════════════════════════════
# TEST RUNNER
# ═════════════════════════════════════════════════════════════════════════════

SNMT_PATH = ROOT / "data" / "networks" / "ccna_lab.yaml"

class Runner:
    def __init__(self):
        self.passed=self.failed=0; self.errors=[]
        self.snmt=self.compiler=None

    def setup(self):
        self.snmt = SNMTLoader.from_file(SNMT_PATH)

    def run(self, name, fn):
        try:
            fn(); ok(name); self.passed+=1
        except AssertionError as e:
            fail(f"{name}: {e}"); self.failed+=1; self.errors.append((name,str(e)))
        except Exception as e:
            fail(f"{name}: {type(e).__name__}: {e}")
            self.failed+=1; self.errors.append((name,traceback.format_exc()))

    def _ep(self, name):
        e = self.snmt.get_entity(name); assert e and e.primary_gateway
        gw = e.primary_gateway
        return Endpoint(entity_name=name,router=gw.router,interface=gw.interface,prefix=gw.prefix)

    def _iface(self, entity_name, direction=Direction.INBOUND):
        e = self.snmt.get_entity(entity_name); assert e and e.primary_gateway
        gw = e.primary_gateway
        return InterfaceTarget(router=gw.router, interface=gw.interface, direction=direction)

    def _rule(self, action=Action.DENY, src="Sales Network", dst="Management Network",
              protocol=Protocol.TCP, dst_ports=None, **kwargs):
        r = CanonicalRule(
            rule_name="test_rule", description="test", intent_text="test",
            sources=[self._ep(src)], destinations=[self._ep(dst)],
            protocol=protocol,
            dst_ports=dst_ports if dst_ports is not None else [PortSpec(PortOperator.EQ, 22)],
            interfaces=[self._iface(src)], action=action,
        )
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    # ── SNMT tests ─────────────────────────────────────────────────────────

    def test_snmt_loads(self): assert self.snmt is not None
    def test_snmt_network_name(self): assert "CCNA" in self.snmt.network_name
    def test_snmt_entity_count(self): assert len(self.snmt.get_all_entities()) >= 8
    def test_snmt_sales_network(self):
        e = self.snmt.get_entity("Sales Network")
        assert e and e.primary_gateway.prefix == "10.40.0.0/24"
    def test_snmt_sales_interface(self):
        e = self.snmt.get_entity("Sales Network")
        assert "0/0/1.40" in e.primary_gateway.interface
    def test_snmt_operations_network(self):
        e = self.snmt.get_entity("Operations Network")
        assert e and "10.30.0.0/24" == e.primary_gateway.prefix
    def test_snmt_management_network(self):
        e = self.snmt.get_entity("Management Network")
        assert e and "10.20.0.0/24" == e.primary_gateway.prefix
    def test_snmt_pca_host32(self):
        e = self.snmt.get_entity("PC-A"); assert e and e.primary_gateway.prefix == "10.30.0.10/32"
    def test_snmt_pcb_host32(self):
        e = self.snmt.get_entity("PC-B"); assert e and e.primary_gateway.prefix == "10.40.0.10/32"
    def test_snmt_fuzzy_lookup(self):
        assert self.snmt.get_entity_fuzzy("sales network").name == "Sales Network"
    def test_snmt_no_aliases(self): assert "aliases:" not in open(SNMT_PATH).read()
    def test_snmt_no_acl_interfaces(self): assert "acl_interfaces:" not in open(SNMT_PATH).read()
    def test_snmt_prompt_block_complete(self):
        block = self.snmt.to_prompt_block()
        assert all(n in block for n in ["Sales Network","Operations Network","Management Network"])

    # ── CanonicalRule model tests ───────────────────────────────────────────

    def test_rule_basic_creation(self):
        r = self._rule(); assert r.rule_name == "test_rule"
    def test_rule_estimated_line_count_1x1x1(self):
        r = self._rule(dst_ports=[PortSpec(PortOperator.EQ,22)])
        assert r.estimated_line_count() == 1
    def test_rule_estimated_line_count_1x1x2(self):
        r = self._rule(dst_ports=[PortSpec(PortOperator.EQ,80), PortSpec(PortOperator.EQ,443)])
        assert r.estimated_line_count() == 2
    def test_rule_estimated_line_count_1x2x2(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Sales Network")],
            destinations=[self._ep("Management Network"), self._ep("Operations Network")],
            protocol=Protocol.TCP,
            dst_ports=[PortSpec(PortOperator.EQ,80), PortSpec(PortOperator.EQ,443)],
            interfaces=[self._iface("Sales Network")], action=Action.DENY,
        )
        assert r.estimated_line_count() == 4  # 1 × 2 × 2
    def test_portspec_range_valid(self):
        ps = PortSpec(PortOperator.RANGE, 1024, 65535)
        assert ps.port==1024 and ps.port_high==65535
    def test_portspec_range_invalid_order(self):
        try: PortSpec(PortOperator.RANGE, 500, 100); assert False
        except AssertionError: pass
    def test_portspec_any_no_port(self):
        ps = PortSpec(PortOperator.ANY); assert ps.port is None
    def test_portspec_any_with_port_invalid(self):
        try: PortSpec(PortOperator.ANY, 80); assert False
        except AssertionError: pass

    # ── Wildcard / address formatting ──────────────────────────────────────

    def test_wc_slash24(self): assert _wc("10.40.0.0/24") == "0.0.0.255"
    def test_wc_slash16(self): assert _wc("10.0.0.0/16") == "0.0.255.255"
    def test_wc_slash8(self):  assert _wc("10.0.0.0/8")  == "0.255.255.255"
    def test_wc_slash32(self): assert _wc("10.1.1.1/32") == "0.0.0.0"
    def test_wc_slash0(self):  assert _wc("0.0.0.0/0")   == "255.255.255.255"
    def test_fmt_any(self):    assert _fmt("any") == "any"
    def test_fmt_host(self):   assert _fmt("10.40.0.10/32") == "host 10.40.0.10"
    def test_fmt_network(self):assert _fmt("10.40.0.0/24") == "10.40.0.0 0.0.0.255"
    def test_fmt_slash0(self): assert _fmt("0.0.0.0/0") == "any"

    # ── ACL name generation ─────────────────────────────────────────────────

    def test_acl_name_gi(self):
        assert _acl_name("GigabitEthernet0/0/1.40","in") == "ACL_Gi0_0_1_40_IN"
    def test_acl_name_fa(self):
        assert _acl_name("FastEthernet0/1","out") == "ACL_Fa0_1_OUT"
    def test_acl_name_loopback(self):
        assert _acl_name("Loopback1","in") == "ACL_Lo1_IN"

    # ── Compiler tests ─────────────────────────────────────────────────────

    def test_compile_simple_deny_ssh(self):
        r = self._rule()
        c = compile_rule(r)
        deny = [l for l in c.lines if "deny" in l.text and "any any" not in l.text]
        assert len(deny) == 1
        assert "deny tcp 10.40.0.0 0.0.0.255 10.20.0.0 0.0.0.255 eq 22" in deny[0].text

    def test_compile_named_acl_style(self):
        r = self._rule()
        c = compile_rule(r)
        cfg = c.to_cisco_config()
        assert "ip access-list extended" in cfg
        assert "ACL_" in c.acl_name
        assert "access-list 101" not in cfg   # no numbered ACL style

    def test_compile_interface_command(self):
        r = self._rule()
        c = compile_rule(r)
        cfg = c.to_cisco_config()
        assert "interface GigabitEthernet0/0/1.40" in cfg
        assert "ip access-group ACL_Gi0_0_1_40_IN in" in cfg

    def test_compile_enumeration_two_ports(self):
        r = self._rule(dst_ports=[PortSpec(PortOperator.EQ,80), PortSpec(PortOperator.EQ,443)])
        c = compile_rule(r)
        deny = [l for l in c.lines if "deny" in l.text and "any any" not in l.text]
        assert len(deny) == 2
        assert {80,443} == {int(l.text.split("eq ")[1].split()[0]) for l in deny}

    def test_compile_enumeration_two_dst(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Sales Network")],
            destinations=[self._ep("Management Network"), self._ep("Operations Network")],
            protocol=Protocol.ICMP,
            dst_ports=[], interfaces=[self._iface("Sales Network")], action=Action.DENY,
            icmp_type="echo",
        )
        c = compile_rule(r)
        deny = [l for l in c.lines if "deny" in l.text and "any any" not in l.text]
        assert len(deny) == 2

    def test_compile_icmp_echo_no_port(self):
        r = self._rule(protocol=Protocol.ICMP, dst_ports=[], icmp_type="echo")
        c = compile_rule(r)
        line = [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0]
        assert "icmp" in line.text and "echo" in line.text and "eq" not in line.text

    def test_compile_host_syntax(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("PC-B")],
            destinations=[self._ep("Management Network")],
            protocol=Protocol.TCP, dst_ports=[PortSpec(PortOperator.EQ,22)],
            interfaces=[self._iface("PC-B")], action=Action.DENY,
        )
        c = compile_rule(r)
        line = [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0]
        assert "host 10.40.0.10" in line.text

    def test_compile_reject_maps_to_deny(self):
        r = self._rule(action=Action.REJECT)
        c = compile_rule(r)
        deny = [l for l in c.lines if "deny" in l.text and "any any" not in l.text]
        assert len(deny) == 1  # REJECT → deny on Cisco IOS

    def test_compile_deny_ip_any_any_always_last(self):
        r = self._rule()
        c = compile_rule(r)
        assert c.lines[-1].text == "deny ip any any"

    def test_compile_sequence_numbers(self):
        r = self._rule(dst_ports=[PortSpec(PortOperator.EQ,22), PortSpec(PortOperator.EQ,80)])
        c = compile_rule(r)
        seqs = [l.seq for l in c.lines]
        assert seqs == [10, 20, 30]  # 2 deny + 1 implicit deny ip any any

    def test_compile_permit_rule(self):
        r = self._rule(action=Action.PERMIT)
        c = compile_rule(r)
        first = [l for l in c.lines if "permit" in l.text and "any any" not in l.text]
        assert len(first) == 1 and "permit tcp" in first[0].text

    def test_compile_any_destination(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Sales Network")], destinations=[],
            destination_is_any=True, protocol=Protocol.TCP,
            dst_ports=[PortSpec(PortOperator.EQ,22)],
            interfaces=[self._iface("Sales Network")], action=Action.DENY,
        )
        c = compile_rule(r)
        line = [l for l in c.lines if "deny" in l.text and "ip any any" not in l.text][0]
        assert line.text.endswith("any eq 22")

    def test_compile_tcp_established(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Internet")], destinations=[self._ep("Management Network")],
            source_is_any=False, destination_is_any=False,
            protocol=Protocol.TCP, dst_ports=[],
            interfaces=[self._iface("Internet")],
            action=Action.PERMIT, tcp_established=True,
        )
        c = compile_rule(r)
        permit = [l for l in c.lines if "permit" in l.text and "any any" not in l.text]
        assert any("established" in l.text for l in permit)

    def test_compile_port_range(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Sales Network")], destinations=[self._ep("Management Network")],
            protocol=Protocol.UDP,
            dst_ports=[PortSpec(PortOperator.RANGE, 1024, 65535)],
            interfaces=[self._iface("Sales Network")], action=Action.DENY,
        )
        c = compile_rule(r)
        line = [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0]
        assert "range 1024 65535" in line.text

    def test_compile_time_range(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Sales Network")], destinations=[self._ep("Management Network")],
            protocol=Protocol.TCP, dst_ports=[PortSpec(PortOperator.EQ,80)],
            interfaces=[self._iface("Sales Network")], action=Action.DENY,
            time_range=TimeRange("BUSINESS_HOURS","periodic",["weekdays"],"08:00","17:00"),
        )
        c = compile_rule(r)
        cfg = c.to_cisco_config()
        assert "time-range BUSINESS_HOURS" in cfg
        assert "time-range BUSINESS_HOURS" in [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0].text

    def test_compile_logging(self):
        r = self._rule(logging=True)
        c = compile_rule(r)
        line = [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0]
        assert line.text.endswith("log")

    def test_compile_outbound_direction(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Sales Network")], destinations=[self._ep("Internet")],
            protocol=Protocol.TCP, dst_ports=[PortSpec(PortOperator.EQ,443)],
            interfaces=[InterfaceTarget("R1","GigabitEthernet0/0/1.40",Direction.OUTBOUND)],
            action=Action.PERMIT, direction=Direction.OUTBOUND,
        )
        c = compile_rule(r)
        assert c.direction == "out"
        assert "ip access-group ACL_Gi0_0_1_40_OUT out" in c.to_cisco_config()

    # ── CCNA lab exact policy match tests ──────────────────────────────────

    def test_policy1_exact_line(self):
        """Lab: deny tcp 10.40.0.0 0.0.0.255 10.20.0.0 0.0.0.255 eq 22"""
        r = self._rule()
        c = compile_rule(r)
        deny = [l for l in c.lines if "deny" in l.text and "any any" not in l.text]
        assert "deny tcp 10.40.0.0 0.0.0.255 10.20.0.0 0.0.0.255 eq 22" in deny[0].text

    def test_policy2_http_deny(self):
        r = self._rule(dst_ports=[PortSpec(PortOperator.EQ,80)])
        c = compile_rule(r)
        assert "eq 80" in [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0].text

    def test_policy2_https_deny(self):
        r = self._rule(dst_ports=[PortSpec(PortOperator.EQ,443)])
        c = compile_rule(r)
        assert "eq 443" in [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0].text

    def test_policy3_icmp_echo_mgmt(self):
        r = self._rule(protocol=Protocol.ICMP, dst_ports=[], icmp_type="echo")
        c = compile_rule(r)
        line = [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0]
        assert "deny icmp 10.40.0.0 0.0.0.255 10.20.0.0 0.0.0.255 echo" in line.text

    def test_policy4_ops_no_icmp_to_sales(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Operations Network")],
            destinations=[self._ep("Sales Network")],
            protocol=Protocol.ICMP, dst_ports=[],
            interfaces=[self._iface("Operations Network")], action=Action.DENY,
            icmp_type="echo",
        )
        c = compile_rule(r)
        assert "GigabitEthernet0/0/1.30" in c.interface
        line = [l for l in c.lines if "deny" in l.text and "any any" not in l.text][0]
        assert "deny icmp 10.30.0.0 0.0.0.255 10.40.0.0 0.0.0.255 echo" in line.text

    def test_policy4_interface_is_ops(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[self._ep("Operations Network")],
            destinations=[self._ep("Sales Network")],
            protocol=Protocol.ICMP, dst_ports=[],
            interfaces=[self._iface("Operations Network")], action=Action.DENY,
            icmp_type="echo",
        )
        c = compile_rule(r)
        assert "GigabitEthernet0/0/1.30" in c.interface

    # ── Linter tests ───────────────────────────────────────────────────────

    def test_linter_valid_no_errors(self):
        r = self._rule(); assert not run_linter(r, self.snmt).has_errors
    def test_linter_null_rule(self):
        r = run_linter(None); assert r.has_errors and r.issues[0].code == "NULL_RULE"
    def test_linter_empty_sources(self):
        r = self._rule(); r.sources = []; r.source_is_any = False
        assert any(i.code=="EMPTY_SOURCE" for i in run_linter(r).issues)
    def test_linter_icmp_with_ports(self):
        r = self._rule(protocol=Protocol.ICMP)
        # dst_ports already set from _rule default — should trigger linter
        issues = run_linter(r).issues
        assert any(i.code=="ICMP_WITH_PORTS" for i in issues)
    def test_linter_ip_with_ports(self):
        r = self._rule(protocol=Protocol.IP)
        assert any(i.code=="IP_WITH_PORTS" for i in run_linter(r).issues)
    def test_linter_no_interface_warning(self):
        r = self._rule(); r.interfaces = []
        assert any(i.code=="NO_INTERFACE" for i in run_linter(r).issues)
    def test_linter_low_confidence(self):
        r = self._rule(); r.confidence = 0.5
        assert any(i.code=="LOW_CONFIDENCE" for i in run_linter(r).issues)
    def test_linter_unknown_entity(self):
        r = self._rule()
        r.sources = [Endpoint("FAKE_ENTITY","RX","E1/0","1.2.3.0/24")]
        assert any(i.code=="UNKNOWN_SRC" for i in run_linter(r, self.snmt).issues)
    def test_linter_ambiguity(self):
        r = self._rule(); r.ambiguities = ["unclear entity"]
        assert any(i.code=="LLM_AMBIGUITY" for i in run_linter(r).issues)

    # ── Safety gate tests ──────────────────────────────────────────────────

    def test_safety_deny_is_safe(self):
        safe, _ = run_safety_gate(self._rule()); assert safe
    def test_safety_specific_permit_safe(self):
        safe, _ = run_safety_gate(self._rule(action=Action.PERMIT)); assert safe
    def test_safety_any_to_any_permit_blocked(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[], destinations=[], source_is_any=True, destination_is_any=True,
            protocol=Protocol.IP, dst_ports=[],
            interfaces=[self._iface("Sales Network")], action=Action.PERMIT,
        )
        safe, errors = run_safety_gate(r)
        assert not safe and any("ANY_TO_ANY_PERMIT" in e for e in errors)
    def test_safety_no_interface_blocked(self):
        r = self._rule(); r.interfaces = []
        safe, errors = run_safety_gate(r)
        assert not safe and any("NO_INTERFACE" in e for e in errors)
    def test_safety_low_conf_permit_blocked(self):
        r = self._rule(action=Action.PERMIT); r.confidence = 0.3
        safe, errors = run_safety_gate(r)
        assert not safe and any("LOW_CONFIDENCE_PERMIT" in e for e in errors)
    def test_safety_null_blocked(self):
        safe, _ = run_safety_gate(None); assert not safe
    def test_safety_deny_any_src_safe(self):
        r = CanonicalRule(
            rule_name="t", description="t", intent_text="t",
            sources=[], destinations=[self._ep("Management Network")],
            source_is_any=True, destination_is_any=False,
            protocol=Protocol.TCP, dst_ports=[PortSpec(PortOperator.EQ,22)],
            interfaces=[self._iface("Sales Network")], action=Action.DENY,
        )
        safe, _ = run_safety_gate(r); assert safe


def main():
    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{CYAN}   NL2Firewall — CanonicalRule + CiscoIOS Tests{RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════{RESET}\n")

    r = Runner()
    try:
        r.setup()
        ok(f"Setup: '{r.snmt.network_name}' ({len(r.snmt.get_all_entities())} entities)")
    except Exception as e:
        print(f"\n{RED}FATAL: {e}{RESET}"); traceback.print_exc(); sys.exit(1)

    tests = [(n, getattr(r,n)) for n in sorted(dir(r)) if n.startswith("test_")]
    categories = {
        "SNMT":          [(n,f) for n,f in tests if "snmt" in n],
        "Rule model":    [(n,f) for n,f in tests if "rule_" in n or "portspec" in n],
        "Wildcards":     [(n,f) for n,f in tests if "wc" in n or "fmt" in n or "acl_name" in n],
        "Compiler":      [(n,f) for n,f in tests if "compile" in n],
        "CCNA policies": [(n,f) for n,f in tests if "policy" in n],
        "Linter":        [(n,f) for n,f in tests if "linter" in n],
        "Safety":        [(n,f) for n,f in tests if "safety" in n],
    }

    for cat, cat_tests in categories.items():
        if not cat_tests: continue
        print(f"\n{BOLD}── {cat} ({len(cat_tests)}) ──{RESET}")
        for name, fn in cat_tests:
            r.run(name.replace("test_","").replace("_"," "), fn)

    total = r.passed + r.failed
    print(f"\n{BOLD}{'═'*50}{RESET}")
    if r.failed == 0:
        print(f"{BOLD}{GREEN}✓ All {total} tests passed{RESET}")
    else:
        print(f"{BOLD}{RED}✗ {r.failed}/{total} failed{RESET}")
        for name, err in r.errors:
            print(f"\n  {RED}•{RESET} {name}: {err.split(chr(10))[0]}")
    print()
    sys.exit(0 if r.failed == 0 else 1)

if __name__ == "__main__":
    main()