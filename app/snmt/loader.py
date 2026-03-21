"""
SNMT Loader — loads and queries the Semantics-Network Mapping Table.

The SNMT is the "grounding" component from Xumi §4.1.
It maps entity names to (router, interface, prefix) tuples so the LLM
has the topology facts it cannot know from training.

Design:
  - No hardcoded paths. The loader is given a path or raw content explicitly.
  - No aliases — the LLM handles natural language variation through CoT reasoning.
  - No acl_interfaces section — the compiler derives deployment interface
    directly from the source entity primary gateway (Cisco best practice:
    extended ACLs go inbound on the interface closest to the source).
  - No applications section — the LLM knows SSH=22, HTTP=80 etc. from training.
  - One entity can have multiple gateway tuples (like Xumi's "Group X" example).

SNMT YAML format (Xumi-style):
    network_name: "My Network"
    entities:
      Sales Network:
        gateways:
          - router: "R1"
            interface: "GigabitEthernet0/0/1.40"
            prefix: "10.40.0.0/24"
      Group X:
        gateways:
          - router: "RC"
            interface: "Ethernet0/2"
            prefix: "10.1.0.0/16"
          - router: "RD"
            interface: "Ethernet0/2"
            prefix: "10.2.0.0/16"
"""

from __future__ import annotations

import yaml
from pathlib import Path
from dataclasses import dataclass, field


@dataclass(frozen=True)
class GatewayTuple:
    """One (router, interface, prefix) entry for an entity. Mirrors Xumi Figure 4."""
    router: str
    interface: str
    prefix: str

    @property
    def wildcard(self) -> str:
        """Derive Cisco wildcard mask from CIDR prefix length."""
        if "/" not in self.prefix:
            return "0.0.0.0"
        bits = int(self.prefix.split("/")[1])
        if bits == 32:
            return "0.0.0.0"
        if bits == 0:
            return "255.255.255.255"
        mask = (0xFFFFFFFF >> bits) & 0xFFFFFFFF
        return ".".join(str((mask >> (8 * i)) & 0xFF) for i in reversed(range(4)))

    @property
    def network_ip(self) -> str:
        return self.prefix.split("/")[0]

    @property
    def prefix_len(self) -> int:
        if "/" not in self.prefix:
            return 32
        return int(self.prefix.split("/")[1])


@dataclass
class SNMTEntity:
    """
    One network entity with one or more gateway tuples.
    Directly mirrors Xumi SNMT format (Figure 4):
        Endpoint | Gateway(s)+Interface(s) | Prefix(es)
    """
    name: str
    gateways: list[GatewayTuple] = field(default_factory=list)

    @property
    def primary_gateway(self) -> GatewayTuple | None:
        return self.gateways[0] if self.gateways else None

    @property
    def all_prefixes(self) -> list[str]:
        return [gw.prefix for gw in self.gateways]


class SNMTLoader:
    """
    Loads and provides query access to a network context YAML file.

    Usage:
        # From file path
        snmt = SNMTLoader.from_file("data/networks/ccna_lab.yaml")

        # From raw YAML string (e.g. uploaded via API)
        snmt = SNMTLoader.from_string(yaml_content)

        # Query
        entity = snmt.get_entity("Sales Network")
        block  = snmt.to_prompt_block()
    """

    def __init__(
        self,
        network_name: str,
        description: str,
        entities: dict[str, SNMTEntity],
    ) -> None:
        self.network_name = network_name
        self.description = description
        self._entities = entities

    # ─── Constructors ────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str | Path) -> "SNMTLoader":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Network context file not found: {path}")
        with open(path, encoding="utf-8") as f:
            return cls.from_string(f.read())

    @classmethod
    def from_string(cls, yaml_content: str) -> "SNMTLoader":
        """Parse SNMT from a raw YAML string. Used for API file uploads."""
        raw = yaml.safe_load(yaml_content)
        if not isinstance(raw, dict):
            raise ValueError("Network context file must be a YAML mapping")

        network_name = raw.get("network_name", "Unnamed Network")
        description = raw.get("description", "")

        entities: dict[str, SNMTEntity] = {}
        for entity_name, entity_data in raw.get("entities", {}).items():
            gateways = []
            for gw in entity_data.get("gateways", []):
                gateways.append(GatewayTuple(
                    router=gw["router"],
                    interface=gw["interface"],
                    prefix=gw["prefix"],
                ))
            entities[entity_name] = SNMTEntity(
                name=entity_name,
                gateways=gateways,
            )

        if not entities:
            raise ValueError("Network context file has no entities defined")

        return cls(network_name, description, entities)

    # ─── Entity queries ──────────────────────────────────────────────────────

    def get_entity(self, name: str) -> SNMTEntity | None:
        """Exact name lookup (case-sensitive, as written in SNMT)."""
        return self._entities.get(name)

    def get_entity_fuzzy(self, name: str) -> SNMTEntity | None:
        """Case-insensitive fallback lookup."""
        name_lower = name.lower()
        for entity_name, entity in self._entities.items():
            if entity_name.lower() == name_lower:
                return entity
        return None

    def get_all_entities(self) -> list[SNMTEntity]:
        return list(self._entities.values())

    def get_entity_names(self) -> list[str]:
        return list(self._entities.keys())

    def find_entity_by_prefix(self, prefix: str) -> SNMTEntity | None:
        for entity in self._entities.values():
            for gw in entity.gateways:
                if gw.prefix == prefix:
                    return entity
        return None

    # ─── Deployment interface inference ──────────────────────────────────────

    def get_deployment_gateway(self, source_entity_name: str) -> GatewayTuple | None:
        """
        Return the gateway tuple to use for ACL deployment.

        Rule (Cisco best practice): extended ACLs go inbound on the interface
        closest to the SOURCE. That interface IS the source entity's primary
        gateway in the SNMT.

        Example:
            source = "Sales Network"
            → primary gateway = R1 GigabitEthernet0/0/1.40
            → ACL applied: ip access-group N in on GigabitEthernet0/0/1.40
        """
        entity = (
            self.get_entity(source_entity_name)
            or self.get_entity_fuzzy(source_entity_name)
        )
        if not entity:
            return None
        return entity.primary_gateway

    # ─── LLM prompt formatting ───────────────────────────────────────────────

    def to_prompt_block(self) -> str:
        """
        Format the SNMT as a structured text block for the LLM system prompt.
        Matches Xumi Figure 4 table format exactly.
        """
        lines = [
            f"=== NETWORK CONTEXT: {self.network_name} ===",
            "Use ONLY the entity names below when resolving source/destination.",
            "Do NOT invent names, IP addresses, or interfaces.",
            "Use the EXACT entity name as written in the left column.",
            "",
            f"  {'ENTITY NAME':<25} {'ROUTER':<8} {'INTERFACE':<35} {'PREFIX':<20}",
            "  " + "─" * 91,
        ]

        for entity in self._entities.values():
            for i, gw in enumerate(entity.gateways):
                name_col = entity.name if i == 0 else ""
                lines.append(
                    f"  {name_col:<25} {gw.router:<8} {gw.interface:<35} {gw.prefix:<20}"
                )

        lines.extend([
            "  " + "─" * 91,
            "",
            "NOTES:",
            "  - Use entity names exactly as shown (case-sensitive).",
            "  - An entity with multiple rows has multiple prefixes — list ALL in sources[]/destinations[].",
            "  - Prefix /32 = single host → the compiler will use 'host X.X.X.X' syntax.",
            "  - For truly unspecified source or destination, set source_is_any/destination_is_any=true.",
            "=== END NETWORK CONTEXT ===",
        ])

        return "\n".join(lines)

    def to_compact_json(self) -> dict:
        return {
            "network_name": self.network_name,
            "description": self.description,
            "entities": {
                entity.name: [
                    {"router": gw.router, "interface": gw.interface, "prefix": gw.prefix}
                    for gw in entity.gateways
                ]
                for entity in self._entities.values()
            },
        }

    def __repr__(self) -> str:
        return f"SNMTLoader(network='{self.network_name}', entities={len(self._entities)})"


# ─── Active network context registry ─────────────────────────────────────────
# No singleton with a hardcoded path. Loaded explicitly via API or auto-load.

_active_snmt: SNMTLoader | None = None


def set_active_snmt(snmt: SNMTLoader) -> None:
    """Set the globally active SNMT (called by API on file upload)."""
    global _active_snmt
    _active_snmt = snmt


def get_active_snmt() -> SNMTLoader | None:
    """Get the currently active SNMT. Returns None if not yet loaded."""
    return _active_snmt


def require_snmt() -> SNMTLoader:
    """Get the active SNMT or raise a clear error."""
    if _active_snmt is None:
        raise RuntimeError(
            "No network context loaded. "
            "Upload a network context file via POST /api/network first."
        )
    return _active_snmt


def reset_snmt() -> None:
    """Clear the active SNMT. Used in tests."""
    global _active_snmt
    _active_snmt = None


def try_autoload(networks_dir: str | Path) -> SNMTLoader | None:
    """
    Auto-load from a directory on startup (development convenience).
    Loads the first .yaml/.yml file found alphabetically.
    Returns None if directory is empty or missing.
    """
    networks_dir = Path(networks_dir)
    if not networks_dir.exists():
        return None
    yaml_files = sorted(networks_dir.glob("*.yaml")) + sorted(networks_dir.glob("*.yml"))
    if not yaml_files:
        return None
    snmt = SNMTLoader.from_file(yaml_files[0])
    set_active_snmt(snmt)
    return snmt
