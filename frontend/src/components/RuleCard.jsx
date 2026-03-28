import React from "react";
import { AlertTriangle } from "lucide-react";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatEndpoints(endpoints, isAny) {
  if (isAny) return "Any";
  if (!endpoints || endpoints.length === 0) return "—";
  return endpoints
    .map((ep) => {
      if (ep.entity_name === "Not Found") return `Not Found`;
      if (ep.prefix) return `${ep.entity_name} (${ep.prefix})`;
      return ep.entity_name;
    })
    .join(", ");
}

function formatPorts(ports) {
  if (!ports || ports.length === 0) return null;
  const specs = ports
    .map((p) => {
      if (!p || p.operator === "any") return null;
      if (p.operator === "range") return `${p.port}–${p.port_high}`;
      if (p.operator === "eq") return `${p.port}`;
      if (p.operator === "gt") return `> ${p.port}`;
      if (p.operator === "lt") return `< ${p.port}`;
      if (p.operator === "neq") return `!= ${p.port}`;
      return `${p.operator} ${p.port}`;
    })
    .filter(Boolean);
  return specs.length > 0 ? specs.join(", ") : null;
}

function formatProtocol(protocol, icmp_type, tcp_established, dst_ports) {
  if (!protocol) return "—";
  const proto = protocol.toUpperCase();

  const parts = [proto];

  if (protocol === "icmp" && icmp_type) {
    parts.push(`(${icmp_type})`);
  }

  if (tcp_established) {
    parts.push("established");
  }

  const portStr = formatPorts(dst_ports);
  if (portStr && protocol !== "icmp" && protocol !== "ip") {
    parts.push(`port ${portStr}`);
  }

  return parts.join(" ");
}

function formatInterfaces(interfaces) {
  if (!interfaces || interfaces.length === 0) return "—";
  return interfaces
    .map((iface) => {
      const dir = iface.direction ? iface.direction.toLowerCase() : "";
      return `${iface.router} ${iface.interface} (${dir})`;
    })
    .join(", ");
}

function formatTimeRange(tr) {
  if (!tr) return null;
  const days = tr.days && tr.days.length > 0 ? tr.days.join(", ") : "daily";
  const times =
    tr.time_start && tr.time_end ? ` ${tr.time_start}–${tr.time_end}` : "";
  return `${days}${times}`;
}

function hasNotFound(endpoints) {
  return endpoints && endpoints.some((ep) => ep.entity_name === "Not Found");
}

// ─── Row component ────────────────────────────────────────────────────────────

function Row({ label, value, warn }) {
  return (
    <div className="ir-row">
      <span className="ir-row__label">{label}</span>
      <span className={`ir-row__value ${warn ? "ir-row__value--warn" : ""}`}>
        {value}
      </span>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function RuleCard({ rule }) {
  if (!rule) return null;

  const {
    rule_name,
    description,
    sources = [],
    destinations = [],
    source_is_any,
    destination_is_any,
    protocol,
    dst_ports = [],
    src_ports = [],
    action,
    direction,
    interfaces = [],
    tcp_established,
    icmp_type,
    time_range,
    logging,
    ambiguities = [],
    incomplete,
  } = rule;

  const srcNotFound = hasNotFound(sources);
  const dstNotFound = hasNotFound(destinations);

  const srcStr = formatEndpoints(sources, source_is_any);
  const dstStr = formatEndpoints(destinations, destination_is_any);
  const protoStr = formatProtocol(
    protocol,
    icmp_type,
    tcp_established,
    dst_ports,
  );
  const ifaceStr = formatInterfaces(interfaces);
  const srcPortStr = formatPorts(src_ports);
  const timeStr = formatTimeRange(time_range);

  const actionStr = action ? action.toUpperCase() : "—";

  return (
    <div className="ir-card">
      {/* ── Rule name + description ── */}
      <div className="ir-card__heading">
        <span className="ir-card__name">{rule_name || "Unnamed Rule"}</span>
        {incomplete && (
          <span className="ir-card__incomplete">
            <AlertTriangle size={12} /> Incomplete
          </span>
        )}
      </div>
      {description && <p className="ir-card__description">{description}</p>}

      {/* ── Field rows ── */}
      <div className="ir-rows">
        <Row label="Action" value={actionStr} />
        <Row label="Source" value={srcStr} warn={srcNotFound} />
        <Row label="Destination" value={dstStr} warn={dstNotFound} />
        <Row label="Protocol" value={protoStr} />
        {srcPortStr && <Row label="Source Port" value={srcPortStr} />}
        <Row label="Interface" value={ifaceStr} />
        <Row
          label="Direction"
          value={direction ? direction.toLowerCase() : "—"}
        />
        {timeStr && <Row label="Time" value={timeStr} />}
        {logging && <Row label="Logging" value="enabled" />}
      </div>

      {/* ── Ambiguities ── */}
      {ambiguities.length > 0 && (
        <div className="ir-ambiguities">
          <p className="ir-ambiguities__title">
            <AlertTriangle size={12} />
            Notes &amp; ambiguities
          </p>
          <ul className="ir-ambiguities__list">
            {ambiguities.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
