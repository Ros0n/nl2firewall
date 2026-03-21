"""
Prompts for the firewall rule extraction pipeline.

Implements:
  - Chain-of-Thought (CoT) reasoning — 7 steps covering all IR fields
  - Interface/direction reasoning from SNMT (new — LLM decides deployment)
  - Self-reflection verification
  - Generic few-shot examples (not network-specific)
  - Full IR JSON schema matching CanonicalRule

Key changes from old prompts:
  - No 'protect' action
  - PortSpec has operator field (eq/range/gt/lt)
  - InterfaceTarget added — LLM infers from SNMT + intent
  - tcp_established, icmp_type, icmp_code, time_range added
  - logging field added
"""

# ─── IR JSON Schema ────────────────────────────────────────────────────────────

IR_JSON_SCHEMA = """{
  "rule_name": "<short_snake_case_name, e.g. Block_SSH_Finance_to_Servers>",
  "description": "<one sentence explaining what this rule does>",
  "intent_text": "<original intent verbatim>",

  "sources": [
    {
      "entity_name": "<exact name from SNMT>",
      "router": "<router from SNMT>",
      "interface": "<interface from SNMT>",
      "prefix": "<CIDR from SNMT>",
      "zone": null
    }
  ],
  "destinations": [
    {
      "entity_name": "<exact name from SNMT>",
      "router": "<router from SNMT>",
      "interface": "<interface from SNMT>",
      "prefix": "<CIDR from SNMT>",
      "zone": null
    }
  ],

  "source_is_any": false,
  "destination_is_any": false,

  "protocol": "tcp" | "udp" | "icmp" | "ip" | "gre" | "esp",

  "src_ports": [],
  "dst_ports": [
    {
      "operator": "eq" | "neq" | "lt" | "gt" | "range" | "any",
      "port": <integer or null>,
      "port_high": <integer or null, only for range>
    }
  ],

  "action": "permit" | "deny" | "reject",
  "direction": "inbound" | "outbound",

  "interfaces": [
    {
      "router": "<router name>",
      "interface": "<interface name>",
      "direction": "inbound" | "outbound",
      "zone": null
    }
  ],

  "tcp_established": false,
  "icmp_type": null,
  "icmp_code": null,
  "time_range": null,

  "logging": false,
  "confidence": 0.0-1.0,
  "ambiguities": []
}"""

# ─── Chain-of-Thought steps ───────────────────────────────────────────────────

COT_STEPS = """
Follow these SEVEN steps in order. Think through each step before writing the JSON.

STEP 1 — Identify the ACTION:
  - block / deny / prevent / disallow / forbid → "deny"
  - allow / permit / enable / let / authorize  → "permit"
  - reject (send error back to sender)         → "reject"
  - No action word found → state your assumption in ambiguities[].

STEP 2 — Resolve SOURCE:
  - Find the entity in the SNMT that matches the source description.
  - Copy entity_name, router, interface, prefix EXACTLY as they appear in the SNMT.
  - If the source spans multiple SNMT entities, list ALL of them in sources[].
  - If source is "any" or truly unspecified → source_is_any=true, sources=[].
  - NEVER invent an IP address or entity not in the SNMT.

STEP 3 — Resolve DESTINATION:
  - Same rules as Step 2 but for the destination.
  - "any destination" or "anywhere" → destination_is_any=true, destinations=[].

STEP 4 — Identify PROTOCOL and PORTS:
  - SSH       → protocol=tcp, dst_ports=[{operator:eq, port:22}]
  - HTTP      → protocol=tcp, dst_ports=[{operator:eq, port:80}]
  - HTTPS     → protocol=tcp, dst_ports=[{operator:eq, port:443}]
  - DNS       → BOTH tcp AND udp, port 53 (create two separate rules or use two entries)
  - ping/ICMP → protocol=icmp, dst_ports=[], icmp_type="echo"
  - ping reply → protocol=icmp, icmp_type="echo-reply"
  - web/HTTP+HTTPS → two entries in dst_ports: [{eq,80},{eq,443}]
  - "all traffic" / "any" → protocol=ip, dst_ports=[]
  - port range (e.g. "1024 to 65535") → operator=range, port=1024, port_high=65535
  - "above port 1023" → operator=gt, port=1023
  - NEVER add dst_ports when protocol is icmp or ip.

STEP 5 — Infer DIRECTION and DEPLOYMENT INTERFACE:
  This is critical. Read the intent carefully to understand traffic flow.
  Then look at the SNMT to find the right interface.

  Direction rules:
    - "inbound" = traffic entering an interface FROM outside toward the router
    - "outbound" = traffic leaving an interface FROM the router toward outside
    - For DENY rules: place INBOUND on the SOURCE's gateway interface.
      This stops the traffic as close to the source as possible.
    - For PERMIT rules: consider where traffic flows.
      Usually also INBOUND on the source interface.
    - If the intent says "from the internet" or "incoming from outside" → INBOUND
      on the interface facing the internet/external network.
    - If the intent says "outbound to internet" or "leaving the network" → OUTBOUND
      on the external-facing interface.

  Interface selection from SNMT:
    - Find the source entity in the SNMT.
    - The source entity's gateway interface IS the deployment interface for inbound rules.
    - For outbound rules, find the destination entity's gateway interface.
    - If multiple source entities → one InterfaceTarget per unique interface.

  Example reasoning:
    Intent: "Block Dept-A from SSHing to Servers"
    SNMT shows: Dept-A gateway = RouterX Ethernet1/0
    → direction = inbound (block as it enters from Dept-A)
    → interface = Ethernet1/0 on RouterX
    → interfaces = [{router: RouterX, interface: Ethernet1/0, direction: inbound}]

STEP 6 — Check MATCHING EXTRAS:
  - tcp_established: Set to TRUE only when the intent is about RETURN traffic
    (e.g., "allow replies", "permit established connections", "stateful return").
    For most block rules this is FALSE.
  - icmp_type: Set when protocol=icmp and type matters.
    "ping" → "echo", "ping reply" → "echo-reply", "unreachable" → "unreachable".
  - time_range: Set when the intent mentions time constraints.
    "during business hours" → {name: BUSINESS_HOURS, type: periodic,
                               days: [weekdays], time_start: 08:00, time_end: 17:00}
    "on weekends" → {name: WEEKENDS, type: periodic, days: [weekends]}
    No time mention → null.
  - logging: True if intent mentions "log", "audit", "track", "record".

STEP 7 — Assess CONFIDENCE and AMBIGUITIES:
  - confidence=1.0: All entities found in SNMT, protocol clear, direction obvious.
  - confidence=0.8: Minor ambiguity (one interpretation chosen from two reasonable ones).
  - confidence=0.6: Significant ambiguity (entity name unclear, protocol not specified).
  - confidence<0.6: Do NOT guess. Describe uncertainty in ambiguities[] instead.
  - List every assumption you made in ambiguities[] for the human reviewer.
"""

# ─── Self-reflection verification ────────────────────────────────────────────

SELF_REFLECTION = """
Before writing the final JSON, verify ALL of the following:

Verify 1 — Entity names exact:
  Every entity_name in sources[] and destinations[] MUST exist in the SNMT.
  Check now. If any name is not in the SNMT, either correct it or add to ambiguities[].

Verify 2 — Protocol-port consistency:
  - protocol=icmp → dst_ports MUST be empty, use icmp_type instead.
  - protocol=ip   → dst_ports MUST be empty.
  - protocol=tcp/udp → dst_ports may have entries with operator+port.
  - tcp_established → only if protocol=tcp.
  Check every port spec now.

Verify 3 — Interface reasoning correct:
  - interfaces[] must NOT be empty.
  - For inbound deny rules: interface = source entity's gateway from SNMT.
  - For outbound rules: interface = exit interface toward destination.
  - direction field in InterfaceTarget matches intent semantics.
  Check now.

Verify 4 — PortSpec structure:
  - operator="any" → port must be null.
  - operator="range" → both port and port_high must be set, port < port_high.
  - operator="eq"/"neq"/"lt"/"gt" → port must be set, port_high must be null.
  Check every PortSpec in dst_ports and src_ports.

Verify 5 — Action is one of: permit / deny / reject. Nothing else.

Verify 6 — direction in interfaces[] matches direction field at rule level.
"""

# ─── Few-shot examples (generic, not network-specific) ───────────────────────

FEW_SHOT_EXAMPLES = """
=== FEW-SHOT EXAMPLES ===
These use a FICTIONAL network. Always use YOUR loaded network context.
Never copy entity names, IPs, or interface names from these examples.

--- EXAMPLE 1: Simple deny, single port ---
Network context has:
  Finance Dept  | RouterX | Ethernet1/0 | 192.168.10.0/24
  App Servers   | RouterX | Ethernet2/0 | 10.0.1.0/24

Intent: "Block the Finance department from SSH access to App Servers"

Step 1: action = deny
Step 2: source = Finance Dept (192.168.10.0/24, RouterX, Ethernet1/0)
Step 3: destination = App Servers (10.0.1.0/24, RouterX, Ethernet2/0)
Step 4: SSH = tcp, dst_ports=[{eq, 22}]
Step 5: Deny → inbound on source interface Ethernet1/0
Step 6: No extras
Step 7: confidence=1.0

{
  "rule_name": "Block_SSH_Finance_to_AppServers",
  "description": "Deny SSH from Finance to App Servers",
  "intent_text": "Block the Finance department from SSH access to App Servers",
  "sources": [{"entity_name":"Finance Dept","router":"RouterX","interface":"Ethernet1/0","prefix":"192.168.10.0/24","zone":null}],
  "destinations": [{"entity_name":"App Servers","router":"RouterX","interface":"Ethernet2/0","prefix":"10.0.1.0/24","zone":null}],
  "source_is_any": false, "destination_is_any": false,
  "protocol": "tcp",
  "src_ports": [],
  "dst_ports": [{"operator":"eq","port":22,"port_high":null}],
  "action": "deny",
  "direction": "inbound",
  "interfaces": [{"router":"RouterX","interface":"Ethernet1/0","direction":"inbound","zone":null}],
  "tcp_established": false, "icmp_type": null, "icmp_code": null, "time_range": null,
  "logging": false, "confidence": 1.0, "ambiguities": []
}

--- EXAMPLE 2: Multiple ports (web = HTTP + HTTPS) ---
Intent: "Deny web access from Guest Wifi to Internal Servers"

Step 4: "web" = HTTP(80) + HTTPS(443) → two entries in dst_ports

{
  "rule_name": "Block_Web_GuestWifi_to_InternalServers",
  "description": "Deny HTTP and HTTPS from Guest Wifi to Internal Servers",
  "intent_text": "Deny web access from Guest Wifi to Internal Servers",
  "sources": [{"entity_name":"Guest Wifi","router":"RouterY","interface":"Ethernet3/0","prefix":"172.16.50.0/24","zone":null}],
  "destinations": [{"entity_name":"Internal Servers","router":"RouterY","interface":"Ethernet1/0","prefix":"10.10.0.0/24","zone":null}],
  "source_is_any": false, "destination_is_any": false,
  "protocol": "tcp",
  "src_ports": [],
  "dst_ports": [
    {"operator":"eq","port":80,"port_high":null},
    {"operator":"eq","port":443,"port_high":null}
  ],
  "action": "deny",
  "direction": "inbound",
  "interfaces": [{"router":"RouterY","interface":"Ethernet3/0","direction":"inbound","zone":null}],
  "tcp_established": false, "icmp_type": null, "icmp_code": null, "time_range": null,
  "logging": false, "confidence": 1.0, "ambiguities": []
}

--- EXAMPLE 3: ICMP ping — port MUST be null, icmp_type MUST be set ---
Intent: "Prevent Dept-B from pinging the servers"

Step 4: ping = icmp, icmp_type="echo". NEVER put a port in dst_ports for ICMP.

{
  "rule_name": "Block_Ping_DeptB_to_Servers",
  "description": "Deny ICMP echo (ping) from Dept-B to Servers",
  "intent_text": "Prevent Dept-B from pinging the servers",
  "sources": [{"entity_name":"Dept-B","router":"RouterX","interface":"Ethernet2/0","prefix":"192.168.20.0/24","zone":null}],
  "destinations": [{"entity_name":"Servers","router":"RouterX","interface":"Ethernet3/0","prefix":"10.0.2.0/24","zone":null}],
  "source_is_any": false, "destination_is_any": false,
  "protocol": "icmp",
  "src_ports": [], "dst_ports": [],
  "action": "deny",
  "direction": "inbound",
  "interfaces": [{"router":"RouterX","interface":"Ethernet2/0","direction":"inbound","zone":null}],
  "tcp_established": false, "icmp_type": "echo", "icmp_code": null, "time_range": null,
  "logging": false, "confidence": 1.0, "ambiguities": []
}

--- EXAMPLE 4: Time-based rule ---
Intent: "Block social media from Office network during business hours weekdays"

Step 6: time_range present → name=BUSINESS_HOURS, periodic, weekdays, 08:00-17:00

{
  "rule_name": "Block_SocialMedia_Office_BusinessHours",
  "description": "Deny social media ports from Office during business hours",
  "intent_text": "Block social media from Office network during business hours weekdays",
  "sources": [{"entity_name":"Office Network","router":"RouterX","interface":"Ethernet1/0","prefix":"10.1.0.0/24","zone":null}],
  "destinations": [{"entity_name":"Internet","router":"RouterX","interface":"Ethernet0/0","prefix":"0.0.0.0/0","zone":null}],
  "source_is_any": false, "destination_is_any": false,
  "protocol": "tcp",
  "src_ports": [],
  "dst_ports": [{"operator":"eq","port":443,"port_high":null}],
  "action": "deny",
  "direction": "inbound",
  "interfaces": [{"router":"RouterX","interface":"Ethernet1/0","direction":"inbound","zone":null}],
  "tcp_established": false, "icmp_type": null, "icmp_code": null,
  "time_range": {
    "name": "BUSINESS_HOURS",
    "type": "periodic",
    "days": ["weekdays"],
    "time_start": "08:00",
    "time_end": "17:00"
  },
  "logging": false, "confidence": 1.0, "ambiguities": []
}

--- EXAMPLE 5: tcp_established (return traffic) ---
Intent: "Allow internal users to browse the web, but block inbound web connections from outside"

Step 4: Outbound HTTP/HTTPS permitted; inbound only if established (return traffic)
Step 5: Outbound: direction=outbound on external interface
        Return: tcp_established=true, permit, inbound on external interface

Rule for return traffic (this example):
{
  "rule_name": "Permit_Web_ReturnTraffic_External",
  "description": "Allow established TCP return traffic for web browsing",
  "intent_text": "Allow internal users to browse the web, but block inbound web connections from outside",
  "sources": [{"entity_name":"Internet","router":"RouterX","interface":"Ethernet0/0","prefix":"0.0.0.0/0","zone":null}],
  "destinations": [{"entity_name":"Internal Network","router":"RouterX","interface":"Ethernet1/0","prefix":"10.0.0.0/8","zone":null}],
  "source_is_any": false, "destination_is_any": false,
  "protocol": "tcp",
  "src_ports": [],
  "dst_ports": [],
  "action": "permit",
  "direction": "inbound",
  "interfaces": [{"router":"RouterX","interface":"Ethernet0/0","direction":"inbound","zone":null}],
  "tcp_established": true, "icmp_type": null, "icmp_code": null, "time_range": null,
  "logging": false, "confidence": 0.9,
  "ambiguities": ["Split into two rules: one permit outbound, one permit established return — this is the return traffic rule"]
}

--- EXAMPLE 6: Port range ---
Intent: "Allow high-port UDP traffic from DataCenter to Analytics"

Step 4: "high-port" typically means ephemeral ports 1024-65535 → operator=range

{
  "rule_name": "Allow_HighPort_UDP_DC_to_Analytics",
  "description": "Permit high ephemeral UDP ports from DataCenter to Analytics",
  "intent_text": "Allow high-port UDP traffic from DataCenter to Analytics",
  "sources": [{"entity_name":"DataCenter","router":"CoreRouter","interface":"Ethernet10/0","prefix":"10.100.0.0/16","zone":null}],
  "destinations": [{"entity_name":"Analytics","router":"CoreRouter","interface":"Ethernet10/1","prefix":"10.200.0.0/24","zone":null}],
  "source_is_any": false, "destination_is_any": false,
  "protocol": "udp",
  "src_ports": [],
  "dst_ports": [{"operator":"range","port":1024,"port_high":65535}],
  "action": "permit",
  "direction": "inbound",
  "interfaces": [{"router":"CoreRouter","interface":"Ethernet10/0","direction":"inbound","zone":null}],
  "tcp_established": false, "icmp_type": null, "icmp_code": null, "time_range": null,
  "logging": true, "confidence": 0.85,
  "ambiguities": ["'High-port' interpreted as ephemeral range 1024-65535"]
}

=== END FEW-SHOT EXAMPLES ===
"""

# ─── Full system prompt ───────────────────────────────────────────────────────

def build_system_prompt(snmt_block: str) -> str:
    return f"""You are an expert network security engineer and firewall policy analyst.

Your task is to translate a natural language network security intent into a
structured JSON Intermediate Representation (IR) that will be compiled into
vendor-specific firewall rules.

=== YOUR ROLE ===
- You are a precise parser and resolver. Translate intent faithfully.
- Do NOT add restrictions the user did not ask for.
- Do NOT be more permissive than intended.
- Use ONLY entity names, IPs, and interfaces from the network context below.
- If you cannot resolve something from the network context, say so in ambiguities[].

{snmt_block}

=== OUTPUT FORMAT ===
Output ONLY valid JSON conforming exactly to this schema.
No markdown, no backticks, no explanation outside the JSON.

{IR_JSON_SCHEMA}

=== INSTRUCTIONS ===
{COT_STEPS}

{SELF_REFLECTION}

{FEW_SHOT_EXAMPLES}

=== CRITICAL RULES (never violate) ===
1. Output ONLY the JSON object. No ```json``` fences. No text before or after.
2. Every entity_name, router, interface, prefix MUST be copied EXACTLY from the SNMT.
3. ICMP rules: dst_ports MUST be empty. Use icmp_type field.
4. IP protocol: dst_ports MUST be empty.
5. interfaces[] MUST NOT be empty. Infer from SNMT using Step 5 reasoning.
6. confidence below 0.6: do NOT guess. Describe uncertainty in ambiguities[].
7. rule_name must be a short snake_case string, no spaces.
"""


def build_feedback_prompt(
    original_intent: str,
    wrong_ir_json: str,
    human_feedback: str,
) -> str:
    return f"""The previous rule IR had errors. The human reviewer provided feedback.

=== ORIGINAL INTENT ===
{original_intent}

=== PREVIOUS (INCORRECT) IR ===
{wrong_ir_json}

=== HUMAN FEEDBACK ===
{human_feedback}

=== YOUR TASK ===
Generate a CORRECTED IR JSON that addresses all feedback above.
Apply the same 7-step reasoning and all verification checks.
Output ONLY the corrected JSON. No explanation outside the JSON.
"""


def build_explanation_prompt(rule_json: str, compiled_config: str) -> str:
    return f"""Given this firewall rule IR:
{rule_json}

And this compiled configuration:
{compiled_config}

Write a clear, concise explanation (3-5 sentences) for a network administrator:
1. What traffic this rule affects (who, what protocol/port, to where)
2. What the rule does (permit/deny)
3. Where it is applied (interface, direction)
4. Any important caveats (e.g. time restrictions, TCP established, logging)

Be specific. Use IP addresses and port numbers. No jargon.
"""