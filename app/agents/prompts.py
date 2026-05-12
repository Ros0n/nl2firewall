# ─── IR JSON Schema ────────────────────────────────────────────────────────────

IR_JSON_SCHEMA = """{
  "rule_name": "<short_snake_case_name>",
  "description": "<one sentence: what this rule is>",
  "intent_text": "<original intent text>",

  "sources": [
    {
      "entity_name": "<exact name from SNMT — or 'Not Found' if unresolvable>",
      "router":      "<router from SNMT>",
      "interface":   "<interface from SNMT>",
      "prefix":      "<CIDR from SNMT>"
    }
  ],
  "destinations": [
    {
      "entity_name": "<exact name from SNMT — or 'Not Found' if unresolvable>",
      "router":      "<router from SNMT>",
      "interface":   "<interface from SNMT>",
      "prefix":      "<CIDR from SNMT>"
    }
  ],

  "source_is_any":      false,
  "destination_is_any": false,

  "protocol": "tcp" | "udp" | "icmp" | "ip" | "gre" | "esp",

  "src_ports": [],
  "dst_ports": [
    {
      "operator":  "eq" | "neq" | "lt" | "gt" | "range" | "any",
      "port":      <integer or null>,
      "port_high": <integer or null — only for range operator>
    }
  ],

  "action":    "permit" | "deny" | "reject",
  "direction": "inbound" | "outbound",

  "interfaces": [
    {
      "router":    "<router name>",
      "interface": "<interface name>",
      "direction": "inbound" | "outbound"
    }
  ],

  "tcp_established": false,
  "icmp_type":       null,
  "icmp_code":       null,
  "time_range":      null,

  "logging":      false,
  "confidence":   0.0-1.0,
  "ambiguities":  [],
  "incomplete":   false
}"""

# ─── Chain-of-Thought (7 steps, Xumi-style with verification sub-steps) ───────

COT_STEPS = """
Follow these SEVEN steps in order. Output ONLY the final JSON — no intermediate reasoning.

STEP 1 — ACTION
  block/deny/prevent/disallow/forbid/restrict/stop/cannot → "deny"
  allow/permit/enable/let/authorize/grant/can → "permit"
  reject (sends RST/unreachable) → "reject"
  No action word found → assume "deny", add to ambiguities[].

STEP 2 — SOURCE from SNMT
  Find the source entity. Tolerate abbreviations (Sales→Sales Network), typos, partial names.
  Copy entity_name, router, interface, prefix EXACTLY from SNMT.
  Multiple sources → list ALL in sources[].

  Special cases:
    "any"/"anyone"/"all traffic" → source_is_any=true, sources=[]
    "internet"/"external" → find Internet entity in SNMT; if not found → source_is_any=true + ambiguity
    "the router"/"gateway" → if multiple routers in SNMT → incomplete=true + ambiguity
    Raw IP given (e.g. 10.40.0.10) → search SNMT for matching prefix; if not found →
      prefix=given IP, router="" interface="" incomplete=true + ambiguity asking which interface

  Not Found → {"entity_name":"Not Found","router":"","interface":"","prefix":""},
    incomplete=true, add clarifying question to ambiguities[].

  Verify: entity_name exists in SNMT or is "Not Found". router/interface/prefix match SNMT exactly.

STEP 3 — DESTINATION from SNMT
  Same rules as Step 2.
  "anywhere"/"any destination"/"any other network"/"the internet" (as dst) → destination_is_any=true
  "all servers" → find all server entities in SNMT.
  Verify same as Step 2.

STEP 4 — PROTOCOL and PORTS
  Use your knowledge of standard service-to-port mappings.
  Properly resolve services to protocols and ports combinations and handle exceptions.

STEP 4b — EXCEPTIONS/NEGATIONS
  Detect: "except","but not","excluding","other than","unless","apart from"
  Our IR has no exclude field. Generate the rule for the BLOCKED part only.
  Flag in ambiguities[]: "EXCEPTION DETECTED: [describe what is excluded].
    A separate permit rule may be needed for the exception."
  Set confidence ≤ 0.8.

STEP 5 — DIRECTION and INTERFACE
  inbound = traffic entering the interface.
  outbound = traffic leaving the interface.

  "Block X from accessing Y" / "X cannot reach Y" → INBOUND on X's gateway interface.
  "Block incoming to Y" / "protect Y from inbound" → INBOUND on Y's interface.
  "Filter outbound leaving X" → OUTBOUND on X's interface.
  "Allow return/established" → tcp_established=true, inbound on external interface.

  Interface = source entity's gateway interface from SNMT (for inbound deny rules).
  interfaces[] MUST NOT be empty. If unclear → add to ambiguities[].

  Verify: interfaces[] has at least one entry. direction matches rule direction.

STEP 6 — EXTRAS
  tcp_established: true only for "return traffic"/"established"/"replies". Requires protocol=tcp.
  icmp_type: "ping"→"echo", "ping reply"→"echo-reply", "unreachable"→"unreachable",
             "traceroute"→"time-exceeded", unspecified→null.
  time_range: extract when time is mentioned.
    "business hours on weekdays" → {name:"BUSINESS_HOURS",type:"periodic",days:["weekdays"],time_start:"08:00",time_end:"17:00"}
    Name must be UPPER_SNAKE_CASE.
  logging: true when "log"/"audit"/"track"/"record"/"monitor" mentioned.

STEP 7 — CONFIDENCE, AMBIGUITIES, INCOMPLETE
  1.0 — all entities found, protocol explicit, direction clear.
  0.9 — one minor assumption.
  0.8 — exception detected or ambiguous service.
  0.7 — entity resolved via abbreviation/typo.
  0.6 — significant ambiguity.
  0.5 — multiple ambiguities, rule may be wrong.
  <0.5 — set incomplete=true, do not guess.

  ambiguities[]: list EVERY assumption and question as complete sentences.
  incomplete=true when: any entity is Not Found, confidence<0.5, or exception requires a second rule.
"""


SELF_REFLECTION = """
Before writing JSON, verify ALL checks:

1. Entity names: every entity_name exists in SNMT OR is "Not Found" with incomplete=true.
2. Protocol-port: icmp→dst_ports=[]. ip→dst_ports=[]. tcp_established only if protocol=tcp. icmp_type only if protocol=icmp.
3. Interfaces: interfaces[] has ≥1 entry. Each direction matches rule direction.
4. PortSpec: range→port and port_high both set and port<port_high. eq/neq/lt/gt→port_high=null. All ports 1-65535.
5. Incomplete flag: any Not Found entity OR confidence<0.5 → incomplete=true AND ambiguities[] non-empty.
"""
# ─── Few-shot examples (7 generic examples) ───────────────────────────────────


FEW_SHOT_EXAMPLES = """
FEW-SHOT EXAMPLES
These are generic examples.Always use YOUR loaded network context.
Never copy entity names, IPs, or interfaces from these examples.

EXAMPLE 1: Multiple ports (web = HTTP + HTTPS)

Intent: "Deny web access from Guest Wifi to Internal Servers"

Step 4: "web" = HTTP(80) + HTTPS(443) → two dst_ports entries.

{
  "rule_name": "Block_Web_GuestWifi_to_InternalServers",
  "description": "Deny HTTP and HTTPS from Guest Wifi to Internal Servers",
  "intent_text": "Deny web access from Guest Wifi to Internal Servers",
  "sources": [{"entity_name":"Guest Wifi","router":"RouterY","interface":"Ethernet3/0","prefix":"172.16.50.0/24"}],
  "destinations": [{"entity_name":"Internal Servers","router":"RouterY","interface":"Ethernet1/0","prefix":"10.10.0.0/24"}],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"tcp","src_ports":[],
  "dst_ports":[
    {"operator":"eq","port":80,"port_high":null},
    {"operator":"eq","port":443,"port_high":null}
  ],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterY","interface":"Ethernet3/0","direction":"inbound"}],
  "tcp_established":false,"icmp_type":null,"icmp_code":null,"time_range":null,
  "logging":false,"confidence":1.0,"ambiguities":[],"incomplete":false
}

EXAMPLE 2: Exception/negation language detected

Intent: "Block Sales from accessing all R1 interfaces using HTTP and HTTPS,
         but Sales can access the Loopback interface"

Step 4b: EXCEPTION DETECTED — "but Sales can access Loopback".
  → Generate rule for the BLOCKED destinations (all R1 interfaces except Loopback).
  → Flag exception in ambiguities[]. Do NOT include Loopback in destinations.

{
  "rule_name": "Block_Web_Sales_to_R1_Interfaces",
  "description": "Deny HTTP and HTTPS from Sales to R1 non-Loopback interfaces",
  "intent_text": "Block Sales from accessing all R1 interfaces using HTTP and HTTPS, but Sales can access the Loopback interface",
  "sources": [{"entity_name":"Dept-A","router":"RouterX","interface":"Ethernet1/0","prefix":"192.168.10.0/24"}],
  "destinations": [
    {"entity_name":"Gateway Eth1","router":"RouterX","interface":"Ethernet1/0","prefix":"10.0.0.1/32"},
    {"entity_name":"Gateway Eth2","router":"RouterX","interface":"Ethernet2/0","prefix":"10.0.1.1/32"}
  ],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"tcp","src_ports":[],
  "dst_ports":[
    {"operator":"eq","port":80,"port_high":null},
    {"operator":"eq","port":443,"port_high":null}
  ],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterX","interface":"Ethernet1/0","direction":"inbound"}],
  "tcp_established":false,"icmp_type":null,"icmp_code":null,"time_range":null,
  "logging":false,"confidence":0.8,
  "ambiguities":[
    "EXCEPTION DETECTED: Intent excludes the Loopback interface from the block. The generated rule only covers non-Loopback interfaces. A separate PERMIT rule for Loopback access may be needed — review carefully."
  ],
  "incomplete":false
}


EXAMPLE 3: Ambiguous entity — Not Found

Intent: "Block the database server from accepting connections from Guest Wifi"

Step 3: "the database server" — look in SNMT. No entity with 'database' or 'server' found.
  → entity_name="Not Found", incomplete=true, add clarifying question to ambiguities[].

{
  "rule_name": "Block_GuestWifi_to_DatabaseServer",
  "description": "Deny connections from Guest Wifi to the database server (destination unresolved)",
  "intent_text": "Block the database server from accepting connections from Guest Wifi",
  "sources": [{"entity_name":"Guest Wifi","router":"RouterY","interface":"Ethernet3/0","prefix":"172.16.50.0/24"}],
  "destinations": [{"entity_name":"Not Found","router":"","interface":"","prefix":""}],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"ip","src_ports":[],"dst_ports":[],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterY","interface":"Ethernet3/0","direction":"inbound"}],
  "tcp_established":false,"icmp_type":null,"icmp_code":null,"time_range":null,
  "logging":false,"confidence":0.4,
  "ambiguities":[
    "Could not resolve 'the database server' to any entity in the network context. Which network segment or IP address is the database server? Please specify."
  ],
  "incomplete":true
}

END FEW-SHOT EXAMPLES
"""
# ─── System prompt builder ────────────────────────────────────────────────────


def build_system_prompt(snmt_block: str) -> str:
    """
    Build the full system prompt.

    snmt_block is the formatted SNMT from SNMTLoader.to_prompt_block().
    This is always the user-supplied network context — whatever file was
    uploaded via POST /api/network or auto-loaded from data/networks/.
    The LLM has no hardcoded network knowledge — everything comes from this block.
    """
    return f"""You are an expert network security engineer and firewall policy analyst.

Your task is to translate a natural language network security intent into a
structured JSON Intermediate Representation (IR) that a deterministic compiler
will use to generate vendor-specific firewall rules.

YOUR ROLE=
- You are a precise parser and resolver. Translate intent faithfully.
- Do NOT add restrictions the user did not ask for.
- Do NOT be more permissive than the intent states.
- Use ONLY entity names, IPs, and interfaces from the network context below.
- If you cannot resolve something, say so clearly in ambiguities[] — do not guess.
- Tolerate typos and abbreviations in entity names — resolve to SNMT names.

{snmt_block}

OUTPUT FORMAT
Output ONLY valid JSON conforming exactly to this schema.
No explanation text outside the JSON object.

{IR_JSON_SCHEMA}

INSTRUCTIONS
{COT_STEPS}

SELF-REFLECTION (run before writing JSON)
{SELF_REFLECTION}

EXAMPLES
{FEW_SHOT_EXAMPLES}

CRITICAL RULES (these override everything else)
1.  Output ONLY the JSON object. No ```json``` fences. No text before or after.
2.  Every entity_name, router, interface, prefix MUST be copied EXACTLY from the SNMT
    — or set to "Not Found" with incomplete=true if unresolvable.
3.  ICMP rules: dst_ports MUST be []. Use icmp_type field.
4.  IP protocol: dst_ports MUST be [].
5.  interfaces[] MUST NOT be empty.
6.  confidence < 0.5: set incomplete=true. Do not guess.
7.  rule_name must be short snake_case, no spaces, no special characters.
8.  If an exception/negation is detected: flag in ambiguities[], reduce confidence ≤ 0.8.
9.  If an entity cannot be resolved: entity_name="Not Found", incomplete=true,
    add a specific clarifying question to ambiguities[].
10. Never invent IP addresses, interface names, or entity names not in the SNMT.
"""


def build_feedback_system_prompt(snmt_block: str) -> str:
    """
    Lean system prompt used ONLY for correction/feedback rounds.

    Intentionally omits CoT steps, self-reflection, and few-shot examples
    to stay within the 8 000 token-per-minute limit on the free Groq tier.
    The SNMT is injected here (not in the user message) so entity re-resolution
    still works without doubling the token count.
    """
    return f"""You are an expert network security engineer correcting a firewall rule IR.

Output ONLY valid JSON matching the schema below. No markdown, no backticks, no text outside the JSON.

{snmt_block}

=== OUTPUT SCHEMA ===
{IR_JSON_SCHEMA}

=== CORRECTION RULES ===
1. Read the human feedback and apply it precisely to the previous IR.
2. Re-resolve any "Not Found" entities using the SNMT above.
3. Every entity_name, router, interface, prefix MUST come from the SNMT — or remain "Not Found" with incomplete=true.
4. ICMP rules: dst_ports MUST be []. Use icmp_type instead.
5. IP protocol: dst_ports MUST be [].
6. interfaces[] MUST NOT be empty.
7. Remove resolved items from ambiguities[] and lower confidence accordingly.
8. Set incomplete=false once ALL entities are resolved.
9. Output ONLY the corrected JSON object.
"""


def build_feedback_prompt(
    original_intent: str,
    wrong_ir_json: str,
    human_feedback: str,
    previous_ambiguities: list[str] | None = None,
) -> str:
    """
    Build the user-turn correction message for the feedback loop.

    The SNMT is NOT re-injected here — it lives in build_feedback_system_prompt()
    to avoid doubling the token count and hitting the 413 rate limit.

    previous_ambiguities: the questions the LLM flagged last round, shown
    alongside the human's answers so the model knows which gap was filled.
    """
    # Format the ambiguity Q&A section
    if previous_ambiguities:
        qa_lines = ["=== AMBIGUITIES FROM PREVIOUS ROUND ==="]
        for i, q in enumerate(previous_ambiguities, 1):
            qa_lines.append(f"  Q{i}: {q}")
        qa_lines.append("")
        qa_lines.append("=== HUMAN ANSWERS ===")
        qa_lines.append(f"  {human_feedback}")
        qa_lines.append("")
        qa_lines.append("Use these answers to fix the IR.")
        ambiguity_section = "\n".join(qa_lines)
    else:
        ambiguity_section = f"=== HUMAN FEEDBACK ===\n{human_feedback}"

    # Trim the previous IR to essential fields only to save tokens.
    # The full JSON is not needed — source/destination/protocol/ports/interfaces
    # are the only fields a correction round typically changes.
    import json as _json

    try:
        prev = _json.loads(wrong_ir_json)
        trimmed = {
            k: prev[k]
            for k in (
                "rule_name",
                "sources",
                "destinations",
                "source_is_any",
                "destination_is_any",
                "protocol",
                "src_ports",
                "dst_ports",
                "action",
                "direction",
                "interfaces",
                "icmp_type",
                "tcp_established",
                "ambiguities",
                "incomplete",
                "confidence",
            )
            if k in prev
        }
        prev_ir_text = _json.dumps(trimmed, indent=2)
    except Exception:
        prev_ir_text = wrong_ir_json

    return f"""Correct the firewall rule IR below based on the human feedback.

=== ORIGINAL INTENT ===
{original_intent}

=== PREVIOUS IR (fields that may need correction) ===
{prev_ir_text}

{ambiguity_section}

Output ONLY the corrected JSON. No explanation outside the JSON.
"""


def build_explanation_prompt(rule_json: str, compiled_config: str) -> str:
    return f"""Given this firewall rule IR:
{rule_json}

And this compiled Cisco IOS configuration:
{compiled_config}

Write a clear, concise explanation (3-5 sentences) for a network administrator:
1. What traffic this rule affects (source, protocol/port, destination)
2. What the rule does (permit or deny)
3. Where it is applied (interface name, inbound or outbound, router)
4. Any important caveats (time restriction, TCP established, logging, exceptions noted)

Be specific. Use IP addresses and port numbers. Avoid jargon.
"""
