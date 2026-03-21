"""
Prompts for the NL2Firewall pipeline.

Prompting strategy — 7 techniques combined:
  1. Role + task definition
  2. Dynamic SNMT context injection (user-supplied network context file)
  3. Chain-of-Thought (CoT) — 7 steps with verification sub-steps (Xumi-style)
  4. Self-reflection — 6 verification checks before writing JSON
  5. Few-shot examples — 7 generic examples covering all major patterns
  6. Hard constraints — critical rules that override everything
  7. Feedback prompt — re-injects SNMT so entity re-resolution works

Improvements over v1:
  - Extended protocol vocabulary (15+ protocols)
  - Exception/negation language ('except', 'but not', 'excluding')
  - Ambiguous entity reference handling ('the router', 'any host', 'the internet')
  - Direction edge cases ('incoming from outside', 'traffic leaving the network')
  - Typo/abbreviation tolerance (from Xumi paper)
  - 'Not Found' + 'Incomplete' pattern for unresolvable entities (from Xumi paper)
  - Feedback prompt now re-injects SNMT for correct entity re-resolution
  - Ambiguity flagging with specific clarifying questions for human reviewer
"""

# ─── IR JSON Schema ────────────────────────────────────────────────────────────

IR_JSON_SCHEMA = """{
  "rule_name": "<short_snake_case_name e.g. Block_SSH_Finance_to_Servers>",
  "description": "<one sentence: what this rule does and why>",
  "intent_text": "<original intent text verbatim — do not modify>",

  "sources": [
    {
      "entity_name": "<exact name from SNMT — or 'Not Found' if unresolvable>",
      "router":      "<router from SNMT>",
      "interface":   "<interface from SNMT>",
      "prefix":      "<CIDR from SNMT>",
      "zone":        null
    }
  ],
  "destinations": [
    {
      "entity_name": "<exact name from SNMT — or 'Not Found' if unresolvable>",
      "router":      "<router from SNMT>",
      "interface":   "<interface from SNMT>",
      "prefix":      "<CIDR from SNMT>",
      "zone":        null
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
      "direction": "inbound" | "outbound",
      "zone":      null
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
Follow these SEVEN steps in order. Perform the verification sub-step after each
main step before continuing. Only output the final JSON — do not output
intermediate reasoning.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — Identify the ACTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  block / deny / prevent / disallow / forbid / restrict / stop / cannot → "deny"
  allow / permit / enable / let / authorize / grant / can / should be able → "permit"
  reject (send TCP RST or ICMP unreachable back to sender) → "reject"

  If NO action word is found:
    → assume "deny" (security default) and add to ambiguities[]:
      "No action word found — assumed deny (security default). Confirm if permit was intended."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — Resolve SOURCE from SNMT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  2a. Read the source description from the intent.
  2b. Find the matching entity in the SNMT. Tolerate:
      - Abbreviations: "Sales" → "Sales Network", "Mgmt" → "Management Network"
      - Typos: "Slaes Network" → "Sales Network"
      - Partial names: "Operations" → "Operations Network"
      - Synonyms: "the users", "user segment" → look for a user/client entity in SNMT
  2c. Copy entity_name, router, interface, prefix EXACTLY as they appear in SNMT.
  2d. Multiple source entities: list ALL of them in sources[].

  AMBIGUOUS ENTITY REFERENCES — resolve as follows:
    "any host" / "anyone" / "any source" / "all traffic"
      → source_is_any=true, sources=[]
    "the internet" / "external" / "outside" / "internet users"
      → look for an Internet/External entity in SNMT first.
        If found → use it. If not → source_is_any=true, add to ambiguities[].
    "the router" / "the gateway" / "the firewall"
      → look for all router entities in SNMT.
        If ONE router → use it.
        If MULTIPLE routers → set incomplete=true, add to ambiguities[]:
          "Ambiguous: 'the router' matches [R1, R2] in SNMT. Which router did you mean?"
    "internal network" / "internal users" / "the LAN"
      → look for any entity whose prefix is a private IP range (10.x, 172.16.x, 192.168.x).
        List all matching entities in sources[].
        Add to ambiguities[]: "Interpreted 'internal network' as [entity list] — confirm."
    "any host in X" / "all of X"
      → find entity X in SNMT, use its prefix.

  NOT FOUND — if entity cannot be resolved after all attempts:
    → add {"entity_name": "Not Found", "router": "", "interface": "", "prefix": "", "zone": null}
    → set incomplete=true
    → add to ambiguities[]: "Could not resolve '[original text]' to any entity in the network context.
      Please clarify which network segment you mean."

  Verify 2: (1) entity_name exists in SNMT or is 'Not Found'.
            (2) router, interface, prefix match SNMT exactly.
            (3) mapping is correct. If not — redo step 2.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — Resolve DESTINATION from SNMT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Same rules as Step 2. Apply the same abbreviation tolerance, ambiguous
  reference handling, and Not Found pattern.

  Additional destination patterns:
    "anywhere" / "any destination" / "the internet" (as destination)
      → destination_is_any=true, destinations=[]
    "all servers" / "the servers"
      → look for any entity with "server" in its name in SNMT.
        List all matches. If none → Not Found + add to ambiguities[].
    "the web server" / "the database server"
      → look for a matching named entity in SNMT.
        If not found → Not Found + add to ambiguities[]:
          "Could not find 'web server' in network context. Please specify which entity."

  Verify 3: Same as Verify 2 for destinations.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4 — Identify PROTOCOL and PORTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  APPLICATION → PROTOCOL + PORT MAPPING:

  Common services (memorise these exactly):
    SSH / Secure Shell          → tcp, port 22
    Telnet                      → tcp, port 23
    SMTP / email sending        → tcp, port 25
    DNS                         → BOTH tcp AND udp, port 53
                                  (add two entries in dst_ports, or note in ambiguities)
    HTTP / web (unencrypted)    → tcp, port 80
    POP3 / email retrieval      → tcp, port 110
    IMAP                        → tcp, port 143
    HTTPS / web (encrypted)     → tcp, port 443
    RDP / Remote Desktop        → tcp, port 3389
    MySQL / database            → tcp, port 3306
    MSSQL / SQL Server          → tcp, port 1433
    PostgreSQL                  → tcp, port 5432
    Oracle DB                   → tcp, port 1521
    LDAP / directory            → tcp AND udp, port 389
    SNMP (monitoring)           → udp, port 161
    SNMP traps                  → udp, port 162
    NTP / time sync             → udp, port 123
    DHCP server                 → udp, port 67
    DHCP client                 → udp, port 68
    TFTP                        → udp, port 69
    Syslog                      → udp, port 514
    FTP control                 → tcp, port 21
    FTP data                    → tcp, port 20
    BGP                         → tcp, port 179
    SMB / Windows file sharing  → tcp, port 445
    ping / ICMP echo            → icmp, icmp_type="echo", dst_ports=[]
    ping reply / echo-reply     → icmp, icmp_type="echo-reply", dst_ports=[]
    traceroute                  → icmp, icmp_type="time-exceeded", dst_ports=[]
    ICMP unreachable            → icmp, icmp_type="unreachable", dst_ports=[]

  Ambiguous service names — resolve as follows:
    "web traffic" / "web access"    → BOTH HTTP(80) AND HTTPS(443) → two dst_ports entries
    "email"                         → tcp port 25 (SMTP). Add to ambiguities[]:
                                      "Interpreted 'email' as SMTP (tcp/25). Also add POP3/IMAP if needed."
    "database traffic"              → add to ambiguities[]:
                                      "Ambiguous: 'database' could be MySQL/3306, MSSQL/1433, etc.
                                       Assumed MySQL (tcp/3306). Please confirm."
    "file sharing"                  → tcp port 445 (SMB). Add to ambiguities[].
    "all traffic" / "any protocol"  → protocol=ip, dst_ports=[]
    "high ports" / "ephemeral"      → operator=range, port=1024, port_high=65535
    "above port X"                  → operator=gt, port=X
    "below port X"                  → operator=lt, port=X
    "port X to Y"                   → operator=range, port=X, port_high=Y

  CRITICAL RULES for this step:
    - protocol=icmp → dst_ports MUST be []. Use icmp_type field instead.
    - protocol=ip   → dst_ports MUST be []. ip matches all traffic.
    - protocol=tcp/udp → dst_ports has entries with operator + port.
    - FTP needs TWO ports: port 20 (data) and port 21 (control).
      → two entries in dst_ports: [{eq,20},{eq,21}]
    - DNS needs both tcp AND udp port 53.
      → use protocol=tcp for one entry, add to ambiguities[] that UDP/53 also needed.

  Verify 4: (1) protocol keyword is valid.
            (2) port numbers are in valid range 1-65535.
            (3) ICMP has no ports. IP has no ports. TCP/UDP have ports.
            (4) range operator has port < port_high.
            If not — redo step 4.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4b — EXCEPTION / NEGATION LANGUAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Detect exception phrases: "except", "but not", "excluding", "other than",
  "unless", "apart from", "with the exception of"

  Our IR has no 'exclude' field. Handle exceptions as follows:

  Case A — Exception is a DESTINATION:
    "Block Sales from accessing all R1 interfaces EXCEPT Loopback1"
    → The primary rule blocks the non-excepted destinations.
    → Generate the rule for the BLOCKED destinations only (exclude the exception).
    → Add to ambiguities[]:
      "EXCEPTION DETECTED: Intent excludes [Loopback1] from the block.
       The generated rule only covers the blocked destinations.
       A separate PERMIT rule for [Loopback1] may be needed — review carefully."

  Case B — Exception is a SOURCE:
    "Block all traffic to Management EXCEPT from Operations Network"
    → Generate the deny rule for source_is_any=true (all sources).
    → Add to ambiguities[]:
      "EXCEPTION DETECTED: Intent allows [Operations Network] as an exception.
       This rule denies ALL sources. A preceding PERMIT rule for Operations Network
       is required to implement the exception. Review rule ordering carefully."

  Case C — Exception is a PROTOCOL/PORT:
    "Block all web traffic except HTTPS"
    → Generate deny for HTTP(80) only, not HTTPS(443).
    → Add to ambiguities[]:
      "EXCEPTION DETECTED: HTTPS (443) excluded from the block — only HTTP (80) denied."

  ALWAYS set confidence ≤ 0.8 when an exception is detected.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 5 — Infer DIRECTION and DEPLOYMENT INTERFACE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Direction meaning:
    "inbound"  = packets ENTERING an interface (arriving from outside toward router)
    "outbound" = packets LEAVING an interface (departing from router toward outside)

  DEFAULT RULE (covers 90% of cases):
    For DENY rules → place INBOUND on the SOURCE entity's gateway interface.
    Rationale: stop traffic as early as possible, closest to the source (Cisco best practice).
    Example: deny from Sales → inbound on GigabitEthernet0/0/1.40 (Sales gateway)

  DIRECTION INFERENCE from intent language:

    "Block X from accessing Y"
    "X cannot reach Y"
    "Prevent X from sending to Y"
      → INBOUND on X's gateway interface (source-closest)

    "Block traffic coming IN to Y"
    "Block inbound connections to Y"
    "Protect Y from incoming traffic"
      → INBOUND on Y's gateway interface (destination-closest)
        Add to ambiguities[]: "Interpreted 'incoming to Y' as inbound on Y's interface."

    "Block traffic going OUT from X"
    "Filter outbound traffic leaving X"
    "X should not send outbound traffic to..."
      → OUTBOUND on X's gateway interface

    "Block traffic from the internet to Y"
    "Block external/inbound connections from outside"
    "Incoming connections from internet"
      → Find the external-facing interface in SNMT (the one with internet/external entity).
        Apply INBOUND on that external interface.

    "Allow X to browse the internet" (outbound permit)
      → OUTBOUND on the external-facing interface, OR
        INBOUND on X's internal interface (equivalent for this traffic direction).
        Prefer INBOUND on X's interface (source-closest).

    "Allow return traffic / established connections"
      → tcp_established=true, INBOUND on the external interface.

  Interface selection:
    1. Find source entity in SNMT.
    2. Source entity's primary gateway interface = deployment interface for inbound rules.
    3. For outbound rules: use the interface on the path toward the destination.
    4. Multiple source entities → one InterfaceTarget per UNIQUE interface.
    5. If unclear which interface → add to ambiguities[] with specific question:
       "Ambiguous interface: could be [interface A] or [interface B]. Which did you intend?"

  Verify 5: interfaces[] must NOT be empty. direction in InterfaceTarget matches rule direction.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 6 — Check MATCHING EXTRAS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  tcp_established — set TRUE only for return/reply/established traffic:
    "allow replies to outbound connections" → true
    "permit established connections" → true
    "stateful return traffic" → true
    For all other rules → false

  icmp_type — set when protocol=icmp and a specific type is mentioned:
    "ping" / "echo request" → "echo"
    "ping reply" / "echo reply" → "echo-reply"
    "destination unreachable" → "unreachable"
    "TTL exceeded" / "traceroute" → "time-exceeded"
    "all ICMP" / icmp not specified → null (matches all ICMP types)

  time_range — set when intent mentions time constraints:
    "during business hours" → {name:"BUSINESS_HOURS", type:"periodic",
                               days:["weekdays"], time_start:"08:00", time_end:"17:00"}
    "on weekends"           → {name:"WEEKENDS", type:"periodic",
                               days:["weekends"], time_start:"00:00", time_end:"23:59"}
    "daily from 22:00 to 06:00" → {name:"NIGHTLY", type:"periodic",
                                    days:["daily"], time_start:"22:00", time_end:"06:00"}
    "until 31 December 2025"    → {name:"UNTIL_EOY", type:"absolute",
                                    days:[], time_start:"00:00", time_end:"23:59"}
    No time mentioned → null

  logging — set TRUE when intent mentions:
    "log", "audit", "track", "record", "monitor", "alert"

  Verify 6: tcp_established only if protocol=tcp.
            icmp_type only if protocol=icmp.
            time_range name is uppercase_snake_case with no spaces.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 7 — Assess CONFIDENCE, AMBIGUITIES, INCOMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  confidence calibration:
    1.0 — All entities found in SNMT, protocol explicit, direction obvious, no exceptions.
    0.9 — One minor assumption made (e.g. DNS interpreted as TCP only).
    0.8 — One exception/negation detected, or one ambiguous service name resolved.
    0.7 — Entity resolved via abbreviation/typo tolerance.
    0.6 — Significant ambiguity: entity partially matched, direction unclear.
    0.5 — Multiple significant ambiguities. Rule may be wrong.
    <0.5 → Do NOT guess. Set incomplete=true. Describe exactly what is missing
           in ambiguities[] as a specific question for the human reviewer.

  ambiguities[] — list EVERY assumption, interpretation, and question:
    - Format each ambiguity as a complete sentence the human can read and act on.
    - For unresolvable items: phrase as a question: "Which X did you mean?"
    - For exceptions: "EXCEPTION DETECTED: ..." (see Step 4b)
    - For assumptions: "Assumed X means Y — confirm if different."

  incomplete — set TRUE when:
    - Any entity is "Not Found"
    - confidence < 0.5
    - An exception was detected that requires a second rule to implement correctly
"""

# ─── Self-reflection (6 verification checks) ──────────────────────────────────

SELF_REFLECTION = """
Before writing the final JSON, verify ALL six checks. Fix any failures before output.

CHECK 1 — Entity names:
  Every entity_name in sources[] and destinations[] must EITHER:
    (a) exist exactly in the SNMT, OR
    (b) be the string "Not Found" with incomplete=true
  If any name is invented or guessed → correct it now.

CHECK 2 — Protocol-port consistency:
  protocol=icmp  → dst_ports MUST be []. icmp_type used instead.
  protocol=ip    → dst_ports MUST be [].
  protocol=tcp/udp → dst_ports entries must each have operator + port.
  tcp_established → ONLY if protocol=tcp.
  icmp_type/code → ONLY if protocol=icmp.

CHECK 3 — Interfaces not empty:
  interfaces[] must have at least one entry.
  direction in each InterfaceTarget must match the rule-level direction field.
  For inbound deny: interface = source entity's gateway from SNMT.

CHECK 4 — PortSpec structure:
  operator="any"   → port must be null, port_high must be null.
  operator="range" → port and port_high must both be set, port < port_high.
  operator="eq"/"neq"/"lt"/"gt" → port must be set, port_high must be null.
  All port numbers must be 1-65535.

CHECK 5 — Action and direction valid:
  action must be exactly one of: permit / deny / reject
  direction must be exactly one of: inbound / outbound

CHECK 6 — incomplete flag consistency:
  If any source or destination has entity_name="Not Found" → incomplete must be true.
  If incomplete=true → ambiguities[] must contain at least one clarifying question.
  If confidence < 0.5 → incomplete must be true.
"""

# ─── Few-shot examples (7 generic examples) ───────────────────────────────────

FEW_SHOT_EXAMPLES = """
=== FEW-SHOT EXAMPLES ===
These use a FICTIONAL network. Always use YOUR loaded network context.
Never copy entity names, IPs, or interfaces from these examples.

─────────────────────────────────────────────────────────
EXAMPLE 1: Simple deny, single port (SSH)
─────────────────────────────────────────────────────────
Intent: "Block the Finance department from SSH access to App Servers"

Step 1: "block" → action=deny
Step 2: "Finance department" → Finance Dept in SNMT (RouterX, Ethernet1/0, 192.168.10.0/24)
Step 3: "App Servers" → App Servers in SNMT (RouterX, Ethernet2/0, 10.0.1.0/24)
Step 4: SSH → tcp, port 22
Step 5: deny → inbound on source interface Ethernet1/0
Step 4b: No exception language detected.
Step 6: No extras.
Step 7: confidence=1.0, no ambiguities.

{
  "rule_name": "Block_SSH_Finance_to_AppServers",
  "description": "Deny SSH (tcp/22) from Finance Dept to App Servers",
  "intent_text": "Block the Finance department from SSH access to App Servers",
  "sources": [{"entity_name":"Finance Dept","router":"RouterX","interface":"Ethernet1/0","prefix":"192.168.10.0/24","zone":null}],
  "destinations": [{"entity_name":"App Servers","router":"RouterX","interface":"Ethernet2/0","prefix":"10.0.1.0/24","zone":null}],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"tcp","src_ports":[],
  "dst_ports":[{"operator":"eq","port":22,"port_high":null}],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterX","interface":"Ethernet1/0","direction":"inbound","zone":null}],
  "tcp_established":false,"icmp_type":null,"icmp_code":null,"time_range":null,
  "logging":false,"confidence":1.0,"ambiguities":[],"incomplete":false
}

─────────────────────────────────────────────────────────
EXAMPLE 2: Multiple ports (web = HTTP + HTTPS)
─────────────────────────────────────────────────────────
Intent: "Deny web access from Guest Wifi to Internal Servers"

Step 4: "web" = HTTP(80) + HTTPS(443) → two dst_ports entries.

{
  "rule_name": "Block_Web_GuestWifi_to_InternalServers",
  "description": "Deny HTTP and HTTPS from Guest Wifi to Internal Servers",
  "intent_text": "Deny web access from Guest Wifi to Internal Servers",
  "sources": [{"entity_name":"Guest Wifi","router":"RouterY","interface":"Ethernet3/0","prefix":"172.16.50.0/24","zone":null}],
  "destinations": [{"entity_name":"Internal Servers","router":"RouterY","interface":"Ethernet1/0","prefix":"10.10.0.0/24","zone":null}],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"tcp","src_ports":[],
  "dst_ports":[
    {"operator":"eq","port":80,"port_high":null},
    {"operator":"eq","port":443,"port_high":null}
  ],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterY","interface":"Ethernet3/0","direction":"inbound","zone":null}],
  "tcp_established":false,"icmp_type":null,"icmp_code":null,"time_range":null,
  "logging":false,"confidence":1.0,"ambiguities":[],"incomplete":false
}

─────────────────────────────────────────────────────────
EXAMPLE 3: ICMP ping — dst_ports MUST be empty
─────────────────────────────────────────────────────────
Intent: "Prevent Dept-B from pinging the Servers"

Step 4: ping = icmp, icmp_type="echo". NEVER put a port in dst_ports for ICMP.

{
  "rule_name": "Block_Ping_DeptB_to_Servers",
  "description": "Deny ICMP echo (ping) from Dept-B to Servers",
  "intent_text": "Prevent Dept-B from pinging the Servers",
  "sources": [{"entity_name":"Dept-B","router":"RouterX","interface":"Ethernet2/0","prefix":"192.168.20.0/24","zone":null}],
  "destinations": [{"entity_name":"Servers","router":"RouterX","interface":"Ethernet3/0","prefix":"10.0.2.0/24","zone":null}],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"icmp","src_ports":[],"dst_ports":[],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterX","interface":"Ethernet2/0","direction":"inbound","zone":null}],
  "tcp_established":false,"icmp_type":"echo","icmp_code":null,"time_range":null,
  "logging":false,"confidence":1.0,"ambiguities":[],"incomplete":false
}

─────────────────────────────────────────────────────────
EXAMPLE 4: Exception/negation language detected
─────────────────────────────────────────────────────────
Intent: "Block Sales from accessing all R1 interfaces using HTTP and HTTPS,
         but Sales can access the Loopback interface"

Step 4b: EXCEPTION DETECTED — "but Sales can access Loopback".
  → Generate rule for the BLOCKED destinations (all R1 interfaces except Loopback).
  → Flag exception in ambiguities[]. Do NOT include Loopback in destinations.

{
  "rule_name": "Block_Web_Sales_to_R1_Interfaces",
  "description": "Deny HTTP and HTTPS from Sales to R1 non-Loopback interfaces",
  "intent_text": "Block Sales from accessing all R1 interfaces using HTTP and HTTPS, but Sales can access the Loopback interface",
  "sources": [{"entity_name":"Dept-A","router":"RouterX","interface":"Ethernet1/0","prefix":"192.168.10.0/24","zone":null}],
  "destinations": [
    {"entity_name":"Gateway Eth1","router":"RouterX","interface":"Ethernet1/0","prefix":"10.0.0.1/32","zone":null},
    {"entity_name":"Gateway Eth2","router":"RouterX","interface":"Ethernet2/0","prefix":"10.0.1.1/32","zone":null}
  ],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"tcp","src_ports":[],
  "dst_ports":[
    {"operator":"eq","port":80,"port_high":null},
    {"operator":"eq","port":443,"port_high":null}
  ],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterX","interface":"Ethernet1/0","direction":"inbound","zone":null}],
  "tcp_established":false,"icmp_type":null,"icmp_code":null,"time_range":null,
  "logging":false,"confidence":0.8,
  "ambiguities":[
    "EXCEPTION DETECTED: Intent excludes the Loopback interface from the block. The generated rule only covers non-Loopback interfaces. A separate PERMIT rule for Loopback access may be needed — review carefully."
  ],
  "incomplete":false
}

─────────────────────────────────────────────────────────
EXAMPLE 5: Ambiguous entity — Not Found
─────────────────────────────────────────────────────────
Intent: "Block the database server from accepting connections from Guest Wifi"

Step 3: "the database server" — look in SNMT. No entity with 'database' or 'server' found.
  → entity_name="Not Found", incomplete=true, add clarifying question to ambiguities[].

{
  "rule_name": "Block_GuestWifi_to_DatabaseServer",
  "description": "Deny connections from Guest Wifi to the database server (destination unresolved)",
  "intent_text": "Block the database server from accepting connections from Guest Wifi",
  "sources": [{"entity_name":"Guest Wifi","router":"RouterY","interface":"Ethernet3/0","prefix":"172.16.50.0/24","zone":null}],
  "destinations": [{"entity_name":"Not Found","router":"","interface":"","prefix":"","zone":null}],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"ip","src_ports":[],"dst_ports":[],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterY","interface":"Ethernet3/0","direction":"inbound","zone":null}],
  "tcp_established":false,"icmp_type":null,"icmp_code":null,"time_range":null,
  "logging":false,"confidence":0.4,
  "ambiguities":[
    "Could not resolve 'the database server' to any entity in the network context. Which network segment or IP address is the database server? Please specify."
  ],
  "incomplete":true
}

─────────────────────────────────────────────────────────
EXAMPLE 6: Time-based rule + logging
─────────────────────────────────────────────────────────
Intent: "Block and log social media traffic from Office during business hours on weekdays"

Step 6: time_range present. logging=true.

{
  "rule_name": "Block_Log_SocialMedia_Office_BusinessHours",
  "description": "Deny and log social media (tcp/443) from Office during business hours",
  "intent_text": "Block and log social media traffic from Office during business hours on weekdays",
  "sources": [{"entity_name":"Office Network","router":"RouterX","interface":"Ethernet1/0","prefix":"10.1.0.0/24","zone":null}],
  "destinations": [{"entity_name":"Internet","router":"RouterX","interface":"Ethernet0/0","prefix":"0.0.0.0/0","zone":null}],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"tcp","src_ports":[],
  "dst_ports":[{"operator":"eq","port":443,"port_high":null}],
  "action":"deny","direction":"inbound",
  "interfaces":[{"router":"RouterX","interface":"Ethernet1/0","direction":"inbound","zone":null}],
  "tcp_established":false,"icmp_type":null,"icmp_code":null,
  "time_range":{"name":"BUSINESS_HOURS","type":"periodic","days":["weekdays"],"time_start":"08:00","time_end":"17:00"},
  "logging":true,"confidence":0.9,
  "ambiguities":["'Social media' interpreted as HTTPS (tcp/443) — confirm if additional ports needed."],
  "incomplete":false
}

─────────────────────────────────────────────────────────
EXAMPLE 7: TCP established (return traffic) + direction edge case
─────────────────────────────────────────────────────────
Intent: "Allow return traffic for web browsing initiated by Internal Network — block new inbound connections from outside"

Step 5: "incoming from outside" → inbound on external interface.
Step 6: tcp_established=true (return traffic only).

{
  "rule_name": "Permit_Established_Web_Return_External",
  "description": "Permit only established TCP return traffic inbound on external interface",
  "intent_text": "Allow return traffic for web browsing initiated by Internal Network — block new inbound connections from outside",
  "sources": [{"entity_name":"Internet","router":"RouterX","interface":"Ethernet0/0","prefix":"0.0.0.0/0","zone":null}],
  "destinations": [{"entity_name":"Internal Network","router":"RouterX","interface":"Ethernet1/0","prefix":"10.0.0.0/8","zone":null}],
  "source_is_any":false,"destination_is_any":false,
  "protocol":"tcp","src_ports":[],"dst_ports":[],
  "action":"permit","direction":"inbound",
  "interfaces":[{"router":"RouterX","interface":"Ethernet0/0","direction":"inbound","zone":null}],
  "tcp_established":true,"icmp_type":null,"icmp_code":null,"time_range":null,
  "logging":false,"confidence":0.9,
  "ambiguities":["Split into two rules: (1) permit outbound from Internal to Internet, (2) permit established return — this is rule 2."],
  "incomplete":false
}

=== END FEW-SHOT EXAMPLES ===
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

=== YOUR ROLE ===
- You are a precise parser and resolver. Translate intent faithfully.
- Do NOT add restrictions the user did not ask for.
- Do NOT be more permissive than the intent states.
- Use ONLY entity names, IPs, and interfaces from the network context below.
- If you cannot resolve something, say so clearly in ambiguities[] — do not guess.
- Tolerate typos and abbreviations in entity names — resolve to SNMT names.

{snmt_block}

=== OUTPUT FORMAT ===
Output ONLY valid JSON conforming exactly to this schema.
No markdown, no backticks, no explanation text outside the JSON object.

{IR_JSON_SCHEMA}

=== INSTRUCTIONS ===
{COT_STEPS}

=== SELF-REFLECTION (run before writing JSON) ===
{SELF_REFLECTION}

=== EXAMPLES ===
{FEW_SHOT_EXAMPLES}

=== CRITICAL RULES (these override everything else) ===
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


def build_feedback_prompt(
    original_intent: str,
    wrong_ir_json: str,
    human_feedback: str,
    snmt_block: str,          # re-injected so LLM can re-resolve entities
) -> str:
    """
    Build the correction prompt for the feedback loop.

    SNMT is re-injected here so the LLM can correctly resolve any entity
    names mentioned in the human feedback without hallucinating.
    """
    return f"""The previous firewall rule IR was incorrect. The human reviewer provided feedback.
Apply the feedback and generate a corrected IR.

=== ORIGINAL INTENT ===
{original_intent}

=== PREVIOUS (INCORRECT) IR ===
{wrong_ir_json}

=== HUMAN FEEDBACK ===
{human_feedback}

=== NETWORK CONTEXT (use this to re-resolve any entities mentioned in feedback) ===
{snmt_block}

=== YOUR TASK ===
1. Identify exactly what the feedback is asking to change.
2. Re-apply the 7-step CoT reasoning with the correction in mind.
3. Re-check all 6 self-reflection checks.
4. Output ONLY the corrected JSON. No explanation outside the JSON.

If the feedback resolves a previous ambiguity or "Not Found" entity:
  - Update the entity with the correct SNMT values.
  - Remove the resolved ambiguity from ambiguities[].
  - Update incomplete=false if all entities are now resolved.
  - Increase confidence accordingly.
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