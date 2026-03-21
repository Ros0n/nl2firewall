# NL2Firewall — Natural Language to Cisco ACL

Translates natural language network security intents into correct, deployable Cisco IOS
extended IPv4 ACL configurations. Verified by Batfish before output.

```
"Block Sales from SSHing to Management"
          ↓
access-list 101 deny tcp 10.40.0.0 0.0.0.255 10.20.0.0 0.0.0.255 eq 22
access-list 101 permit ip any any

interface GigabitEthernet0/0/1.40
 ip access-group 101 in
```

---

## Architecture

```
Natural Language Intent
        │
        ▼
  ┌─────────────┐   SNMT (entity→prefix lookup)
  │  Resolver   │◄──────────────────────────────
  │   Agent     │   CoT + Self-Reflection prompts
  └──────┬──────┘
         │  resolved entities
         ▼
  ┌─────────────┐
  │  IR Builder │   Pydantic ACL_IR validation
  │   Agent     │   lists: sources × destinations × ports
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │   Human     │   Review IR JSON
  │   Review    │   Approve or send feedback (loops back)
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │   Linter    │   Structural warnings (advisory)
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Safety     │   Hard block: any→any permit, low confidence, etc.
  │   Gate      │
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Compiler   │   Enumerates IR → Cisco ACL lines
  │  (custom)   │   src × dst × port = N lines
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Batfish    │   Snapshot verification: parse, shadowing, reachability
  │  Verify     │
  └──────┬──────┘
         │
         ▼
  Deployable Config + Explanation
```

**Key design decisions:**
- No Aerleon — custom Python compiler (50 lines, fully deterministic)
- No TMF bitarrays — Batfish handles conflict/shadowing at our scale
- No deployment optimization — single topology, clear interface placement
- LLM = Gemini 2.0 Flash (free tier); structured JSON output only
- Pipeline = LangGraph state machine with human-in-the-loop interrupt

---

## SNMT (Semantics-Network Mapping Table)

The SNMT is the critical grounding table from Xumi §4.1. It maps entity names
to concrete IP prefixes and gateway interfaces so the LLM never has to guess:

| Entity           | Prefix          | Gateway Interface          |
|------------------|-----------------|---------------------------|
| Sales_Network    | 10.40.0.0/24    | R1 GigabitEthernet0/0/1.40 |
| Operations_Network| 10.30.0.0/24   | R1 GigabitEthernet0/0/1.30 |
| Management_Network| 10.20.0.0/24   | R1 GigabitEthernet0/0/1.20 |
| Internet         | 172.16.1.0/24   | R1 Loopback1               |
| PC_A             | 10.30.0.10/32   | R1 GigabitEthernet0/0/1.30 |
| PC_B             | 10.40.0.10/32   | R1 GigabitEthernet0/0/1.40 |
| ...              | ...             | ...                        |

Aliases are handled by the LLM — "Sales", "VLAN 40", "PC-B network" all resolve
to `Sales_Network` through the CoT reasoning steps.

---

## Quickstart

### 1. Prerequisites

- Python 3.11+
- Docker & Docker Compose (for Batfish)
- Groq API key (GPT 120b OSS): 

### 2. Setup

```bash
git clone <repo>
cd nl2firewall

# Create .env
cp .env.example .env
# Edit .env and set: GROQ_API_KEY=your_key_here

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Start Batfish

```bash
cd docker
docker-compose up batfish -d
# Wait ~30 seconds for Batfish to start
```

### 4. Run the API

```bash
# From project root
python main.py
# API available at http://localhost:8000
# Interactive docs at http://localhost:8000/docs
```

### 5. Run tests (no API key needed)

```bash
python3 tests/standalone_test.py
# → 72 tests, all passing
```

---

## Usage

### Submit an intent

```bash
curl -X POST http://localhost:8000/api/intents \
  -H "Content-Type: application/json" \
  -d '{"intent": "Block SSH from the Sales network to the Management network"}'
```

Response:
```json
{
  "session_id": "abc-123",
  "status": "pending",
  "message": "Pipeline started. Poll GET /api/intents/abc-123 for status."
}
```

### Poll for status

```bash
curl http://localhost:8000/api/intents/abc-123
```

When `status == "awaiting_review"`, the `resolved_ir` field shows the LLM's
interpretation as structured JSON. Review it, then approve or provide feedback.

### Approve the IR

```bash
curl -X POST http://localhost:8000/api/intents/45ec3b0a-9ea3-4e14-89f6-5c597909cd65/review \
  -H "Content-Type: application/json" \
  -d '{"approve": true}'
```

### Provide feedback (loops back to LLM)

```bash
curl -X POST http://localhost:8000/api/intents/45ec3b0a-9ea3-4e14-89f6-5c597909cd65/review 
  -H "Content-Type: application/json" 
  -d '{"approve": false, "feedback": "The destination should be Management_Network not Operations_Network"}'
```

### Get final config

```bash
curl http://localhost:8000/api/intents/abc-123/config
```

Response:
```json
{
  "intent": "Block SSH from the Sales network to the Management network",
  "config": "access-list 101 remark Deny SSH from Sales to Management\naccess-list 101 deny tcp 10.40.0.0 0.0.0.255 10.20.0.0 0.0.0.255 eq 22\naccess-list 101 permit ip any any\n\ninterface GigabitEthernet0/0/1.40\n ip access-group 101 in",
  "explanation": "This ACL denies TCP port 22 (SSH) traffic originating from the Sales VLAN (10.40.0.0/24) destined for the Management VLAN (10.20.0.0/24). It is applied inbound on R1's GigabitEthernet0/0/1.40 sub-interface, which is the Sales network gateway. All other traffic from Sales is permitted by the catch-all rule.",
  "acl_number": 101,
  "interface": "GigabitEthernet0/0/1.40",
  "line_count": 2,
  "batfish_passed": true
}
```


---

## Project Structure

```
nl2firewall/
├── app/
│   ├── api/
│   │   └── main.py           # FastAPI app, endpoints, session management
│   ├── agents/
│   │   ├── pipeline.py       # LangGraph graph definition (all 8 nodes)
│   │   ├── prompts.py        # System prompt, CoT steps, few-shot examples
│   │   └── gemini_client.py  # Gemini API wrapper with JSON extraction
│   ├── compiler/
│   │   └── cisco.py          # Custom Cisco ACL compiler (enumeration)
│   ├── models/
│   │   └── ir.py             # ACL_IR, PipelineState, all Pydantic models
│   ├── safety/
│   │   ├── gate.py           # Safety Gate (hard blocker)
│   │   └── linter.py         # Structural linter (advisory)
│   ├── snmt/
│   │   └── loader.py         # SNMT YAML loader + query API
│   ├── verification/
│   │   └── batfish_manager.py # Batfish snapshot + verification
│   └── core/
│       └── config.py         # Pydantic settings from .env
├── data/
│   ├── snmt/
│   │   └── ccna_lab.yaml     # SNMT for CCNA extended ACL lab
│   └── topology/
│       ├── R1.cfg            # Base R1 config for Batfish
│       └── R2.cfg            # Base R2 config for Batfish
├── tests/
│   ├── standalone_test.py    # 72 stdlib-only tests (no pip needed)
│   └── test_pipeline.py      # pytest tests (requires pip install)
├── docker/
│   ├── docker-compose.yml    # Batfish + API services
│   └── Dockerfile
├── main.py                   # Entry point
├── requirements.txt
└── .env.example
```

---

