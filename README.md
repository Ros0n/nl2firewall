# NL2Firewall — Natural Language to Cisco ACL

Translates natural language network security intents into correct ACL configurations. Verified by Batfish before output.

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
  -d '{"intent": "your_intent_message"}'
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
  -d '{"approve": false, "feedback": "your_feedback_message"}'
```

### Get final config

```bash
curl http://localhost:8000/api/intents/abc-123/config
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


