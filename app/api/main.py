"""
FastAPI application entry point.

Endpoints:
  POST /api/intents           — Submit a new intent, start pipeline
  GET  /api/intents/{id}      — Get current pipeline state
  POST /api/intents/{id}/review  — Submit human review (approve or feedback)
  GET  /api/intents/{id}/config  — Get final compiled config
  GET  /api/snmt              — Get SNMT as JSON (for UI display)
  GET  /health                — Health check

Pipeline execution model:
  - Each intent gets a unique session_id (UUID)
  - Pipeline runs asynchronously in a background task
  - LangGraph checkpointer stores state in memory (keyed by session_id)
  - Pipeline pauses at await_review node waiting for POST /review
  - Frontend polls GET /intents/{id} to track progress
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.agents.pipeline import get_pipeline
from app.core.config import get_settings
from app.models.ir import PipelineState, PipelineStatus
from app.snmt.loader import (
    SNMTLoader,
    get_active_snmt,
    require_snmt,
    reset_snmt,
    set_active_snmt,
    try_autoload,
)

logger = logging.getLogger(__name__)

# ─── In-memory session store ─────────────────────────────────────────────────
# Maps session_id → PipelineState
# In production this would be Redis or a database
_sessions: dict[str, PipelineState] = {}


# ─── Lifespan ────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    logger.info(f"Starting {settings.app_name}")

    # Try to auto-load network context from data/networks/ (dev convenience)
    # In production, upload via POST /api/network
    networks_dir = Path(settings.networks_dir)
    snmt = try_autoload(networks_dir)
    if snmt:
        logger.info(
            f"Auto-loaded network context: '{snmt.network_name}' ({len(snmt.get_all_entities())} entities)"
        )
    else:
        logger.info(
            "No network context loaded — upload via POST /api/network before submitting intents"
        )

    # Pre-compile LangGraph pipeline
    get_pipeline()
    logger.info("LangGraph pipeline compiled")

    yield

    logger.info("Shutting down")


# ─── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="NL2Firewall API",
    description="Natural Language to Cisco ACL configuration pipeline",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Static files (React build output) ───────────────────────────────────────
_STATIC_DIR = Path(__file__).parent.parent / "static"
if _STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=_STATIC_DIR / "assets"), name="assets")


# ─── Request / Response models ───────────────────────────────────────────────


class IntentRequest(BaseModel):
    intent: str
    auto_approve: bool = False  # If True, skip human review (for testing)


class ReviewRequest(BaseModel):
    approve: bool = True
    feedback: str = ""  # If not approving, provide feedback


class IntentResponse(BaseModel):
    session_id: str
    status: str
    current_step: str
    message: str


class PipelineStateResponse(BaseModel):
    session_id: str
    status: str
    current_step: str
    intent_text: str
    feedback_rounds: int
    error: str | None

    # Stage results
    resolved_rule: dict | None = None
    lint_issues: list[dict] | None = None
    safety_result: dict | None = None
    final_config: str | None = None
    explanation: str | None = None
    batfish_summary: str | None = None
    batfish_report: dict | None = None
    # Disambiguation / ambiguity surfacing
    clarification_needed: bool = False
    clarification_questions: list[str] = []
    incomplete: bool = False

    # Metadata
    estimated_line_count: int | None = None


# ─── Background pipeline runner ──────────────────────────────────────────────


async def _run_pipeline(session_id: str, initial_state: PipelineState) -> None:
    """
    Runs the LangGraph pipeline for a given session.
    LangGraph receives the PipelineState directly (it is the graph schema).
    After each node, we pull the current checkpointed state back into _sessions
    so the API can serve live status.
    """
    pipeline = get_pipeline()
    config = {"configurable": {"thread_id": session_id}}

    try:
        logger.info(f"[{session_id}] Starting pipeline phase 1")

        async for event in pipeline.astream(initial_state, config=config):
            # Sync latest checkpointed state back to our session store
            _sync_from_checkpoint(session_id, pipeline, config)
            node_name = list(event.keys())[0] if event else "unknown"
            logger.debug(f"[{session_id}] Node '{node_name}' completed")

        # After streaming ends, do one final sync
        _sync_from_checkpoint(session_id, pipeline, config)

        # If still showing RESOLVING/BUILDING_IR it means we hit the interrupt
        current = _sessions.get(session_id)
        if current and current.status not in (
            PipelineStatus.COMPLETE,
            PipelineStatus.FAILED,
            PipelineStatus.BLOCKED,
        ):
            current.status = PipelineStatus.AWAITING_REVIEW
            current.current_step = "Awaiting human review — approve or provide feedback"

        logger.info(f"[{session_id}] Pipeline phase 1 complete / interrupted")

    except Exception as e:
        logger.exception(f"[{session_id}] Pipeline error in phase 1: {e}")
        state = _sessions.get(session_id)
        if state:
            state.status = PipelineStatus.FAILED
            state.error = str(e)


# Per-session lock: prevents two concurrent _resume_pipeline calls for the same session
# (e.g. user double-clicks Approve while the pipeline is still running).
_resume_locks: dict[str, bool] = {}


async def _resume_pipeline(session_id: str, approved: bool, feedback: str) -> None:
    """Resume the pipeline after human review."""

    # ── Concurrency guard ────────────────────────────────────────────────────
    # If a resume is already in-flight for this session, ignore the duplicate.
    if _resume_locks.get(session_id):
        logger.warning(f"[{session_id}] Duplicate resume ignored — already running")
        return
    _resume_locks[session_id] = True

    pipeline = get_pipeline()
    config = {"configurable": {"thread_id": session_id}}

    state = _sessions.get(session_id)
    if not state:
        logger.error(f"[{session_id}] Session not found for resume")
        _resume_locks.pop(session_id, None)
        return

    # Remember whether this was a feedback round (not an approval).
    # If it fails we can restore AWAITING_REVIEW so the user can retry.
    is_feedback_round = not approved and bool(feedback)

    # Mark as RUNNING immediately so the frontend stops showing the review panel
    # and the API's review guard rejects any concurrent approve clicks.
    state.status = (
        PipelineStatus.RESOLVING if is_feedback_round else PipelineStatus.LINTING
    )
    state.current_step = (
        "Re-resolving with your feedback…" if is_feedback_round else "Running pipeline…"
    )
    state.error = None

    # Patch the checkpointed state with the review decision
    state.human_feedback = "approve" if approved else feedback
    if is_feedback_round:
        state.feedback_rounds += 1
    pipeline.update_state(
        config,
        {
            "human_feedback": state.human_feedback,
            "feedback_rounds": state.feedback_rounds,
        },
    )

    try:
        logger.info(f"[{session_id}] Resuming pipeline (approved={approved})")

        async for event in pipeline.astream(None, config=config):
            node_name = list(event.keys())[0] if event else "unknown"
            logger.debug(f"[{session_id}] Node '{node_name}' completed (resume)")

            # Only sync progress fields during streaming — never let mid-stream
            # checkpoint writes flip the status to AWAITING_REVIEW, which would
            # re-show the review panel while the pipeline is still running.
            _sync_progress_only(session_id, pipeline, config)

        # Streaming finished — do ONE authoritative final sync + status resolution.
        _sync_from_checkpoint(session_id, pipeline, config)

        snap = pipeline.get_state(config)
        next_nodes = list(snap.next) if snap and snap.next else []

        s = _sessions.get(session_id)
        if not s:
            return

        if "await_review" in next_nodes:
            # Graph is paused at the interrupt: feedback loop re-resolved,
            # needs another human review pass.
            s.status = PipelineStatus.AWAITING_REVIEW
            s.current_step = "Awaiting human review — approve or provide feedback"
            s.error = None
            logger.info(f"[{session_id}] Pipeline interrupted again at await_review")
        else:
            # Pipeline ran to completion (COMPLETE / FAILED / BLOCKED all set
            # by the nodes themselves and already synced above).
            logger.info(f"[{session_id}] Pipeline resume complete (status={s.status})")

    except Exception as e:
        logger.exception(f"[{session_id}] Pipeline error in resume: {e}")
        s = _sessions.get(session_id)
        if s:
            if is_feedback_round:
                # Feedback re-resolve failed — restore AWAITING_REVIEW so the
                # user can correct their feedback or approve the previous IR.
                s.status = PipelineStatus.AWAITING_REVIEW
                s.current_step = "Awaiting human review — approve or provide feedback"
                s.error = (
                    f"Re-resolve failed: {str(e)[:200]}. "
                    "Correct your feedback or approve the previous rule."
                )
                logger.warning(
                    f"[{session_id}] Feedback re-resolve failed — restored to AWAITING_REVIEW: {e}"
                )
            else:
                s.status = PipelineStatus.FAILED
                s.error = str(e)
    finally:
        _resume_locks.pop(session_id, None)


def _sync_from_checkpoint(session_id: str, pipeline, config: dict) -> None:
    """
    Full sync: pull ALL fields from the LangGraph checkpoint into _sessions.
    Call this only ONCE after streaming ends — never mid-stream during a resume,
    because mid-stream checkpoints can contain intermediate statuses (e.g.
    AWAITING_REVIEW from the await_review node transiting through) that would
    incorrectly re-show the review panel while the pipeline is still running.
    """
    try:
        snap = pipeline.get_state(config)
        if snap and snap.values:
            vals = snap.values
            if isinstance(vals, PipelineState):
                _sessions[session_id] = vals
            elif isinstance(vals, dict):
                existing = _sessions.get(session_id)
                if existing:
                    for k, v in vals.items():
                        if hasattr(existing, k) and v is not None:
                            try:
                                setattr(existing, k, v)
                            except Exception:
                                pass
    except Exception as e:
        logger.debug(f"Checkpoint sync failed (non-fatal): {e}")


def _sync_progress_only(session_id: str, pipeline, config: dict) -> None:
    """
    Partial sync used MID-STREAM during _resume_pipeline.

    Only updates safe progress fields (current_step, resolved_rule, lint_result,
    safety_result, compiled_acl, batfish_result). Deliberately NEVER overwrites
    status — that is set authoritatively only after streaming ends so we never
    flash AWAITING_REVIEW mid-stream and re-enable the Approve button.
    """
    _PROGRESS_FIELDS = {
        "current_step",
        "resolved_rule",
        "lint_result",
        "safety_result",
        "compiled_acl",
        "batfish_result",
        "error",
    }
    try:
        snap = pipeline.get_state(config)
        if not (snap and snap.values):
            return
        vals = snap.values
        existing = _sessions.get(session_id)
        if not existing:
            return
        if isinstance(vals, PipelineState):
            for field in _PROGRESS_FIELDS:
                v = getattr(vals, field, None)
                if v is not None:
                    try:
                        setattr(existing, field, v)
                    except Exception:
                        pass
        elif isinstance(vals, dict):
            for k, v in vals.items():
                if k in _PROGRESS_FIELDS and hasattr(existing, k) and v is not None:
                    try:
                        setattr(existing, k, v)
                    except Exception:
                        pass
    except Exception as e:
        logger.debug(f"Progress sync failed (non-fatal): {e}")


def _state_to_response(state: PipelineState) -> PipelineStateResponse:
    """Convert PipelineState to API response model."""
    return PipelineStateResponse(
        session_id=state.session_id,
        status=state.status.value
        if hasattr(state.status, "value")
        else str(state.status),
        current_step=state.current_step,
        intent_text=state.intent_text,
        feedback_rounds=state.feedback_rounds,
        error=state.error,
        resolved_rule=state.resolved_rule.model_dump() if state.resolved_rule else None,
        lint_issues=[i.model_dump() for i in state.lint_result.issues]
        if state.lint_result
        else None,
        safety_result=state.safety_result.model_dump() if state.safety_result else None,
        final_config=state.final_config,
        explanation=state.explanation,
        batfish_summary=state.batfish_result.summary()
        if state.batfish_result
        else None,
        batfish_report=state.batfish_result.raw_output
        if state.batfish_result
        else None,
        clarification_needed=(
            bool(state.resolved_rule and state.resolved_rule.ambiguities)
            or bool(state.resolved_rule and state.resolved_rule.incomplete)
        )
        if state.resolved_rule
        else False,
        clarification_questions=(
            state.resolved_rule.ambiguities if state.resolved_rule else []
        ),
        incomplete=(state.resolved_rule.incomplete if state.resolved_rule else False),
        estimated_line_count=(
            state.resolved_rule.estimated_line_count() if state.resolved_rule else None
        ),
    )


# ─── Endpoints ───────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    return {"status": "ok", "service": "nl2firewall"}


@app.get("/api/network")
async def get_network_context():
    """Return the currently loaded network context as JSON."""
    snmt = get_active_snmt()
    if not snmt:
        return {
            "loaded": False,
            "message": "No network context loaded. POST /api/network to upload one.",
        }
    return {"loaded": True, **snmt.to_compact_json()}


@app.post("/api/network")
async def upload_network_context(file: UploadFile = File(...)):
    """
    Upload a network context YAML file.
    This loads the SNMT and makes it available for all subsequent intent submissions.

    The file must be a valid YAML with this structure:
        network_name: "My Network"
        entities:
          Entity Name:
            gateways:
              - router: "RouterX"
                interface: "Ethernet1/0"
                prefix: "192.168.10.0/24"
    """
    if not file.filename.endswith((".yaml", ".yml")):
        raise HTTPException(status_code=400, detail="File must be a .yaml or .yml file")

    content_bytes = await file.read()
    try:
        yaml_content = content_bytes.decode("utf-8")
        snmt = SNMTLoader.from_string(yaml_content)
        set_active_snmt(snmt)
        logger.info(
            f"Network context loaded via API: '{snmt.network_name}' ({len(snmt.get_all_entities())} entities)"
        )
        return {
            "loaded": True,
            "network_name": snmt.network_name,
            "entity_count": len(snmt.get_all_entities()),
            "entities": snmt.get_entity_names(),
            "message": f"Network context '{snmt.network_name}' loaded successfully.",
        }
    except (ValueError, KeyError) as e:
        raise HTTPException(
            status_code=422, detail=f"Invalid network context file: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to load network context: {str(e)}"
        )


@app.post("/api/intents", response_model=IntentResponse)
async def submit_intent(
    request: IntentRequest,
    background_tasks: BackgroundTasks,
):
    """
    Submit a natural language intent.
    Starts the pipeline asynchronously.
    Returns a session_id for polling.
    """
    if not request.intent.strip():
        raise HTTPException(status_code=400, detail="Intent cannot be empty")

    session_id = str(uuid.uuid4())
    state = PipelineState(
        intent_text=request.intent.strip(),
        session_id=session_id,
        status=PipelineStatus.PENDING,
        current_step="Initializing pipeline",
    )
    _sessions[session_id] = state

    # If auto_approve, we'll approve automatically after IR is built
    if request.auto_approve:
        state.human_feedback = "approve"

    background_tasks.add_task(_run_pipeline, session_id, state)

    return IntentResponse(
        session_id=session_id,
        status="pending",
        current_step="Pipeline starting",
        message=f"Pipeline started. Poll GET /api/intents/{session_id} for status.",
    )


@app.get("/api/intents/{session_id}", response_model=PipelineStateResponse)
async def get_intent_status(session_id: str):
    """Get the current state of a pipeline session."""
    state = _sessions.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return _state_to_response(state)


@app.post("/api/intents/{session_id}/review", response_model=IntentResponse)
async def review_intent(
    session_id: str,
    request: ReviewRequest,
    background_tasks: BackgroundTasks,
):
    """
    Submit human review decision.

    Two use cases:
    1. Approve: set approve=true — pipeline continues to compile.
    2. Clarify ambiguities: set approve=false, feedback = your answers to the
       clarification_questions shown in the status response. The LLM will
       re-resolve unresolved entities using your answers.

    If the status shows clarification_needed=true, read clarification_questions
    first and answer them in the feedback field before approving.
    """
    state = _sessions.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    status_val = (
        state.status.value if hasattr(state.status, "value") else str(state.status)
    )

    # If a resume is already in-flight (concurrency guard), reject immediately.
    if _resume_locks.get(session_id):
        raise HTTPException(
            status_code=409,
            detail="A resume is already in progress for this session. Please wait.",
        )

    if status_val != "awaiting_review":
        # Give a human-readable explanation based on the actual status
        if status_val == "failed":
            error_hint = state.error or "An unknown error occurred."
            detail = (
                f"The pipeline failed and is no longer awaiting review. "
                f"Reason: {error_hint} "
                f"Please submit a new intent."
            )
        elif status_val == "complete":
            detail = "This pipeline has already completed. Use GET /config to retrieve the result."
        elif status_val == "blocked":
            detail = f"This pipeline was blocked by the safety gate: {state.error or 'see session details'}."
        elif status_val in (
            "pending",
            "resolving",
            "building_ir",
            "linting",
            "safety_check",
            "compiling",
            "verifying",
        ):
            detail = (
                f"The pipeline is still running (status: {status_val}). Please wait."
            )
        else:
            detail = f"Session is not awaiting review (current status: {status_val})."
        raise HTTPException(status_code=400, detail=detail)

    background_tasks.add_task(
        _resume_pipeline,
        session_id,
        request.approve,
        request.feedback,
    )

    action = "approved" if request.approve else "feedback submitted"
    return IntentResponse(
        session_id=session_id,
        status="resuming",
        current_step=f"Review {action} — pipeline resuming",
        message=f"Review {action}. Pipeline will continue.",
    )


@app.get("/api/intents/{session_id}/config")
async def get_final_config(session_id: str):
    """Get the final deployable Cisco config for a completed pipeline."""
    state = _sessions.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    status_val = (
        state.status.value if hasattr(state.status, "value") else str(state.status)
    )
    if status_val != "complete":
        raise HTTPException(
            status_code=400, detail=f"Pipeline not complete yet (status: {status_val})"
        )

    return {
        "session_id": session_id,
        "intent": state.intent_text,
        "config": state.final_config,
        "explanation": state.explanation,
        "acl_name": state.compiled_acl.acl_name if state.compiled_acl else None,
        "interface": state.compiled_acl.interface if state.compiled_acl else None,
        "line_count": len(state.compiled_acl.lines) if state.compiled_acl else 0,
        "batfish_passed": state.batfish_result.passed if state.batfish_result else None,
        "batfish_report": state.batfish_result.raw_output
        if state.batfish_result
        else None,
        "batfish_flow_traces": state.batfish_result.flow_traces()
        if state.batfish_result
        else [],
    }


@app.get("/api/sessions")
async def list_sessions():
    """List all active sessions (for debugging)."""
    return {
        sid: {
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "intent": s.intent_text[:60],
            "feedback_rounds": s.feedback_rounds,
        }
        for sid, s in _sessions.items()
    }


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Clean up a session."""
    if session_id in _sessions:
        del _sessions[session_id]
        return {"deleted": session_id}
    raise HTTPException(status_code=404, detail="Session not found")


# ─── SPA catch-all — serve React index.html for all non-API routes ────────────
# Must be registered LAST so it doesn't shadow any API routes.


@app.get("/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    """Serve the React SPA for any route that isn't an API endpoint."""
    index = _STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"detail": "Frontend not built. Run: cd frontend && npm run build"}
