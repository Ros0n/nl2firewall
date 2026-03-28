import { useState, useEffect, useRef, useCallback } from "react";
import {
  submitIntent,
  getIntentStatus,
  reviewIntent,
  getFinalConfig,
} from "../api/client.js";

// Statuses where the pipeline is actively running server-side.
// While in these states the review panel must not be shown and
// approve/feedback buttons must be disabled.
const RUNNING_STATUSES = new Set([
  "pending",
  "resolving",
  "building_ir",
  "linting",
  "safety_check",
  "compiling",
  "verifying",
  "resuming",
]);

// Pipeline statuses that mean "still running — keep polling"
const POLLING_STATUSES = new Set([
  "pending",
  "resolving",
  "building_ir",
  "linting",
  "safety_check",
  "compiling",
  "verifying",
  "resuming",
]);

// Terminal statuses — stop polling
const TERMINAL_STATUSES = new Set(["complete", "failed", "blocked"]);

const POLL_INTERVAL_MS = 1500;

export function usePipeline() {
  // ── Session list (each entry is one full intent turn in the chat) ──────────
  // Shape of one session entry:
  // {
  //   id: string (uuid),
  //   intent: string,
  //   phase: 'running' | 'awaiting_review' | 'complete' | 'failed' | 'blocked',
  //   pipelineState: object | null,   // raw API response from GET /api/intents/{id}
  //   finalConfig: object | null,     // from GET /api/intents/{id}/config
  //   error: string | null,
  //   reviewLocked: bool,             // true while an approve/feedback POST is in-flight
  // }
  const [sessions, setSessions] = useState([]);
  const [networkContext, setNetworkContext] = useState(null); // { network_name, entity_count }
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Map of sessionId → polling interval ref
  const pollingRefs = useRef({});

  // ── Helpers ────────────────────────────────────────────────────────────────

  const updateSession = useCallback((sessionId, patch) => {
    setSessions((prev) =>
      prev.map((s) => (s.id === sessionId ? { ...s, ...patch } : s)),
    );
  }, []);

  const stopPolling = useCallback((sessionId) => {
    if (pollingRefs.current[sessionId]) {
      clearInterval(pollingRefs.current[sessionId]);
      delete pollingRefs.current[sessionId];
    }
  }, []);

  // ── Poll one session ───────────────────────────────────────────────────────

  const pollSession = useCallback(
    async (sessionId) => {
      let state;
      try {
        state = await getIntentStatus(sessionId);
      } catch (err) {
        updateSession(sessionId, {
          phase: "failed",
          error: err.message,
        });
        stopPolling(sessionId);
        return;
      }

      const status = state.status;

      // Always keep latest pipeline state in sync.
      // If the server says the pipeline is actively running, force phase='running'
      // so the review panel is hidden and buttons stay disabled — even if a
      // previous poll briefly surfaced 'awaiting_review' mid-stream.
      if (RUNNING_STATUSES.has(status)) {
        updateSession(sessionId, { pipelineState: state, phase: "running" });
        return;
      }

      updateSession(sessionId, { pipelineState: state });

      if (status === "awaiting_review") {
        stopPolling(sessionId);
        // Release the review lock when the server confirms we are back at review.
        updateSession(sessionId, {
          phase: "awaiting_review",
          reviewLocked: false,
        });
        return;
      }

      if (status === "complete") {
        stopPolling(sessionId);
        // Fetch full config
        try {
          const config = await getFinalConfig(sessionId);
          updateSession(sessionId, {
            phase: "complete",
            finalConfig: config,
            error: null,
          });
        } catch (err) {
          updateSession(sessionId, {
            phase: "complete",
            error: `Config fetch failed: ${err.message}`,
          });
        }
        return;
      }

      if (status === "failed") {
        stopPolling(sessionId);
        updateSession(sessionId, {
          phase: "failed",
          error: state.error || "Pipeline failed",
        });
        return;
      }

      if (status === "blocked") {
        stopPolling(sessionId);
        updateSession(sessionId, {
          phase: "blocked",
          error: state.error || "Blocked by safety gate",
        });
        return;
      }

      // Still running — keep polling (phase stays 'running')
      if (POLLING_STATUSES.has(status)) {
        updateSession(sessionId, { phase: "running" });
      }
    },
    [updateSession, stopPolling],
  );

  const startPolling = useCallback(
    (sessionId) => {
      // Immediate first poll
      pollSession(sessionId);
      // Then interval
      pollingRefs.current[sessionId] = setInterval(() => {
        pollSession(sessionId);
      }, POLL_INTERVAL_MS);
    },
    [pollSession],
  );

  // ── Submit a new intent ────────────────────────────────────────────────────

  const submit = useCallback(
    async (intentText) => {
      if (!intentText.trim()) return;
      setIsSubmitting(true);

      try {
        const response = await submitIntent(intentText.trim());
        const sessionId = response.session_id;

        // Add new session entry at the bottom of the chat
        setSessions((prev) => [
          ...prev,
          {
            id: sessionId,
            intent: intentText.trim(),
            phase: "running",
            pipelineState: null,
            finalConfig: null,
            error: null,
          },
        ]);

        startPolling(sessionId);
      } catch (err) {
        // Add a failed entry so the user sees the error in the chat
        setSessions((prev) => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            intent: intentText.trim(),
            phase: "failed",
            pipelineState: null,
            finalConfig: null,
            error: err.message,
          },
        ]);
      } finally {
        setIsSubmitting(false);
      }
    },
    [startPolling],
  );

  // ── Approve IR ────────────────────────────────────────────────────────────

  const approve = useCallback(
    async (sessionId) => {
      // Find the session and bail if a review action is already in-flight.
      const existing = sessions.find((s) => s.id === sessionId);
      if (existing?.reviewLocked) {
        return;
      }
      // Lock immediately + switch to running so the review panel disappears.
      updateSession(sessionId, {
        phase: "running",
        error: null,
        reviewLocked: true,
      });
      try {
        await reviewIntent(sessionId, true, "");
        startPolling(sessionId);
      } catch (err) {
        // 409 = server-side concurrency guard fired — just wait for the in-flight
        // resume to finish (polling will update the phase naturally).
        if (err.message && err.message.includes("409")) {
          startPolling(sessionId);
          return;
        }
        updateSession(sessionId, {
          phase: "failed",
          error: err.message,
          reviewLocked: false,
        });
      }
    },
    [sessions, updateSession, startPolling],
  );

  // ── Submit feedback (disambiguation / correction) ─────────────────────────

  const sendFeedback = useCallback(
    async (sessionId, feedback) => {
      if (!feedback.trim()) return;
      const existing = sessions.find((s) => s.id === sessionId);
      if (existing?.reviewLocked) {
        return;
      }
      updateSession(sessionId, {
        phase: "running",
        error: null,
        reviewLocked: true,
      });
      try {
        await reviewIntent(sessionId, false, feedback.trim());
        startPolling(sessionId);
      } catch (err) {
        if (err.message && err.message.includes("409")) {
          startPolling(sessionId);
          return;
        }
        updateSession(sessionId, {
          phase: "failed",
          error: err.message,
          reviewLocked: false,
        });
      }
    },
    [sessions, updateSession, startPolling],
  );

  // ── Cleanup on unmount ────────────────────────────────────────────────────

  useEffect(() => {
    return () => {
      Object.values(pollingRefs.current).forEach(clearInterval);
    };
  }, []);

  return {
    sessions,
    networkContext,
    setNetworkContext,
    isSubmitting,
    submit,
    approve,
    sendFeedback,
  };
}
