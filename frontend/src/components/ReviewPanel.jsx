import React, { useState } from "react";
import {
  CheckCircle,
  MessageSquare,
  RotateCcw,
  AlertTriangle,
  XCircle,
} from "lucide-react";
import RuleCard from "./RuleCard.jsx";

// ─── Sub-component: Feedback form ─────────────────────────────────────────────

function FeedbackForm({
  ambiguities,
  feedbackRounds,
  maxRounds,
  onSubmit,
  onCancel,
}) {
  const [text, setText] = useState("");
  const remaining = maxRounds - feedbackRounds;

  const handleSubmit = () => {
    if (!text.trim()) return;
    onSubmit(text.trim());
    setText("");
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <div className="feedback-form">
      {ambiguities && ambiguities.length > 0 && (
        <div className="feedback-form__questions">
          <p className="feedback-form__questions-title">
            Please answer the following questions to resolve ambiguities:
          </p>
          <ol className="feedback-form__questions-list">
            {ambiguities.map((q, i) => (
              <li key={i}>{q}</li>
            ))}
          </ol>
        </div>
      )}

      <textarea
        className="feedback-form__textarea"
        placeholder={
          ambiguities && ambiguities.length > 0
            ? "Answer the questions above, or describe what should be corrected…"
            : "Describe what needs to be changed or clarified…"
        }
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={handleKeyDown}
        rows={3}
        autoFocus
      />

      <div className="feedback-form__footer">
        <span className="feedback-form__rounds-hint">
          {remaining > 0
            ? `${remaining} feedback round${remaining !== 1 ? "s" : ""} remaining`
            : "Last feedback round — will proceed regardless after this"}
        </span>
        <div className="feedback-form__actions">
          <button className="btn btn--ghost" onClick={onCancel}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            onClick={handleSubmit}
            disabled={!text.trim()}
          >
            <RotateCcw size={14} />
            Send & Re-resolve
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main ReviewPanel ─────────────────────────────────────────────────────────

export default function ReviewPanel({ session, onApprove, onFeedback }) {
  const [mode, setMode] = useState("review"); // 'review' | 'feedback'

  const { pipelineState, phase, error } = session;
  const rule = pipelineState?.resolved_rule;
  const ambiguities = pipelineState?.clarification_questions || [];
  const needsClarification = pipelineState?.clarification_needed || false;
  const incomplete = pipelineState?.incomplete || false;
  const feedbackRounds = pipelineState?.feedback_rounds || 0;
  const maxRounds = 3;

  // A re-resolve error: pipeline failed during feedback but was restored to
  // awaiting_review so the user can correct their feedback or approve as-is.
  const reResolveError =
    error && error.startsWith("Re-resolve failed:")
      ? error
          .replace(/^Re-resolve failed:\s*/, "")
          .replace(/\.\s*You can.*$/, "")
      : null;

  const handleApprove = () => {
    setMode("review");
    onApprove(session.id);
  };

  const handleFeedback = (text) => {
    setMode("review");
    onFeedback(session.id, text);
  };

  // While re-resolving after feedback, this panel won't be shown
  // (phase === 'running'), so we only render when phase === 'awaiting_review'
  if (phase !== "awaiting_review") return null;

  return (
    <div className="review-panel">
      {/* ── Header ── */}
      <div className="review-panel__header">
        <div className="review-panel__header-left">
          <span className="review-panel__title">Review Resolved Rule</span>
          {feedbackRounds > 0 && (
            <span className="review-panel__round-badge">
              Round {feedbackRounds + 1}
            </span>
          )}
        </div>

        {needsClarification && (
          <div className="review-panel__clarification-flag">
            <AlertTriangle size={14} />
            <span>Clarification needed before approving</span>
          </div>
        )}
      </div>

      {/* ── Re-resolve error banner ── */}
      {reResolveError && (
        <div className="review-panel__reresolve-error">
          <XCircle size={14} className="review-panel__reresolve-error-icon" />
          <div className="review-panel__reresolve-error-body">
            <span className="review-panel__reresolve-error-title">
              Re-resolve failed
            </span>
            <span className="review-panel__reresolve-error-msg">
              {reResolveError}
            </span>
            <span className="review-panel__reresolve-error-hint">
              Correct your feedback below, or approve the rule shown as-is.
            </span>
          </div>
        </div>
      )}

      {/* ── Rule Card ── */}
      <RuleCard rule={rule} />

      {/* ── Action area ── */}
      {mode === "review" && (
        <div className="review-panel__actions">
          {incomplete || needsClarification ? (
            <>
              {/* Clarification required — only show feedback, grey out approve */}
              <button
                className="btn btn--approve btn--approve-muted"
                onClick={handleApprove}
                title="You can still approve, but unresolved entities may cause compiler errors"
              >
                <CheckCircle size={16} />
                Approve anyway
              </button>
              <button
                className="btn btn--feedback btn--feedback-primary"
                onClick={() => setMode("feedback")}
              >
                <MessageSquare size={16} />
                Answer & Re-resolve
              </button>
            </>
          ) : (
            <>
              <button
                className="btn btn--feedback"
                onClick={() => setMode("feedback")}
              >
                <MessageSquare size={16} />
                Give Feedback
              </button>
              <button className="btn btn--approve" onClick={handleApprove}>
                <CheckCircle size={16} />
                Approve
              </button>
            </>
          )}
        </div>
      )}

      {/* ── Feedback form ── */}
      {mode === "feedback" && (
        <FeedbackForm
          ambiguities={needsClarification ? ambiguities : []}
          feedbackRounds={feedbackRounds}
          maxRounds={maxRounds}
          onSubmit={handleFeedback}
          onCancel={() => setMode("review")}
        />
      )}
    </div>
  );
}
