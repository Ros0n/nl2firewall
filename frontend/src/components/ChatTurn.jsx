import React from 'react'
import { Loader, ShieldX, ShieldAlert } from 'lucide-react'
import PipelineProgress from './PipelineProgress.jsx'
import ReviewPanel from './ReviewPanel.jsx'
import ConfigOutput from './ConfigOutput.jsx'

// ─── User bubble ──────────────────────────────────────────────────────────────

function UserBubble({ text }) {
  return (
    <div className="chat-turn__user-row">
      <div className="chat-turn__user-bubble">
        {text}
      </div>
    </div>
  )
}

// ─── Running state ────────────────────────────────────────────────────────────

function RunningCard({ session }) {
  const status = session.pipelineState?.status || 'pending'
  const currentStep = session.pipelineState?.current_step || 'Starting pipeline…'

  return (
    <div className="assistant-card">
      <PipelineProgress status={status} currentStepLabel={currentStep} />
    </div>
  )
}

// ─── Failed state ─────────────────────────────────────────────────────────────

function FailedCard({ error, pipelineState }) {
  const step = pipelineState?.current_step
  return (
    <div className="assistant-card assistant-card--error">
      <div className="error-card__header">
        <ShieldX size={18} className="error-card__icon" />
        <span className="error-card__title">Pipeline Failed</span>
      </div>
      {step && <p className="error-card__step">Failed at: {step}</p>}
      {error && <p className="error-card__message">{error}</p>}
    </div>
  )
}

// ─── Blocked state ────────────────────────────────────────────────────────────

function BlockedCard({ error, pipelineState }) {
  const step = pipelineState?.current_step
  return (
    <div className="assistant-card assistant-card--blocked">
      <div className="error-card__header">
        <ShieldAlert size={18} className="error-card__icon" />
        <span className="error-card__title">Blocked by Safety Gate</span>
      </div>
      {step && <p className="error-card__step">Blocked at: {step}</p>}
      {error && <p className="error-card__message">{error}</p>}
    </div>
  )
}

// ─── ChatTurn ─────────────────────────────────────────────────────────────────

export default function ChatTurn({ session, onApprove, onFeedback, isLatest }) {
  const { intent, phase, error, pipelineState } = session

  return (
    <div className={`chat-turn ${isLatest ? 'chat-turn--latest' : ''}`}>

      {/* User message bubble */}
      <UserBubble text={intent} />

      {/* Assistant response area */}
      <div className="chat-turn__assistant">

        {/* ── Running (pipeline in progress) ── */}
        {phase === 'running' && (
          <RunningCard session={session} />
        )}

        {/* ── Awaiting review — show progress + review panel ── */}
        {phase === 'awaiting_review' && (
          <div className="assistant-card">
            <PipelineProgress
              status={pipelineState?.status || 'awaiting_review'}
              currentStepLabel={pipelineState?.current_step}
            />
            <ReviewPanel
              session={session}
              onApprove={onApprove}
              onFeedback={onFeedback}
            />
          </div>
        )}

        {/* ── Complete ── */}
        {phase === 'complete' && (
          <div className="assistant-card">
            <PipelineProgress
              status="complete"
              currentStepLabel={pipelineState?.current_step}
            />
            <ConfigOutput session={session} />
          </div>
        )}

        {/* ── Failed ── */}
        {phase === 'failed' && (
          <FailedCard error={error} pipelineState={pipelineState} />
        )}

        {/* ── Blocked ── */}
        {phase === 'blocked' && (
          <BlockedCard error={error} pipelineState={pipelineState} />
        )}

      </div>
    </div>
  )
}
