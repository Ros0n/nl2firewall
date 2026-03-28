import React from 'react'
import { Check, X, Loader, Circle } from 'lucide-react'

const STEPS = [
  { key: 'resolving',     label: 'Resolve' },
  { key: 'building_ir',   label: 'Build IR' },
  { key: 'awaiting_review', label: 'Review' },
  { key: 'linting',       label: 'Lint' },
  { key: 'safety_check',  label: 'Safety' },
  { key: 'compiling',     label: 'Compile' },
  { key: 'verifying',     label: 'Batfish' },
  { key: 'complete',      label: 'Done' },
]

const STATUS_ORDER = {
  pending:          -1,
  resolving:         0,
  building_ir:       1,
  awaiting_review:   2,
  linting:           3,
  safety_check:      4,
  compiling:         5,
  verifying:         6,
  complete:          7,
  failed:            99,
  blocked:           99,
}

function stepState(stepKey, currentStatus, isFailed, isBlocked) {
  if (isFailed || isBlocked) {
    const currentIdx = STATUS_ORDER[currentStatus] ?? -1
    const stepIdx    = STATUS_ORDER[stepKey]      ?? 0
    if (stepIdx < currentIdx) return 'done'
    if (stepIdx === currentIdx) return 'error'
    return 'waiting'
  }

  const currentIdx = STATUS_ORDER[currentStatus] ?? -1
  const stepIdx    = STATUS_ORDER[stepKey]        ?? 0

  if (stepIdx < currentIdx) return 'done'
  if (stepIdx === currentIdx) return 'active'
  return 'waiting'
}

export default function PipelineProgress({ status, currentStepLabel }) {
  const isFailed  = status === 'failed'
  const isBlocked = status === 'blocked'

  return (
    <div className="pipeline-progress">
      <div className="pipeline-steps">
        {STEPS.map((step, i) => {
          const state = stepState(step.key, status, isFailed, isBlocked)

          return (
            <React.Fragment key={step.key}>
              <div className={`pipeline-step pipeline-step--${state}`}>
                <div className="pipeline-step__bubble">
                  {state === 'done'    && <Check size={12} strokeWidth={3} />}
                  {state === 'active'  && <Loader size={12} className="spin" />}
                  {state === 'error'   && <X size={12} strokeWidth={3} />}
                  {state === 'waiting' && <Circle size={8} />}
                </div>
                <span className="pipeline-step__label">{step.label}</span>
              </div>
              {i < STEPS.length - 1 && (
                <div className={`pipeline-connector ${state === 'done' ? 'pipeline-connector--done' : ''}`} />
              )}
            </React.Fragment>
          )
        })}
      </div>

      {currentStepLabel && (
        <p className="pipeline-step-detail">{currentStepLabel}</p>
      )}
    </div>
  )
}
