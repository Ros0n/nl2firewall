import React, { useState } from 'react'
import {
  CheckCircle,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Shield,
  Terminal,
  FileText,
} from 'lucide-react'

// ─── Copy button with transient "Copied!" state ────────────────────────────────

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback for older browsers
      const el = document.createElement('textarea')
      el.value = text
      el.style.position = 'fixed'
      el.style.opacity = '0'
      document.body.appendChild(el)
      el.select()
      document.execCommand('copy')
      document.body.removeChild(el)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <button
      className={`copy-btn ${copied ? 'copy-btn--copied' : ''}`}
      onClick={handleCopy}
      title={copied ? 'Copied!' : 'Copy to clipboard'}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
      <span>{copied ? 'Copied!' : 'Copy'}</span>
    </button>
  )
}

// ─── Batfish report accordion ─────────────────────────────────────────────────

function BatfishReport({ report, summary, passed }) {
  const [open, setOpen] = useState(false)

  if (!report && !summary) return null

  const parseWarnings     = report?.parse_warnings     || []
  const undefinedRefs     = report?.undefined_references || []
  const shadowedLines     = report?.shadowed_lines      || []
  const searchViolations  = report?.search_violations   || []
  const flowTraces        = report?.flow_traces         || []

  const issueCount =
    parseWarnings.length +
    undefinedRefs.length +
    shadowedLines.length +
    searchViolations.length

  return (
    <div className={`batfish-accordion ${passed ? 'batfish-accordion--pass' : 'batfish-accordion--warn'}`}>
      <button
        className="batfish-accordion__toggle"
        onClick={() => setOpen(o => !o)}
      >
        <div className="batfish-accordion__toggle-left">
          <Shield size={15} />
          <span className="batfish-accordion__title">Batfish Verification</span>
          {passed && issueCount === 0 ? (
            <span className="badge badge--pass">All checks passed ✓</span>
          ) : (
            <span className="badge badge--warn">{issueCount} issue{issueCount !== 1 ? 's' : ''}</span>
          )}
        </div>
        {open ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
      </button>

      {open && (
        <div className="batfish-accordion__body">

          {/* Summary line */}
          {summary && (
            <p className="batfish-summary-line">{summary}</p>
          )}

          {/* Parse warnings */}
          {parseWarnings.length > 0 && (
            <div className="batfish-section">
              <div className="batfish-section__heading">
                <AlertTriangle size={13} /> Parse Warnings ({parseWarnings.length})
              </div>
              <ul className="batfish-list">
                {parseWarnings.map((w, i) => <li key={i}>{w}</li>)}
              </ul>
            </div>
          )}

          {/* Undefined references */}
          {undefinedRefs.length > 0 && (
            <div className="batfish-section">
              <div className="batfish-section__heading">
                <AlertTriangle size={13} /> Undefined References ({undefinedRefs.length})
              </div>
              <ul className="batfish-list">
                {undefinedRefs.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}

          {/* Shadowed lines */}
          {shadowedLines.length > 0 && (
            <div className="batfish-section">
              <div className="batfish-section__heading">
                <AlertTriangle size={13} /> Shadowed Lines ({shadowedLines.length})
              </div>
              <ul className="batfish-list">
                {shadowedLines.map((s, i) => (
                  <li key={i}>
                    <code className="batfish-code">{s.unreachable_line}</code>
                    <span className="batfish-list__note">
                      shadowed by: {Array.isArray(s.blocking_lines) ? s.blocking_lines.join(', ') : s.blocking_lines}
                      {s.different_action && (
                        <span className="batfish-list__risk"> ⚠ different action</span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Policy violations */}
          {searchViolations.length > 0 && (
            <div className="batfish-section">
              <div className="batfish-section__heading">
                <AlertTriangle size={13} /> Policy Violations ({searchViolations.length})
              </div>
              <ul className="batfish-list">
                {searchViolations.map((v, i) => (
                  <li key={i}>
                    <span className="batfish-list__rule">{v.rule}</span>
                    <span className="batfish-list__note">
                      Intended <strong>{v.intended}</strong>, found <strong>{v.violation}</strong>
                    </span>
                    {v.example_flow && (
                      <code className="batfish-code">{v.example_flow}</code>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Flow traces */}
          {flowTraces.length > 0 && (
            <div className="batfish-section">
              <div className="batfish-section__heading">
                <Terminal size={13} /> Flow Traces ({flowTraces.length})
              </div>
              <ul className="batfish-list">
                {flowTraces.map((t, i) => (
                  <li key={i}>
                    <code className="batfish-code">{t.flow}</code>
                    <span className={`batfish-list__action batfish-list__action--${(t.action || '').toLowerCase()}`}>
                      → {t.action}
                    </span>
                    {t.matched_line && (
                      <span className="batfish-list__note">matched: {t.matched_line}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* All clear */}
          {issueCount === 0 && flowTraces.length === 0 && (
            <p className="batfish-all-clear">No issues found.</p>
          )}

        </div>
      )}
    </div>
  )
}

// ─── Main ConfigOutput component ──────────────────────────────────────────────

export default function ConfigOutput({ session }) {
  const { finalConfig, pipelineState, phase } = session

  if (phase !== 'complete' || !finalConfig) return null

  const config       = finalConfig.config || ''
  const explanation  = finalConfig.explanation || ''
  const aclName      = finalConfig.acl_name || ''
  const iface        = finalConfig.interface || ''
  const lineCount    = finalConfig.line_count || 0
  const batfishPassed = finalConfig.batfish_passed
  const batfishReport = finalConfig.batfish_report || null
  const batfishSummary = pipelineState?.batfish_summary || ''

  return (
    <div className="config-output">

      {/* ── Success header ── */}
      <div className="config-output__header">
        <div className="config-output__header-left">
          <CheckCircle size={18} className="config-output__check" />
          <span className="config-output__title">Rule Generated</span>
        </div>
        <div className="config-output__meta">
          {aclName && <span className="badge badge--acl"><Terminal size={11} /> {aclName}</span>}
          {iface && <span className="badge badge--iface">{iface}</span>}
          {lineCount > 0 && (
            <span className="badge badge--lines">{lineCount} line{lineCount !== 1 ? 's' : ''}</span>
          )}
        </div>
      </div>

      {/* ── Explanation ── */}
      {explanation && (
        <div className="config-output__explanation">
          <div className="config-output__section-label">
            <FileText size={13} /> Explanation
          </div>
          <p className="config-output__explanation-text">{explanation}</p>
        </div>
      )}

      {/* ── Cisco config block ── */}
      {config && (
        <div className="config-output__code-block">
          <div className="config-output__code-header">
            <span className="config-output__section-label">
              <Terminal size={13} /> Cisco IOS Config
            </span>
            <CopyButton text={config} />
          </div>
          <pre className="config-output__pre"><code>{config}</code></pre>
        </div>
      )}

      {/* ── Batfish report (collapsible) ── */}
      <BatfishReport
        report={batfishReport}
        summary={batfishSummary}
        passed={batfishPassed !== false}
      />

    </div>
  )
}
