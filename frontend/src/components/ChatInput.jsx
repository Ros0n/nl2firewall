import React, { useState, useRef, useEffect } from 'react'
import { Send } from 'lucide-react'
import FileUploadButton from './FileUploadButton.jsx'

export default function ChatInput({ onSubmit, onUploaded, disabled, networkLoaded }) {
  const [text, setText] = useState('')
  const textareaRef = useRef(null)

  // Auto-resize textarea as user types
  useEffect(() => {
    const el = textareaRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = Math.min(el.scrollHeight, 160) + 'px'
  }, [text])

  const handleSubmit = () => {
    const trimmed = text.trim()
    if (!trimmed || disabled || !networkLoaded) return
    onSubmit(trimmed)
    setText('')
    // Reset height
    if (textareaRef.current) textareaRef.current.style.height = 'auto'
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit()
    }
  }

  const placeholder = !networkLoaded
    ? 'Upload a network context file before submitting an intent…'
    : 'Describe a firewall rule in plain English… (e.g. "Block SSH from Sales Network to Management Network")'

  return (
    <div className="chat-input-wrapper">
      <div className={`chat-input-box ${!networkLoaded ? 'chat-input-box--disabled' : ''}`}>
        <textarea
          ref={textareaRef}
          className="chat-input-textarea"
          placeholder={placeholder}
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={disabled || !networkLoaded}
          rows={1}
        />
        <div className="chat-input-actions">
          <FileUploadButton onUploaded={onUploaded} />
          <button
            className="send-btn"
            onClick={handleSubmit}
            disabled={!text.trim() || disabled || !networkLoaded}
            title="Send intent (Enter)"
          >
            <Send size={18} />
          </button>
        </div>
      </div>
      {!networkLoaded && (
        <p className="chat-input-hint">
          Upload a <code>.yaml</code> network context file to get started.
        </p>
      )}
    </div>
  )
}
