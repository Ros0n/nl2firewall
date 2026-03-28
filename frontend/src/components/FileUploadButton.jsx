import React, { useRef, useState } from 'react'
import { Paperclip, CheckCircle, AlertCircle, Loader } from 'lucide-react'
import { uploadNetworkContext } from '../api/client.js'

export default function FileUploadButton({ onUploaded }) {
  const inputRef = useRef(null)
  const [state, setState] = useState('idle') // 'idle' | 'uploading' | 'success' | 'error'
  const [label, setLabel] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')

  const handleFile = async (file) => {
    if (!file) return
    if (!file.name.endsWith('.yaml') && !file.name.endsWith('.yml')) {
      setState('error')
      setErrorMsg('Please upload a .yaml or .yml file')
      setTimeout(() => setState('idle'), 3000)
      return
    }

    setState('uploading')
    setErrorMsg('')
    try {
      const data = await uploadNetworkContext(file)
      setLabel(data.network_name)
      setState('success')
      onUploaded && onUploaded(data)
    } catch (err) {
      setState('error')
      setErrorMsg(err.message || 'Upload failed')
      setTimeout(() => setState('idle'), 4000)
    }
  }

  const handleChange = (e) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
    // Reset so same file can be re-uploaded
    e.target.value = ''
  }

  const handleDrop = (e) => {
    e.preventDefault()
    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
  }

  const handleDragOver = (e) => e.preventDefault()

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        accept=".yaml,.yml"
        style={{ display: 'none' }}
        onChange={handleChange}
      />

      <button
        className={`upload-btn upload-btn--${state}`}
        onClick={() => state === 'uploading' ? null : inputRef.current?.click()}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        title={
          state === 'success'
            ? `Network context loaded: ${label}`
            : state === 'error'
            ? errorMsg
            : 'Upload network context (.yaml)'
        }
        disabled={state === 'uploading'}
      >
        {state === 'idle' && <Paperclip size={18} />}
        {state === 'uploading' && <Loader size={18} className="spin" />}
        {state === 'success' && <CheckCircle size={18} />}
        {state === 'error' && <AlertCircle size={18} />}

        <span className="upload-btn__label">
          {state === 'idle' && 'Upload context'}
          {state === 'uploading' && 'Uploading…'}
          {state === 'success' && label}
          {state === 'error' && errorMsg}
        </span>
      </button>
    </>
  )
}
