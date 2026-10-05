import { useState, type KeyboardEvent } from 'react'

type TypingBarProps = {
  onSend: (text: string) => void
  disabled?: boolean
}

export function TypingBar({ onSend, disabled = false }: TypingBarProps) {
  const [value, setValue] = useState('')

  const send = () => {
    const text = value.trim()
    if (!text || disabled) return

    setValue('')
    onSend(text)
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        left: '50%',
        bottom: '28px',
        transform: 'translateX(-50%)',
        width: 'min(760px, calc(100vw - 40px))',
        display: 'flex',
        gap: '10px',
        zIndex: 1000,
      }}
    >
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={onKeyDown}
        disabled={disabled}
        placeholder="Type a message to JARVIS..."
        autoComplete="off"
        style={{
          flex: 1,
          height: '52px',
          padding: '0 18px',
          borderRadius: '8px',
          border: '1px solid rgba(255,255,255,.18)',
          background: 'rgba(8,12,18,.88)',
          color: '#fff',
          outline: 'none',
          fontSize: '15px',
          backdropFilter: 'blur(12px)',
        }}
      />

      <button
        onClick={send}
        disabled={disabled || !value.trim()}
        style={{
          height: '52px',
          padding: '0 22px',
          borderRadius: '8px',
          border: '1px solid rgba(255,255,255,.18)',
          background: disabled ? '#333' : '#111820',
          color: '#fff',
          cursor: disabled ? 'not-allowed' : 'pointer',
          fontSize: '14px',
          fontWeight: 600,
        }}
      >
        SEND
      </button>
    </div>
  )
}
