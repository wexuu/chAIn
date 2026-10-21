import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { setApiErrorSink } from './api.js'

// ---- toast notifications (bottom-left, auto-dismiss) ----------------------
const ToastCtx = createContext(null)

export function useToast() {
  return useContext(ToastCtx) || { push: () => {}, dismiss: () => {} }
}

let _toastSeq = 0

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const timers = useRef({})

  const dismiss = useCallback((id) => {
    setToasts((list) => list.filter((t) => t.id !== id))
    clearTimeout(timers.current[id])
    delete timers.current[id]
  }, [])

  const push = useCallback(
    (message, opts = {}) => {
      const id = ++_toastSeq
      const toast = {
        id,
        message: String(message || 'something went wrong'),
        kind: opts.kind || 'error',
        detail: opts.detail || null,
      }
      setToasts((list) => [...list, toast])
      timers.current[id] = setTimeout(() => dismiss(id), opts.duration || 10000)
      return id
    },
    [dismiss]
  )

  // Route every failed API request to a toast.
  useEffect(() => {
    setApiErrorSink((err, info) =>
      push(err.message || String(err), {
        kind: 'error',
        detail: info ? `${info.method} ${info.path}` : null,
      })
    )
    return () => setApiErrorSink(null)
  }, [push])

  // Clean up timers on unmount.
  useEffect(() => () => Object.values(timers.current).forEach(clearTimeout), [])

  return (
    <ToastCtx.Provider value={{ push, dismiss }}>
      {children}
      <div className="toast-wrap" aria-live="polite" aria-atomic="false">
        {toasts.map((t) => (
          <div key={t.id} className="toast" data-kind={t.kind} role="status">
            <div className="toast-body">
              <span className="toast-msg">{t.message}</span>
              {t.detail && <span className="toast-detail mono-sm">{t.detail}</span>}
            </div>
            <button className="toast-x" onClick={() => dismiss(t.id)} aria-label="dismiss">
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

// ---- matrix cell status model -------------------------------------------
export const CELL_STATUSES = [
  'untested',
  'candidate',
  'confirmed',
  'tested_negative',
  'not_applicable',
  'reviewed',
]
// Server requires a non-empty reason for these transitions.
export const REASON_REQUIRED = new Set(['tested_negative', 'not_applicable', 'reviewed'])

export function statusLabel(s) {
  return (s || '').replace(/_/g, ' ')
}

// ---- async data hook ------------------------------------------------------
// Fetches on mount and whenever `deps` change; exposes { data, error, loading,
// reload, setData }. Errors are surfaced as readable strings.
export function useAsync(fn, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const fnRef = useRef(fn)
  fnRef.current = fn
  const aliveRef = useRef(true)

  const reload = useCallback(() => {
    setLoading(true)
    setError(null)
    return Promise.resolve()
      .then(() => fnRef.current())
      .then(
        (d) => {
          if (aliveRef.current) {
            setData(d)
            setLoading(false)
          }
          return d
        },
        (e) => {
          if (aliveRef.current) {
            setError(e.message || String(e))
            setLoading(false)
          }
          throw e
        }
      )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    aliveRef.current = true
    reload().catch(() => {})
    return () => {
      aliveRef.current = false
    }
  }, [reload])

  return { data, error, loading, reload, setData }
}

// ---- imperative action hook (buttons / form submits) ----------------------
export function useAction() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const run = useCallback(async (fn) => {
    setBusy(true)
    setError(null)
    try {
      return await fn()
    } catch (e) {
      setError(e.message || String(e))
      throw e
    } finally {
      setBusy(false)
    }
  }, [])
  return { busy, error, setError, run }
}

// ---- presentational components -------------------------------------------
export function Panel({ title, actions, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  )
}

export function Button({ children, variant = '', ...rest }) {
  return (
    <button className={`btn ${variant ? `btn-${variant}` : ''}`} {...rest}>
      {children}
    </button>
  )
}

export function ErrorText({ error, onDismiss }) {
  if (!error) return null
  return (
    <div className="error" role="alert">
      <span>{String(error)}</span>
      {onDismiss && (
        <button className="error-x" onClick={onDismiss} aria-label="dismiss">
          ×
        </button>
      )}
    </div>
  )
}

export function Loading({ what = 'data' }) {
  return <div className="muted loading">loading {what}…</div>
}

export function Empty({ children }) {
  return <div className="muted empty">{children}</div>
}

export function StatusBadge({ status }) {
  return (
    <span className="badge" data-status={status}>
      {statusLabel(status)}
    </span>
  )
}

export function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span className="field-label">
        {label}
        {hint && <em className="field-hint"> {hint}</em>}
      </span>
      {children}
    </label>
  )
}

export function Modal({ title, onClose, children, footer }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <header className="modal-head">
          <h3>{title}</h3>
          <button className="error-x" onClick={onClose} aria-label="close">
            ×
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </div>
  )
}

export function KV({ k, v }) {
  return (
    <div className="kv">
      <span className="kv-k">{k}</span>
      <span className="kv-v">{v}</span>
    </div>
  )
}

// Short orienting header shown at the top of a tab: what this page is for and
// how it fits the workflow.
export function TabIntro({ title, lead, children }) {
  return (
    <div className="tab-intro">
      <h1>{title}</h1>
      {lead && <p>{lead}</p>}
      {children}
    </div>
  )
}
