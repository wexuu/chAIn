import React, { useState } from 'react'
import { Button, CELL_STATUSES, ErrorText, Field, Modal, REASON_REQUIRED, useAction } from '../ui.jsx'

// Generic status editor for a matrix / service-matrix cell.
// `onSave` receives the patch body and should perform the PATCH and throw on error.
export default function CellEditor({ title, cell, withScopeNote = false, onSave, onClose }) {
  const [status, setStatus] = useState(cell.status || 'untested')
  const [reason, setReason] = useState(cell.reason || '')
  const [scopeNote, setScopeNote] = useState(cell.scope_note || '')
  const { busy, error, setError, run } = useAction()

  const reasonNeeded = REASON_REQUIRED.has(status)

  const save = async () => {
    if (reasonNeeded && !reason.trim()) {
      setError(`status "${status}" requires a reason`)
      return
    }
    const body = { status }
    if (reason.trim()) body.reason = reason.trim()
    else body.reason = null
    if (withScopeNote) body.scope_note = scopeNote.trim() || null
    await run(() => onSave(body))
    onClose()
  }

  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            cancel
          </Button>
          <Button variant="primary" onClick={save} disabled={busy}>
            save
          </Button>
        </>
      }
    >
      <div className="stack">
        <div className="legend-inline">
          {CELL_STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              className={`badge badge-btn ${status === s ? 'badge-sel' : ''}`}
              data-status={s}
              onClick={() => setStatus(s)}
            >
              {s.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
        <Field
          label="Reason"
          hint={reasonNeeded ? '(required for this status)' : '(optional)'}
        >
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            placeholder={reasonNeeded ? 'why is this status justified?' : ''}
          />
        </Field>
        {withScopeNote && (
          <Field label="Scope note" hint="(optional)">
            <textarea
              value={scopeNote}
              onChange={(e) => setScopeNote(e.target.value)}
              rows={2}
            />
          </Field>
        )}
        <ErrorText error={error} />
      </div>
    </Modal>
  )
}
