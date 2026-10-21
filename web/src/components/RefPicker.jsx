import React, { useMemo, useState } from 'react'
import { get } from '../api.js'
import { Button, Empty, ErrorText, Loading, Modal, useAsync } from '../ui.jsx'
import { useCells } from './CellPicker.jsx'

// Picks an edge endpoint reference (cell:/hyp:/finding:) visually instead of
// making the operator type raw ids. Cells and hypotheses are listed; a free
// text box covers anything else (e.g. finding:1).
export default function RefPicker({ target, title = 'Pick reference', onPick, onClose }) {
  const [mode, setMode] = useState('cell')
  const { matrix, cells } = useCells(target)
  const hyps = useAsync(() => get(`/targets/${target.id}/hypotheses`), [target.id])
  const [q, setQ] = useState('')
  const [custom, setCustom] = useState('')

  const choose = (ref) => {
    onPick(ref)
    onClose()
  }

  const filteredCells = useMemo(() => {
    const n = q.trim().toLowerCase()
    return n ? cells.filter((c) => c.label.toLowerCase().includes(n)) : cells
  }, [cells, q])

  const hypList = hyps.data || []
  const filteredHyps = useMemo(() => {
    const n = q.trim().toLowerCase()
    return n ? hypList.filter((h) => (h.title || '').toLowerCase().includes(n)) : hypList
  }, [hypList, q])

  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <form
          className="row custom-ref"
          onSubmit={(e) => {
            e.preventDefault()
            if (custom.trim()) choose(custom.trim())
          }}
        >
          <input
            value={custom}
            onChange={(e) => setCustom(e.target.value)}
            placeholder="or type a ref, e.g. finding:1"
            spellCheck={false}
          />
          <Button variant="ghost" type="submit" disabled={!custom.trim()}>
            use
          </Button>
        </form>
      }
    >
      <div className="segmented">
        <button type="button" className={mode === 'cell' ? 'seg-active' : ''} onClick={() => setMode('cell')}>
          Cells
        </button>
        <button type="button" className={mode === 'hyp' ? 'seg-active' : ''} onClick={() => setMode('hyp')}>
          Hypotheses
        </button>
      </div>
      <input
        className="picker-search"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="filter…"
        spellCheck={false}
      />
      {mode === 'cell' ? (
        <>
          <ErrorText error={matrix.error} />
          {matrix.loading && !matrix.data ? (
            <Loading what="cells" />
          ) : filteredCells.length === 0 ? (
            <Empty>no cells — generate the matrix first.</Empty>
          ) : (
            <ul className="picker-list">
              {filteredCells.map((c) => (
                <li key={c.id}>
                  <button type="button" className="picker-row" onClick={() => choose(`cell:${c.id}`)}>
                    <span className="method" data-method={c.method}>
                      {c.method}
                    </span>
                    <span className="mono-sm picker-path">{c.path}</span>
                    <span className="picker-class">{c.vuln_class}</span>
                    <span className="badge" data-status={c.status}>
                      {c.status.replace(/_/g, ' ')}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <>
          <ErrorText error={hyps.error} />
          {hyps.loading && !hyps.data ? (
            <Loading what="hypotheses" />
          ) : filteredHyps.length === 0 ? (
            <Empty>no hypotheses yet.</Empty>
          ) : (
            <ul className="picker-list">
              {filteredHyps.map((h) => (
                <li key={h.id}>
                  <button type="button" className="picker-row" onClick={() => choose(`hyp:${h.id}`)}>
                    <span className="badge" data-status={h.status}>
                      {h.status}
                    </span>
                    <span className="picker-path">{h.title}</span>
                    <span className="muted tiny">#{h.id}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Modal>
  )
}
