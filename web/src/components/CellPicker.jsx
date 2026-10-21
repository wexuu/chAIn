import React, { useMemo, useState } from 'react'
import { get } from '../api.js'
import { Button, Empty, ErrorText, Loading, Modal, useAsync } from '../ui.jsx'

// Flatten the matrix into pickable cells. Each carries a human label so callers
// never have to deal with bare numeric ids.
export function useCells(target) {
  const matrix = useAsync(() => get(`/targets/${target.id}/matrix`), [target.id])
  const cells = useMemo(() => {
    const out = []
    for (const ep of matrix.data?.endpoints || []) {
      for (const c of ep.cells || []) {
        out.push({
          id: c.id,
          status: c.status,
          vuln_class: c.vuln_class,
          param_name: c.param_name,
          method: ep.method,
          path: ep.path,
          label: `${ep.method} ${ep.path} · ${c.vuln_class}${c.param_name ? ` [${c.param_name}]` : ''}`,
        })
      }
    }
    return out
  }, [matrix.data])
  return { matrix, cells }
}

// Visual, searchable cell selector. `multiple` → returns an array of cells;
// otherwise returns a single cell. Opens as a modal.
export default function CellPicker({ target, multiple = true, initial = [], onPick, onClose }) {
  const { matrix, cells } = useCells(target)
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(() => new Set(initial))

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return cells
    return cells.filter((c) => c.label.toLowerCase().includes(needle) || c.status.includes(needle))
  }, [cells, q])

  const toggle = (c) => {
    if (!multiple) {
      onPick(c)
      onClose()
      return
    }
    setSel((prev) => {
      const next = new Set(prev)
      next.has(c.id) ? next.delete(c.id) : next.add(c.id)
      return next
    })
  }

  const confirm = () => {
    onPick(cells.filter((c) => sel.has(c.id)))
    onClose()
  }

  return (
    <Modal
      title={multiple ? 'Select cells' : 'Select a cell'}
      onClose={onClose}
      footer={
        multiple ? (
          <>
            <Button variant="ghost" onClick={onClose}>
              cancel
            </Button>
            <Button variant="primary" onClick={confirm} disabled={sel.size === 0}>
              use {sel.size} cell{sel.size === 1 ? '' : 's'}
            </Button>
          </>
        ) : (
          <Button variant="ghost" onClick={onClose}>
            cancel
          </Button>
        )
      }
    >
      <ErrorText error={matrix.error} />
      <input
        className="picker-search"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="filter by path, vuln class or status…"
        spellCheck={false}
        autoFocus
      />
      {matrix.loading && !matrix.data ? (
        <Loading what="cells" />
      ) : cells.length === 0 ? (
        <Empty>no cells yet — generate the matrix first (Matrix tab).</Empty>
      ) : filtered.length === 0 ? (
        <Empty>nothing matches “{q}”.</Empty>
      ) : (
        <ul className="picker-list">
          {filtered.map((c) => (
            <li key={c.id}>
              <button
                type="button"
                className={`picker-row ${sel.has(c.id) ? 'picker-row-sel' : ''}`}
                onClick={() => toggle(c)}
              >
                {multiple && <span className="picker-check">{sel.has(c.id) ? '◼' : '◻'}</span>}
                <span className="method" data-method={c.method}>
                  {c.method}
                </span>
                <span className="mono-sm picker-path">{c.path}</span>
                <span className="picker-class">{c.vuln_class}</span>
                {c.param_name && <span className="chip chip-tiny">{c.param_name}</span>}
                <span className="badge" data-status={c.status}>
                  {c.status.replace(/_/g, ' ')}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Modal>
  )
}
