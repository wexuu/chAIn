import React, { useMemo, useState } from 'react'
import { get, patch, post } from '../api.js'
import { Button, CELL_STATUSES, Empty, ErrorText, Loading, Panel, useAction, useAsync } from '../ui.jsx'
import CellEditor from '../components/CellEditor.jsx'
import CheckJobPanel from '../components/CheckJobPanel.jsx'

export default function Matrix({ target }) {
  const matrix = useAsync(() => get(`/targets/${target.id}/matrix`), [target.id])
  const [editing, setEditing] = useState(null) // cell object
  const [selected, setSelected] = useState(() => new Set())
  const [job, setJob] = useState(null)
  const gen = useAction()
  const checks = useAction()

  const data = matrix.data
  const cols = data?.columns || []
  const endpoints = data?.endpoints || []
  const summary = data?.summary

  const allCells = useMemo(() => {
    const out = []
    for (const ep of endpoints) for (const c of ep.cells || []) out.push(c)
    return out
  }, [endpoints])

  const toggleSelect = (id) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const queueMatching = () => {
    const next = new Set(selected)
    for (const c of allCells) if (c.status === 'untested' || c.status === 'candidate') next.add(c.id)
    setSelected(next)
  }

  const generate = () =>
    gen.run(async () => {
      await post(`/targets/${target.id}/matrix/generate`)
      await matrix.reload()
    })

  const runChecks = () =>
    checks.run(async () => {
      const body = selected.size ? { cell_ids: [...selected] } : {}
      const j = await post(`/targets/${target.id}/checkjobs`, body)
      setJob(j)
    })

  const saveCell = (cell) => async (body) => {
    await patch(`/cells/${cell.id}`, body)
    await matrix.reload()
  }

  return (
    <div className="tab-grid">
      <Panel
        title="Coverage matrix"
        actions={
          <>
            <Button variant="ghost" onClick={matrix.reload}>
              ⟳
            </Button>
          </>
        }
      >
        <ErrorText error={matrix.error} />
        {summary && (
          <div className="summary">
            <div className="summary-big">
              <span className="summary-num">{summary.coverage_pct}%</span>
              <span className="summary-lbl">coverage</span>
            </div>
            <div className="summary-kvs">
              <span>
                covered <b>{summary.covered}</b>/<b>{summary.applicable}</b> applicable
              </span>
              <span>
                untested <b>{summary.by_status?.untested ?? 0}</b>
              </span>
              <span>
                total cells <b>{summary.total_cells}</b>
              </span>
            </div>
          </div>
        )}
        <div className="toolbar">
          <Button variant="primary" onClick={generate} disabled={gen.busy}>
            {gen.busy ? 'generating…' : 'generate cells'}
          </Button>
          <Button variant="ghost" onClick={queueMatching} disabled={allCells.length === 0}>
            queue untested+candidate
          </Button>
          {selected.size > 0 && (
            <Button variant="ghost" onClick={() => setSelected(new Set())}>
              clear ({selected.size})
            </Button>
          )}
          <Button
            variant="danger"
            onClick={runChecks}
            disabled={checks.busy || allCells.length === 0}
            title={selected.size ? `run ${selected.size} selected cells` : 'run all applicable cells'}
          >
            {checks.busy ? 'queuing…' : `run deep checks${selected.size ? ` (${selected.size})` : ''}`}
          </Button>
        </div>
        <ErrorText error={gen.error || checks.error} />
        {!target.authorized && (
          <p className="muted tiny">target not authorized — deep checks will be refused (403).</p>
        )}
        <Legend />
      </Panel>

      {job && <CheckJobPanel target={target} job={job} onSettled={matrix.reload} />}

      <Panel title="Grid" className="grid-panel">
        {matrix.loading && !data ? (
          <Loading what="matrix" />
        ) : endpoints.length === 0 || cols.length === 0 ? (
          <Empty>
            no cells yet — add endpoints (Import / Recon) then press “generate cells”.
          </Empty>
        ) : (
          <div className="grid-scroll">
            <table className="matrix">
              <thead>
                <tr>
                  <th className="sticky-col corner">endpoint</th>
                  {cols.map((c) => (
                    <th key={c.key} title={(c.wstg || []).join(', ')}>
                      <div className="col-head">
                        <span>{c.label || c.key}</span>
                        {c.param_specific && <span className="chip chip-tiny">param</span>}
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {endpoints.map((ep) => (
                  <tr key={ep.id}>
                    <th className="sticky-col">
                      <span className="method" data-method={ep.method}>
                        {ep.method}
                      </span>{' '}
                      <span className="mono-sm">{ep.path}</span>
                    </th>
                    {cols.map((col) => {
                      const cells = (ep.cells || []).filter((c) => c.vuln_class === col.key)
                      return (
                        <td key={col.key} className="matrix-cell">
                          {cells.length === 0 ? (
                            <span className="cell-blank">·</span>
                          ) : (
                            cells.map((cell) => (
                              <CellChip
                                key={cell.id}
                                cell={cell}
                                selected={selected.has(cell.id)}
                                onOpen={() => setEditing(cell)}
                                onToggle={() => toggleSelect(cell.id)}
                              />
                            ))
                          )}
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {editing && (
        <CellEditor
          title={`cell #${editing.id} — ${editing.vuln_class}${
            editing.param_name ? ` [${editing.param_name}]` : ''
          }`}
          cell={editing}
          withScopeNote
          onSave={saveCell(editing)}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}

function CellChip({ cell, selected, onOpen, onToggle }) {
  return (
    <span className={`cell ${selected ? 'cell-selected' : ''}`} data-status={cell.status}>
      <button
        className="cell-sel"
        title={selected ? 'remove from deep-check queue' : 'queue for deep check'}
        onClick={onToggle}
      >
        {selected ? '◼' : '◻'}
      </button>
      <button
        className="cell-label"
        onClick={onOpen}
        title={`${cell.status}${cell.reason ? ` — ${cell.reason}` : ''}`}
      >
        {cell.param_name ? cell.param_name : cell.status.replace(/_/g, ' ').slice(0, 6)}
      </button>
    </span>
  )
}

function Legend() {
  return (
    <div className="legend">
      {CELL_STATUSES.map((s) => (
        <span key={s} className="legend-item">
          <span className="swatch" data-status={s} />
          {s.replace(/_/g, ' ')}
        </span>
      ))}
    </div>
  )
}
