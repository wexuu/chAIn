import React, { useState } from 'react'
import { get, patch, post } from '../api.js'
import { Button, Empty, ErrorText, Loading, Panel, useAction, useAsync } from '../ui.jsx'
import CellEditor from '../components/CellEditor.jsx'

export default function ServiceMatrix({ target }) {
  const matrix = useAsync(() => get(`/targets/${target.id}/service-matrix`), [target.id])
  const [editing, setEditing] = useState(null)
  const gen = useAction()

  const data = matrix.data
  const cols = data?.columns || []
  const services = data?.services || []

  const generate = () =>
    gen.run(async () => {
      await post(`/targets/${target.id}/service-matrix/generate`)
      await matrix.reload()
    })

  const saveCell = (cell) => async (body) => {
    // service-cells PATCH accepts {status, reason} only
    await patch(`/service-cells/${cell.id}`, { status: body.status, reason: body.reason ?? null })
    await matrix.reload()
  }

  return (
    <div className="tab-grid">
      <Panel
        title="Service matrix"
        actions={
          <Button variant="ghost" onClick={matrix.reload}>
            ⟳
          </Button>
        }
      >
        <ErrorText error={matrix.error} />
        <div className="toolbar">
          <Button variant="primary" onClick={generate} disabled={gen.busy}>
            {gen.busy ? 'generating…' : 'generate cells'}
          </Button>
        </div>
        <ErrorText error={gen.error} />
      </Panel>

      <Panel title="Grid" className="grid-panel">
        {matrix.loading && !data ? (
          <Loading what="service matrix" />
        ) : services.length === 0 || cols.length === 0 ? (
          <Empty>no services — run recon, then “generate cells”.</Empty>
        ) : (
          <div className="grid-scroll">
            <table className="matrix">
              <thead>
                <tr>
                  <th className="sticky-col corner">service</th>
                  {cols.map((c) => (
                    <th key={c.key}>{c.label || c.key}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {services.map((svc) => (
                  <tr key={svc.id}>
                    <th className="sticky-col">
                      <span className="mono-sm">
                        {svc.host}:{svc.port}/{svc.proto}
                      </span>
                      <div className="muted tiny">
                        {svc.service}
                        {svc.version ? ` ${svc.version}` : ''}
                      </div>
                    </th>
                    {cols.map((col) => {
                      const cells = (svc.cells || []).filter(
                        (c) => c.service_vuln_class === col.key
                      )
                      return (
                        <td key={col.key} className="matrix-cell">
                          {cells.length === 0 ? (
                            <span className="cell-blank">·</span>
                          ) : (
                            cells.map((cell) => (
                              <span
                                key={cell.id}
                                className="cell"
                                data-status={cell.status}
                              >
                                <button
                                  className="cell-label"
                                  onClick={() => setEditing({ ...cell, _col: col })}
                                  title={`${cell.status}${cell.reason ? ` — ${cell.reason}` : ''}`}
                                >
                                  {cell.status.replace(/_/g, ' ').slice(0, 7)}
                                </button>
                              </span>
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
          title={`service cell #${editing.id} — ${editing.service_vuln_class}`}
          cell={editing}
          onSave={saveCell(editing)}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}
