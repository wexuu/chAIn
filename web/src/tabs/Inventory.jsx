import React from 'react'
import { get } from '../api.js'
import { Button, Empty, ErrorText, Loading, Panel, useAsync } from '../ui.jsx'

export default function Inventory({ target }) {
  const inv = useAsync(() => get(`/targets/${target.id}/inventory`), [target.id])
  const data = inv.data
  const hosts = data?.hosts || []
  const endpoints = data?.endpoints || []

  return (
    <div className="tab-grid">
      <Panel
        title={`Hosts (${hosts.length})`}
        actions={
          <Button variant="ghost" onClick={inv.reload}>
            ⟳
          </Button>
        }
      >
        <ErrorText error={inv.error} />
        {inv.loading && !data ? (
          <Loading what="inventory" />
        ) : hosts.length === 0 ? (
          <Empty>no hosts — run recon first</Empty>
        ) : (
          hosts.map((h) => (
            <div key={h.id} className="host-card">
              <div className="host-head">
                <strong>{h.hostname || h.ip || `host#${h.id}`}</strong>
                <span className="muted tiny">
                  {h.ip}
                  {h.os_guess ? ` · ${h.os_guess}` : ''}
                </span>
              </div>
              {h.services && h.services.length > 0 ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>port</th>
                      <th>proto</th>
                      <th>service</th>
                      <th>product</th>
                      <th>ver</th>
                      <th>http</th>
                    </tr>
                  </thead>
                  <tbody>
                    {h.services.map((s, i) => (
                      <tr key={i}>
                        <td className="mono-sm">{s.port}</td>
                        <td>{s.proto}</td>
                        <td>{s.name}</td>
                        <td className="muted tiny">{s.product}</td>
                        <td className="muted tiny">{s.version}</td>
                        <td>{s.is_http ? '✓' : ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <Empty>no services</Empty>
              )}
            </div>
          ))
        )}
      </Panel>

      <Panel title={`Endpoints (${endpoints.length})`}>
        {endpoints.length === 0 ? (
          <Empty>no endpoints — import a surface or run recon</Empty>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>method</th>
                <th>path</th>
                <th>source</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e) => (
                <tr key={e.id}>
                  <td>
                    <span className="method" data-method={e.method}>
                      {e.method}
                    </span>
                  </td>
                  <td className="mono-sm">{e.path}</td>
                  <td className="muted tiny">{e.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}
