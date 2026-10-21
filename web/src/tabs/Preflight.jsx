import React from 'react'
import { get } from '../api.js'
import { Button, Empty, ErrorText, Loading, Panel, useAsync } from '../ui.jsx'

export default function Preflight() {
  const pf = useAsync(() => get('/preflight'), [])
  const data = pf.data
  const tools = data?.tools || {}
  const missing = data?.missing || []
  const toolEntries = Object.entries(tools)

  return (
    <div className="tab-grid">
      <Panel
        title="Preflight"
        actions={
          <Button variant="ghost" onClick={pf.reload}>
            ⟳
          </Button>
        }
      >
        <ErrorText error={pf.error} />
        {pf.loading && !data ? (
          <Loading what="preflight" />
        ) : !data ? null : (
          <>
            <div className="row wrap preflight-flags">
              <span className={`chip ${data.firewall_apply_enabled ? 'chip-ok' : 'chip-warn'}`}>
                firewall apply: {data.firewall_apply_enabled ? 'enabled' : 'disabled'}
              </span>
              <span className={`chip ${missing.length ? 'chip-warn' : 'chip-ok'}`}>
                {missing.length} missing
              </span>
            </div>

            {toolEntries.length === 0 ? (
              <Empty>no tools reported</Empty>
            ) : (
              <div className="tool-grid">
                {toolEntries.map(([name, ok]) => (
                  <div key={name} className={`tool ${ok ? 'tool-ok' : 'tool-bad'}`}>
                    <span className="tool-dot" />
                    <span className="tool-name">{name}</span>
                    <span className="tool-state">{ok ? 'ok' : 'missing'}</span>
                  </div>
                ))}
              </div>
            )}

            {missing.length > 0 && (
              <div className="gaps">
                <h4>missing tools</h4>
                <ul>
                  {missing.map((m) => (
                    <li key={m} className="mono-sm">
                      {m}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </Panel>
    </div>
  )
}
