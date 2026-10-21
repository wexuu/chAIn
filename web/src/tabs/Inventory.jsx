import React, { useState } from 'react'
import { get, post } from '../api.js'
import { Button, Empty, ErrorText, Loading, Panel, TabIntro, useAction, useAsync } from '../ui.jsx'

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

const splitList = (s) =>
  s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)

export default function Inventory({ target }) {
  const inv = useAsync(() => get(`/targets/${target.id}/inventory`), [target.id])
  const data = inv.data
  const hosts = data?.hosts || []
  const endpoints = data?.endpoints || []

  return (
    <div className="tab-intro-wrap">
      <TabIntro
        title="Inventory"
        lead="Hosts and services come from recon. Endpoints are the request surface the matrix tests — add them by hand as you explore the app."
      />
      <div className="tab-grid">
        <Panel
          title={`Hosts (${hosts.length})`}
          actions={<Button variant="ghost" onClick={inv.reload}>⟳</Button>}
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
          <AddEndpoint target={target} onAdded={inv.reload} />
          {endpoints.length === 0 ? (
            <Empty>no endpoints — add one above, import a surface, or run recon.</Empty>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>method</th>
                  <th>path</th>
                  <th>params</th>
                  <th>body fields</th>
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
                    <td className="field-cell">
                      {(e.params || []).map((p) => (
                        <span key={p} className="chip chip-tiny">
                          {p}
                        </span>
                      ))}
                    </td>
                    <td className="field-cell">
                      {(e.body_fields || []).map((p) => (
                        <span key={p} className="chip chip-tiny">
                          {p}
                        </span>
                      ))}
                    </td>
                    <td className="muted tiny">{e.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </div>
  )
}

function AddEndpoint({ target, onAdded }) {
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [params, setParams] = useState('')
  const [bodyFields, setBodyFields] = useState('')
  const { busy, error, run } = useAction()

  const hasBody = BODY_METHODS.has(method)

  const submit = async (e) => {
    e.preventDefault()
    // Keep the path; lift query-param NAMES out of a pasted URL.
    let path = url.trim()
    const qKeys = []
    const qi = path.indexOf('?')
    if (qi >= 0) {
      const qs = path.slice(qi + 1)
      path = path.slice(0, qi)
      for (const pair of qs.split('&')) {
        const k = pair.split('=')[0].trim()
        if (k) qKeys.push(k)
      }
    }
    // strip scheme+host if a full URL was pasted
    const m = path.match(/^https?:\/\/[^/]+(\/.*)?$/i)
    if (m) path = m[1] || '/'
    const allParams = [...new Set([...qKeys, ...splitList(params)])]
    const body = { method, path: path || '/', params: allParams }
    if (hasBody) body.body_fields = splitList(bodyFields)
    await run(() => post(`/targets/${target.id}/endpoints`, body))
    setUrl('')
    setParams('')
    setBodyFields('')
    onAdded()
  }

  return (
    <form className="add-endpoint" onSubmit={submit}>
      <div className="row wrap">
        <select className="method-select" value={method} onChange={(e) => setMethod(e.target.value)}>
          {METHODS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <input
          className="grow"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="/api/users?id=1   (path or full URL)"
          spellCheck={false}
        />
      </div>
      <div className="row wrap">
        <input
          value={params}
          onChange={(e) => setParams(e.target.value)}
          placeholder="extra query params: id, filter"
          spellCheck={false}
        />
        {hasBody && (
          <input
            value={bodyFields}
            onChange={(e) => setBodyFields(e.target.value)}
            placeholder="body fields: username, password"
            spellCheck={false}
          />
        )}
        <Button variant="primary" type="submit" disabled={busy || !url.trim()}>
          add
        </Button>
      </div>
      <p className="muted tiny add-endpoint-note">
        Stored as method + path + the <b>names</b> of query params and body fields — enough for the
        matrix to generate param-specific tests and for an agent to craft requests. No raw request
        body is kept.
      </p>
      <ErrorText error={error} />
    </form>
  )
}
