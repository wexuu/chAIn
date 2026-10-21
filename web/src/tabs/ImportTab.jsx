import React, { useState } from 'react'
import { post } from '../api.js'
import { Button, ErrorText, Field, Panel, useAction } from '../ui.jsx'

export default function ImportTab({ target, onTargetChanged }) {
  const [format, setFormat] = useState('openapi')
  const [content, setContent] = useState('')
  const [result, setResult] = useState(null)
  const { busy, error, run } = useAction()

  const submit = async (e) => {
    e.preventDefault()
    setResult(null)
    const r = await run(() => post(`/targets/${target.id}/import`, { format, content }))
    setResult(r)
    onTargetChanged && onTargetChanged()
  }

  const onFile = async (e) => {
    const f = e.target.files && e.target.files[0]
    if (!f) return
    const text = await f.text()
    setContent(text)
  }

  return (
    <div className="tab-grid">
      <Panel title="Import attack surface">
        <form onSubmit={submit} className="stack">
          <div className="row wrap">
            <Field label="Format">
              <select value={format} onChange={(e) => setFormat(e.target.value)}>
                <option value="openapi">openapi</option>
                <option value="har">har</option>
              </select>
            </Field>
            <Field label="Load from file" hint="(optional)">
              <input type="file" accept=".json,.har,.yaml,.yml,application/json" onChange={onFile} />
            </Field>
          </div>
          <Field label="Content">
            <textarea
              className="code"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={16}
              placeholder={
                format === 'openapi'
                  ? 'paste an OpenAPI/Swagger JSON document…'
                  : 'paste a HAR capture JSON…'
              }
              spellCheck={false}
            />
          </Field>
          <Button variant="primary" type="submit" disabled={busy || !content.trim()}>
            {busy ? 'importing…' : 'import'}
          </Button>
          <ErrorText error={error} />
          {result && (
            <div className="result ok">
              imported — <b>{result.endpoints_created}</b> endpoint
              {result.endpoints_created === 1 ? '' : 's'} created.
              {Object.keys(result).length > 1 && (
                <pre className="code-block">{JSON.stringify(result, null, 2)}</pre>
              )}
            </div>
          )}
        </form>
      </Panel>
    </div>
  )
}
