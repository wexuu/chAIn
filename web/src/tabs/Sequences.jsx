import React, { useState } from 'react'
import { get, post } from '../api.js'
import { Button, Empty, ErrorText, Field, Loading, Panel, useAction, useAsync } from '../ui.jsx'

const SAMPLE = `[
  { "name": "login", "method": "POST", "path": "/api/login",
    "body": { "user": "admin", "pass": "{{PASS}}" },
    "capture": { "token": "json:$.token" } },
  { "name": "whoami", "method": "GET", "path": "/api/me",
    "headers": { "Authorization": "Bearer {{token}}" } }
]`

export default function Sequences({ target }) {
  const seqs = useAsync(() => get(`/targets/${target.id}/sequences`), [target.id])

  return (
    <div className="tab-grid">
      <CreateSequence target={target} onCreated={seqs.reload} />
      <SequenceList target={target} seqs={seqs} />
    </div>
  )
}

function CreateSequence({ target, onCreated }) {
  const [name, setName] = useState('')
  const [stepsText, setStepsText] = useState(SAMPLE)
  const { busy, error, setError, run } = useAction()

  const submit = async (e) => {
    e.preventDefault()
    let steps
    try {
      steps = JSON.parse(stepsText)
    } catch (err) {
      setError(`steps is not valid JSON: ${err.message}`)
      return
    }
    if (!Array.isArray(steps) || steps.length === 0) {
      setError('steps must be a non-empty JSON array')
      return
    }
    await run(() => post(`/targets/${target.id}/sequences`, { name: name.trim(), steps }))
    setName('')
    onCreated()
  }

  return (
    <Panel title="Create sequence">
      <form onSubmit={submit} className="stack">
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="login-then-fetch" spellCheck={false} />
        </Field>
        <Field label="Steps (JSON array)">
          <textarea
            className="code"
            value={stepsText}
            onChange={(e) => setStepsText(e.target.value)}
            rows={12}
            spellCheck={false}
          />
        </Field>
        <Button variant="primary" type="submit" disabled={busy || !name.trim()}>
          create sequence
        </Button>
        <ErrorText error={error} />
      </form>
    </Panel>
  )
}

function SequenceList({ target, seqs }) {
  const list = seqs.data || []
  return (
    <Panel
      title={`Sequences (${list.length})`}
      actions={
        <Button variant="ghost" onClick={seqs.reload}>
          ⟳
        </Button>
      }
    >
      <ErrorText error={seqs.error} />
      {seqs.loading && !seqs.data ? (
        <Loading what="sequences" />
      ) : list.length === 0 ? (
        <Empty>no sequences yet</Empty>
      ) : (
        <ul className="seq-list">
          {list.map((q) => (
            <SequenceRow key={q.id} seq={q} target={target} />
          ))}
        </ul>
      )}
    </Panel>
  )
}

function SequenceRow({ seq, target }) {
  const [host, setHost] = useState('')
  const [result, setResult] = useState(null)
  const { busy, error, run } = useAction()

  const runSeq = async () => {
    const body = {}
    if (host.trim()) body.host = host.trim()
    const r = await run(() => post(`/sequences/${seq.id}/run`, body))
    setResult(r)
  }

  return (
    <li className="seq">
      <div className="seq-head">
        <strong>{seq.name}</strong>
        <span className="muted tiny">#{seq.id} · {seq.steps} steps</span>
      </div>
      <div className="row wrap">
        <input
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="host override (optional)"
          spellCheck={false}
        />
        <Button variant="primary" onClick={runSeq} disabled={busy}>
          {busy ? 'running…' : 'run'}
        </Button>
      </div>
      {!target.authorized && <p className="muted tiny">target not authorized — run will be refused (403).</p>}
      <ErrorText error={error} />
      {result && (
        <div className="result">
          <div className="row">
            <span className="muted tiny">run #{result.run_id}</span>
            <span className="badge" data-status={result.status}>
              {result.status}
            </span>
          </div>
          <pre className="code-block">{JSON.stringify(result.results, null, 2)}</pre>
        </div>
      )}
    </li>
  )
}
