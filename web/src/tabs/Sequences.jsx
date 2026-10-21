import React, { useMemo, useState } from 'react'
import { get, post } from '../api.js'
import { Button, Empty, ErrorText, Field, Loading, Panel, TabIntro, useAction, useAsync } from '../ui.jsx'

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const CAPTURE_KINDS = ['json', 'regex', 'header']

let _sid = 0
const newId = () => ++_sid

const emptyStep = (over = {}) => ({
  _id: newId(),
  name: '',
  method: 'GET',
  path: '/',
  headers: [],
  body: '',
  captures: [],
  auth_profile: '',
  ...over,
})

// A working two-step example: log in, capture the token, reuse it.
const starterSteps = () => [
  emptyStep({
    name: 'login',
    method: 'POST',
    path: '/api/login',
    body: '{\n  "user": "admin",\n  "pass": "{{PASS}}"\n}',
    captures: [{ _id: newId(), name: 'token', kind: 'json', expr: 'token' }],
  }),
  emptyStep({
    name: 'whoami',
    method: 'GET',
    path: '/api/me',
    headers: [{ _id: newId(), k: 'Authorization', v: 'Bearer {{token}}' }],
  }),
]

export default function Sequences({ target }) {
  const seqs = useAsync(() => get(`/targets/${target.id}/sequences`), [target.id])

  return (
    <div className="tab-intro-wrap">
      <TabIntro title="Sequences">
        <p>
          A sequence is a chain of requests run in order. Each step can{' '}
          <b>capture</b> a value from its response (a JSON field, regex match or header) into a
          variable; later steps reference it as <code>{'{{name}}'}</code> in the path, headers or
          body. Classic use: log in, grab the token, then hit an authenticated endpoint.
        </p>
      </TabIntro>
      <div className="tab-grid">
        <Builder target={target} onCreated={seqs.reload} />
        <SequenceList target={target} seqs={seqs} />
      </div>
    </div>
  )
}

function Builder({ target, onCreated }) {
  const [name, setName] = useState('')
  const [steps, setSteps] = useState(starterSteps)
  const [showJson, setShowJson] = useState(false)
  const { busy, error, setError, run } = useAction()

  const patchStep = (id, patch) =>
    setSteps((list) => list.map((s) => (s._id === id ? { ...s, ...patch } : s)))
  const removeStep = (id) => setSteps((list) => list.filter((s) => s._id !== id))
  const move = (id, dir) =>
    setSteps((list) => {
      const i = list.findIndex((s) => s._id === id)
      const j = i + dir
      if (i < 0 || j < 0 || j >= list.length) return list
      const copy = [...list]
      ;[copy[i], copy[j]] = [copy[j], copy[i]]
      return copy
    })

  const built = useMemo(() => {
    return steps.map((s) => {
      const step = { method: s.method, path: s.path || '/' }
      if (s.name.trim()) step.name = s.name.trim()
      const headers = {}
      for (const h of s.headers) if (h.k.trim()) headers[h.k.trim()] = h.v
      if (Object.keys(headers).length) step.headers = headers
      if (s.body.trim()) {
        try {
          step.body = JSON.parse(s.body)
        } catch {
          step.body = s.body
        }
      }
      const caps = s.captures
        .filter((c) => c.name.trim() && c.expr.trim())
        .map((c) => ({ name: c.name.trim(), kind: c.kind, expr: c.expr.trim() }))
      if (caps.length) step.captures = caps
      if (s.auth_profile.trim()) step.auth_profile = s.auth_profile.trim()
      return step
    })
  }, [steps])

  const submit = async (e) => {
    e.preventDefault()
    if (!name.trim()) return setError('name is required')
    if (!built.length) return setError('add at least one step')
    await run(() => post(`/targets/${target.id}/sequences`, { name: name.trim(), steps: built }))
    setName('')
    setSteps(starterSteps())
    onCreated()
  }

  return (
    <Panel
      title="Build sequence"
      actions={
        <Button variant="ghost" type="button" onClick={() => setShowJson((v) => !v)}>
          {showJson ? 'hide JSON' : 'view JSON'}
        </Button>
      }
    >
      <form onSubmit={submit} className="stack">
        <Field label="Name">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="login-then-fetch"
            spellCheck={false}
          />
        </Field>

        {steps.map((s, i) => (
          <StepCard
            key={s._id}
            n={i + 1}
            step={s}
            first={i === 0}
            last={i === steps.length - 1}
            onChange={(patch) => patchStep(s._id, patch)}
            onRemove={() => removeStep(s._id)}
            onMove={(dir) => move(s._id, dir)}
          />
        ))}

        <div className="row">
          <Button variant="ghost" type="button" onClick={() => setSteps((l) => [...l, emptyStep()])}>
            + add step
          </Button>
        </div>

        {showJson && <pre className="code-block">{JSON.stringify(built, null, 2)}</pre>}

        <Button variant="primary" type="submit" disabled={busy || !name.trim()}>
          create sequence
        </Button>
        <ErrorText error={error} />
      </form>
    </Panel>
  )
}

function StepCard({ n, step, first, last, onChange, onRemove, onMove }) {
  const setHeader = (id, patch) =>
    onChange({ headers: step.headers.map((h) => (h._id === id ? { ...h, ...patch } : h)) })
  const setCap = (id, patch) =>
    onChange({ captures: step.captures.map((c) => (c._id === id ? { ...c, ...patch } : c)) })

  return (
    <div className="step-card">
      <div className="step-top">
        <span className="step-num">Step {n}</span>
        <input
          className="step-name"
          value={step.name}
          onChange={(e) => onChange({ name: e.target.value })}
          placeholder="label (optional)"
          spellCheck={false}
        />
        <div className="step-tools">
          <button type="button" className="icon-btn" disabled={first} onClick={() => onMove(-1)} title="move up">
            ↑
          </button>
          <button type="button" className="icon-btn" disabled={last} onClick={() => onMove(1)} title="move down">
            ↓
          </button>
          <button type="button" className="icon-btn danger" onClick={onRemove} title="remove step">
            ×
          </button>
        </div>
      </div>

      <div className="row step-req">
        <select value={step.method} onChange={(e) => onChange({ method: e.target.value })}>
          {METHODS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <input
          className="grow"
          value={step.path}
          onChange={(e) => onChange({ path: e.target.value })}
          placeholder="/api/login  (or {{var}})"
          spellCheck={false}
        />
      </div>

      <div className="step-sub">
        <div className="step-sub-head">
          <span>Headers</span>
          <button
            type="button"
            className="link-btn"
            onClick={() => onChange({ headers: [...step.headers, { _id: newId(), k: '', v: '' }] })}
          >
            + header
          </button>
        </div>
        {step.headers.map((h) => (
          <div key={h._id} className="row kv-row">
            <input
              value={h.k}
              onChange={(e) => setHeader(h._id, { k: e.target.value })}
              placeholder="Authorization"
              spellCheck={false}
            />
            <input
              value={h.v}
              onChange={(e) => setHeader(h._id, { v: e.target.value })}
              placeholder="Bearer {{token}}"
              spellCheck={false}
            />
            <button
              type="button"
              className="icon-btn danger"
              onClick={() => onChange({ headers: step.headers.filter((x) => x._id !== h._id) })}
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <div className="step-sub">
        <div className="step-sub-head">
          <span>Body</span>
          <span className="muted tiny">JSON or raw — {'{{vars}}'} allowed</span>
        </div>
        <textarea
          className="code"
          rows={step.body ? 4 : 2}
          value={step.body}
          onChange={(e) => onChange({ body: e.target.value })}
          placeholder='{ "user": "admin" }'
          spellCheck={false}
        />
      </div>

      <div className="step-sub">
        <div className="step-sub-head">
          <span>Capture</span>
          <button
            type="button"
            className="link-btn"
            onClick={() =>
              onChange({ captures: [...step.captures, { _id: newId(), name: '', kind: 'json', expr: '' }] })
            }
          >
            + capture
          </button>
        </div>
        {step.captures.length === 0 && (
          <span className="muted tiny">pull a value from the response into a variable</span>
        )}
        {step.captures.map((c) => (
          <div key={c._id} className="row cap-row">
            <input
              className="cap-name"
              value={c.name}
              onChange={(e) => setCap(c._id, { name: e.target.value })}
              placeholder="token"
              spellCheck={false}
            />
            <span className="cap-arrow">←</span>
            <select value={c.kind} onChange={(e) => setCap(c._id, { kind: e.target.value })}>
              {CAPTURE_KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <input
              className="grow"
              value={c.expr}
              onChange={(e) => setCap(c._id, { expr: e.target.value })}
              placeholder={c.kind === 'json' ? 'data.token' : c.kind === 'header' ? 'Location' : '(\\w+)'}
              spellCheck={false}
            />
            <button
              type="button"
              className="icon-btn danger"
              onClick={() => onChange({ captures: step.captures.filter((x) => x._id !== c._id) })}
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

function SequenceList({ target, seqs }) {
  const list = seqs.data || []
  return (
    <Panel title={`Sequences (${list.length})`} actions={<Button variant="ghost" onClick={seqs.reload}>⟳</Button>}>
      <ErrorText error={seqs.error} />
      {seqs.loading && !seqs.data ? (
        <Loading what="sequences" />
      ) : list.length === 0 ? (
        <Empty>no sequences yet — build one on the left</Empty>
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
  const { busy, run } = useAction()

  const runSeq = async () => {
    const body = {}
    if (host.trim()) body.host = host.trim()
    const r = await run(() => post(`/sequences/${seq.id}/run`, body))
    setResult(r)
  }

  const steps = result?.results?.steps || []
  return (
    <li className="seq">
      <div className="seq-head">
        <strong>{seq.name}</strong>
        <span className="muted tiny">
          #{seq.id} · {seq.steps} steps
        </span>
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
      {result && (
        <div className="result">
          <div className="row">
            <span className="muted tiny">run #{result.run_id}</span>
            <span className="badge" data-status={result.status}>
              {result.status}
            </span>
          </div>
          {steps.length > 0 && (
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>step</th>
                  <th>req</th>
                  <th>status</th>
                  <th>captured</th>
                </tr>
              </thead>
              <tbody>
                {steps.map((s, i) => (
                  <tr key={i}>
                    <td className="mono-sm">{s.step}</td>
                    <td>{s.name || ''}</td>
                    <td className="mono-sm">
                      {s.method} {s.path}
                    </td>
                    <td>{s.error ? <span className="chip chip-danger">err</span> : s.status}</td>
                    <td className="muted tiny">
                      {s.error ? s.error : Object.keys(s.captured || {}).join(', ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </li>
  )
}
