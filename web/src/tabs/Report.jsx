import React, { useState } from 'react'
import { getText, post } from '../api.js'
import { Button, ErrorText, Field, Panel, useAction } from '../ui.jsx'

export default function Report({ target }) {
  const jsonUrl = `/targets/${target.id}/export?format=json`

  return (
    <div className="tab-grid">
      <NewFinding target={target} />
      <ReportView target={target} jsonUrl={jsonUrl} />
    </div>
  )
}

function NewFinding({ target }) {
  const [form, setForm] = useState({
    title: '',
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    vuln_class_key: '',
    endpoints: '',
    remediation: '',
  })
  const [result, setResult] = useState(null)
  const { busy, error, run } = useAction()

  const submit = async (e) => {
    e.preventDefault()
    setResult(null)
    const body = { title: form.title.trim(), cvss_vector: form.cvss_vector.trim() }
    if (form.vuln_class_key.trim()) body.vuln_class_key = form.vuln_class_key.trim()
    if (form.remediation.trim()) body.remediation = form.remediation.trim()
    const eps = form.endpoints.split(',').map((s) => s.trim()).filter(Boolean)
    if (eps.length) body.endpoints = eps
    const r = await run(() => post(`/targets/${target.id}/findings`, body))
    setResult(r)
  }

  return (
    <Panel title="New finding">
      <form onSubmit={submit} className="stack">
        <Field label="Title">
          <input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
        </Field>
        <Field label="CVSS vector">
          <input
            className="code"
            value={form.cvss_vector}
            onChange={(e) => setForm({ ...form, cvss_vector: e.target.value })}
            spellCheck={false}
          />
        </Field>
        <div className="row wrap">
          <Field label="Vuln class key" hint="(optional)">
            <input
              value={form.vuln_class_key}
              onChange={(e) => setForm({ ...form, vuln_class_key: e.target.value })}
              placeholder="sqli"
              spellCheck={false}
            />
          </Field>
          <Field label="Endpoints" hint="(optional, comma-sep)">
            <input
              value={form.endpoints}
              onChange={(e) => setForm({ ...form, endpoints: e.target.value })}
              placeholder="/api/users/{id}"
              spellCheck={false}
            />
          </Field>
        </div>
        <Field label="Remediation" hint="(optional)">
          <textarea value={form.remediation} onChange={(e) => setForm({ ...form, remediation: e.target.value })} rows={2} />
        </Field>
        <Button variant="primary" type="submit" disabled={busy || !form.title.trim() || !form.cvss_vector.trim()}>
          record finding
        </Button>
        <ErrorText error={error} />
        {result && (
          <div className="result ok">
            scored <b>{result.cvss_score}</b> —{' '}
            <span className="badge" data-status={result.severity}>
              {result.severity}
            </span>
          </div>
        )}
      </form>
    </Panel>
  )
}

function ReportView({ target, jsonUrl }) {
  const [md, setMd] = useState(null)
  const { busy, error, run } = useAction()

  const load = () =>
    run(async () => {
      const text = await getText(`/targets/${target.id}/export?format=md`)
      setMd(text)
    })

  return (
    <Panel
      title="Report"
      actions={
        <>
          <Button variant="primary" onClick={load} disabled={busy}>
            {busy ? 'loading…' : md ? 'reload markdown' : 'load markdown'}
          </Button>
          <a className="btn btn-ghost" href={jsonUrl} target="_blank" rel="noreferrer">
            open JSON ↗
          </a>
        </>
      }
    >
      <ErrorText error={error} />
      {md == null ? (
        <p className="muted tiny">Press “load markdown” to render the exported report.</p>
      ) : md.trim() === '' ? (
        <p className="muted tiny">(empty report)</p>
      ) : (
        <pre className="report-md">{md}</pre>
      )}
    </Panel>
  )
}
