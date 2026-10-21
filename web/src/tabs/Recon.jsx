import React, { useEffect, useRef, useState } from 'react'
import { get, post } from '../api.js'
import { Button, Empty, ErrorText, Field, Loading, Panel, useAction, useAsync } from '../ui.jsx'

export default function Recon({ target }) {
  const coverage = useAsync(() => get(`/targets/${target.id}/recon-coverage`), [target.id])
  const subs = useAsync(() => get(`/targets/${target.id}/subdomains`), [target.id])
  const [job, setJob] = useState(null)

  return (
    <div className="tab-grid">
      <StartJob
        target={target}
        onStarted={(j) => setJob(j)}
        onDone={() => {
          coverage.reload()
          subs.reload()
        }}
      />
      {job && <JobStatus target={target} job={job} onSettled={() => coverage.reload()} />}
      <Coverage coverage={coverage} />
      <Subdomains target={target} subs={subs} />
    </div>
  )
}

function StartJob({ target, onStarted, onDone }) {
  const [tier, setTier] = useState('quick')
  const [host, setHost] = useState('')
  const [keys, setKeys] = useState('')
  const { busy, error, run } = useAction()

  const submit = async (e) => {
    e.preventDefault()
    const body = { tier, host: host.trim() }
    const k = keys.split(',').map((s) => s.trim()).filter(Boolean)
    if (k.length) body.keys = k
    const j = await run(() => post(`/targets/${target.id}/recon`, body))
    onStarted(j)
  }

  return (
    <Panel title="Start recon">
      <form onSubmit={submit} className="stack">
        <div className="row wrap">
          <Field label="Tier">
            <select value={tier} onChange={(e) => setTier(e.target.value)}>
              <option value="quick">quick</option>
              <option value="thorough">thorough</option>
            </select>
          </Field>
          <Field label="Host">
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="target.example.com"
              spellCheck={false}
            />
          </Field>
        </div>
        <Field label="Task keys" hint="(optional, comma-separated)">
          <input
            value={keys}
            onChange={(e) => setKeys(e.target.value)}
            placeholder="subdomains,ports,http-fingerprint"
            spellCheck={false}
          />
        </Field>
        <div className="row">
          <Button variant="primary" type="submit" disabled={busy || !host.trim()}>
            start job
          </Button>
          <Button variant="ghost" type="button" onClick={onDone}>
            refresh coverage
          </Button>
        </div>
        <ErrorText error={error} />
        {!target.authorized && (
          <p className="muted tiny">target is not authorized — recon will be refused (403).</p>
        )}
      </form>
    </Panel>
  )
}

function JobStatus({ target, job, onSettled }) {
  const jobId = job.job_id
  const [state, setState] = useState(job)
  const timer = useRef(null)
  const settledRef = useRef(false)

  useEffect(() => {
    settledRef.current = false
    const poll = async () => {
      try {
        const r = await get(`/targets/${target.id}/recon/${jobId}`)
        setState(r)
        if (['done', 'error', 'failed', 'complete', 'completed'].includes(r.status)) {
          if (!settledRef.current) {
            settledRef.current = true
            onSettled()
          }
          return
        }
      } catch {
        /* keep last state */
      }
      timer.current = setTimeout(poll, 2000)
    }
    poll()
    return () => clearTimeout(timer.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId, target.id])

  const tasks = state.tasks || []
  return (
    <Panel title={`Recon job #${jobId}`} actions={<span className="badge" data-status={state.status}>{state.status}</span>}>
      {state.error && <ErrorText error={state.error} />}
      {tasks.length === 0 ? (
        <Empty>no tasks reported</Empty>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>key</th>
              <th>status</th>
              <th>importance</th>
              <th>note</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((t, i) => (
              <tr key={t.key || i}>
                <td className="mono-sm">{t.key}</td>
                <td>{t.status}</td>
                <td>{t.importance ?? (t.selected ? 'selected' : '')}</td>
                <td className="muted tiny">{t.note || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  )
}

function Coverage({ coverage }) {
  const data = coverage.data
  return (
    <Panel
      title="Recon coverage"
      actions={
        <Button variant="ghost" onClick={coverage.reload}>
          ⟳
        </Button>
      }
    >
      <ErrorText error={coverage.error} />
      {coverage.loading && !data ? (
        <Loading what="coverage" />
      ) : !data ? null : (
        <>
          {data.flagged_gaps && data.flagged_gaps.length > 0 && (
            <div className="gaps">
              <h4>flagged gaps (high importance, not run)</h4>
              <ul>
                {data.flagged_gaps.map((g, i) => (
                  <li key={g.key || i}>
                    <span className="chip chip-warn">{g.status}</span>{' '}
                    <span className="mono-sm">{g.key}</span>
                    {g.could_yield ? <span className="muted tiny"> → {g.could_yield}</span> : null}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {(!data.tasks || data.tasks.length === 0) ? (
            <Empty>no recon tasks recorded yet</Empty>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>key</th>
                  <th>tier</th>
                  <th>status</th>
                  <th>importance</th>
                  <th>could yield</th>
                  <th>sel</th>
                </tr>
              </thead>
              <tbody>
                {data.tasks.map((t, i) => (
                  <tr key={t.key || i}>
                    <td className="mono-sm">{t.key}</td>
                    <td>{t.tier}</td>
                    <td>
                      <span className="badge" data-status={t.status}>
                        {t.status}
                      </span>
                    </td>
                    <td>{t.importance}</td>
                    <td className="muted tiny">{t.could_yield}</td>
                    <td>{t.selected ? '✓' : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </Panel>
  )
}

function Subdomains({ target, subs }) {
  const { busy, error, run } = useAction()
  const [approving, setApproving] = useState(null)

  const approve = async (sub) => {
    setApproving(sub.id)
    try {
      await run(() => post(`/targets/${target.id}/subdomains/${sub.id}/approve`))
      subs.reload()
    } finally {
      setApproving(null)
    }
  }

  const list = subs.data || []
  return (
    <Panel
      title="Subdomains"
      actions={
        <Button variant="ghost" onClick={subs.reload}>
          ⟳
        </Button>
      }
    >
      <ErrorText error={subs.error || error} />
      {list.length === 0 ? (
        <Empty>no subdomains discovered</Empty>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>name</th>
              <th>status</th>
              <th>source</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {list.map((sd) => (
              <tr key={sd.id}>
                <td className="mono-sm">{sd.name}</td>
                <td>
                  <span className="badge" data-status={sd.status}>
                    {sd.status}
                  </span>
                </td>
                <td className="muted tiny">{sd.source}</td>
                <td>
                  {sd.status !== 'approved' && (
                    <Button
                      variant="primary"
                      disabled={busy && approving === sd.id}
                      onClick={() => approve(sd)}
                    >
                      approve
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  )
}
