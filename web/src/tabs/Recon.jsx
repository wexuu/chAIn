import React, { useEffect, useMemo, useRef, useState } from 'react'
import { get, post } from '../api.js'
import {
  Button,
  Empty,
  ErrorText,
  Field,
  Loading,
  Panel,
  TabIntro,
  useAction,
  useAsync,
} from '../ui.jsx'

const TIER_ORDER = ['quick', 'thorough']
const TIER_LABEL = { quick: 'Quick (fast, start poking)', thorough: 'Thorough (deep, slower)' }

export default function Recon({ target }) {
  const coverage = useAsync(() => get(`/targets/${target.id}/recon-coverage`), [target.id])
  const subs = useAsync(() => get(`/targets/${target.id}/subdomains`), [target.id])
  const [job, setJob] = useState(null)

  return (
    <div className="tab-intro-wrap">
      <TabIntro
        title="Recon"
        lead="Pick the discovery tasks to run against a host, then launch. nmap seeds the hosts, services and a root endpoint for every web port; httpx/ffuf/katana add more endpoints. Anything high-importance you skip is flagged below as a gap."
      />
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
    </div>
  )
}

function StartJob({ target, onStarted }) {
  const catalog = useAsync(() => get('/recon/catalog'), [])
  const preflight = useAsync(() => get('/preflight'), [])
  const scope = useAsync(() => get(`/targets/${target.id}/scope`), [target.id])
  const [host, setHost] = useState('')
  const [manual, setManual] = useState(false)
  const [checked, setChecked] = useState(null) // Set of keys, or null until catalog loads
  const { busy, error, run } = useAction()

  const tasks = useMemo(() => catalog.data || [], [catalog.data])
  const toolsAvailable = preflight.data?.tools || {}

  // In-scope hosts you can scan directly: allow-rules that name a host or range.
  const scopeHosts = useMemo(
    () =>
      (scope.data || [])
        .filter((r) => r.allow && (r.kind === 'host' || r.kind === 'cidr'))
        .map((r) => r.value),
    [scope.data]
  )

  // Default the host to the first scope entry; fall back to manual entry when
  // the scope list is empty.
  useEffect(() => {
    if (!scope.data || manual || host) return
    if (scopeHosts.length) setHost(scopeHosts[0])
    else setManual(true)
  }, [scope.data, scopeHosts, manual, host])

  // Initialise the checkbox state from each task's default once the catalog loads.
  useEffect(() => {
    if (tasks.length && checked === null) {
      setChecked(new Set(tasks.filter((t) => t.default_selected).map((t) => t.key)))
    }
  }, [tasks, checked])

  const sel = checked || new Set()
  const toggle = (key) =>
    setChecked((prev) => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })

  const preset = (fn) => setChecked(new Set(tasks.filter(fn).map((t) => t.key)))

  const byTier = useMemo(() => {
    const m = {}
    for (const t of tasks) (m[t.tier] ||= []).push(t)
    return m
  }, [tasks])

  const submit = async (e) => {
    e.preventDefault()
    const keys = [...sel]
    // tier is derived: thorough if any thorough task is selected.
    const tier = keys.some((k) => tasks.find((t) => t.key === k)?.tier === 'thorough')
      ? 'thorough'
      : 'quick'
    const j = await run(() => post(`/targets/${target.id}/recon`, { tier, host: host.trim(), keys }))
    onStarted(j)
  }

  return (
    <Panel title="Start recon">
      <form onSubmit={submit} className="stack">
        <Field
          label="Host"
          hint={manual || scopeHosts.length === 0 ? 'hostname, IP or CIDR' : 'pick from scope'}
        >
          {manual || scopeHosts.length === 0 ? (
            <div className="row">
              <input
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="target.example.com / 10.10.11.42"
                spellCheck={false}
                autoFocus={manual}
              />
              {scopeHosts.length > 0 && (
                <Button
                  variant="ghost"
                  type="button"
                  onClick={() => {
                    setManual(false)
                    setHost(scopeHosts[0])
                  }}
                  title="pick from the scope list"
                >
                  from scope
                </Button>
              )}
            </div>
          ) : (
            <select
              value={host}
              onChange={(e) => {
                if (e.target.value === '__custom__') {
                  setManual(true)
                  setHost('')
                } else setHost(e.target.value)
              }}
            >
              {scopeHosts.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
              <option value="__custom__">✎ custom…</option>
            </select>
          )}
          {scopeHosts.length === 0 && !scope.loading && (
            <span className="muted tiny">
              no in-scope hosts yet — add one on the Scope tab, or type one here.
            </span>
          )}
        </Field>

        <div className="checklist-head">
          <span className="field-label">Tasks</span>
          <div className="preset-row">
            <button type="button" className="preset-btn" onClick={() => preset((t) => t.tier === 'quick')}>
              Quick
            </button>
            <button type="button" className="preset-btn" onClick={() => preset(() => true)}>
              All
            </button>
            <button type="button" className="preset-btn" onClick={() => preset(() => false)}>
              None
            </button>
          </div>
        </div>

        <ErrorText error={catalog.error || preflight.error} />
        {catalog.loading && !tasks.length ? (
          <Loading what="task catalog" />
        ) : (
          TIER_ORDER.filter((tier) => byTier[tier]?.length).map((tier) => (
            <div key={tier} className="checkgroup">
              <div className="checkgroup-title">{TIER_LABEL[tier] || tier}</div>
              {byTier[tier].map((t) => {
                const missing = toolsAvailable[t.tool] === false
                return (
                  <label key={t.key} className={`checkitem ${missing ? 'checkitem-missing' : ''}`}>
                    <input type="checkbox" checked={sel.has(t.key)} onChange={() => toggle(t.key)} />
                    <span className="checkitem-main">
                      <span className="checkitem-label">
                        {t.label}
                        {t.importance === 'high' && <span className="chip chip-tiny">high</span>}
                        {missing && (
                          <span className="chip chip-warn chip-tiny" title={`${t.tool} not installed`}>
                            {t.tool} missing
                          </span>
                        )}
                      </span>
                      <span className="checkitem-hint">{t.could_yield}</span>
                    </span>
                  </label>
                )
              })}
            </div>
          ))
        )}

        <div className="row">
          <Button variant="primary" type="submit" disabled={busy || !host.trim() || sel.size === 0}>
            {busy ? 'starting…' : `run ${sel.size} task${sel.size === 1 ? '' : 's'}`}
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
    <Panel
      title={`Recon job #${jobId}`}
      actions={<span className="badge" data-status={state.status}>{state.status}</span>}
    >
      {state.error && <ErrorText error={state.error} />}
      {tasks.length === 0 ? (
        <Empty>no tasks reported</Empty>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>task</th>
              <th>status</th>
              <th>note</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((t, i) => (
              <tr key={t.key || i}>
                <td className="mono-sm">{t.key}</td>
                <td>
                  <span className="badge" data-status={t.status}>
                    {t.status}
                  </span>
                </td>
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
    <Panel title="Recon coverage" actions={<Button variant="ghost" onClick={coverage.reload}>⟳</Button>}>
      <ErrorText error={coverage.error} />
      {coverage.loading && !data ? (
        <Loading what="coverage" />
      ) : !data ? null : (
        <>
          {data.flagged_gaps && data.flagged_gaps.length > 0 && (
            <div className="gaps">
              <h4>gaps — high-importance tasks not run</h4>
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
          {!data.tasks || data.tasks.length === 0 ? (
            <Empty>no recon tasks recorded yet — run a scan above</Empty>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>task</th>
                  <th>tier</th>
                  <th>status</th>
                  <th>importance</th>
                  <th>ran</th>
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
  const { busy, run } = useAction()
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
    <Panel title="Subdomains" actions={<Button variant="ghost" onClick={subs.reload}>⟳</Button>}>
      <ErrorText error={subs.error} />
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
