import React, { useEffect, useMemo, useRef, useState } from 'react'
import { get, post } from '../api.js'
import { Button, Empty, ErrorText, Field, Loading, Panel, TabIntro, useAction, useAsync } from '../ui.jsx'

const TERMINAL = ['done', 'error', 'failed', 'complete', 'completed']

export default function Recon({ target }) {
  const coverage = useAsync(() => get(`/targets/${target.id}/recon-coverage`), [target.id])
  const subs = useAsync(() => get(`/targets/${target.id}/subdomains`), [target.id])
  const [job, setJob] = useState(null)

  return (
    <div className="tab-intro-wrap">
      <TabIntro
        title="Recon"
        lead="Check the discovery tasks to run against this machine, then launch. nmap seeds hosts, services and a root endpoint for each web port; httpx/ffuf/katana add more. The latest run's status shows on the right."
      />
      <div className="tab-grid two-col">
        <RunRecon
          target={target}
          onStarted={(j) => setJob(j)}
          onReload={() => {
            coverage.reload()
            subs.reload()
          }}
        />
        <LatestRun target={target} job={job} coverage={coverage} onSettled={coverage.reload} />
      </div>
      <Subdomains target={target} subs={subs} />
    </div>
  )
}

function RunRecon({ target, onStarted, onReload }) {
  const catalog = useAsync(() => get('/recon/catalog'), [])
  const preflight = useAsync(() => get('/preflight'), [])
  const [host, setHost] = useState(target.address || '')
  const [manual, setManual] = useState(!target.address)
  const [checked, setChecked] = useState(null)
  const { busy, error, run } = useAction()

  const tasks = useMemo(() => catalog.data || [], [catalog.data])
  const toolsAvailable = preflight.data?.tools || {}

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

  const effectiveHost = (manual ? host : target.address || host).trim()

  const submit = async (e) => {
    e.preventDefault()
    const keys = [...sel]
    const tier = keys.some((k) => tasks.find((t) => t.key === k)?.tier === 'thorough')
      ? 'thorough'
      : 'quick'
    const j = await run(() =>
      post(`/targets/${target.id}/recon`, { tier, host: effectiveHost, keys })
    )
    onStarted(j)
    onReload()
  }

  return (
    <Panel title="Run recon">
      <form onSubmit={submit} className="stack">
        <Field label="Machine" hint={manual ? 'custom host' : 'this target'}>
          {!manual && target.address ? (
            <div className="row machine-pick">
              <span className="machine-name">{target.name}</span>
              <span className="chip chip-tiny">{target.address}</span>
              <button type="button" className="link-btn" onClick={() => setManual(true)}>
                different host
              </button>
            </div>
          ) : (
            <div className="row">
              <input
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="target.example.com / 10.10.11.42"
                spellCheck={false}
                autoFocus={manual}
              />
              {target.address && (
                <Button
                  variant="ghost"
                  type="button"
                  onClick={() => {
                    setManual(false)
                    setHost(target.address)
                  }}
                >
                  use {target.name}
                </Button>
              )}
            </div>
          )}
          {!target.address && (
            <span className="muted tiny">
              tip: set this target's address on the Scope tab so it's picked automatically.
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
          <table className="data-table task-table">
            <thead>
              <tr>
                <th className="col-check"></th>
                <th>task</th>
                <th>yields</th>
                <th className="col-imp">imp.</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((t) => {
                const missing = toolsAvailable[t.tool] === false
                return (
                  <tr key={t.key} data-tier={t.tier} className={missing ? 'row-missing' : ''}>
                    <td className="col-check">
                      <input type="checkbox" checked={sel.has(t.key)} onChange={() => toggle(t.key)} />
                    </td>
                    <td>
                      <div className="task-label">
                        <span>{t.label}</span>
                        <span className="chip chip-tiny" data-tier={t.tier}>
                          {t.tier}
                        </span>
                        {missing && (
                          <span className="chip chip-warn chip-tiny" title={`${t.tool} not installed`}>
                            {t.tool} missing
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="muted tiny">{t.could_yield}</td>
                    <td>{t.importance}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
        <div className="tier-note muted tiny">quick tasks are shaded; thorough tasks are darker.</div>

        <div className="row">
          <Button
            variant="primary"
            type="submit"
            disabled={busy || !effectiveHost || sel.size === 0}
          >
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

function LatestRun({ target, job, coverage, onSettled }) {
  const [state, setState] = useState(null)
  const timer = useRef(null)
  const settledRef = useRef(false)

  useEffect(() => {
    if (!job) return
    setState(job)
    settledRef.current = false
    const poll = async () => {
      try {
        const r = await get(`/targets/${target.id}/recon/${job.job_id}`)
        setState(r)
        if (TERMINAL.includes(r.status)) {
          if (!settledRef.current) {
            settledRef.current = true
            onSettled && onSettled()
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
  }, [job, target.id])

  const data = coverage.data
  const liveTasks = state?.tasks || []
  const covTasks = data?.tasks || []
  const gaps = data?.flagged_gaps || []

  return (
    <Panel
      title="Latest run"
      actions={
        state ? (
          <span className="badge" data-status={state.status}>
            {state.status}
          </span>
        ) : (
          <Button variant="ghost" onClick={coverage.reload}>
            ⟳
          </Button>
        )
      }
    >
      <ErrorText error={coverage.error || state?.error} />
      {gaps.length > 0 && (
        <div className="gaps">
          <h4>gaps — high-importance tasks not run</h4>
          <ul>
            {gaps.map((g, i) => (
              <li key={g.key || i}>
                <span className="chip chip-warn">{g.status}</span>{' '}
                <span className="mono-sm">{g.key}</span>
                {g.could_yield ? <span className="muted tiny"> → {g.could_yield}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      )}
      {state ? (
        liveTasks.length === 0 ? (
          <Empty>running…</Empty>
        ) : (
          <TaskStatusTable rows={liveTasks} />
        )
      ) : coverage.loading && !data ? (
        <Loading what="coverage" />
      ) : covTasks.length === 0 ? (
        <Empty>no recon run yet — launch one on the left</Empty>
      ) : (
        <TaskStatusTable rows={covTasks} />
      )}
    </Panel>
  )
}

function TaskStatusTable({ rows }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>task</th>
          <th>status</th>
          <th>note</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((t, i) => (
          <tr key={t.key || i}>
            <td className="mono-sm">{t.key}</td>
            <td>
              <span className="badge" data-status={t.status}>
                {t.status}
              </span>
            </td>
            <td className="muted tiny">{t.note || t.could_yield || ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
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
