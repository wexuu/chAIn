import React from 'react'
import { get } from '../api.js'
import { Button, Empty, ErrorText, Loading, Panel, TabIntro, useAsync, CELL_STATUSES } from '../ui.jsx'

// One place to see where the engagement stands, pulled from every section so
// you don't have to tab around. Built mostly from the export bundle (matrix
// summary + findings + recon coverage) plus inventory and chains counts.
export default function Coverage({ target }) {
  const report = useAsync(() => get(`/targets/${target.id}/export`), [target.id])
  const inv = useAsync(() => get(`/targets/${target.id}/inventory`), [target.id])
  const hyps = useAsync(() => get(`/targets/${target.id}/hypotheses`), [target.id])
  const edges = useAsync(() => get(`/targets/${target.id}/edges`), [target.id])

  const data = report.data
  const summary = data?.coverage_annex?.summary
  const findings = data?.findings || []
  const recon = data?.recon_coverage || {}
  const reconTasks = recon.tasks || []
  const gaps = recon.flagged_gaps || []
  const hosts = inv.data?.hosts || []
  const endpoints = inv.data?.endpoints || []
  const services = hosts.reduce((n, h) => n + (h.services?.length || 0), 0)
  const hypList = hyps.data || []
  const edgeList = edges.data || []

  const reconDone = reconTasks.filter((t) => ['done', 'complete', 'completed'].includes(t.status)).length
  const confirmed = findings.filter((f) => f.status === 'confirmed').length
  const bySeverity = countBy(findings, (f) => (f.severity || 'unknown').toLowerCase())
  const refresh = () => {
    report.reload()
    inv.reload()
    hyps.reload()
    edges.reload()
  }

  return (
    <div className="tab-intro-wrap">
      <TabIntro
        title="Coverage"
        lead="A single overview of the whole engagement — matrix progress, findings, recon, surface and chains — so you don't have to walk the tabs."
      >
        <div>
          <Button variant="ghost" onClick={refresh}>
            ⟳ refresh
          </Button>
        </div>
      </TabIntro>

      <ErrorText error={report.error} />
      {report.loading && !data ? (
        <Loading what="coverage" />
      ) : (
        <>
          <div className="stat-row">
            <StatTile
              big={summary ? `${summary.coverage_pct}%` : '—'}
              label="matrix coverage"
              sub={summary ? `${summary.covered}/${summary.applicable} applicable cells` : 'no cells'}
              accent
            />
            <StatTile big={findings.length} label="findings" sub={`${confirmed} confirmed`} />
            <StatTile
              big={`${reconDone}/${reconTasks.length || 0}`}
              label="recon tasks"
              sub={gaps.length ? `${gaps.length} gap${gaps.length === 1 ? '' : 's'}` : 'no gaps'}
            />
            <StatTile big={endpoints.length} label="endpoints" sub={`${hosts.length} hosts`} />
            <StatTile big={services} label="services" />
            <StatTile big={hypList.length} label="hypotheses" sub={`${edgeList.length} edges`} />
          </div>

          <div className="tab-grid two-col">
            <Panel title="Cells by status">
              {!summary ? (
                <Empty>no matrix cells yet — generate the matrix.</Empty>
              ) : (
                <div className="bar-list">
                  {CELL_STATUSES.map((s) => {
                    const v = summary.by_status?.[s] || 0
                    const pct = summary.total_cells ? Math.round((v / summary.total_cells) * 100) : 0
                    return (
                      <div key={s} className="bar-row">
                        <span className="bar-label">
                          <span className="swatch" data-status={s} /> {s.replace(/_/g, ' ')}
                        </span>
                        <span className="bar-track">
                          <span className="bar-fill" data-status={s} style={{ width: `${pct}%` }} />
                        </span>
                        <span className="bar-val">{v}</span>
                      </div>
                    )
                  })}
                </div>
              )}
            </Panel>

            <Panel title="Findings by severity">
              {findings.length === 0 ? (
                <Empty>no findings yet</Empty>
              ) : (
                <ul className="scope-list">
                  {Object.entries(bySeverity)
                    .sort((a, b) => b[1] - a[1])
                    .map(([sev, n]) => (
                      <li key={sev}>
                        <span className="badge" data-status={sev}>
                          {sev}
                        </span>{' '}
                        <b>{n}</b>
                      </li>
                    ))}
                </ul>
              )}
            </Panel>

            <Panel title="Recon gaps">
              {gaps.length === 0 ? (
                <Empty>no high-importance gaps</Empty>
              ) : (
                <ul className="scope-list">
                  {gaps.map((g, i) => (
                    <li key={g.key || i}>
                      <span className="chip chip-warn">{g.status}</span>{' '}
                      <span className="mono-sm">{g.key}</span>
                      {g.could_yield ? <span className="muted tiny"> → {g.could_yield}</span> : null}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Chains">
              {hypList.length === 0 ? (
                <Empty>no hypotheses yet</Empty>
              ) : (
                <ul className="scope-list">
                  {hypList.slice(0, 8).map((h) => (
                    <li key={h.id}>
                      <span className="badge" data-status={h.status}>
                        {h.status}
                      </span>{' '}
                      {h.title}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>
        </>
      )}
    </div>
  )
}

function StatTile({ big, label, sub, accent = false }) {
  return (
    <div className={`stat-tile ${accent ? 'stat-accent' : ''}`}>
      <span className="stat-big">{big}</span>
      <span className="stat-label">{label}</span>
      {sub && <span className="stat-sub">{sub}</span>}
    </div>
  )
}

function countBy(list, keyFn) {
  const out = {}
  for (const x of list) {
    const k = keyFn(x)
    out[k] = (out[k] || 0) + 1
  }
  return out
}
