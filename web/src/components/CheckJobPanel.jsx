import React, { useEffect, useRef, useState } from 'react'
import { get } from '../api.js'
import { Empty, ErrorText, Panel } from '../ui.jsx'

const TERMINAL = ['done', 'error', 'failed', 'complete', 'completed']

// Polls a check job until it reaches a terminal status.
export default function CheckJobPanel({ target, job, onSettled }) {
  const jobId = job.job_id
  const [state, setState] = useState(job)
  const [err, setErr] = useState(null)
  const timer = useRef(null)
  const settled = useRef(false)

  useEffect(() => {
    settled.current = false
    const poll = async () => {
      try {
        const r = await get(`/targets/${target.id}/checkjobs/${jobId}`)
        setState(r)
        setErr(null)
        if (TERMINAL.includes(r.status)) {
          if (!settled.current) {
            settled.current = true
            onSettled && onSettled()
          }
          return
        }
      } catch (e) {
        setErr(e.message || String(e))
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
      title={`Check job #${jobId}`}
      actions={
        <span className="badge" data-status={state.status}>
          {state.status}
        </span>
      }
    >
      <ErrorText error={err || state.error} />
      {tasks.length === 0 ? (
        <Empty>no tasks</Empty>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>cell</th>
              <th>tool</th>
              <th>status</th>
              <th>note</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((t, i) => (
              <tr key={i}>
                <td className="mono-sm">{t.cell_id}</td>
                <td>{t.tool}</td>
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
