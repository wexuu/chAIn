import React from 'react'
import { api, get, post } from '../api.js'
import { Button, Empty, ErrorText, Loading, Panel, TabIntro, useAction, useAsync } from '../ui.jsx'

// Archived machines: hidden from the main picker but kept with all their data.
// Restore one to work on it again, or delete it permanently.
export default function Archive({ onActiveChanged }) {
  const archived = useAsync(() => get('/targets/list?archived=true'), [])
  const { busy, run } = useAction()

  const restore = (t) =>
    run(async () => {
      await post(`/targets/${t.id}/restore`)
      archived.reload()
      onActiveChanged && onActiveChanged()
    })

  const remove = (t) =>
    run(async () => {
      if (!window.confirm(`Permanently delete "${t.name}" and all its data? This cannot be undone.`)) {
        return
      }
      await api(`/targets/${t.id}`, { method: 'DELETE' })
      archived.reload()
      onActiveChanged && onActiveChanged()
    })

  const list = archived.data || []
  return (
    <div className="tab-intro-wrap">
      <TabIntro
        title="Archive"
        lead="Machines you've put aside. Their recon, matrix and findings are all preserved — restore one to pick it up again, or delete it for good."
      />
      <Panel
        title={`Archived machines (${list.length})`}
        actions={<Button variant="ghost" onClick={archived.reload}>⟳</Button>}
      >
        <ErrorText error={archived.error} />
        {archived.loading && !archived.data ? (
          <Loading what="archive" />
        ) : list.length === 0 ? (
          <Empty>nothing archived</Empty>
        ) : (
          <ul className="archive-list">
            {list.map((t) => (
              <li key={t.id} className="archive-row">
                <span className="archive-main">
                  <strong>{t.name}</strong>
                  <span className="mono-sm muted">{t.address || 'no address'}</span>
                </span>
                <span className={`chip ${t.authorized ? 'chip-ok' : 'chip-warn'}`}>
                  {t.authorized ? 'authz' : 'unauthz'}
                </span>
                <div className="row">
                  <Button variant="primary" disabled={busy} onClick={() => restore(t)}>
                    restore
                  </Button>
                  <Button variant="danger" disabled={busy} onClick={() => remove(t)}>
                    delete
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}
