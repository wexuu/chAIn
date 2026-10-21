import React, { useState } from 'react'
import { get } from './api.js'
import { useAsync } from './ui.jsx'
import TargetBar from './components/TargetBar.jsx'
import Recon from './tabs/Recon.jsx'
import Inventory from './tabs/Inventory.jsx'
import Matrix from './tabs/Matrix.jsx'
import ServiceMatrix from './tabs/ServiceMatrix.jsx'
import Chains from './tabs/Chains.jsx'
import Sequences from './tabs/Sequences.jsx'
import ImportTab from './tabs/ImportTab.jsx'
import Report from './tabs/Report.jsx'
import Preflight from './tabs/Preflight.jsx'

const TABS = [
  { key: 'recon', label: 'Recon', Comp: Recon },
  { key: 'inventory', label: 'Inventory', Comp: Inventory },
  { key: 'matrix', label: 'Matrix', Comp: Matrix },
  { key: 'service-matrix', label: 'Service Matrix', Comp: ServiceMatrix },
  { key: 'chains', label: 'Chains', Comp: Chains },
  { key: 'sequences', label: 'Sequences', Comp: Sequences },
  { key: 'import', label: 'Import', Comp: ImportTab },
  { key: 'report', label: 'Report', Comp: Report },
  { key: 'preflight', label: 'Preflight', Comp: Preflight },
]

export default function App() {
  const targets = useAsync(() => get('/targets/list'), [])
  const [selectedId, setSelectedId] = useState(null)
  const [tab, setTab] = useState('recon')

  const list = targets.data || []
  const selected = list.find((t) => t.id === selectedId) || null

  // Auto-select the first target once loaded.
  if (!selected && list.length > 0 && selectedId == null) {
    setSelectedId(list[0].id)
  }

  const Active = TABS.find((t) => t.key === tab)?.Comp

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-ai">chAIn</span>
          <span className="brand-sub">operator console</span>
        </div>
        <nav className="tabs" aria-label="sections">
          {TABS.map((t) => (
            <button
              key={t.key}
              className={`tab ${tab === t.key ? 'tab-active' : ''}`}
              onClick={() => setTab(t.key)}
              disabled={!selected && t.key !== 'preflight'}
              title={!selected && t.key !== 'preflight' ? 'select a target first' : ''}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <TargetBar
            targets={targets}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        </aside>

        <main className="content">
          {tab === 'preflight' ? (
            <Preflight />
          ) : selected ? (
            Active && <Active key={selected.id} target={selected} onTargetChanged={targets.reload} />
          ) : (
            <div className="placeholder">
              <p className="muted">
                No target selected. Create or pick a target on the left to begin, or open the
                Preflight tab to check tool availability.
              </p>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
