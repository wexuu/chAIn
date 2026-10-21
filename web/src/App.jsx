import React, { useState } from 'react'
import { get } from './api.js'
import { ToastProvider, useAsync } from './ui.jsx'
import TargetSelect from './components/TargetSelect.jsx'
import Scope from './tabs/Scope.jsx'
import Recon from './tabs/Recon.jsx'
import Coverage from './tabs/Coverage.jsx'
import Inventory from './tabs/Inventory.jsx'
import Matrix from './tabs/Matrix.jsx'
import ServiceMatrix from './tabs/ServiceMatrix.jsx'
import Chains from './tabs/Chains.jsx'
import Sequences from './tabs/Sequences.jsx'
import ImportTab from './tabs/ImportTab.jsx'
import Report from './tabs/Report.jsx'
import Archive from './tabs/Archive.jsx'
import Preflight from './tabs/Preflight.jsx'

// Tabs are grouped left→right along the workflow: set up the target, discover
// surface, track coverage, reason about chains, then report. `global` tabs
// don't need a selected target.
const TABS = [
  { key: 'scope', label: 'Scope', Comp: Scope, group: 'setup' },
  { key: 'recon', label: 'Recon', Comp: Recon, group: 'discover' },
  { key: 'coverage', label: 'Coverage', Comp: Coverage, group: 'cover' },
  { key: 'inventory', label: 'Inventory', Comp: Inventory, group: 'discover' },
  { key: 'matrix', label: 'Matrix', Comp: Matrix, group: 'cover' },
  { key: 'service-matrix', label: 'Services', Comp: ServiceMatrix, group: 'cover' },
  { key: 'chains', label: 'Chains', Comp: Chains, group: 'reason' },
  { key: 'sequences', label: 'Sequences', Comp: Sequences, group: 'reason' },
  { key: 'import', label: 'Import', Comp: ImportTab, group: 'discover' },
  { key: 'report', label: 'Report', Comp: Report, group: 'report' },
  { key: 'archive', label: 'Archive', Comp: Archive, group: 'global' },
  { key: 'preflight', label: 'Preflight', Comp: Preflight, group: 'global' },
]

export default function App() {
  return (
    <ToastProvider>
      <Shell />
    </ToastProvider>
  )
}

function Shell() {
  const targets = useAsync(() => get('/targets/list'), [])
  const [selectedId, setSelectedId] = useState(null)
  const [tab, setTab] = useState('scope')

  const list = targets.data || []
  const selected = list.find((t) => t.id === selectedId) || null

  // Auto-select the first target once loaded, and re-select if the current one
  // disappears (archived / deleted).
  if (!selected && list.length > 0) {
    setSelectedId(list[0].id)
  }

  const active = TABS.find((t) => t.key === tab)
  const Active = active?.Comp
  const needsTarget = active && active.group !== 'global' && active.key !== 'scope'

  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-row">
          <div className="brand">
            <span className="brand-ai">chAIn</span>
            <span className="brand-sub">operator console</span>
          </div>
          <TargetSelect
            targets={targets}
            selectedId={selectedId}
            onSelect={setSelectedId}
            onManage={() => setTab('scope')}
          />
        </div>
        <nav className="tabs" aria-label="sections">
          {TABS.map((t) => {
            const disabled = t.group !== 'global' && t.key !== 'scope' && !selected
            return (
              <button
                key={t.key}
                className={`tab ${tab === t.key ? 'tab-active' : ''}`}
                data-group={t.group}
                onClick={() => setTab(t.key)}
                disabled={disabled}
                title={disabled ? 'select a target first' : ''}
              >
                {t.label}
              </button>
            )
          })}
        </nav>
      </header>

      <main className="content">
        {tab === 'preflight' ? (
          <Preflight />
        ) : tab === 'archive' ? (
          <Archive onActiveChanged={targets.reload} />
        ) : tab === 'scope' ? (
          <Scope
            target={selected}
            targets={targets}
            onSelect={setSelectedId}
            onTargetChanged={targets.reload}
          />
        ) : !selected ? (
          <div className="placeholder">
            <p className="muted">
              No target selected. Pick one in the top bar, or open <b>Scope</b> to create and
              authorize one.
            </p>
          </div>
        ) : needsTarget && Active ? (
          <Active key={selected.id} target={selected} onTargetChanged={targets.reload} />
        ) : null}
      </main>
    </div>
  )
}
