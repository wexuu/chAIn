import React from 'react'

// Compact target switcher for the top navbar. The full target CRUD + scope /
// auth config lives on the Scope tab; this is just the "which target am I on"
// control that stays consistent across every page.
export default function TargetSelect({ targets, selectedId, onSelect, onManage }) {
  const list = targets.data || []
  const selected = list.find((t) => t.id === selectedId) || null

  return (
    <div className="target-select">
      <select
        className="target-dd"
        value={selectedId ?? ''}
        onChange={(e) => {
          const v = e.target.value
          if (v === '__new__') onManage()
          else onSelect(Number(v))
        }}
        title="active target"
      >
        {list.length === 0 && <option value="">no targets yet</option>}
        {list.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
        <option value="__new__">＋ new / manage…</option>
      </select>
      {selected && (
        <span
          className={`chip ${selected.authorized ? 'chip-ok' : 'chip-warn'}`}
          title={selected.authorized ? 'authorized' : 'NOT authorized — recon/checks refused'}
        >
          {selected.authorized ? 'authorized' : 'unauthorized'}
        </span>
      )}
    </div>
  )
}
