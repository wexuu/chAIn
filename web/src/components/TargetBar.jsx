import React, { useState } from 'react'
import { get, post } from '../api.js'
import { Button, ErrorText, Field, useAction, useAsync } from '../ui.jsx'

const SCOPE_KINDS = ['host', 'cidr', 'url_prefix']

export default function TargetBar({ targets, selectedId, onSelect }) {
  const list = targets.data || []
  const selected = list.find((t) => t.id === selectedId) || null

  return (
    <div className="targetbar">
      <TargetList targets={targets} selectedId={selectedId} onSelect={onSelect} />
      <CreateTarget onCreated={targets.reload} onSelect={onSelect} />
      {selected && (
        <TargetDetail
          key={selected.id}
          target={selected}
          onChanged={targets.reload}
        />
      )}
    </div>
  )
}

function TargetList({ targets, selectedId, onSelect }) {
  const list = targets.data || []
  return (
    <div className="panel">
      <header className="panel-head">
        <h2>Targets</h2>
        <div className="panel-actions">
          <Button variant="ghost" onClick={targets.reload} title="refresh">
            ⟳
          </Button>
        </div>
      </header>
      <div className="panel-body">
        <ErrorText error={targets.error} />
        {list.length === 0 && !targets.loading && (
          <div className="muted empty">no targets yet</div>
        )}
        <ul className="target-list">
          {list.map((t) => (
            <li key={t.id}>
              <button
                className={`target-row ${t.id === selectedId ? 'target-row-active' : ''}`}
                onClick={() => onSelect(t.id)}
              >
                <span className="target-name">{t.name}</span>
                <span
                  className={`chip ${t.authorized ? 'chip-ok' : 'chip-warn'}`}
                  title={t.authorized ? 'authorized' : 'NOT authorized'}
                >
                  {t.authorized ? 'authz' : 'unauthz'}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}

function CreateTarget({ onCreated, onSelect }) {
  const [name, setName] = useState('')
  const { busy, error, run } = useAction()
  const submit = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    const t = await run(() => post('/targets', { name: name.trim() }))
    setName('')
    onCreated()
    if (t && t.id != null) onSelect(t.id)
  }
  return (
    <form className="panel compact" onSubmit={submit}>
      <div className="panel-body">
        <Field label="New target">
          <div className="row">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="acme-prod"
              spellCheck={false}
            />
            <Button variant="primary" type="submit" disabled={busy || !name.trim()}>
              create
            </Button>
          </div>
        </Field>
        <ErrorText error={error} />
      </div>
    </form>
  )
}

function TargetDetail({ target, onChanged }) {
  return (
    <>
      <Authorize target={target} onChanged={onChanged} />
      <Destructive target={target} />
      <ScopeEditor target={target} />
      <AuthProfiles target={target} />
    </>
  )
}

function Authorize({ target, onChanged }) {
  const [note, setNote] = useState('')
  const { busy, error, run } = useAction()
  const submit = async (e) => {
    e.preventDefault()
    await run(() => post(`/targets/${target.id}/authorize`, { note: note.trim() }))
    onChanged()
  }
  return (
    <form className="panel compact" onSubmit={submit}>
      <header className="panel-head">
        <h2>Authorization</h2>
        <span className={`chip ${target.authorized ? 'chip-ok' : 'chip-warn'}`}>
          {target.authorized ? 'authorized' : 'not authorized'}
        </span>
      </header>
      <div className="panel-body">
        <p className="muted tiny">
          Records your authorization attestation. Recon / checks / sequences refuse to run on an
          unauthorized target.
        </p>
        <Field label="Attestation note">
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="signed SoW #1234, scope confirmed"
            spellCheck={false}
          />
        </Field>
        <Button variant="primary" type="submit" disabled={busy}>
          {target.authorized ? 're-attest' : 'authorize'}
        </Button>
        <ErrorText error={error} />
      </div>
    </form>
  )
}

function Destructive({ target }) {
  // No GET for current state; reflect last known value after toggling.
  const [enabled, setEnabled] = useState(null)
  const { busy, error, run } = useAction()
  const toggle = async (next) => {
    const r = await run(() => post(`/targets/${target.id}/destructive`, { enabled: next }))
    setEnabled(r && typeof r.destructive_opt_in === 'boolean' ? r.destructive_opt_in : next)
  }
  const current = enabled
  return (
    <div className="panel compact">
      <header className="panel-head">
        <h2>Destructive</h2>
        <span className={`chip ${current ? 'chip-danger' : ''}`}>
          {current == null ? 'unknown' : current ? 'ENABLED' : 'disabled'}
        </span>
      </header>
      <div className="panel-body">
        <p className="muted tiny">Opt in to checks that may mutate target state. Off by default.</p>
        <div className="row">
          <Button variant={current ? 'ghost' : 'danger'} disabled={busy} onClick={() => toggle(true)}>
            enable
          </Button>
          <Button variant="ghost" disabled={busy} onClick={() => toggle(false)}>
            disable
          </Button>
        </div>
        <ErrorText error={error} />
      </div>
    </div>
  )
}

function ScopeEditor({ target }) {
  const scope = useAsync(() => get(`/targets/${target.id}/scope`), [target.id])
  const [kind, setKind] = useState('host')
  const [value, setValue] = useState('')
  const [allow, setAllow] = useState(true)
  const { busy, error, run } = useAction()

  const submit = async (e) => {
    e.preventDefault()
    if (!value.trim()) return
    await run(() => post(`/targets/${target.id}/scope`, { kind, value: value.trim(), allow }))
    setValue('')
    scope.reload()
  }

  const rules = scope.data || []
  return (
    <form className="panel compact" onSubmit={submit}>
      <header className="panel-head">
        <h2>Scope</h2>
        <div className="panel-actions">
          <Button variant="ghost" type="button" onClick={scope.reload} title="refresh">
            ⟳
          </Button>
        </div>
      </header>
      <div className="panel-body">
        <ErrorText error={scope.error} />
        {rules.length === 0 ? (
          <div className="muted empty tiny">no scope rules</div>
        ) : (
          <ul className="scope-list">
            {rules.map((r) => (
              <li key={r.id} className={r.allow ? 'scope-allow' : 'scope-deny'}>
                <span className="mono-sm">{r.allow ? '+' : '−'}</span> {r.kind}:{r.value}
              </li>
            ))}
          </ul>
        )}
        <div className="row wrap">
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            {SCOPE_KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={kind === 'cidr' ? '10.0.0.0/24' : kind === 'url_prefix' ? 'https://x/api' : 'host.example.com'}
            spellCheck={false}
          />
        </div>
        <label className="checkbox">
          <input type="checkbox" checked={allow} onChange={(e) => setAllow(e.target.checked)} />
          <span>{allow ? 'allow' : 'deny'}</span>
        </label>
        <Button variant="primary" type="submit" disabled={busy || !value.trim()}>
          add rule
        </Button>
        <ErrorText error={error} />
      </div>
    </form>
  )
}

function AuthProfiles({ target }) {
  const profiles = useAsync(() => get(`/targets/${target.id}/auth-profiles`), [target.id])
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState({ name: '', type: 'bearer', secret: '', headers: '', notes: '' })
  const { busy, error, setError, run } = useAction()

  const submit = async (e) => {
    e.preventDefault()
    let headers = null
    if (form.headers.trim()) {
      try {
        headers = JSON.parse(form.headers)
      } catch {
        setError('headers must be valid JSON (e.g. {"X-Api-Key":"..."})')
        return
      }
    }
    await run(() =>
      post(`/targets/${target.id}/auth-profiles`, {
        name: form.name.trim(),
        type: form.type,
        secret: form.secret || null,
        headers,
        notes: form.notes || null,
      })
    )
    setForm({ name: '', type: 'bearer', secret: '', headers: '', notes: '' })
    profiles.reload()
  }

  const list = profiles.data || []
  return (
    <div className="panel compact">
      <header className="panel-head">
        <h2>Auth profiles</h2>
        <div className="panel-actions">
          <Button variant="ghost" onClick={() => setOpen((o) => !o)}>
            {open ? '–' : '+'}
          </Button>
        </div>
      </header>
      <div className="panel-body">
        <ErrorText error={profiles.error} />
        {list.length === 0 ? (
          <div className="muted empty tiny">none (secrets are never returned)</div>
        ) : (
          <ul className="scope-list">
            {list.map((p) => (
              <li key={p.id}>
                {p.name} <span className="muted tiny">[{p.type}]</span>
                {p.notes ? <span className="muted tiny"> — {p.notes}</span> : null}
              </li>
            ))}
          </ul>
        )}
        {open && (
          <form onSubmit={submit} className="stack">
            <input
              placeholder="name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              spellCheck={false}
            />
            <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
              {['none', 'bearer', 'cookie', 'header', 'basic'].map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              placeholder="secret (write-only)"
              value={form.secret}
              onChange={(e) => setForm({ ...form, secret: e.target.value })}
              spellCheck={false}
            />
            <textarea
              placeholder='headers JSON, e.g. {"X-Api-Key":"..."}'
              value={form.headers}
              onChange={(e) => setForm({ ...form, headers: e.target.value })}
              rows={2}
              spellCheck={false}
            />
            <input
              placeholder="notes"
              value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })}
            />
            <Button variant="primary" type="submit" disabled={busy || !form.name.trim()}>
              add profile
            </Button>
          </form>
        )}
        <ErrorText error={error} />
      </div>
    </div>
  )
}
