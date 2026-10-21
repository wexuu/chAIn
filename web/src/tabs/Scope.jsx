import React, { useState } from 'react'
import { api, get, post } from '../api.js'
import { Button, Empty, ErrorText, Field, Panel, TabIntro, useAction, useAsync } from '../ui.jsx'

const SCOPE_KINDS = ['host', 'cidr', 'url_prefix']

// Everything about *defining and authorizing a target* lives here: create /
// pick targets, attest authorization, opt into destructive checks, set the
// scope allow/deny rules, and store auth profiles. This replaces the old left
// sidebar.
export default function Scope({ target, targets, onSelect, onTargetChanged }) {
  return (
    <div className="tab-intro-wrap">
      <TabIntro
        title="Scope & authorization"
        lead="Define what you're allowed to touch before anything runs. Recon, deep checks and sequences all refuse to run unless the target is authorized and the host passes these scope rules."
      />
      <div className="tab-grid two-col">
        <Targets targets={targets} selectedId={target?.id} onSelect={onSelect} />
        {target ? (
          <>
            <Machine key={`m${target.id}`} target={target} onChanged={onTargetChanged} />
            <Authorize target={target} onChanged={onTargetChanged} />
            <Destructive target={target} />
            <ScopeRules target={target} />
            <AuthProfiles target={target} />
          </>
        ) : (
          <Panel title="No target selected">
            <Empty>Create a target on the left to begin.</Empty>
          </Panel>
        )}
      </div>
    </div>
  )
}

function Targets({ targets, selectedId, onSelect }) {
  const [address, setAddress] = useState('')
  const [name, setName] = useState('')
  const { busy, error, run } = useAction()
  const row = useAction()
  const list = targets.data || []

  const create = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    const t = await run(() =>
      post('/targets', { name: name.trim(), address: address.trim() || null })
    )
    setName('')
    setAddress('')
    targets.reload()
    if (t && t.id != null) onSelect(t.id)
  }

  const archive = (t) =>
    row.run(async () => {
      await post(`/targets/${t.id}/archive`)
      targets.reload()
    })
  const remove = (t) =>
    row.run(async () => {
      if (!window.confirm(`Delete "${t.name}" and all its data? This cannot be undone.`)) return
      await api(`/targets/${t.id}`, { method: 'DELETE' })
      targets.reload()
    })

  return (
    <Panel
      title="Machines"
      actions={
        <Button variant="ghost" onClick={targets.reload} title="refresh">
          ⟳
        </Button>
      }
    >
      <p className="muted help">
        A target is one machine: its IP or hostname, plus a name you choose (e.g. the HTB box
        name). The address auto-populates the scope rules so recon can launch.
      </p>
      <ErrorText error={targets.error || row.error} />
      {list.length === 0 ? (
        <Empty>no machines yet — add one below</Empty>
      ) : (
        <ul className="target-list">
          {list.map((t) => (
            <li
              key={t.id}
              className={`machine-row ${t.id === selectedId ? 'machine-row-active' : ''}`}
            >
              <button
                type="button"
                className="machine-select"
                onClick={() => onSelect(t.id)}
                aria-pressed={t.id === selectedId}
                title={`select ${t.name}`}
              >
                <span className="target-name">{t.name}</span>
                <span className="mono-sm muted target-addr">{t.address || 'no address'}</span>
              </button>
              <div className="machine-controls">
                <span
                  className={`chip ${t.authorized ? 'chip-ok' : 'chip-warn'}`}
                  title={t.authorized ? 'authorized' : 'not authorized'}
                >
                  {t.authorized ? 'authz' : 'unauthz'}
                </span>
                <button
                  type="button"
                  className="machine-ctrl"
                  title="archive"
                  aria-label={`archive ${t.name}`}
                  disabled={row.busy}
                  onClick={() => archive(t)}
                >
                  ⇩
                </button>
                <button
                  type="button"
                  className="machine-ctrl danger"
                  title="delete"
                  aria-label={`delete ${t.name}`}
                  disabled={row.busy}
                  onClick={() => remove(t)}
                >
                  ✕
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <form className="stack create-row" onSubmit={create}>
        <div className="row wrap">
          <input
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="IP / hostname / CIDR  (e.g. 10.10.11.42)"
            spellCheck={false}
          />
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name  (e.g. HTB Management)"
            spellCheck={false}
          />
          <Button variant="primary" type="submit" disabled={busy || !name.trim()}>
            add machine
          </Button>
        </div>
      </form>
      <ErrorText error={error} />
    </Panel>
  )
}

function Machine({ target, onChanged }) {
  const [address, setAddress] = useState(target.address || '')
  const { busy, error, run } = useAction()
  const save = async (e) => {
    e.preventDefault()
    await run(() => post(`/targets/${target.id}/address`, { address: address.trim() }))
    onChanged()
  }
  return (
    <Panel title="Machine address">
      <p className="muted help">
        The IP or hostname recon scans by default. Changing it adds the matching allow scope rules.
        Archive or delete this machine from the Machines list.
      </p>
      <form className="row" onSubmit={save}>
        <input
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          placeholder="10.10.11.42 / box.htb"
          spellCheck={false}
        />
        <Button variant="primary" type="submit" disabled={busy}>
          save
        </Button>
      </form>
      <ErrorText error={error} />
    </Panel>
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
    <Panel
      title="Authorization"
      actions={
        <span className={`chip ${target.authorized ? 'chip-ok' : 'chip-warn'}`}>
          {target.authorized ? 'authorized' : 'not authorized'}
        </span>
      }
    >
      <p className="muted help">
        Records your attestation that you're cleared to test this target. Until this is set, recon,
        deep checks and sequences return 403.
      </p>
      <form className="stack" onSubmit={submit}>
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
      </form>
      <ErrorText error={error} />
    </Panel>
  )
}

function Destructive({ target }) {
  const [enabled, setEnabled] = useState(null)
  const { busy, error, run } = useAction()
  const toggle = async (next) => {
    const r = await run(() => post(`/targets/${target.id}/destructive`, { enabled: next }))
    setEnabled(r && typeof r.destructive_opt_in === 'boolean' ? r.destructive_opt_in : next)
  }
  return (
    <Panel
      title="Destructive checks"
      actions={
        <span className={`chip ${enabled ? 'chip-danger' : ''}`}>
          {enabled == null ? 'unknown' : enabled ? 'ENABLED' : 'disabled'}
        </span>
      }
    >
      <p className="muted help">
        Opt in to checks that may change target state (writes, deletes, injections with side
        effects). Off by default.
      </p>
      <div className="row">
        <Button variant={enabled ? 'ghost' : 'danger'} disabled={busy} onClick={() => toggle(true)}>
          enable
        </Button>
        <Button variant="ghost" disabled={busy} onClick={() => toggle(false)}>
          disable
        </Button>
      </div>
      <ErrorText error={error} />
    </Panel>
  )
}

function ScopeRules({ target }) {
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
    <Panel
      title="Scope rules"
      actions={
        <Button variant="ghost" type="button" onClick={scope.reload} title="refresh">
          ⟳
        </Button>
      }
    >
      <p className="muted help">
        Allow/deny rules decide which hosts and paths are in bounds. Deny wins over allow, and the
        most specific rule wins. Private/loopback/metadata ranges are blocked unless you add an
        explicit allow.
      </p>
      <ErrorText error={scope.error} />
      {rules.length === 0 ? (
        <Empty>no scope rules</Empty>
      ) : (
        <ul className="scope-list">
          {rules.map((r) => (
            <li key={r.id} className={r.allow ? 'scope-allow' : 'scope-deny'}>
              <span className="scope-sign">{r.allow ? '+' : '−'}</span>
              <span className="chip chip-tiny">{r.kind}</span>
              <span className="mono-sm">{r.value}</span>
            </li>
          ))}
        </ul>
      )}
      <form className="stack" onSubmit={submit}>
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
            placeholder={
              kind === 'cidr' ? '10.0.0.0/24' : kind === 'url_prefix' ? 'https://x/api' : 'host.example.com'
            }
            spellCheck={false}
          />
          <label className="checkbox">
            <input type="checkbox" checked={allow} onChange={(e) => setAllow(e.target.checked)} />
            <span>{allow ? 'allow' : 'deny'}</span>
          </label>
          <Button variant="primary" type="submit" disabled={busy || !value.trim()}>
            add rule
          </Button>
        </div>
      </form>
      <ErrorText error={error} />
    </Panel>
  )
}

function AuthProfiles({ target }) {
  const profiles = useAsync(() => get(`/targets/${target.id}/auth-profiles`), [target.id])
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
    <Panel
      title="Auth profiles"
      actions={
        <Button variant="ghost" onClick={profiles.reload} title="refresh">
          ⟳
        </Button>
      }
    >
      <p className="muted help">
        Credentials that checks and sequences attach to requests. Secrets are write-only — never
        returned once saved.
      </p>
      <ErrorText error={profiles.error} />
      {list.length === 0 ? (
        <Empty>none yet</Empty>
      ) : (
        <ul className="scope-list">
          {list.map((p) => (
            <li key={p.id}>
              <strong>{p.name}</strong> <span className="chip chip-tiny">{p.type}</span>
              {p.notes ? <span className="muted tiny"> — {p.notes}</span> : null}
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={submit} className="stack">
        <div className="row wrap">
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
        </div>
        <input
          placeholder="secret (write-only)"
          value={form.secret}
          onChange={(e) => setForm({ ...form, secret: e.target.value })}
          spellCheck={false}
        />
        <textarea
          placeholder='extra headers JSON, e.g. {"X-Api-Key":"..."}'
          value={form.headers}
          onChange={(e) => setForm({ ...form, headers: e.target.value })}
          rows={2}
          spellCheck={false}
        />
        <input
          placeholder="notes (optional)"
          value={form.notes}
          onChange={(e) => setForm({ ...form, notes: e.target.value })}
        />
        <Button variant="primary" type="submit" disabled={busy || !form.name.trim()}>
          add profile
        </Button>
      </form>
      <ErrorText error={error} />
    </Panel>
  )
}
