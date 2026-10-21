import React, { useState } from 'react'
import { get, post } from '../api.js'
import { Button, Empty, ErrorText, Field, Loading, Panel, useAction, useAsync } from '../ui.jsx'

const PROMOTIONS = ['validated', 'confirmed', 'rejected']
const EDGE_KINDS = ['source_to_sink', 'precondition']

export default function Chains({ target }) {
  const hyps = useAsync(() => get(`/targets/${target.id}/hypotheses`), [target.id])
  const edges = useAsync(() => get(`/targets/${target.id}/edges`), [target.id])

  return (
    <div className="tab-grid">
      <ProposeHypothesis target={target} onCreated={hyps.reload} />
      <HypothesisList target={target} hyps={hyps} />
      <AddEdge target={target} onAdded={edges.reload} />
      <EdgeList edges={edges} />
    </div>
  )
}

function ProposeHypothesis({ target, onCreated }) {
  const [title, setTitle] = useState('')
  const [rationale, setRationale] = useState('')
  const [members, setMembers] = useState('')
  const { busy, error, run } = useAction()

  const submit = async (e) => {
    e.preventDefault()
    const member_cells = members
      .split(',')
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isFinite(n))
    const body = { title: title.trim() }
    if (rationale.trim()) body.rationale = rationale.trim()
    if (member_cells.length) body.member_cells = member_cells
    await run(() => post(`/targets/${target.id}/hypotheses`, body))
    setTitle('')
    setRationale('')
    setMembers('')
    onCreated()
  }

  return (
    <Panel title="Propose hypothesis">
      <form onSubmit={submit} className="stack">
        <Field label="Title">
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="IDOR → account takeover" />
        </Field>
        <Field label="Rationale" hint="(optional)">
          <textarea value={rationale} onChange={(e) => setRationale(e.target.value)} rows={2} />
        </Field>
        <Field label="Member cell ids" hint="(optional, comma-separated)">
          <input value={members} onChange={(e) => setMembers(e.target.value)} placeholder="12, 34, 56" spellCheck={false} />
        </Field>
        <Button variant="primary" type="submit" disabled={busy || !title.trim()}>
          propose
        </Button>
        <ErrorText error={error} />
      </form>
    </Panel>
  )
}

function HypothesisList({ hyps, target }) {
  const list = hyps.data || []
  return (
    <Panel
      title={`Hypotheses (${list.length})`}
      actions={
        <Button variant="ghost" onClick={hyps.reload}>
          ⟳
        </Button>
      }
    >
      <ErrorText error={hyps.error} />
      {hyps.loading && !hyps.data ? (
        <Loading what="hypotheses" />
      ) : list.length === 0 ? (
        <Empty>no hypotheses yet</Empty>
      ) : (
        <ul className="hyp-list">
          {list.map((h) => (
            <HypothesisRow key={h.id} hyp={h} onChanged={hyps.reload} />
          ))}
        </ul>
      )}
    </Panel>
  )
}

function HypothesisRow({ hyp, onChanged }) {
  const { busy, error, run } = useAction()
  const promote = (to) =>
    run(async () => {
      await post(`/hypotheses/${hyp.id}/promote`, { to })
      onChanged()
    })
  return (
    <li className="hyp">
      <div className="hyp-head">
        <span className="badge" data-status={hyp.status}>
          {hyp.status}
        </span>
        <strong>{hyp.title}</strong>
        <span className="muted tiny">#{hyp.id} · {hyp.origin}</span>
      </div>
      {hyp.rationale && <p className="muted tiny">{hyp.rationale}</p>}
      {hyp.member_cells && hyp.member_cells.length > 0 && (
        <p className="muted tiny">cells: {hyp.member_cells.join(', ')}</p>
      )}
      <div className="row wrap">
        {PROMOTIONS.map((to) => (
          <Button key={to} variant={to === 'rejected' ? 'danger' : 'ghost'} disabled={busy} onClick={() => promote(to)}>
            {to}
          </Button>
        ))}
      </div>
      <ErrorText error={error} />
    </li>
  )
}

function AddEdge({ target, onAdded }) {
  const [kind, setKind] = useState('source_to_sink')
  const [fromRef, setFromRef] = useState('')
  const [toRef, setToRef] = useState('')
  const [note, setNote] = useState('')
  const { busy, error, run } = useAction()

  const submit = async (e) => {
    e.preventDefault()
    const body = { kind, from_ref: fromRef.trim(), to_ref: toRef.trim() }
    if (note.trim()) body.note = note.trim()
    await run(() => post(`/targets/${target.id}/edges`, body))
    setFromRef('')
    setToRef('')
    setNote('')
    onAdded()
  }

  return (
    <Panel title="Add edge">
      <form onSubmit={submit} className="stack">
        <Field label="Kind">
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            {EDGE_KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
        </Field>
        <div className="row wrap">
          <Field label="From ref">
            <input value={fromRef} onChange={(e) => setFromRef(e.target.value)} placeholder="cell:12 / hyp:3" spellCheck={false} />
          </Field>
          <Field label="To ref">
            <input value={toRef} onChange={(e) => setToRef(e.target.value)} placeholder="cell:34 / finding:1" spellCheck={false} />
          </Field>
        </div>
        <Field label="Note" hint="(optional)">
          <input value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
        <Button variant="primary" type="submit" disabled={busy || !fromRef.trim() || !toRef.trim()}>
          add edge
        </Button>
        <ErrorText error={error} />
      </form>
    </Panel>
  )
}

function EdgeList({ edges }) {
  const list = edges.data || []
  return (
    <Panel
      title={`Edges (${list.length})`}
      actions={
        <Button variant="ghost" onClick={edges.reload}>
          ⟳
        </Button>
      }
    >
      <ErrorText error={edges.error} />
      {list.length === 0 ? (
        <Empty>no edges</Empty>
      ) : (
        <ul className="scope-list">
          {list.map((e) => (
            <li key={e.id}>
              <span className="chip chip-tiny">{e.kind}</span>{' '}
              <span className="mono-sm">
                {e.from} → {e.to}
              </span>
              {e.note ? <span className="muted tiny"> — {e.note}</span> : null}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
