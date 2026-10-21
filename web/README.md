# chAIn web console

A dark, monospace operator console for chAIn, built with React 18 + Vite. It is a
single-page app that talks to chAIn's existing HTTP API on the **same origin**
(all API paths are root-absolute, e.g. `fetch("/targets/list")`).

## Build

```sh
npm install && npm run build
```

This produces `web/dist/index.html` plus hashed assets under `web/dist/assets/`.

FastAPI mounts the built app at **`/app`** (see `chain/app.py`: it serves
`web/dist` via `StaticFiles(..., html=True)` when the directory exists). Open the
tool in a browser at `/app/` once the server is running. The API itself stays at
the server root, which is why the app uses root-absolute paths for all fetches.

Vite is configured with `base: './'` so the built `index.html` references its
assets relatively and therefore works correctly under the `/app` mount.

## Develop

```sh
npm run dev
```

Vite's dev server runs on its own port; API calls to root-absolute paths will
only resolve if you proxy them to a running chAIn server (not configured here —
the console is meant to be built and served by FastAPI).

## Layout

- `index.html` — entry document
- `src/main.jsx` — React bootstrap
- `src/App.jsx` — shell: target selector + section tabs
- `src/api.js` — fetch helper with API-error surfacing
- `src/ui.jsx` — shared components + hooks (`useAsync`, `useAction`)
- `src/components/` — `TargetBar`, `CellEditor`, `CheckJobPanel`
- `src/tabs/` — Recon, Inventory, Matrix, ServiceMatrix, Chains, Sequences,
  Import, Report, Preflight
- `src/styles.css` — dark monospace theme + status colors

## Sections

Target bar (create / authorize / scope / destructive toggle / auth profiles) plus
tabs for Recon (+ coverage, flagged gaps, subdomain approval), Inventory, the
coverage Matrix (status grid, generate cells, deep checks), Service Matrix,
Chains (hypotheses + edges), Sequences (JSON step editor + run), Import, Report
(markdown export + findings), and Preflight (tool availability).
