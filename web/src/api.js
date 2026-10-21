// Robust fetch helper for the chAIn HTTP API.
//
// All paths are ROOT-ABSOLUTE (e.g. "/targets/list") because the API is served
// at the server root, while this SPA is mounted under /app. Do not prefix paths.
//
// On a non-2xx response this throws an Error whose `.message` is the API's own
// error text (FastAPI `{detail: ...}`), so callers can surface it directly.

function formatDetail(detail, fallback) {
  if (detail == null) return fallback
  if (typeof detail === 'string') return detail
  // FastAPI validation errors: detail is a list of {loc, msg, type}
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        if (d && typeof d === 'object' && d.msg) {
          const loc = Array.isArray(d.loc) ? d.loc.join('.') : ''
          return loc ? `${loc}: ${d.msg}` : d.msg
        }
        return typeof d === 'string' ? d : JSON.stringify(d)
      })
      .join('; ')
  }
  return JSON.stringify(detail)
}

/**
 * @param {string} path  root-absolute API path, e.g. "/targets/list"
 * @param {object} opts  { method, body, raw }
 *   - body: a JS value, JSON-encoded automatically (sets Content-Type)
 *   - raw: when true, always resolve the response body as text
 * @returns parsed JSON (default), or text when the response is text/raw
 */
export async function api(path, opts = {}) {
  const { method = 'GET', body, raw = false } = opts
  const init = { method, headers: { Accept: 'application/json, text/plain, */*' } }
  if (body !== undefined && body !== null) {
    init.headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }

  let res
  try {
    res = await fetch(path, init)
  } catch (networkErr) {
    throw new Error(`network error: ${networkErr.message || networkErr} (is the chAIn server running?)`)
  }

  const ctype = res.headers.get('content-type') || ''
  const isJson = ctype.includes('application/json')
  let data
  if (raw || !isJson) {
    data = await res.text()
    // Some endpoints (export json) still return JSON without a perfect header.
    if (!raw && data && (data[0] === '{' || data[0] === '[')) {
      try {
        data = JSON.parse(data)
      } catch {
        /* keep as text */
      }
    }
  } else {
    data = await res.json()
  }

  if (!res.ok) {
    let msg
    if (data && typeof data === 'object') {
      msg = formatDetail(data.detail !== undefined ? data.detail : data, `HTTP ${res.status}`)
    } else {
      msg = (typeof data === 'string' && data.trim()) || `HTTP ${res.status} ${res.statusText}`
    }
    const err = new Error(msg)
    err.status = res.status
    err.body = data
    throw err
  }
  return data
}

export const get = (path) => api(path)
export const post = (path, body) => api(path, { method: 'POST', body })
export const patch = (path, body) => api(path, { method: 'PATCH', body })
export const getText = (path) => api(path, { raw: true })
