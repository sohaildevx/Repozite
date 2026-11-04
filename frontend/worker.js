
const BACKEND = 'https://repozite.onrender.com'



function upstreamError(request, status) {
  const detail =
    'The backend service is unavailable (HTTP ' + status + '). ' +
    'It may be restarting - please try again in a few seconds.'
  const prefersHtml = (request.headers.get('accept') || '').includes('text/html')

  if (prefersHtml) {
    return new Response(
      '<!doctype html><meta charset="utf-8">' +
        '<title>Backend unavailable</title>' +
        '<p>' + detail + '</p>' +
        '<p><a href="/">Back to Repozite</a></p>',
      { status, headers: { 'content-type': 'text/html; charset=utf-8' } },
    )
  }
  return new Response(JSON.stringify({ detail }), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    if (url.pathname.startsWith('/api/')) {
      const upstream = new URL(request.url)
      upstream.host = new URL(BACKEND).host

      const headers = new Headers(request.headers)

      headers.delete('host')
      headers.set('x-forwarded-host', url.host)
      headers.set('x-forwarded-proto', url.protocol.slice(0, -1))

      const init = {
        method: request.method,
        headers,

        redirect: 'manual',
      }
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        init.body = request.body
      }

      let resp
      try {
        resp = await fetch(new Request(upstream, init))
      } catch {
        return upstreamError(request, 502)
      }

      const contentType = resp.headers.get('content-type') || ''
      if (resp.status >= 500 && !contentType.includes('json')) {
        return upstreamError(request, resp.status)
      }

      return resp
    }

    return env.ASSETS.fetch(request)
  },
}
