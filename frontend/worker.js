
const BACKEND = 'https://repozite.onrender.com' 

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

      return fetch(new Request(upstream, init))
    }

    
    return env.ASSETS.fetch(request)
  },
}
