
function hasUnsafeCharCode(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
   
    if (code <= 0x20 || code === 0x7f) {
      return true
    }
  }
  return false
}


const AUTH_PATHS = new Set(['/login', '/register'])

export function safeNextPath(raw: string | null | undefined): string {
  if (!raw) {
    return '/'
  }
  const value = raw.trim()
  if (
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.includes('\\') ||
    value.includes('://') ||
    hasUnsafeCharCode(value)
  ) {
    return '/'
  }
  // Compare on the path only: /login?next=... is still /login.
  return AUTH_PATHS.has(value.split('?')[0]) ? '/' : value
}


export function returnToFor(pathname: string, search = ''): string {
  if (AUTH_PATHS.has(pathname)) {
    return safeNextPath(new URLSearchParams(search).get('next'))
  }
  return safeNextPath(pathname + search)
}

/** Build the login URL for a given return destination. */
export function loginPathFor(next: string): string {
  return `/login?next=${encodeURIComponent(safeNextPath(next))}`
}

/** Build the registration URL for a given return destination. */
export function registerPathFor(next: string): string {
  return `/register?next=${encodeURIComponent(safeNextPath(next))}`
}
