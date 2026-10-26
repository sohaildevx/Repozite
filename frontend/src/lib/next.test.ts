import { describe, expect, it } from 'vitest'
import { loginPathFor, registerPathFor, returnToFor, safeNextPath } from '@/lib/next'

describe('safeNextPath', () => {
  it('keeps same-origin paths, including query and fragment', () => {
    expect(safeNextPath('/scan/11/issues/5')).toBe('/scan/11/issues/5')
    expect(safeNextPath('/scan/11?tab=findings')).toBe('/scan/11?tab=findings')
    expect(safeNextPath('/')).toBe('/')
  })

  it('collapses missing or empty values to the landing page', () => {
    expect(safeNextPath(null)).toBe('/')
    expect(safeNextPath(undefined)).toBe('/')
    expect(safeNextPath('')).toBe('/')
    expect(safeNextPath('   ')).toBe('/')
  })

  it('rejects absolute external URLs', () => {
    expect(safeNextPath('https://evil.example')).toBe('/')
    expect(safeNextPath('http://evil.example')).toBe('/')
    expect(safeNextPath('javascript:alert(1)')).toBe('/')
  })

  it('rejects protocol-relative and backslash-smuggled hosts', () => {
    expect(safeNextPath('//evil.example')).toBe('/')
    expect(safeNextPath('/\\evil.example')).toBe('/')
    expect(safeNextPath('/\\/evil.example')).toBe('/')
  })

  it('rejects values containing whitespace or control characters', () => {
    expect(safeNextPath('/scan/1 2')).toBe('/')
    expect(safeNextPath('/scan/\t1')).toBe('/')
    expect(safeNextPath('/scan/\n1')).toBe('/')
  })

  it('trims surrounding whitespace from otherwise valid paths', () => {
    expect(safeNextPath('  /scan/11  ')).toBe('/scan/11')
  })
})

describe('loginPathFor / registerPathFor', () => {
  it('encode a validated destination into the query string', () => {
    expect(loginPathFor('/scan/1/issues/2')).toBe(
      '/login?next=%2Fscan%2F1%2Fissues%2F2',
    )
    expect(registerPathFor('/scan/1/issues/2')).toBe(
      '/register?next=%2Fscan%2F1%2Fissues%2F2',
    )
  })

  it('never emit an unsafe destination', () => {
    expect(loginPathFor('https://evil.example')).toBe('/login?next=%2F')
    expect(registerPathFor('//evil.example')).toBe('/register?next=%2F')
  })
})

describe('auth routes as destinations', () => {
  it('never treat an auth page as a next destination', () => {
    expect(safeNextPath('/login')).toBe('/')
    expect(safeNextPath('/register')).toBe('/')
    expect(safeNextPath('/login?next=%2Fscan%2F3')).toBe('/')
    expect(safeNextPath('/register?github=failed')).toBe('/')
  })
})

describe('returnToFor', () => {
  it('uses the current location on ordinary pages', () => {
    expect(returnToFor('/')).toBe('/')
    expect(returnToFor('/scan/3')).toBe('/scan/3')
    expect(returnToFor('/scan/3', '?tab=findings')).toBe('/scan/3?tab=findings')
  })

  it('keeps the destination an auth page was already pointed at', () => {
    expect(returnToFor('/login', '?next=%2Fscan%2F3')).toBe('/scan/3')
    expect(returnToFor('/register', '?next=%2Fscan%2F3')).toBe('/scan/3')
  })

  it('never carries the auth page itself forward', () => {
    // Regression guard: the navbar built `next` from
    // location.pathname + location.search, so on /login?github=...&next=/ it
    // encoded the login URL as its own destination. The OAuth round trip then
    // bounced back to a visually identical page and read as a pointless
    // refresh -- "click, nothing happens".
    expect(returnToFor('/login')).toBe('/')
    expect(returnToFor('/login', '?github=unconfigured&next=%2F')).toBe('/')
    expect(returnToFor('/register', '?github=failed')).toBe('/')
    expect(returnToFor('/login', '?next=%2Flogin%3Fnext%3D%252F')).toBe('/')
  })
})
