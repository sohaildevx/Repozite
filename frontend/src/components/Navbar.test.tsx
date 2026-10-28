import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Navbar } from '@/components/Navbar'

const signOut = vi.fn()

vi.mock('@/lib/auth', () => ({
  useAuth: () => useAuthMock(),
}))

type MockUser = { id: number; username: string; avatar_url?: string } | null

let useAuthMock: () => {
  user: MockUser
  loading: boolean
  refresh: () => Promise<void>
  signOut: () => Promise<void>
}

function setAuth(user: MockUser) {
  useAuthMock = () => ({
    user,
    loading: false,
    refresh: async () => {},
    signOut,
  })
}

function renderNavbar(entry = '/scan') {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <Navbar />
    </MemoryRouter>,
  )
}

const AVATAR = 'https://avatars.githubusercontent.com/u/42'
const triggerName = 'Account menu for alice'

describe('Navbar account menu', () => {
  afterEach(() => {
    vi.clearAllMocks()
    setAuth(null)
  })

  it('shows the GitHub avatar that came back from sign-in', () => {
    setAuth({ id: 1, username: 'alice', avatar_url: AVATAR })
    renderNavbar()

    const trigger = screen.getByRole('button', { name: triggerName })
    expect(trigger.querySelector('img')).toHaveAttribute('src', AVATAR)
  })

  it('falls back to initials when no avatar came back', () => {
    setAuth({ id: 1, username: 'alice' })
    renderNavbar()

    const trigger = screen.getByRole('button', { name: triggerName })
    expect(trigger).toHaveTextContent('AL')
    expect(trigger.querySelector('img')).toBeNull()
  })

  it('opens a menu containing sign out and runs it', async () => {
    const user = userEvent.setup()
    setAuth({ id: 1, username: 'alice', avatar_url: AVATAR })
    renderNavbar()

    await user.click(screen.getByRole('button', { name: triggerName }))

    const item = await screen.findByRole('menuitem', { name: /sign out/i })
    expect(item).toHaveTextContent('Sign out')

    await user.click(item)
    expect(signOut).toHaveBeenCalledTimes(1)
  })

  it('offers no account menu while signed out', () => {
    setAuth(null)
    renderNavbar()

    expect(
      screen.queryByRole('button', { name: /account menu/i }),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: /sign in with github/i }),
    ).toBeInTheDocument()
  })
})
