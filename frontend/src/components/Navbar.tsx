import { useState } from 'react'
import { LogOut } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Separator } from '@/components/ui/separator'
import { Spinner } from '@/components/ui/spinner'
import { GithubIcon } from '@/components/GithubIcon'
import { useAuth } from '@/lib/auth'
import { loginPathFor, returnToFor, safeNextPath } from '@/lib/next'

const REPO_URL = 'https://github.com/sohaildevx/Repozite'


function githubSignInPath(next: string): string {
  return `/api/auth/github/?next=${encodeURIComponent(safeNextPath(next))}`
}

function focusRepositoryInput() {
  const input = document.getElementById('repository-input')
  if (input instanceof HTMLElement) {
    input.scrollIntoView({ behavior: 'smooth', block: 'center' })
    if (input instanceof HTMLInputElement) {
      input.focus({ preventScroll: true })
    }
  }
}

export function Navbar() {
  const { user, loading, signOut } = useAuth()
  const location = useLocation()
  const onLanding = location.pathname === '/'
  const [signingOut, setSigningOut] = useState(false)
 
  const [failedAvatar, setFailedAvatar] = useState<string | null>(null)
  const avatarSrc =
    user?.avatar_url && failedAvatar !== user.avatar_url ? user.avatar_url : null
  const initials = user ? user.username.slice(0, 2).toUpperCase() : ''

  async function handleSignOut() {
    if (signingOut) {
      return
    }
    setSigningOut(true)
    try {
      await signOut()
    } finally {
      setSigningOut(false)
    }
  }

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-background">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
        <Link
          to="/"
          className="flex items-center gap-2 rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          aria-label="Repozite — home"
        >
          {/* logo.svg is a VTracer trace of a raster mark: it carries its own
              opaque cream (#FDF9F1) square, which would read as a bright block
              against the dark navbar. Rounded into an app-tile so the light
              background reads as intentional, and so the artwork (which only
              fills ~half the canvas) sits close to the wordmark. */}
          <img
            src="/logo.svg"
            alt=""
            width={32}
            height={32}
            aria-hidden="true"
            className="size-8 shrink-0 rounded-md"
          />
          <span className="text-[15px] font-semibold tracking-tight">
            Repo<span className="text-primary">zite</span>
          </span>
        </Link>

        <nav aria-label="Primary" className="flex items-center gap-1 sm:gap-2">
          {onLanding && (
            <a
              href="#how-it-works"
              className="hidden rounded-sm px-3 py-2 text-[13px] text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none sm:inline-block"
            >
              How it works
            </a>
          )}
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
            className="hidden rounded-sm px-3 py-2 text-[13px] text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none sm:inline-block"
          >
            Documentation
          </a>
          <Separator
            orientation="vertical"
            className="mx-1.5 hidden h-4 bg-border sm:block"
          />

          {loading && (
            <Spinner
              className="size-3.5 text-muted-foreground"
              aria-label="Checking session"
            />
          )}
          {!loading && !user && (
            <Link
              to={loginPathFor(returnToFor(location.pathname, location.search))}
              className="rounded-sm px-3 py-2 text-[13px] text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              Sign in
            </Link>
          )}
          {!loading && user && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  aria-label={`Account menu for ${user.username}`}
                  title={user.username}
                  className="ml-1 flex size-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-accent text-[12px] font-semibold text-accent-foreground outline-none ring-offset-background transition-opacity hover:opacity-90 focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                >
                  {avatarSrc ? (
                    <img
                      src={avatarSrc}
                      alt=""
                      aria-hidden="true"
                      onError={() => setFailedAvatar(user.avatar_url ?? '')}
                      className="size-full object-cover"
                    />
                  ) : (
                    <span aria-hidden="true">{initials}</span>
                  )}
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="min-w-[13rem]">
                <DropdownMenuLabel
                  className="truncate font-mono text-[12px]"
                  title={user.username}
                >
                  {user.username}
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  disabled={signingOut}
                 
                  onSelect={(event) => {
                    event.preventDefault()
                    void handleSignOut()
                  }}
                  className="text-muted-foreground focus:text-foreground"
                >
                  {signingOut ? (
                    <Spinner className="size-4" aria-label="Signing out" />
                  ) : (
                    <LogOut aria-hidden="true" />
                  )}
                  {signingOut ? 'Signing out…' : 'Sign out'}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}

          {!loading && !user && (
            <Button size="sm" className="ml-1 h-8 rounded-sm px-3 text-[13px]" asChild>
              <a href={githubSignInPath(returnToFor(location.pathname, location.search))}>
                <GithubIcon className="size-3.5" aria-hidden="true" />
                Sign in with GitHub
              </a>
            </Button>
          )}
          {!loading && user &&
            (onLanding ? (
              <Button
                size="sm"
                className="ml-1 h-8 rounded-sm px-3.5 text-[13px]"
                onClick={focusRepositoryInput}
              >
                Get started
              </Button>
            ) : (
              <Button
                size="sm"
                className="ml-1 h-8 rounded-sm px-3.5 text-[13px]"
                asChild
              >
                <Link to="/">Get started</Link>
              </Button>
            ))}
        </nav>
      </div>
    </header>
  )
}
