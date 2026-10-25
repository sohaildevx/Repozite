import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { Spinner } from '@/components/ui/spinner'
import { GithubIcon } from '@/components/GithubIcon'
import { ApiError, createScan, parseGithubRepoUrl } from '@/lib/api'
import type { ScanResponse } from '@/lib/api'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'

/**
 * The focal element of the landing page: paste a public GitHub URL, the
 * backend fetches and analyzes the repository server-side. No account is
 * needed to scan; AI fixes later require sign-in (stated below the input).
 */
export function RepositoryUrlInput() {
  const navigate = useNavigate()
  const [value, setValue] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const [submitError, setSubmitError] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) {
      return // double-submit guard: one scan per press
    }

    // Client-side validation is convenience only; the backend re-validates.
    try {
      parseGithubRepoUrl(value)
      setLocalError(null)
    } catch (err) {
      setLocalError(
        err instanceof ApiError ? err.message : 'Invalid repository URL.',
      )
      return
    }

    setSubmitting(true)
    setSubmitError(null)
    try {
      const result: ScanResponse = await createScan(value)
      navigate(`/scan/${result.run.id}`)
    } catch (err) {
      if (err instanceof ApiError) {
        // 502 after a snapshot succeeded means the analyzer failed BUT the
        // run was recorded as failed -- send the visitor to that record
        // instead of a bare error message.
        const run = (err.data as ScanResponse | null)?.run
        if (err.status === 502 && run) {
          navigate(`/scan/${run.id}`)
          return
        }
        setSubmitError(err.message)
      } else {
        setSubmitError('Unexpected error — please try again.')
      }
      setSubmitting(false)
    }
  }

  const statusId = 'repository-status'

  return (
    <form
      onSubmit={handleSubmit}
      noValidate
      className="mx-auto w-full max-w-2xl"
      aria-label="Repository scan"
    >
      <Label
        htmlFor="repository-input"
        className="mb-3 block font-mono text-[11px] tracking-[0.18em] text-muted-foreground uppercase"
      >
        Repository URL
      </Label>

      <div className="relative">
        <GithubIcon className="pointer-events-none absolute top-1/2 left-4 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          id="repository-input"
          type="url"
          name="repository"
          autoComplete="url"
          spellCheck={false}
          disabled={submitting}
          required
          aria-invalid={localError ? true : undefined}
          aria-describedby={statusId}
          placeholder="Paste a public GitHub repository URL..."
          value={value}
          onChange={(e) => {
            setValue(e.target.value)
            if (localError) {
              setLocalError(null)
            }
          }}
          className={
            'h-14 rounded-sm bg-card pr-16 pl-12 font-mono text-[13px] transition-colors md:h-16 md:text-sm ' +
            (localError
              ? 'border-destructive focus-visible:border-destructive'
              : 'hover:border-muted-foreground/60 focus-visible:border-primary')
          }
        />
        <Button
          type="submit"
          size="icon"
          disabled={submitting || value.trim().length === 0}
          aria-label="Scan repository"
          className="absolute top-1/2 right-2 size-9 -translate-y-1/2 rounded-sm md:size-10"
        >
          {submitting ? (
            <Spinner aria-label="Starting scan" />
          ) : (
            <ArrowRight className="size-4" aria-hidden="true" />
          )}
        </Button>
      </div>

      <div id={statusId} className="mt-3 min-h-[20px] text-left">
        {localError && (
          <div>
            <p role="alert" className="font-mono text-[12px] text-destructive">
              {localError}
            </p>
            <p className="mt-1 text-[12px] text-muted-foreground/80">
              Example:{' '}
              <span className="font-mono">
                https://github.com/owner/repository
              </span>
            </p>
          </div>
        )}

        {!localError && submitting && (
          <p
            aria-live="polite"
            className="font-mono text-[12px] text-muted-foreground"
          >
            Fetching the repository and running the analyzers — this can take
            a minute…
          </p>
        )}

        {!localError && submitError && (
          <p role="alert" className="font-mono text-[12px] text-destructive">
            {submitError}
          </p>
        )}

        {!localError && !submitting && !submitError && (
          <p className="text-[12px] text-muted-foreground">
            No account needed to scan and read findings.{' '}
            <span className="text-muted-foreground/70">
              AI fix generation asks you to sign in first.
            </span>
          </p>
        )}
      </div>
    </form>
  )
}
