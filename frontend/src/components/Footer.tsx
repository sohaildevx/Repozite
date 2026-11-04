import { Separator } from '@/components/ui/separator'

const REPO_URL = 'https://github.com/sohaildevx/Repozite'

export function Footer() {
  return (
    <footer className="py-12">
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-col items-start justify-between gap-8 md:flex-row md:items-center">
          <div className="max-w-md">
            <div className="flex items-center gap-2.5">
              
              <img
                src="/logo.svg"
                alt=""
                width={32}
                height={32}
                aria-hidden="true"
                className="size-8 shrink-0 rounded-md"
              />
              <span className="text-sm font-semibold tracking-tight">
                Repo<span className="text-primary">zite</span>
              </span>
            </div>
            <p className="mt-3 text-[13px] leading-relaxed text-muted-foreground">
              AI-powered code analysis for Python, JavaScript, and
              TypeScript. Find issues, understand their causes, and validate
              proposed fixes in a restricted environment.
            </p>
          </div>

          <nav aria-label="Footer" className="flex items-center gap-4">
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer"
              className="text-[13px] text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none rounded-sm"
            >
              GitHub
            </a>
            <a
              href="#how-it-works"
              className="text-[13px] text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none rounded-sm"
            >
              How it works
            </a>
          </nav>
        </div>

        <Separator className="my-8 bg-border" />

        <p className="font-mono text-[11px] tracking-wide text-muted-foreground/70 uppercase">
          © 2026 Repozite — built for Python, JavaScript & TypeScript
          repositories
        </p>
      </div>
    </footer>
  )
}
