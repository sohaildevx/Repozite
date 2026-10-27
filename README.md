# Repozite

### Find it. Fix it. Verify it.

Repozite is an AI-powered GitHub repository analyzer that scans a public repository for potential issues, explains each finding, generates a targeted patch with an AI model, and runs whatever validation is available — all in one workflow.

---

## Problem Statement

Finding a bug is only half the work. Developers normally hop between a linter, a security scanner, a debugger, and an AI assistant just to understand one issue — and then have to judge whether the fix they got back is any good.

AI-generated patches are often incomplete, introduce new problems, or silently fail to address the original issue. Worse, when a fix *is* applied, it's usually unclear whether anything was actually run against it.

Repozite collapses that loop: scan → review the finding → generate a patch → validate it → see exactly what was tested and what wasn't. Validation results are reported honestly, so a developer can always tell a verified fix from an unverified suggestion.

---

## Features

* **GitHub Repository Scanning** — clone and analyze public GitHub repositories by URL.
* **Static Analysis** — Python AST inspection, [Ruff](https://docs.astral.sh/ruff/), and [Bandit](https://bandit.readthedocs.io/) for code-quality and security findings.
* **AI-Powered Fixes** — targeted patches generated through Nebius Token Factory (NVIDIA Nemotron, OpenAI-compatible API).
* **Issue-Focused Workflow** — review findings individually and work one issue at a time.
* **Patch Validation** — run available checks against a proposed change and surface the result.
* **Transparent Results** — every check is reported as `passed`, `failed`, or `skipped`, with the reason when it couldn't run.
* **Agent Runs** — optional multi-step bug-fixing runs with bounded retries and a final summary.
* **GitHub Sign-In** — OAuth login, with rate-limited authorize and callback endpoints.
* **Web Interface** — React frontend for scanning, browsing findings, and reviewing patches.

> **Note:** Detection and validation depend on the language, the available tooling, and the execution environment. A clean scan does **not** guarantee a bug-free repository.

---

## Tech Stack

| Component | Technology |
| --- | --- |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| UI lint / tests | oxlint, Vitest |
| Backend API | Django, Django REST Framework |
| Analysis Service | Flask |
| Database | PostgreSQL (Neon) |
| Static Analysis | Python AST, Ruff, Bandit |
| AI Inference | Nebius Token Factory (NVIDIA Nemotron) |
| Isolated Test Runs | Docker (optional, opt-in) |
| Frontend Deployment | Cloudflare Workers |
| Backend Deployment | Render (gunicorn) |

---

## Architecture

```text
 ┌──────────────┐   /api/*    ┌─────────────────────┐   HTTP    ┌──────────────────┐
 │   Browser    │ ──────────► │  Cloudflare Worker  │ ────────► │  Django (Render) │
 │  React SPA   │  same-origin│  (edge proxy)       │  x-forward│  gunicorn :PORT  │
 └──────────────┘             └─────────────────────┘  -host    └────────┬─────────┘
                                                                         │ ANALYZER_URL
                                                                         ▼
                                                              ┌──────────────────────┐
                                                              │ Flask analyzer :5001 │
                                                              │ AST + Ruff + Bandit  │
                                                              └──────────────────────┘
                                                                         │
                                          ┌──────────────────────────────┼───────────────┐
                                          ▼                              ▼               ▼
                                   Nebius (Nemotron)              PostgreSQL         Docker sandbox
                                   patch generation                (Neon)          (opt-in tests)
```

1. **Frontend** — the React interface for submitting scans and reviewing results. In production it is served by a Cloudflare Worker that also proxies `/api/*` to the backend, keeping the browser on a single origin.
2. **Django Backend** — API surface, business logic, authentication, and persistence.
3. **Flask Analyzer** — performs static analysis over HTTP (`ANALYZER_URL`, default `http://127.0.0.1:5001`) and returns structured findings.
4. **AI Integration** — generates patches for a selected finding via Nebius Token Factory.
5. **Validation Workflow** — runs whatever checks are available and records the outcome per check.

Repozite **never pushes changes** to the repository under analysis; patches stay inside Repozite until you apply them yourself.

---

## Project Structure

```text
Repozite/
├── frontend/                  # React + TypeScript SPA
│   ├── src/
│   │   ├── components/
│   │   ├── lib/
│   │   └── pages/
│   ├── public/
│   ├── worker.js              # Cloudflare Worker: /api proxy to Render
│   ├── wrangler.jsonc         # Worker + asset configuration
│   ├── vite.config.ts         # dev server, /api proxy target
│   └── package.json
│
├── backend/                   # Django REST API
│   ├── config/                # settings, urls, wsgi
│   ├── accounts/              # auth, GitHub OAuth
│   ├── repositories/          # repo submission and scan orchestration
│   ├── analysis/              # findings, patches, validation results
│   ├── manage.py
│   ├── requirements.txt
│   ├── .env.example           # committed template
│   └── .env                   # your secrets — never committed
│
├── analyzer/                  # Flask static-analysis service
│   ├── app.py                 # HTTP entry point (127.0.0.1:5001)
│   ├── analyzer.py            # AST / Ruff / Bandit logic
│   ├── tests.py               # unittest suite
│   └── requirements.txt
│
├── docs/                      # design notes and phase write-ups
│   ├── agent-workflow.md
│   └── phase*.md
│
├── .gitignore
└── README.md
```

---

## Prerequisites

* **Python 3.12+** (developed and tested on 3.14)
* **Node.js 20+** and npm
* **PostgreSQL** — a Neon database is what production uses
* **Git**
* **Docker** — *only* if you want to enable isolated test execution
* **Nebius Token Factory API key** — for AI-generated fixes
* **GitHub OAuth credentials** — for the sign-in flow

---

## Getting Started

### 1. Clone

```bash
git clone https://github.com/sohaildevx/Repozite.git
cd Repozite
```

### 2. Configure the backend

Repozite uses **one virtual environment** for the backend *and* the analyzer — the analyzer's Flask, Ruff, and Bandit are installed into it alongside Django.

```bash
cd backend
python -m venv .venv
```

Activate it:

```powershell
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Install dependencies and create your local configuration:

```bash
pip install -r requirements.txt -r ../analyzer/requirements.txt
copy .env.example .env     # Windows
cp .env.example .env       # macOS / Linux
```

Edit `.env` and fill in at minimum:

```dotenv
SECRET_KEY=generate-a-real-one
DEBUG=True
DATABASE_URL=postgresql://…your Neon connection string…?sslmode=require
GITHUB_CLIENT_ID=…
GITHUB_CLIENT_SECRET=…
```

> **Never commit `.env`, API keys, or database credentials.** `.env` is gitignored; `.env.example` is the committed template.

### 3. Run the database migrations

```bash
python manage.py migrate
```

### 4. Start the three services

**Terminal 1 — Django + analyzer**

```bash
# from backend/, with the venv active
cd ..\analyzer && ..\backend\.venv\Scripts\python.exe app.py    # :5001
cd backend && python manage.py runserver 127.0.0.1:8000         # :8000
```

On macOS/Linux:

```bash
(cd analyzer && python app.py) &
(cd backend && python manage.py runserver 127.0.0.1:8000)
```

**Terminal 2 — frontend**

```bash
cd frontend
npm install
npm run dev
```

Open **http://127.0.0.1:5173**. The dev server proxies `/api` to `http://127.0.0.1:8000` (override with `VITE_PROXY_TARGET` in `frontend/.env`).

---

## Environment Variables

All backend variables live in `backend/.env`. `backend/.env.example` documents most of them with comments.

### Core

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `SECRET_KEY` | prod | dev fallback | Django signing key |
| `DEBUG` | prod | `True` | **must be `False` in production** |
| `ALLOWED_HOSTS` | prod | `localhost,127.0.0.1` | Comma-separated, **no spaces** — Django does not trim entries |
| `DATABASE_URL` | yes | `postgresql://localhost:5432/repozite` | Postgres DSN; `sqlite:///file.db` also works |
| `LOG_LEVEL` | no | `INFO` | App logger level |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | for sign-in | empty | GitHub OAuth app credentials |
| `GITHUB_CALLBACK_URL` | prod | `http://127.0.0.1:8000/api/auth/github/callback/` | Absolute backend URL for the OAuth callback |
| `FRONTEND_URL` | prod | `http://127.0.0.1:5173` | Origin the visitor lands on after the round trip |
| `SESSION_COOKIE_SECURE` | prod | `False` | `True` behind HTTPS |

### Analysis service

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANALYZER_URL` | `http://127.0.0.1:5001` | Where Django reaches the Flask analyzer |
| `ANALYZER_TIMEOUT` | `45` | Seconds before a call to the analyzer is abandoned |
| `ANALYZER_TOKEN` | *(empty)* | Optional shared secret; when set, both sides must carry `X-Analyzer-Token` |

> `ANALYZER_*` are not yet present in `.env.example` — the defaults above are what you get when unset.

### AI + agent runs

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEBIUS_API_KEY` / `NEBIUS_MODEL` | empty | Required for AI-generated fixes |
| `NEBIUS_BASE_URL` | `https://api.tokenfactory.nebius.com/v1/` | OpenAI-compatible endpoint |
| `NEBIUS_TIMEOUT` | `120` | Seconds — keep generous, Nemotron is a reasoning model |
| `NEBIUS_REASONING_EFFORT` | `none` | `none`\|`minimal`\|`low`\|`medium`\|`high`\|`xhigh` |
| `GITHUB_TOKEN` | empty | Raises GitHub API limit from 60/h to 5000/h |
| `AGENT_MAX_REPAIR_ATTEMPTS` | `2` | Bounded retries per run |
| `AGENT_TEST_EXECUTION` | `0` | Set to `1` **and** run Docker to actually execute tests |
| `SANDBOX_IMAGE` | `python:3.12-slim` | Trusted sandbox image (never a repo-supplied Dockerfile) |
| `SANDBOX_TIMEOUT_SECONDS` | `120` | Sandbox wall clock |
| `SANDBOX_MEMORY` / `SANDBOX_CPUS` / `SANDBOX_PIDS_LIMIT` | `256m` / `1.0` / `64` | Resource limits |

### Frontend

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_PROXY_TARGET` | `http://127.0.0.1:8000` | Dev-only; production uses the edge proxy |

---

## Tests

```bash
# Backend — 300+ tests (use a throwaway DB so you don't touch production)
cd backend
$env:DATABASE_URL='sqlite:///test_runs.sqlite3'   # PowerShell
python manage.py test
python manage.py check

# Analyzer — Flask service tests
cd analyzer
python tests.py

# Frontend — type-check, lint, unit tests
cd frontend
npx tsc -b
npm run lint
npm test
```

---

## Deployment

Production runs as two services:

| Piece | Where | URL |
| --- | --- | --- |
| Static SPA + edge proxy | Cloudflare Workers | `https://repozite.sohailshaikhdev.workers.dev` |
| Django + Flask analyzer | Render Web Service | `https://repozite.onrender.com` |

The browser only ever talks to `workers.dev`. The Worker forwards `/api/*` to Render and copies the original host into `x-forwarded-host`, which Django accepts via `USE_X_FORWARDED_HOST` and `SECURE_PROXY_SSL_HEADER`. This keeps cookies, CSRF, and the OAuth state cookie on a single origin.

**Render**

* **Build command:** `pip install -r backend/requirements.txt -r analyzer/requirements.txt`
* **Start command** (single line — gunicorn runs the analyzer in the background, Django in the foreground):

  ```bash
  gunicorn --chdir analyzer --bind 127.0.0.1:5001 app:app & sleep 3 && cd backend && python manage.py migrate --noinput && exec gunicorn config.wsgi:application --bind 0.0.0.0:$PORT --workers 2 --timeout 360
  ```

* **Health check path:** `/health`
* Environment must set `DEBUG=False`, `ALLOWED_HOSTS` (Render host **and** the `workers.dev` host), `GITHUB_CALLBACK_URL`, `FRONTEND_URL`, `SESSION_COOKIE_SECURE=True`.

**Cloudflare**

* Config lives at `frontend/wrangler.jsonc`; the Worker name there (`repozite`) must match the Worker name in the dashboard.
* Connect the repo under **Settings → Builds** with root directory `frontend` and build command `npm ci && npm run build`, so pushes deploy automatically.

**GitHub OAuth app** must list **both** callback URLs:

```text
http://127.0.0.1:8000/api/auth/github/callback/
https://repozite.sohailshaikhdev.workers.dev/api/auth/github/callback/
```

---

## Security Considerations

Repozite processes code from external repositories, so handling matters:

* Keep API keys, `SECRET_KEY`, and database credentials in environment variables — never in the repo.
* Validate repository inputs and bound resource consumption (see the `SANDBOX_*` limits).
* Do not execute untrusted code on the application server; test execution is **opt-in** and runs in an isolated Docker container with a trusted image, CPU/memory/PID limits, and a wall-clock timeout.
* Set `AGENT_TEST_EXECUTION=0` (the default) unless a Docker daemon and `SANDBOX_IMAGE` are actually available.
* Rate-limit unauthenticated endpoints (`GITHUB_OAUTH_RATE`, `GITHUB_OAUTH_CALLBACK_RATE`).
* Always report clearly when validation was skipped rather than passed.

---

## Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository and create a branch:

   ```bash
   git checkout -b feat/your-feature
   ```

2. Make your change and add tests covering it.
3. Run the suites above before pushing.
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/):

   ```bash
   git add .
   git commit -m "fix: describe the bug you fixed"
   ```

   Common prefixes used here: `feat:`, `fix:`, `test:`, `chore:`, `docs:`.

5. Push and open a pull request describing the change and how you tested it.

Keep contributions focused, avoid committing secrets, and include reproduction steps for bug reports.

---

## Current Limitations

Repozite is an ongoing project:

* Static analysis cannot detect every logical bug.
* AI-generated fixes may require manual review before use.
* Validation is only as good as the checks that could actually run — some report `skipped`.
* Test execution is disabled by default (`AGENT_TEST_EXECUTION=0`) and requires Docker.
* Support is centered on Python repositories; other languages depend on the bundled tooling.

**Always review generated patches before using them in a real project.**

---

## Future Improvements

* Expand language and framework support.
* Improve the accuracy of issue detection.
* Generate more context-aware patches.
* Strengthen isolated test execution.
* Improve validation reporting and developer experience.

---

## License

No license has been specified yet. Add a `LICENSE` file before distributing the project under a particular open-source license.

---

**Repozite — Find it. Fix it. Verify it.**
