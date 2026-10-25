"""Authentication endpoints for the accounts app.

Each view declares its own permission explicitly:
- register/login: AllowAny
- github/github-callback: public browser redirects (plain Django views, no
  permission classes -- they answer a 302, not JSON)
- logout/me: IsAuthenticated (protected)

CSRF note: DRF's SessionAuthentication re-enforces CSRF on any request where
a session user is present, so logout/me are CSRF-protected. We never disable
CsrfViewMiddleware.
Only cookie instead.
"""

import re
import secrets
from functools import wraps
from urllib.parse import urlencode, urlparse

import requests
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.core.cache import cache
from django.db import IntegrityError
from django.http import HttpResponseRedirect, JsonResponse
from django.http.request import split_domain_port, validate_host
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .serializers import LoginSerializer, RegisterSerializer, UserSerializer

# Generic message shared by every login failure: never reveals whether the
# username exists (user-enumeration protection).
INVALID_CREDENTIALS = "Invalid username or password."

# ---------------------------------------------------------------------------
# GitHub OAuth ("Sign in with GitHub")
# ---------------------------------------------------------------------------

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"
GITHUB_API_VERSION = "2022-11-28"
OAUTH_TIMEOUT_SECONDS = 15


OAUTH_STATE_COOKIE = "repozite_oauth_state"
OAUTH_NEXT_COOKIE = "repozite_oauth_next"

OAUTH_ORIGIN_COOKIE = "repozite_oauth_origin"
OAUTH_COOKIE_MAX_AGE = 600  
OAUTH_SESSION_BACKEND = "django.contrib.auth.backends.ModelBackend"

GITHUB_UNCONFIGURED = "unconfigured"
GITHUB_DENIED = "denied"
GITHUB_FAILED = "failed"
GITHUB_MISMATCH = "mismatch"
GITHUB_THROTTLED = "throttled"


class GithubOAuthError(Exception):
    """Any failure talking to GitHub or reading its response."""


def _cookie_kwargs():
    """Shared attributes for every OAuth cookie.

    `secure` follows SESSION_COOKIE_SECURE so one production setting flips
    the session cookie and these together -- setting Secure on http://127.0.0.1
    would make the browser drop the state cookie and break sign-in outright.
    """
    return {
        "max_age": OAUTH_COOKIE_MAX_AGE,
        "httponly": True,
        "samesite": "Lax",
        "path": "/",
        "secure": settings.SESSION_COOKIE_SECURE,
    }


def _request_origin(request):
    """Where the visitor's frontend actually lives.

    Taken from the Host of the request that *started* the flow, because that
    request comes in on the frontend's own origin (Vite/nginx proxy /api) --
    it is the only moment the real frontend port and scheme are known. The
    callback later arrives on the backend's address, where that information
    is already lost.

    Safe to trust: `request.get_host()` runs Django's ALLOWED_HOSTS check
    itself, so a forged Host yields no origin at all rather than a redirect
    somewhere attacker-controlled.
    """
    try:
        host = request.get_host()  # raises DisallowedHost for a forged Host
    except Exception:  # noqa: BLE001 - a bad Host must not break the flow
        return None
    scheme = "https" if request.is_secure() else "http"
    return f"{scheme}://{host}"


def _safe_origin(raw):
    """Validate a stored origin; None means 'fall back to FRONTEND_URL'."""
    if not raw:
        return None
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    if parsed.path or parsed.query or parsed.fragment:
        return None  
    domain, _port = split_domain_port(parsed.netloc)
    if not domain or not validate_host(domain, settings.ALLOWED_HOSTS):
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _stored_origin(request):
    """The frontend origin recorded when the flow started, if it still checks out."""
    return _safe_origin(request.COOKIES.get(OAUTH_ORIGIN_COOKIE))


def _clear_oauth_cookies(response):
    """Spend the one-time OAuth cookies once the round trip is over.

    Written by hand rather than via delete_cookie() so the Secure flag mirrors
    SESSION_COOKIE_SECURE exactly -- a Secure cookie must not be re-set
    without it, or a hardened deployment could fail to drop them.
    """
    for key in (OAUTH_STATE_COOKIE, OAUTH_NEXT_COOKIE, OAUTH_ORIGIN_COOKIE):
        response.set_cookie(
            key,
            value="",
            max_age=0,
            expires="Thu, 01 Jan 1970 00:00:00 GMT",
            path="/",
            secure=settings.SESSION_COOKIE_SECURE,
            httponly=True,
            samesite="Lax",
        )


def _client_key(request):
    """Best-effort client address for throttling.

    First X-Forwarded-For hop when behind a proxy (the real client), else
    REMOTE_ADDR. Spoofing X-Forwarded-For only buys the attacker their own
    bucket, so it cannot be used to exhaust anyone else's.
    """
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.META.get("REMOTE_ADDR", "unknown")


def _throttled(view_kind, origin_for):
    """Per-client rate limit for the two unauthenticated OAuth routes.

    DRF's throttle classes only guard api_view handlers, and these two are
    plain Django views, so they need their own. Fails OPEN: a broken or
    unavailable cache must never be able to lock people out of signing in.

    `origin_for` picks where the "slow down" notice lands: the authorize leg
    is still on the frontend, the callback is back on the backend and must
    rely on the stored origin.
    """

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            limit, window = settings.GITHUB_OAUTH_THROTTLE[view_kind]
            key = f"repozite-oauth:{view_kind}:{_client_key(request)}"
            try:
                cache.add(key, 0, timeout=window)  # set only if absent
                count = cache.incr(key)
            except Exception:  # noqa: BLE001 - cache trouble is not auth trouble
                return view(request, *args, **kwargs)
            if count > limit:
                next_path = _safe_next(request.GET.get("next"))
                return _failure_redirect(GITHUB_THROTTLED, next_path, origin_for(request))
            return view(request, *args, **kwargs)

        return wrapper

    return decorator


def _safe_next(raw):
    """Server-side mirror of the frontend's safeNextPath().

    Only same-origin absolute paths may be carried through the OAuth round
    trip -- an attacker who controlled `next` could otherwise bounce a freshly
    authenticated session to an external host.
    """
    if not raw:
        return "/"
    value = raw.strip()
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or "://" in value:
        return "/"
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in value):
        return "/"
    return value


def _frontend_redirect(next_path="/", origin=None):
    """Send the browser back to the React app (absolute origin)."""
    return HttpResponseRedirect(f"{origin or settings.FRONTEND_URL}{next_path}")


def _failure_redirect(flag, next_path="/", origin=None):
    """Land on /login with an explanation, preserving the destination.

    Every aborted OAuth leg ends here rather than on the landing page: the
    visitor came to sign in, so show them the reason plus the password form,
    and carry `next` forward so completing the form still reaches the page
    they were headed for.
    """
    base = origin or settings.FRONTEND_URL
    query = urlencode({"github": flag, "next": next_path})
    return HttpResponseRedirect(f"{base}/login?{query}")


def _unconfigured(request, origin=None):
    origin = origin or _stored_origin(request) or settings.FRONTEND_URL
    return _failure_redirect(
        GITHUB_UNCONFIGURED, _safe_next(request.GET.get("next")), origin
    )


@_throttled("authorize", _request_origin)
def github_login(request):
    """GET /api/auth/github/ -- bounce the visitor to GitHub's consent screen.

    Without credentials configured this redirects to /login with an
    explanatory flag instead of failing, so the UI degrades gracefully.
    """
    if not settings.GITHUB_OAUTH_ENABLED:
        return _unconfigured(request, _request_origin(request))

    next_path = _safe_next(request.GET.get("next"))
    state = secrets.token_urlsafe(32)

    query = urlencode(
        {
            "client_id": settings.GITHUB_CLIENT_ID,
            "redirect_uri": settings.GITHUB_CALLBACK_URL,
            "scope": "read:user user:email",
            "state": state,
        }
    )
    response = HttpResponseRedirect(f"{GITHUB_AUTHORIZE_URL}?{query}")
    cookie_kwargs = _cookie_kwargs()
    response.set_cookie(OAUTH_STATE_COOKIE, state, **cookie_kwargs)
    response.set_cookie(OAUTH_NEXT_COOKIE, next_path, **cookie_kwargs)
    
    origin = _request_origin(request)
    if origin:
        response.set_cookie(OAUTH_ORIGIN_COOKIE, origin, **cookie_kwargs)
    return response


@never_cache
@_throttled("callback", _stored_origin)
def github_callback(request):
    """GET /api/auth/github/callback/ -- exchange the code, open a session.

    Verifies `state` against the cookie we set before leaving, exchanges the
    authorisation code for a token, resolves (or creates) the local user, then
    redirects to the frontend carrying the same session cookie that
    /api/auth/login/ would have issued.
    """
    if not settings.GITHUB_OAUTH_ENABLED:
        return _unconfigured(request)

    next_path = _safe_next(request.COOKIES.get(OAUTH_NEXT_COOKIE))
    expected_state = request.COOKIES.get(OAUTH_STATE_COOKIE, "")
    
    origin = _stored_origin(request) or settings.FRONTEND_URL

    if request.GET.get("error") == "access_denied":
        return _failure_redirect(GITHUB_DENIED, next_path, origin)

    code = request.GET.get("code", "")
    state = request.GET.get("state", "")
   
    if not code or not expected_state or not secrets.compare_digest(state, expected_state):
        return _failure_redirect(GITHUB_MISMATCH, next_path, origin)

    try:
        token = _exchange_code(code)
        profile = _fetch_profile(token)
       
        user = _resolve_user(profile)
    except (GithubOAuthError, IntegrityError):
        return _failure_redirect(GITHUB_FAILED, next_path, origin)

    login(request, user, backend=OAUTH_SESSION_BACKEND)

    response = _frontend_redirect(next_path, origin)
    _clear_oauth_cookies(response)
    return response


def _exchange_code(code):
    """Trade the authorisation code for an access token."""
    try:
        response = requests.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GITHUB_CALLBACK_URL,
            },
            timeout=OAUTH_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise GithubOAuthError from exc

    if response.status_code != 200:
        raise GithubOAuthError
    try:
        payload = response.json()
    except ValueError as exc:
        raise GithubOAuthError from exc

    token = payload.get("access_token")
    if payload.get("error") or not token:
        raise GithubOAuthError
    return token


def _github_get(url, token):
    """Authenticated GET against the GitHub API (raises GithubOAuthError)."""
    try:
        response = requests.get(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "Repozite",
            },
            timeout=OAUTH_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise GithubOAuthError from exc

    if response.status_code != 200:
        raise GithubOAuthError
    try:
        return response.json()
    except ValueError as exc:
        raise GithubOAuthError from exc


def _fetch_profile(token):
    """Return {'login': str, 'email': str} for the token's owner.

    /user returns a null email whenever the address is private, so fall back
    to /user/emails and prefer the verified primary address.
    """
    profile = _github_get(GITHUB_USER_URL, token)
    login_name = profile.get("login")
    if not login_name:
        raise GithubOAuthError

    email = profile.get("email") or ""
    if not email:
        try:
            emails = _github_get(GITHUB_EMAILS_URL, token)
        except GithubOAuthError:
            emails = []
        if isinstance(emails, list):
            verified = [e for e in emails if isinstance(e, dict) and e.get("verified")]
            primary = next((e for e in verified if e.get("primary")), None)
            chosen = primary or (verified[0] if verified else None)
            if chosen:
                email = chosen.get("email") or ""

    return {"login": login_name, "email": email}


def _resolve_user(profile):
    """Link to an existing account by verified email, else create one.

    Linking is by email only -- never by username. Matching on username would
    let whoever registers "alice" locally seize the account of the GitHub user
    "alice". A username collision therefore creates a suffixed account instead
    of taking someone else's over.
    """
    User = get_user_model()
    email = profile.get("email") or ""

    if email:
        existing = User.objects.filter(email__iexact=email).order_by("id").first()
        if existing is not None:
            return existing

    
    base = re.sub(r"[^\w.@+-]", "", profile.get("login", ""))[:140] or "github-user"
    username = base
    attempt = 1  # first collision yields "<name>-2", the usual convention
    while User.objects.filter(username=username).exists():
        attempt += 1
        username = f"{base}-{attempt}"  
    return User.objects.create_user(username=username, email=email)


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    """POST /api/auth/register/ -- create a new account (201)."""
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.create(serializer.validated_data)
    return Response(
        {"detail": "Account created.", "user": UserSerializer(user).data},
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    """POST /api/auth/login/ -- authenticate and open a session (200)."""
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = authenticate(
        request,
        username=serializer.validated_data["username"],
        password=serializer.validated_data["password"],
    )

    # authenticate() returns None for unknown user AND wrong password --
    # one generic 401 covers both, so responses reveal nothing.
    if user is None:
        return Response(
            {"detail": INVALID_CREDENTIALS},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    login(request, user)  # creates the session + sessionid cookie
    return Response({"detail": "Logged in.", "user": UserSerializer(user).data})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """POST /api/auth/logout/ -- destroy the session (200)."""
    logout(request)  # flushes the session server-side and rotates the cookie
    return Response({"detail": "Logged out."})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    """GET /api/auth/me/ -- current user (200 / 403)."""
    return Response(UserSerializer(request.user).data)


@ensure_csrf_cookie
def csrf(request):
    """GET /api/auth/csrf/ -- sets the csrftoken cookie for clients.

    Plain Django view on purpose: the React frontend / Postman call this
    once, read the cookie value, and echo it back as the X-CSRFToken header
    on POST/PUT/DELETE requests.
    """
    return JsonResponse({"detail": "CSRF cookie set."})
