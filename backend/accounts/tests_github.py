"""Tests for the GitHub OAuth endpoints ("Sign in with GitHub").

Covers the parts that are deterministic without network access:

- the disabled state degrades to /login instead of erroring
- the authorize redirect carries client_id / redirect_uri / state and parks
  the state, the return path and the *originating frontend* in cookies
- the callback rejects a missing or mismatched state (CSRF on the OAuth leg)
- the callback links an existing account by verified email rather than
  creating a duplicate -- and never takes over an account by username
- a username collision creates a suffixed account instead of seizing it
- the success path opens the same session /api/auth/login/ would
- the per-client rate limit on both unauthenticated routes

The authorize leg is always issued with HTTP_HOST="frontend.test" because
that is what really happens: the button lives on the frontend, so the request
reaching github_login carries the frontend's Host. The callback is then issued
from the default testserver host, which is what GitHub's redirect looks like
-- the backend's own address, with no memory of the frontend except the
origin cookie.

GitHub's HTTP is mocked at accounts.views.requests, so no request escapes the
test process.
"""

from unittest import mock
from urllib.parse import parse_qs, urlencode, urlparse

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from . import views

User = get_user_model()

LOGIN_URL = "/api/auth/github/"
CALLBACK_URL = "/api/auth/github/callback/"

FRONTEND = "http://frontend.test"
CALLBACK_ABS = "http://testserver/api/auth/github/callback/"
# Realistic: the frontend's own host is what starts the flow.
FRONTEND_HOST = "frontend.test"

CONFIG = {
    "GITHUB_CLIENT_ID": "cid",
    "GITHUB_CLIENT_SECRET": "csecret",
    "GITHUB_CALLBACK_URL": CALLBACK_ABS,
    "FRONTEND_URL": FRONTEND,
    "ALLOWED_HOSTS": [
        "frontend.test",
        "testserver",
        "localhost",
        "localhost:5174",
        "127.0.0.1",
    ],
}

# Comfortably above anything a test does, so the limit itself never fires.
NO_LIMIT = {"authorize": (10_000, 60), "callback": (10_000, 60)}


def configured(**extra):
    """override_settings kwargs for a fully configured deployment."""
    base = dict(
        CONFIG,
        GITHUB_OAUTH_ENABLED=True,
        GITHUB_OAUTH_THROTTLE=NO_LIMIT,
    )
    base.update(extra)
    return base


def disabled(**extra):
    """override_settings kwargs for the out-of-the-box state."""
    base = dict(
        CONFIG,
        GITHUB_CLIENT_ID="",
        GITHUB_CLIENT_SECRET="",
        GITHUB_CALLBACK_URL="",
        GITHUB_OAUTH_ENABLED=False,
        GITHUB_OAUTH_THROTTLE=NO_LIMIT,
    )
    base.update(extra)
    return base


def start_flow(client, **params):
    """Hit the authorize endpoint the way the real button does."""
    return client.get(LOGIN_URL, params, HTTP_HOST=FRONTEND_HOST)


def login_redirect_url(flag, next_path="/"):
    """The /login URL the backend sends aborted OAuth legs to."""
    return f"{FRONTEND}/login?{urlencode({'github': flag, 'next': next_path})}"


class FakeResponse:
    """Stand-in for requests.Response with the two attributes we read."""

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        if self._payload is None:
            raise ValueError("no json body")
        return self._payload


def github_user(**overrides):
    profile = {"login": "octo-cat", "id": 42, "email": "octo@example.com"}
    profile.update(overrides)
    return profile


def mock_github(token_payload=None, profile=None, emails=None):
    """Patch the token exchange and the two API reads used by the callback."""
    token_payload = {"access_token": "tok-123"} if token_payload is None else token_payload
    profile = github_user() if profile is None else profile
    if emails is None:
        # A non-null profile email means /user/emails is never requested.
        emails = []

    def fake_get(url, **kwargs):
        if url.endswith("/user/emails"):
            return FakeResponse(emails)
        return FakeResponse(profile)

    return (
        mock.patch("accounts.views.requests.post", return_value=FakeResponse(token_payload)),
        mock.patch("accounts.views.requests.get", side_effect=fake_get),
    )


class GithubLoginDisabledTests(TestCase):
    """Out of the box there are no credentials: degrade, never 500."""

    @override_settings(**disabled())
    def test_redirects_to_login_with_notice(self):
        response = start_flow(self.client)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], login_redirect_url(views.GITHUB_UNCONFIGURED))

    @override_settings(**disabled())
    def test_callback_also_degrades(self):
        response = self.client.get(CALLBACK_URL, {"code": "x", "state": "y"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], login_redirect_url(views.GITHUB_UNCONFIGURED))


class GithubLoginRedirectTests(TestCase):
    @override_settings(**configured())
    def test_redirects_to_github_with_state(self):
        response = start_flow(self.client, next="/scan/7")

        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response["Location"])
        self.assertEqual(parsed.netloc, "github.com")
        self.assertEqual(parsed.path, "/login/oauth/authorize")

        params = parse_qs(parsed.query)
        self.assertEqual(params["client_id"], ["cid"])
        self.assertEqual(params["redirect_uri"], [CALLBACK_ABS])
        self.assertIn("read:user", params["scope"][0])
        self.assertIn("user:email", params["scope"][0])
        self.assertIn("state", params)

        state = params["state"][0]
        self.assertEqual(response.cookies[views.OAUTH_STATE_COOKIE].value, state)
        self.assertEqual(response.cookies[views.OAUTH_NEXT_COOKIE].value, "/scan/7")
        # HttpOnly keeps the state out of reach of any injected script.
        self.assertTrue(response.cookies[views.OAUTH_STATE_COOKIE]["httponly"])

    @override_settings(**configured())
    def test_records_the_originating_frontend_host(self):
        """The callback only sees the backend address, so remember ours."""
        response = start_flow(self.client, next="/scan/7")

        self.assertEqual(
            response.cookies[views.OAUTH_ORIGIN_COOKIE].value,
            f"http://{FRONTEND_HOST}",
        )
        self.assertTrue(response.cookies[views.OAUTH_ORIGIN_COOKIE]["httponly"])

    @override_settings(**configured())
    def test_unsafe_next_is_sanitised(self):
        response = start_flow(self.client, next="//evil.example/x")

        self.assertEqual(response.cookies[views.OAUTH_NEXT_COOKIE].value, "/")

    @override_settings(**configured())
    def test_missing_next_defaults_to_root(self):
        response = start_flow(self.client)

        self.assertEqual(response.cookies[views.OAUTH_NEXT_COOKIE].value, "/")

    @override_settings(**configured(), SESSION_COOKIE_SECURE=True)
    def test_cookies_are_secure_when_session_cookie_is(self):
        """One production switch must flip the OAuth cookies too."""
        response = start_flow(self.client)

        self.assertTrue(response.cookies[views.OAUTH_STATE_COOKIE]["secure"])
        self.assertTrue(response.cookies[views.OAUTH_ORIGIN_COOKIE]["secure"])

    @override_settings(**configured(), SESSION_COOKIE_SECURE=False)
    def test_cookies_stay_insecure_on_plain_http(self):
        """Secure over http://127.0.0.1 would make the browser drop them."""
        response = start_flow(self.client)

        self.assertFalse(response.cookies[views.OAUTH_STATE_COOKIE]["secure"])


class GithubCallbackStateTests(TestCase):
    @override_settings(**configured())
    def test_mismatched_state_is_rejected(self):
        """The state cookie and the callback's state must agree."""
        start_flow(self.client)
        response = self.client.get(
            CALLBACK_URL, {"code": "abc", "state": "forged"}
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], login_redirect_url(views.GITHUB_MISMATCH))
        self.assertFalse(User.objects.exists())

    @override_settings(**configured())
    def test_missing_code_is_rejected(self):
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        response = self.client.get(CALLBACK_URL, {"state": state})

        self.assertEqual(response["Location"], login_redirect_url(views.GITHUB_MISMATCH))

    @override_settings(**configured())
    def test_user_denying_consent_is_reported(self):
        start_flow(self.client, next="/scan/3")
        response = self.client.get(
            CALLBACK_URL, {"error": "access_denied", "error_description": "user"}
        )

        self.assertEqual(
            response["Location"], login_redirect_url(views.GITHUB_DENIED, "/scan/3")
        )

    @override_settings(**configured())
    def test_failed_exchange_is_reported(self):
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post = mock.patch(
            "accounts.views.requests.post",
            return_value=FakeResponse({"error": "bad_verification_code"}),
        )

        with post:
            response = self.client.get(CALLBACK_URL, {"code": "abc", "state": state})

        self.assertEqual(response["Location"], login_redirect_url(views.GITHUB_FAILED))
        self.assertFalse(User.objects.exists())


class GithubCallbackOriginTests(TestCase):
    """Where the callback sends the browser once it is done."""

    @override_settings(**configured())
    def test_returns_to_the_origin_that_started_the_flow(self):
        """The callback arrives on the backend; the frontend may be elsewhere."""
        start_flow(self.client, next="/scan/9")
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github()

        with post, get:
            response = self.client.get(
                CALLBACK_URL, {"code": "abc", "state": state}
            )  # default host: the backend's own address

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], f"http://{FRONTEND_HOST}/scan/9")

    @override_settings(**configured())
    def test_foreign_origin_cookie_is_ignored(self):
        """A hand-crafted origin must not become an open redirect."""
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        self.client.cookies[views.OAUTH_ORIGIN_COOKIE] = "https://evil.example.com"
        post, get = mock_github()

        with post, get:
            response = self.client.get(
                CALLBACK_URL, {"code": "abc", "state": state}
            )

        self.assertEqual(response["Location"], f"{FRONTEND}/")

    @override_settings(**configured())
    def test_non_http_origin_cookie_is_ignored(self):
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        self.client.cookies[views.OAUTH_ORIGIN_COOKIE] = "javascript:alert(1)"
        post, get = mock_github()

        with post, get:
            response = self.client.get(
                CALLBACK_URL, {"code": "abc", "state": state}
            )

        self.assertEqual(response["Location"], f"{FRONTEND}/")

    @override_settings(**configured())
    def test_one_time_cookies_are_cleared(self):
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github()

        with post, get:
            response = self.client.get(
                CALLBACK_URL, {"code": "abc", "state": state}
            )

        self.assertIn(views.OAUTH_STATE_COOKIE, response.cookies)
        self.assertIn(views.OAUTH_NEXT_COOKIE, response.cookies)
        self.assertIn(views.OAUTH_ORIGIN_COOKIE, response.cookies)


class GithubCallbackSuccessTests(TestCase):
    @override_settings(**configured())
    def test_creates_user_and_opens_session(self):
        start_flow(self.client, next="/scan/9")
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github()

        with post, get:
            response = self.client.get(CALLBACK_URL, {"code": "abc", "state": state})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], f"http://{FRONTEND_HOST}/scan/9")

        user = User.objects.get()
        self.assertEqual(user.username, "octo-cat")
        self.assertEqual(user.email, "octo@example.com")
        # No password: this identity is GitHub-only.
        self.assertFalse(user.has_usable_password())
        # Same session contract as /api/auth/login/.
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))

    @override_settings(**configured())
    def test_me_endpoint_confirms_the_session(self):
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github()
        with post, get:
            self.client.get(CALLBACK_URL, {"code": "abc", "state": state})

        api = APIClient()
        api.cookies = self.client.cookies
        me = api.get("/api/auth/me/")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.data["username"], "octo-cat")

    @override_settings(**configured())
    def test_session_backend_is_explicit(self):
        """Not AUTHENTICATION_BACKENDS[0] -- that order is an accident."""
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github()

        with post, get:
            self.client.get(CALLBACK_URL, {"code": "abc", "state": state})

        session = self.client.session
        self.assertEqual(
            session["_auth_user_backend"],
            "django.contrib.auth.backends.ModelBackend",
        )


class GithubCallbackLinkingTests(TestCase):
    @override_settings(**configured())
    def test_links_existing_account_by_email(self):
        """Same verified email -> the existing account, no duplicate."""
        existing = User.objects.create_user(
            username="alice", email="alice@example.com", password="pw"
        )
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github(profile=github_user(login="alice-gh", email="alice@example.com"))

        with post, get:
            self.client.get(CALLBACK_URL, {"code": "abc", "state": state})

        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(self.client.session["_auth_user_id"], str(existing.pk))

    @override_settings(**configured())
    def test_username_collision_never_seizes_an_account(self):
        """A local "alice" with another email must not lose her account."""
        User.objects.create_user(username="alice", email="alice@local.test", password="pw")
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github(profile=github_user(login="alice", email="alice@github.test"))

        with post, get:
            self.client.get(CALLBACK_URL, {"code": "abc", "state": state})

        self.assertEqual(User.objects.count(), 2)
        self.assertTrue(User.objects.filter(username="alice-2").exists())
        original = User.objects.get(username="alice")
        self.assertEqual(original.email, "alice@local.test")
        created = User.objects.get(username="alice-2")
        self.assertNotEqual(self.client.session["_auth_user_id"], str(original.pk))
        self.assertEqual(self.client.session["_auth_user_id"], str(created.pk))

    @override_settings(**configured())
    def test_private_email_falls_back_to_emails_endpoint(self):
        """profile.email is null -> /user/emails supplies the verified one."""
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github(
            profile=github_user(email=None),
            emails=[
                {"email": "other@example.com", "primary": False, "verified": False},
                {"email": "main@example.com", "primary": True, "verified": True},
            ],
        )

        with post, get as get_mock:
            self.client.get(CALLBACK_URL, {"code": "abc", "state": state})
            # /user/emails was consulted because the profile had no email.
            self.assertTrue(any("/user/emails" in str(c) for c in get_mock.call_args_list))

        self.assertEqual(User.objects.get().email, "main@example.com")


class GithubAvatarTests(TestCase):
    """The avatar is session state, not account state.

    It is set only by the OAuth leg and wiped whenever logout() flushes the
    session, so a password account can never inherit somebody else's picture.
    """

    def _signed_in_with_avatar(self):
        """Drive the real flow: authorize -> callback -> session holds one."""
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github(
            profile=github_user(avatar_url="https://avatars.githubusercontent.com/u/42")
        )
        with post, get:
            self.client.get(CALLBACK_URL, {"code": "abc", "state": state})

    @override_settings(**configured())
    def test_avatar_reaches_the_session_and_the_me_endpoint(self):
        self._signed_in_with_avatar()

        self.assertEqual(
            self.client.session["avatar_url"],
            "https://avatars.githubusercontent.com/u/42",
        )

        api = APIClient()
        api.cookies = self.client.cookies
        me = api.get("/api/auth/me/")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(
            me.data["avatar_url"], "https://avatars.githubusercontent.com/u/42"
        )

    @override_settings(**configured())
    def test_a_profile_without_an_avatar_degrades_to_empty(self):
        """github_user() carries no avatar_url -- sign-in must still succeed."""
        start_flow(self.client)
        state = self.client.cookies[views.OAUTH_STATE_COOKIE].value
        post, get = mock_github()

        with post, get:
            response = self.client.get(CALLBACK_URL, {"code": "abc", "state": state})

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("avatar_url", self.client.session)

        api = APIClient()
        api.cookies = self.client.cookies
        self.assertEqual(api.get("/api/auth/me/").data["avatar_url"], "")

    @override_settings(**configured())
    def test_sign_out_clears_the_avatar(self):
        self._signed_in_with_avatar()

        api = APIClient()
        api.cookies = self.client.cookies
        self.assertEqual(api.post("/api/auth/logout/").status_code, 200)

        self.assertNotIn("avatar_url", self.client.session)


class GithubThrottleTests(TestCase):
    """DRF throttles never reach plain Django views, so these carry their own."""

    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    @override_settings(
        **configured(GITHUB_OAUTH_THROTTLE={"authorize": (2, 60), "callback": (5, 60)})
    )
    def test_authorize_is_rate_limited_per_client(self):
        start_flow(self.client)
        start_flow(self.client)
        response = start_flow(self.client)  # third within the window

        self.assertEqual(response.status_code, 302)
        self.assertIn(f"github={views.GITHUB_THROTTLED}", response["Location"])
        # It never even reached GitHub.
        self.assertNotIn("github.com", urlparse(response["Location"]).netloc)

    @override_settings(
        **configured(GITHUB_OAUTH_THROTTLE={"authorize": (2, 60), "callback": (5, 60)})
    )
    def test_callback_is_rate_limited(self):
        for _ in range(5):
            self.client.get(CALLBACK_URL, {"code": "x", "state": "y"})
        response = self.client.get(CALLBACK_URL, {"code": "x", "state": "y"})

        self.assertIn(f"github={views.GITHUB_THROTTLED}", response["Location"])

    @override_settings(
        **configured(GITHUB_OAUTH_THROTTLE={"authorize": (2, 60), "callback": (5, 60)})
    )
    def test_a_broken_cache_fails_open(self):
        """Throttling must never be able to lock someone out of signing in."""
        with mock.patch("accounts.views.cache.add", side_effect=RuntimeError("down")):
            response = start_flow(self.client)

        self.assertIn("github.com", urlparse(response["Location"]).netloc)
