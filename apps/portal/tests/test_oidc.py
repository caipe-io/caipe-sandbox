"""OIDC routes tested with real code exchange/JWKS validation and a fake provider."""

import base64
import json
import re
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from joserfc import jwt
from joserfc.jwk import RSAKey
from test_portal import BASE, OWNER, SETTINGS, Kubernetes, Omnigent

from portal.app import create_app
from portal.auth import COOKIE, Authentication
from portal.config import Settings
from portal.integrations.agent_sandbox.inventory import PREFIX, manifest, owner_label
from portal.namespaces import UserNamespaces
from portal.sandboxes import Store

ORIGIN = "https://portal.example.com"
ISSUER = "https://idp.example.com"
KEY = RSAKey.generate_key(2048)
KEY.ensure_kid()
POLICY = {
    "issuer": ISSUER,
    "client_id": "portal-client",
    "allowed_email_domains": ["example.com"],
    "allowed_groups": ["developers", "auditors"],
    "role_groups": {"user": ["developers"], "viewer": ["auditors"]},
}
OIDC = replace(
    SETTINGS,
    origin=ORIGIN,
    auth_mode="oidc",
    oidc_policy=json.dumps(POLICY),
    oidc_client_secret="provider-client-secret",
    session_secret="test-session-signing-key-32-characters-long",
)


class Provider:
    def __init__(self):
        self.claims = {}
        self.nonce = ""
        self.challenge = ""
        self.token_calls = 0
        self.signing_key = KEY
        self.discovery_issuer = ISSUER
        self.userinfo = {
            "sub": "idp-alice",
            "email": OWNER,
            "email_verified": True,
            "groups": ["developers"],
        }

    def request(self, request):
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": self.discovery_issuer,
                    "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token",
                    "jwks_uri": ISSUER + "/jwks",
                    "userinfo_endpoint": ISSUER + "/userinfo",
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [KEY.as_dict(private=False)]})
        if request.url.path == "/userinfo":
            assert request.headers["authorization"] == "Bearer provider-access-token"
            return httpx.Response(200, json=self.userinfo)
        assert request.url.path == "/token"
        self.token_calls += 1
        params = parse_qs(request.content.decode())
        assert params["grant_type"] == ["authorization_code"]
        assert params["code"] == ["valid-code"]
        import hashlib

        assert (
            base64.urlsafe_b64encode(
                hashlib.sha256(params["code_verifier"][0].encode()).digest()
            )
            .rstrip(b"=")
            .decode()
            == self.challenge
        )
        assert request.headers["authorization"].startswith("Basic ")
        claims = {
            "iss": ISSUER,
            "sub": "idp-alice",
            "aud": "portal-client",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nonce": self.nonce,
            "email": OWNER,
            "email_verified": True,
            "groups": ["developers"],
            **self.claims,
        }
        token = jwt.encode({"alg": "RS256", "kid": KEY.kid}, claims, self.signing_key)
        return httpx.Response(
            200,
            json={
                "access_token": "provider-access-token",
                "token_type": "Bearer",
                "id_token": token,
            },
        )


@pytest.fixture
def oidc_setup():
    kube, upstream, provider = Kubernetes(), Omnigent(), Provider()
    store = Store(
        OIDC,
        custom=kube,
        core=kube,
        namespaces=UserNamespaces(OIDC, kube, kube, kube),
        metadata=kube.metadata,
    )
    app = create_app(OIDC, store, upstream)
    app.state.auth.client.client_kwargs["transport"] = httpx.MockTransport(
        provider.request
    )
    with TestClient(app, base_url=ORIGIN) as browser:
        yield browser, store, kube, upstream, provider


def begin(browser, provider):
    result = browser.get(SETTINGS.base_path + "/auth/login", follow_redirects=False)
    assert result.status_code == 302
    params = parse_qs(urlsplit(result.headers["location"]).query)
    assert params["redirect_uri"] == [ORIGIN + SETTINGS.base_path + "/auth/callback"]
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    provider.nonce = params["nonce"][0]
    provider.challenge = params["code_challenge"][0]
    return params["state"][0]


def finish(browser, state):
    return browser.get(
        SETTINGS.base_path + "/auth/callback",
        params={"state": state, "code": "valid-code"},
        follow_redirects=False,
    )


def login(browser, provider):
    result = finish(browser, begin(browser, provider))
    assert result.status_code == 303, result.text
    return result


def test_real_oidc_login_sets_secure_session_and_uses_verified_owner(oidc_setup):
    browser, _, kube, upstream, provider = oidc_setup
    upstream.get = lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("No Omnigent auth delegation")
    )
    result = login(browser, provider)
    cookie = result.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie
    assert "path=/agent-sandbox-portal/" in cookie
    raw = TimestampSigner(OIDC.session_secret).unsign(browser.cookies[COOKIE])
    data = json.loads(base64.b64decode(raw))
    assert data["identity"]["owner"] == OWNER
    assert "provider-access-token" not in str(data)
    assert "id_token" not in data and "code_verifier" not in str(data)
    result = browser.post(
        BASE + "/sandboxes",
        headers={"Origin": ORIGIN},
        json={"owner": "bob@example.com"},
    )
    assert result.status_code == 422
    result = browser.post(BASE + "/sandboxes", headers={"Origin": ORIGIN}, json={})
    assert result.status_code == 201
    assert result.json()["owner"] == OWNER
    assert len(kube.items) == 1


@pytest.mark.parametrize(
    "override",
    [
        {"iss": "https://other-idp.example.com"},
        {"aud": "other-client"},
        {"nonce": "wrong-nonce"},
        {"exp": int(time.time()) - 10},
        {"email_verified": False},
        {"email": "alice@other.example.com"},
        {"email": "bad-address"},
        {"groups": ["unmapped"]},
        {"groups": "developers"},
        {"sub": ""},
    ],
)
def test_invalid_token_or_disallowed_identity_cannot_create(oidc_setup, override):
    browser, _, kube, _, provider = oidc_setup
    provider.claims = override
    result = finish(browser, begin(browser, provider))
    assert result.status_code in {401, 403}
    assert COOKIE not in browser.cookies
    assert (
        browser.post(BASE + "/sandboxes", headers={"Origin": ORIGIN}).status_code == 401
    )
    assert not kube.items


def test_invalid_signature_is_rejected(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    provider.signing_key = RSAKey.generate_key(2048)
    assert finish(browser, begin(browser, provider)).status_code == 401


def test_wrong_state_never_exchanges_code(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    begin(browser, provider)
    assert finish(browser, "wrong-state").status_code == 401
    assert provider.token_calls == 0


def test_callback_cannot_replay_after_consuming_state(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    state = begin(browser, provider)
    assert finish(browser, state).status_code == 303
    assert finish(browser, state).status_code == 401
    assert provider.token_calls == 1


def test_discovery_must_match_configured_issuer(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    provider.discovery_issuer = "https://other-idp.example.com"
    assert browser.get(SETTINGS.base_path + "/auth/login").status_code == 503


def test_viewer_can_list_but_cannot_mutate_or_open_terminal(oidc_setup):
    browser, store, _, _, provider = oidc_setup
    cr = store.create(OWNER).reference
    name = cr["metadata"]["name"]
    provider.claims = {"groups": ["auditors"]}
    login(browser, provider)
    result = browser.get(BASE + "/sandboxes")
    assert result.status_code == 200
    assert result.json()["role"] == "viewer" and not result.json()["can_manage"]
    for path in [
        "/sandboxes",
        f"/sandboxes/{name}/suspend",
    ]:
        assert browser.post(BASE + path, headers={"Origin": ORIGIN}).status_code == 403
    assert (
        browser.delete(
            BASE + f"/sandboxes/{name}", headers={"Origin": ORIGIN}
        ).status_code
        == 403
    )
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with browser.websocket_connect(
            BASE + f"/sandboxes/{name}/terminal",
            headers={"Origin": ORIGIN, "Cookie": f"{COOKIE}={browser.cookies[COOKIE]}"},
        ) as ws:
            assert ws.receive_json(mode="binary")["code"] == "http-403"
            ws.receive_text()


def test_short_lived_id_token_does_not_shorten_portal_session(oidc_setup, monkeypatch):
    browser, _, _, _, provider = oidc_setup
    started = time.time()
    provider.claims = {"exp": int(started) + 120}
    login(browser, provider)
    raw = TimestampSigner(OIDC.session_secret).unsign(browser.cookies[COOKIE])
    deadline = json.loads(base64.b64decode(raw))["identity"]["expires"]
    assert started + 3600 <= deadline < started + 3605
    monkeypatch.setattr(time, "time", lambda: started + 300)
    assert browser.get(BASE + "/sandboxes").status_code == 200
    monkeypatch.setattr(time, "time", lambda: started + 3500)
    assert browser.get(BASE + "/sandboxes").status_code == 200
    monkeypatch.setattr(time, "time", lambda: deadline + 1)
    assert browser.get(BASE + "/sandboxes").status_code == 401


def test_tampered_or_expired_session_is_rejected(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    login(browser, provider)
    cookie = browser.cookies[COOKIE]
    browser.cookies.clear()
    prefix, signature = cookie.rsplit(".", 1)
    signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    browser.cookies.set(COOKIE, prefix + "." + signature)
    assert browser.get(BASE + "/sandboxes").status_code == 401
    data = {
        "identity": {
            "owner": OWNER,
            "issuer": ISSUER,
            "client_id": "portal-client",
            "groups": ["developers"],
            "expires": time.time() - 1,
        }
    }
    browser.cookies.set(
        COOKIE,
        TimestampSigner(OIDC.session_secret)
        .sign(base64.b64encode(json.dumps(data).encode()))
        .decode(),
    )
    assert browser.get(BASE + "/sandboxes").status_code == 401


def test_logout_clears_session_and_requires_same_origin(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    login(browser, provider)
    assert (
        browser.post(
            SETTINGS.base_path + "/auth/logout",
            headers={"Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert (
        browser.post(
            SETTINGS.base_path + "/auth/logout", headers={"Origin": ORIGIN}
        ).status_code
        == 200
    )
    assert browser.get(BASE + "/sandboxes").status_code == 401


@pytest.mark.parametrize(
    "changes",
    [
        {"auth_mode": "none"},
        {"session_secret": "short"},
        {"oidc_client_secret": ""},
        {"origin": "http://portal.example.com"},
        {"oidc_policy": json.dumps({**POLICY, "issuer": "http://idp.example.com"})},
        {"oidc_policy": json.dumps({**POLICY, "role_groups": {"admin": ["admins"]}})},
        {"oidc_policy": json.dumps({**POLICY, "role_groups": {}})},
    ],
)
def test_auth_configuration_fails_closed(changes):
    with pytest.raises(ValueError):
        Authentication(replace(OIDC, **changes))


def test_role_precedence_and_explicit_default():
    auth = Authentication(OIDC)
    assert auth.policy.role(OWNER, ["developers", "auditors"]) == "user"
    restricted = Authentication(
        replace(
            OIDC,
            oidc_policy=json.dumps(
                {**POLICY, "allowed_groups": [], "default_role": "viewer"}
            ),
        )
    )
    assert restricted.policy.role(OWNER, ["unmapped"]) == "viewer"


@pytest.mark.parametrize(
    "email",
    [OWNER, "long+name." * 15 + "@example.com", "a+b@example.com", "a-b@example.com"],
)
def test_owner_email_label_is_valid_readable_and_annotation_is_exact(email):
    cr = manifest(SETTINGS, email)
    label = cr["metadata"]["labels"][PREFIX + "owner-email"]
    assert len(label) <= 63 and re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", label)
    assert "@" not in label and cr["metadata"]["annotations"][PREFIX + "owner"] == email
    assert (
        cr["spec"]["podTemplate"]["metadata"]["labels"][PREFIX + "owner-email"] == label
    )
    assert owner_label("a+b@example.com") != owner_label("a-b@example.com")


def test_userinfo_claims_are_supported_only_for_matching_subject(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    auth = browser.app.state.auth
    auth.policy.use_userinfo = True
    provider.claims = {"email": None, "groups": []}
    login(browser, provider)
    assert browser.get(BASE + "/sandboxes").json()["role"] == "user"
    provider.userinfo["sub"] = "someone-else"
    assert finish(browser, begin(browser, provider)).status_code == 401


def test_shared_link_survives_oidc_login(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    result = browser.get(
        SETTINGS.base_path + "/auth/login",
        params={"owner": "bob@example.com"},
        follow_redirects=False,
    )
    params = parse_qs(urlsplit(result.headers["location"]).query)
    provider.nonce = params["nonce"][0]
    provider.challenge = params["code_challenge"][0]
    result = finish(browser, params["state"][0])
    assert result.status_code == 303
    assert parse_qs(urlsplit(result.headers["location"]).query)["owner"] == [
        "bob@example.com"
    ]


def test_invalid_sharing_return_parameter_is_rejected(oidc_setup):
    browser, _, _, _, provider = oidc_setup
    assert (
        browser.get(
            SETTINGS.base_path + "/auth/login",
            params={"owner": "https://evil.example.com"},
        ).status_code
        == 422
    )
    assert provider.token_calls == 0


def test_root_portal_is_independent_of_workload_integrations():
    settings = replace(OIDC, base_path="", auth_omnigent_url="")
    kube, provider = Kubernetes(), Provider()
    upstream = MockUpstream()
    store = Store(
        settings,
        custom=kube,
        core=kube,
        namespaces=UserNamespaces(settings, kube, kube, kube),
        metadata=kube.metadata,
    )
    app = create_app(settings, store, upstream)
    app.state.auth.client.client_kwargs["transport"] = httpx.MockTransport(
        provider.request
    )
    with TestClient(app, base_url=ORIGIN) as browser:
        assert browser.get("/").status_code == 200
        assert browser.get("/auth/config").json() == {
            "mode": "oidc",
            "login_url": "/auth/login",
            "header_links": json.loads(SETTINGS.header_links),
        }
        assert browser.get("/api/sandboxes").status_code == 401
        result = browser.get("/auth/login", follow_redirects=False)
        params = parse_qs(urlsplit(result.headers["location"]).query)
        assert params["redirect_uri"] == [ORIGIN + "/auth/callback"]
        provider.nonce = params["nonce"][0]
        provider.challenge = params["code_challenge"][0]
        result = browser.get(
            "/auth/callback",
            params={"state": params["state"][0], "code": "valid-code"},
            follow_redirects=False,
        )
        assert result.status_code == 303
        create = browser.post(
            "/api/sandboxes",
            headers={"Origin": ORIGIN},
            json={"title": "Root workspace"},
        )
        assert create.status_code == 201
        listed = browser.get("/api/sandboxes").json()
        assert listed["sandboxes"][0]["owner"] == OWNER
        assert "connection_status" not in listed
        assert "host_status" not in listed["sandboxes"][0]
        assert "harnesses" not in listed
        assert not kube.secrets


class MockUpstream:
    async def get(self, *args, **kwargs):
        raise AssertionError("OIDC portal must not contact a workload consumer")

    async def post(self, *args, **kwargs):
        raise AssertionError("OIDC portal must not issue workload credentials")


def test_root_settings_use_explicit_profiles_and_independent_oidc(monkeypatch):
    for name, value in {
        "PORTAL_ORIGIN": ORIGIN,
        "PORTAL_AUTH_MODE": "oidc",
        "PORTAL_BASE_PATH": "",
        "PORTAL_PROFILES": SETTINGS.profiles,
        "PORTAL_RUNTIME_CLASS": SETTINGS.runtime_class,
        "PORTAL_DEFAULT_PROFILE": SETTINGS.default_profile,
        "PORTAL_OIDC_POLICY": json.dumps(POLICY),
        "PORTAL_OIDC_CLIENT_SECRET": "test-client",
        "PORTAL_SESSION_SECRET": "test-session-signing-key-32-characters-long",
    }.items():
        monkeypatch.setenv(name, value)
    assert Settings.from_env().auth_mode == "oidc"
    monkeypatch.setenv("PORTAL_AUTH_MODE", "omnigent")
    with pytest.raises(ValueError, match="absolute HTTP"):
        Settings.from_env()
