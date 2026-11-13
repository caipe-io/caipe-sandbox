"""Resource-specific OAuth access tokens; browser credentials never authorize MCP."""

import asyncio
import json
import re
import time
from urllib.parse import urlsplit

import httpx
import jwt
from mcp.server.auth.provider import AccessToken
from pydantic import BaseModel, ConfigDict, Field, model_validator
from fastapi import HTTPException

from ..auth import OIDCPolicy, Principal


class MCPPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = Field(default=False, strict=True)
    resource_url: str = ""
    issuer: str = ""
    jwks_url: str = ""
    algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    read_scope: str = "sandbox:read"
    execute_scope: str = "sandbox:exec"
    identity: OIDCPolicy = Field(
        default_factory=lambda: OIDCPolicy(default_role="user")
    )
    max_sessions: int = Field(default=8, ge=1, le=128)
    max_timeout_seconds: int = Field(default=3600, ge=1, le=86400)
    foreground_wait_seconds: int = Field(default=25, ge=1, le=60)
    output_bytes: int = Field(default=1048576, ge=4096, le=16777216)
    retention_seconds: int = Field(default=300, ge=30, le=3600)
    docs_url: str = ""

    @model_validator(mode="after")
    def validate_urls(self):
        if not self.enabled:
            return self
        for value in (self.resource_url, self.issuer, self.jwks_url):
            parsed = urlsplit(value)
            if (
                not parsed.hostname
                or parsed.username
                or parsed.query
                or parsed.fragment
                or any(character.isspace() for character in value)
                or (
                    parsed.scheme != "https"
                    and not (
                        parsed.scheme == "http"
                        and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                    )
                )
            ):
                raise ValueError(
                    "MCP resource, issuer and JWKS URLs must use HTTPS (HTTP is allowed on loopback)"
                )
            if parsed.port == 0:
                raise ValueError("MCP URLs require a valid service port")
        if not self.algorithms or set(self.algorithms) - {
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "EdDSA",
        }:
            raise ValueError("MCP requires asymmetric JWT signature algorithms")
        if not all(
            re.fullmatch(r"[A-Za-z0-9:._/-]{1,80}", x)
            for x in (self.read_scope, self.execute_scope)
        ):
            raise ValueError("Invalid MCP OAuth scope")
        if self.docs_url and (
            urlsplit(self.docs_url).scheme != "https"
            or not urlsplit(self.docs_url).hostname
        ):
            raise ValueError("MCP documentation URL must use HTTPS")
        return self

    def validate_settings(self, settings):
        if self.enabled:
            if urlsplit(self.resource_url).path != settings.base_path + "/api/mcp":
                raise ValueError(
                    "MCP resource_url path must match base_path + /api/mcp"
                )
            if len(settings.session_secret.encode()) < 32:
                raise ValueError(
                    "MCP execution handles require a shared session secret of at least 32 bytes"
                )


class TokenVerifier:
    def __init__(self, policy, *, client=None):
        self.policy = policy
        self.client = client or httpx.AsyncClient(timeout=5, follow_redirects=False)
        self.owns_client = client is None
        self.keys = []
        self.loaded = 0
        self.lock = asyncio.Lock()

    async def close(self):
        if self.owns_client:
            await self.client.aclose()

    async def key(self, kid):
        async with self.lock:
            found = [k for k in self.keys if not kid or k.get("kid") == kid]
            age = time.monotonic() - self.loaded
            if age >= 300 or (not found and age >= 30):
                async with self.client.stream("GET", self.policy.jwks_url) as response:
                    response.raise_for_status()
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 65536:
                            raise ValueError("Oversized JWKS")
                keys = json.loads(body)["keys"]
                if not isinstance(keys, list) or len(keys) > 64:
                    raise ValueError("Invalid JWKS")
                self.keys = [
                    k
                    for k in keys
                    if isinstance(k, dict)
                    and k.get("kty") in {"RSA", "EC", "OKP"}
                    and not any(x in k for x in ("d", "k"))
                    and k.get("use", "sig") == "sig"
                ]
                self.loaded = time.monotonic()
                found = [k for k in self.keys if not kid or k.get("kid") == kid]
            if len(found) != 1:
                raise ValueError("Unknown or ambiguous signing key")
            return jwt.PyJWK(found[0]).key

    async def verify_token(self, token):
        try:
            if not isinstance(token, str) or len(token) > 16384:
                return None
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in self.policy.algorithms:
                return None
            claims = jwt.decode(
                token,
                await self.key(header.get("kid")),
                algorithms=self.policy.algorithms,
                audience=self.policy.resource_url,
                issuer=self.policy.issuer,
                options={
                    "require": ["exp", "iat", "sub", self.policy.identity.email_claim]
                },
            )
            email = claims.get(self.policy.identity.email_claim)
            groups = claims.get(self.policy.identity.groups_claim, [])
            if (
                not isinstance(email, str)
                or len(email) > 254
                or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
                or not isinstance(claims["sub"], str)
                or not claims["sub"].strip()
                or (
                    self.policy.identity.require_verified_email
                    and claims.get("email_verified") is not True
                )
                or not isinstance(groups, list)
                or any(not isinstance(g, str) for g in groups)
            ):
                return None
            owner = email.lower()
            role = self.policy.identity.role(owner, groups)
            scopes = claims.get("scope", "")
            if not isinstance(scopes, str):
                return None
            return AccessToken(
                token=token,
                client_id=str(
                    claims.get("azp") or claims.get("client_id") or claims["sub"]
                ),
                scopes=scopes.split(),
                expires_at=int(claims["exp"]),
                resource=self.policy.resource_url,
                subject=claims["sub"],
                claims={**claims, "portal_owner": owner, "portal_role": role},
            )
        except (
            jwt.PyJWTError,
            httpx.HTTPError,
            HTTPException,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
        ):
            return None


def principal(token):
    return Principal(token.claims["portal_owner"], token.claims["portal_role"])
