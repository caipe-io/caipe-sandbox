import asyncio
import json
import time
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from kubernetes.client import ApiException
from starlette.websockets import WebSocketDisconnect
from test_oidc import OIDC
from test_portal import BASE, HEADERS, OTHER, OWNER, SETTINGS, Omnigent
from test_provisioning import CleanupKubernetes

from portal.app import create_app
from portal.auth import Authentication
from portal.integrations.agent_sandbox import execution
from portal.namespaces import UserNamespaces
from portal.sandboxes import Store


class AdminKubernetes(CleanupKubernetes):
    def list_cluster_custom_object(self, group, version, plural, limit, _continue):
        assert limit == 200
        values = list(self.items.values())
        if _continue:
            return {"items": deepcopy(values[1:])}
        return {"items": deepcopy(values[:1]), "metadata": {"continue": "next-page"}}

    def read_namespaced_pod(self, name, namespace):
        cr = self.items.get((namespace, name))
        if cr is None:
            raise ApiException(404)
        return SimpleNamespace(
            metadata=SimpleNamespace(
                name=name,
                namespace=namespace,
                uid="pod-uid-" + name,
                owner_references=[SimpleNamespace(uid=cr["metadata"]["uid"])],
            ),
            spec=SimpleNamespace(containers=[SimpleNamespace(name="host")]),
            status=SimpleNamespace(
                phase="Running",
                container_statuses=[],
                init_container_statuses=[],
                conditions=[],
            ),
        )


@pytest.fixture
def admin_setup():
    settings = replace(
        SETTINGS,
        admin_emails=json.dumps([OWNER.upper()]),
        namespace_policy=json.dumps(
            {**json.loads(SETTINGS.namespace_policy), "deleteWhenEmpty": True}
        ),
    )
    kube, upstream = AdminKubernetes(), Omnigent()
    store = Store(
        settings,
        custom=kube,
        core=kube,
        namespaces=UserNamespaces(settings, kube, kube, kube),
        metadata=kube.metadata,
    )
    with TestClient(create_app(settings, store, upstream)) as browser:
        yield browser, store, kube


def foreign(kube, namespace="external-workloads", name="external-sandbox"):
    cr = {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "uid": namespace + "-uid",
            "resourceVersion": "1",
        },
        "spec": {"podTemplate": {"spec": {"containers": [{"name": "runner"}]}}},
        "status": {
            "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 1}]
        },
    }
    kube.items[(namespace, name)] = cr
    return cr


def test_admin_sees_database_owned_records_without_adopting_foreign_allocations(
    admin_setup,
):
    browser, store, kube = admin_setup
    store.create(OWNER).reference
    store.create(OTHER).reference
    external = foreign(kube)
    kube.read_namespaced_secret = Mock(
        side_effect=AssertionError("Admin inventory must not read Secrets")
    )
    response = browser.get(BASE + "/admin/sandboxes", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "admin" and len(body["sandboxes"]) == 2
    assert external["metadata"]["name"] not in {r["id"] for r in body["sandboxes"]}
    assert {r["owner"] for r in body["sandboxes"]} == {OWNER, OTHER}
    assert "podTemplate" not in response.text
    personal = browser.get(BASE + "/sandboxes", headers=HEADERS).json()
    assert personal["role"] == "admin" and personal["can_manage"]
    assert len(personal["sandboxes"]) == 1


@pytest.mark.parametrize(
    "headers,code",
    [
        ({"Cookie": "session=bob", "Origin": SETTINGS.origin}, 403),
        ({"Origin": SETTINGS.origin}, 401),
    ],
)
def test_unseeded_and_anonymous_cannot_list_delete_or_terminal(
    admin_setup, headers, code
):
    browser, store, kube = admin_setup
    cr = store.create(OTHER).reference
    kube.list_cluster_custom_object = Mock(
        side_effect=AssertionError("Unauthorized cluster read")
    )
    path = (
        BASE
        + "/admin/sandboxes/"
        + cr["metadata"]["name"]
        + "?namespace="
        + cr["metadata"]["namespace"]
        + "&uid="
        + cr["metadata"]["uid"]
    )
    assert (
        browser.get(BASE + "/admin/sandboxes?role=admin", headers=headers).status_code
        == code
    )
    assert browser.delete(path, headers=headers).status_code == code
    with browser.websocket_connect(
        path.split("?")[0] + "/terminal?namespace=" + cr["metadata"]["namespace"],
        headers=headers,
    ) as ws:
        assert ws.receive_json(mode="binary")["code"] == f"http-{code}"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()
    assert (cr["metadata"]["namespace"], cr["metadata"]["name"]) in kube.items


def test_admin_delete_exact_namespace_uid_and_managed_cleanup(admin_setup):
    browser, store, kube = admin_setup
    cr = store.create(OTHER).reference
    twin = foreign(kube, name=cr["metadata"]["name"])
    path = BASE + "/admin/sandboxes/" + cr["metadata"]["name"]
    query = (
        "?namespace=" + cr["metadata"]["namespace"] + "&uid=" + cr["metadata"]["uid"]
    )
    assert browser.delete(path, headers=HEADERS).status_code == 422
    assert (
        browser.delete(
            path + query.replace(cr["metadata"]["uid"], "stale"), headers=HEADERS
        ).status_code
        == 409
    )
    assert (
        browser.delete(
            path + query, headers={**HEADERS, "Origin": "https://attacker.test"}
        ).status_code
        == 403
    )
    result = browser.delete(path + query, headers=HEADERS)
    assert result.status_code == 202 and result.json()["status"] == "deleting"
    deadline = time.monotonic() + 2
    while (
        cr["metadata"]["namespace"] in kube.namespace_objects
        and time.monotonic() < deadline
    ):
        store.cleanup_namespaces()
        time.sleep(0.01)
    assert cr["metadata"]["namespace"] not in kube.namespace_objects
    assert (twin["metadata"]["namespace"], twin["metadata"]["name"]) in kube.items
    result = browser.delete(
        path + "?namespace=external-workloads&uid=" + twin["metadata"]["uid"],
        headers=HEADERS,
    )
    assert result.status_code == 404


def test_admin_terminal_requires_matching_sandbox_pod(admin_setup):
    _, store, kube = admin_setup
    cr = store.create(OTHER).reference
    target = store.admin_execution(cr["metadata"]["name"], cr["metadata"]["namespace"])
    assert target.scope == cr["metadata"]["namespace"]
    pod = kube.read_namespaced_pod(cr["metadata"]["name"], cr["metadata"]["namespace"])
    pod.metadata.owner_references[0].uid = "unrelated-pod"
    kube.read_namespaced_pod = Mock(return_value=pod)
    with pytest.raises(HTTPException) as error:
        store.admin_execution(cr["metadata"]["name"], cr["metadata"]["namespace"])
    assert error.value.status_code == 409


@pytest.mark.parametrize(
    "seed", ["{}", '["not-an-email"]', "[null]", '["alice@example.com\n"]']
)
def test_invalid_manual_seed_is_rejected(seed):
    with pytest.raises(ValueError):
        Authentication(replace(SETTINGS, admin_emails=seed))


def test_oidc_admin_seed_still_requires_groups_and_does_not_trust_session_role():
    auth = Authentication(replace(OIDC, admin_emails=json.dumps([OWNER])))
    claims = {
        "email": OWNER,
        "email_verified": True,
        "sub": "alice",
        "groups": [],
        "exp": time.time() + 100,
    }
    with pytest.raises(HTTPException) as error:
        auth.session(claims)
    assert error.value.status_code == 403


def test_admin_seed_revocation_and_untrusted_role():
    record = {
        "identity": {
            "owner": OWNER,
            "issuer": "https://idp.example.com",
            "client_id": "portal-client",
            "groups": ["developers"],
            "expires": time.time() + 100,
            "role": "admin",
        }
    }
    connection = SimpleNamespace(session=record)
    seeded = Authentication(replace(OIDC, admin_emails=json.dumps([OWNER])))
    assert asyncio.run(seeded.principal(connection, None)).role == "admin"
    assert asyncio.run(Authentication(OIDC).principal(connection, None)).role == "user"


def test_oidc_seeded_login_and_removal_reject_admin_api():
    import httpx2 as httpx
    from test_oidc import ORIGIN, Provider, login

    settings = replace(OIDC, admin_emails=json.dumps([OWNER]))
    kube, provider = AdminKubernetes(), Provider()
    store = Store(
        settings,
        custom=kube,
        core=kube,
        namespaces=UserNamespaces(settings, kube, kube, kube),
        metadata=kube.metadata,
    )
    app = create_app(settings, store, Omnigent())
    app.state.auth.client.client_kwargs["transport"] = httpx.MockTransport(
        provider.request
    )
    with TestClient(app, base_url=ORIGIN) as browser:
        login(browser, provider)
        assert browser.get(BASE + "/admin/sandboxes").json()["role"] == "admin"
        app.state.auth.admins.clear()
        assert browser.get(BASE + "/admin/sandboxes").status_code == 403


def test_admin_terminal_exec_target_and_revocation(admin_setup, monkeypatch):
    import portal.app as module

    browser, store, kube = admin_setup
    cr = store.create(OTHER).reference
    pod = kube.read_namespaced_pod(cr["metadata"]["name"], cr["metadata"]["namespace"])
    pod.spec.containers = [SimpleNamespace(name="runner")]
    kube.read_namespaced_pod = Mock(return_value=pod)

    class Exec:
        opened = True
        text = "admin terminal\r\n"

        def is_open(self):
            return self.opened

        def update(self, timeout):
            pass

        def read_all(self):
            result, self.text = self.text, ""
            return result

        def read_channel(self, channel):
            return ""

        def close(self):
            self.opened = False

    terminal = Exec()

    def attach(_method, name, namespace, **options):
        assert (
            name == cr["metadata"]["name"] and namespace == cr["metadata"]["namespace"]
        )
        assert options["container"] == "runner"
        return terminal

    monkeypatch.setattr(execution, "stream", attach)
    monkeypatch.setattr(module, "AUTH_RECHECK_SECONDS", 0.01)
    with browser.websocket_connect(
        BASE
        + f"/admin/sandboxes/{cr['metadata']['name']}/terminal?namespace={cr['metadata']['namespace']}",
        headers=HEADERS,
    ) as ws:
        assert ws.receive_json(mode="binary") == {"type": "ready"}
        assert ws.receive_text() == "admin terminal\r\n"
        browser.app.state.auth.admins.clear()
        assert ws.receive_json(mode="binary")["code"] == "http-403"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()
    assert not terminal.opened
