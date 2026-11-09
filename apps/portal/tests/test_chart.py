import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[3] / "charts/caipe-sandbox"
pytestmark = pytest.mark.skipif(
    not shutil.which("helm") or not CHART.is_dir(),
    reason="Helm and chart sources are required for template checks",
)


def render(tmp_path, settings, profiles=None, *, release="portal", **overrides):
    values = tmp_path / "values.json"
    values.write_text(
        json.dumps(
            {
                "image": {
                    "repository": "example.invalid/portal",
                    "digest": "sha256:" + "0" * 64,
                },
                "settings": {"runtimeClass": "example-runtime", **settings},
                **({"profiles": profiles} if profiles is not None else {}),
                "auth": {
                    "existingSecret": "portal-auth",
                    "omnigentUrl": "http://omnigent:8000",
                },
                **overrides,
            }
        )
    )

    return subprocess.run(
        [
            "helm",
            "template",
            release,
            str(CHART),
            "--kube-version",
            "1.34.0",
            "-f",
            str(values),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "links", [[], [{"title": "Support", "url": "https://example.com/help"}]]
)
def test_header_links_reach_portal_environment(tmp_path, links):
    result = render(tmp_path, {"headerLinks": links})
    assert result.returncode == 0, result.stderr
    deployment = next(
        o for o in yaml.safe_load_all(result.stdout) if o and o["kind"] == "Deployment"
    )
    env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    assert (
        json.loads(next(e["value"] for e in env if e["name"] == "PORTAL_HEADER_LINKS"))
        == links
    )


def test_caipe_auth_uses_secret_references_and_preserves_subpaths(tmp_path):
    result = render(
        tmp_path,
        {
            "basePath": "/apps/sandbox",
            "origin": "https://caipe.example.com",
            "terminalUrl": "wss://shell.example.com/apps/sandbox",
        },
        auth={
            "mode": "caipe",
            "existingSecret": "sandbox-session",
            "caipe": {"existingSecret": "caipe-signing"},
        },
    )
    assert result.returncode == 0, result.stderr
    deployment = next(
        o for o in yaml.safe_load_all(result.stdout) if o and o["kind"] == "Deployment"
    )
    env = {
        e["name"]: e
        for e in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["PORTAL_CAIPE_VERIFICATION_KEY"]["valueFrom"]["secretKeyRef"] == {
        "name": "caipe-signing",
        "key": "signing-key",
    }
    assert env["PORTAL_SESSION_SECRET"]["valueFrom"]["secretKeyRef"] == {
        "name": "sandbox-session",
        "key": "session-secret",
    }
    assert "PORTAL_OIDC_CLIENT_SECRET" not in env
    assert json.loads(env["PORTAL_CAIPE_POLICY"]["value"]) == {
        "issuer": "caipe-agentic-apps",
        "app_id": "sandbox",
        "default_role": "user",
        "session_seconds": 3600,
    }
    assert env["PORTAL_BASE_PATH"]["value"] == "/apps/sandbox"
    assert env["PORTAL_TERMINAL_URL"]["value"] == "wss://shell.example.com/apps/sandbox"


def test_caipe_requires_operator_supplied_keys(tmp_path):
    result = render(
        tmp_path, {}, auth={"mode": "caipe", "existingSecret": "sandbox-session"}
    )
    assert result.returncode != 0
    assert "auth.caipe.existingSecret is required" in result.stderr


def test_sqlite_metadata_has_persistent_single_writer_and_no_policy_configmap(tmp_path):
    result = render(tmp_path, {})
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    deployment = next(o for o in objects if o["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    app = pod["containers"][0]
    migration = pod["initContainers"][0]
    assert deployment["spec"]["replicas"] == 1
    assert deployment["spec"]["strategy"]["type"] == "Recreate"
    assert migration["command"] == ["python", "-m", "portal.storage", "migrate"]
    assert migration["image"] == app["image"]
    database_env = next(e for e in app["env"] if e["name"] == "PORTAL_DATABASE_URL")
    assert database_env == migration["env"][0]
    assert database_env["value"] == "sqlite:////var/lib/portal/metadata.db"
    assert {"name": "metadata", "mountPath": "/var/lib/portal"} in app["volumeMounts"]
    assert migration["volumeMounts"] == [
        {"name": "metadata", "mountPath": "/var/lib/portal"}
    ]
    claim = next(o for o in objects if o["kind"] == "PersistentVolumeClaim")
    assert claim["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert (
        claim["metadata"]["annotations"].get("argocd.argoproj.io/sync-wave", "0") == "0"
    )
    assert claim["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert app["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert app["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert not any(
        o["kind"] == "Job" or o["metadata"]["name"].endswith("-controls")
        for o in objects
    )


def test_tracing_is_opt_in_and_uses_standard_otel_environment(tmp_path):
    default = render(tmp_path, {})
    pod = next(
        o for o in yaml.safe_load_all(default.stdout) if o and o["kind"] == "Deployment"
    )["spec"]["template"]["spec"]
    assert not any(
        e["name"] == "OTEL_EXPORTER_OTLP_ENDPOINT" for e in pod["containers"][0]["env"]
    )
    configured = render(
        tmp_path,
        {},
        observability={
            "tracing": {
                "endpoint": "http://collector.example:4318",
                "sampleRatio": 0.25,
            }
        },
    )
    assert configured.returncode == 0, configured.stderr
    pod = next(
        o
        for o in yaml.safe_load_all(configured.stdout)
        if o and o["kind"] == "Deployment"
    )["spec"]["template"]["spec"]
    env = {e["name"]: e for e in pod["containers"][0]["env"]}
    assert (
        env["OTEL_EXPORTER_OTLP_ENDPOINT"]["value"] == "http://collector.example:4318"
    )
    assert env["OTEL_TRACES_SAMPLER_ARG"]["value"] == "0.25"
    assert env["OTEL_EXPORTER_OTLP_PROTOCOL"]["value"] == "http/protobuf"
    assert env["PORTAL_POD_UID"]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.uid"
    assert "k8s.pod.uid=$(PORTAL_POD_UID)" in env["OTEL_RESOURCE_ATTRIBUTES"]["value"]
    assert not any(
        e["name"].startswith("OTEL_") for e in pod["initContainers"][0]["env"]
    )


@pytest.mark.parametrize(
    "tracing",
    [
        {"endpoint": "http://user:secret@collector:4318"},
        {"endpoint": "http://collector?token=secret"},
        {"sampleRatio": 2},
    ],
)
def test_tracing_rejects_credentials_in_values_and_invalid_sampling(tmp_path, tracing):
    assert render(tmp_path, {}, observability={"tracing": tracing}).returncode != 0


def test_postgres_metadata_uses_the_same_startup_migration_with_secret_and_ca(tmp_path):
    result = render(
        tmp_path,
        {},
        database={
            "url": "",
            "existingSecret": "metadata-connection",
            "secretKey": "connection",
            "caSecret": "postgres-ca",
        },
    )
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    deployment = next(o for o in objects if o["kind"] == "Deployment")
    assert deployment["spec"]["strategy"]["type"] == "Recreate"
    pod = deployment["spec"]["template"]["spec"]
    migration = pod["initContainers"][0]
    app = pod["containers"][0]
    assert migration["image"] == app["image"]
    database_env = next(e for e in app["env"] if e["name"] == "PORTAL_DATABASE_URL")
    assert (
        database_env
        == migration["env"][0]
        == {
            "name": "PORTAL_DATABASE_URL",
            "valueFrom": {
                "secretKeyRef": {"name": "metadata-connection", "key": "connection"}
            },
        }
    )
    assert migration["command"] == ["python", "-m", "portal.storage", "migrate"]
    assert not any(o["kind"] == "Job" for o in objects)
    ca = {"name": "database-ca", "mountPath": "/etc/portal-database", "readOnly": True}
    assert ca in app["volumeMounts"] and migration["volumeMounts"] == [ca]
    assert not any(o["kind"] == "PersistentVolumeClaim" for o in objects)


@pytest.mark.parametrize(
    "database",
    [
        {"url": "", "existingSecret": ""},
        {"existingSecret": "metadata-connection"},
        {"url": "postgresql://private:secret@database/metadata"},
        {"url": "sqlite:////tmp/ephemeral.db"},
    ],
)
def test_chart_rejects_ambiguous_credentials_or_ephemeral_metadata(tmp_path, database):
    result = render(tmp_path, {}, database=database)
    assert result.returncode != 0
    assert "secret@database" not in result.stderr


def test_postgres_without_private_ca_has_no_metadata_mount_or_migration_job(tmp_path):
    result = render(tmp_path, {}, database={"url": "", "existingSecret": "connection"})
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    pod = next(o for o in objects if o["kind"] == "Deployment")["spec"]["template"][
        "spec"
    ]
    assert pod["initContainers"][0]["command"][-1] == "migrate"
    assert not pod["initContainers"][0].get("volumeMounts")
    assert not any(o["kind"] in {"Job", "PersistentVolumeClaim"} for o in objects)


def test_sqlite_rolling_update_is_rejected(tmp_path):
    result = render(tmp_path, {}, strategy={"type": "RollingUpdate"})
    assert result.returncode != 0
    assert (
        "SQLite requires exactly one portal replica and strategy.type=Recreate"
        in result.stderr
    )


def test_postgresql_replication_renders_native_rollout_disruption_and_spread(tmp_path):
    values = yaml.safe_load(
        (Path(__file__).parents[1] / "examples/postgresql.values.yaml").read_text()
    )
    result = render(tmp_path, {}, release="agent-sandbox-portal", **values)
    assert result.returncode == 0, result.stderr
    objects = [item for item in yaml.safe_load_all(result.stdout) if item]
    deployment = next(item for item in objects if item["kind"] == "Deployment")["spec"]
    assert deployment["replicas"] == 2
    assert deployment["strategy"] == {
        "type": "RollingUpdate",
        "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
    }
    pod = deployment["template"]["spec"]
    assert pod["topologySpreadConstraints"] == values["topologySpreadConstraints"]
    assert pod["initContainers"][0]["command"][-1] == "check"
    for container in [pod["containers"][0], pod["initContainers"][0]]:
        assert {"name": "PORTAL_DATABASE_BACKEND", "value": "postgresql"} in container[
            "env"
        ]
    assert {"name": "WEB_CONCURRENCY", "value": "1"} in pod["containers"][0]["env"]
    budget = next(item for item in objects if item["kind"] == "PodDisruptionBudget")
    assert budget["spec"] == {
        "minAvailable": 1,
        "selector": {"matchLabels": {"app.kubernetes.io/name": "agent-sandbox-portal"}},
    }
    assert not any(item["kind"] in {"Job", "PersistentVolumeClaim"} for item in objects)


@pytest.mark.parametrize("replicas", [0, 2, 3])
def test_sqlite_rejects_other_replica_counts(tmp_path, replicas):
    result = render(tmp_path, {}, replicas=replicas)
    assert result.returncode != 0


def test_postgresql_recreate_multiple_replicas_still_migrates_before_startup(tmp_path):
    result = render(
        tmp_path, {}, replicas=2, database={"url": "", "existingSecret": "connection"}
    )
    assert result.returncode == 0, result.stderr
    deployment = next(
        item
        for item in yaml.safe_load_all(result.stdout)
        if item and item["kind"] == "Deployment"
    )
    assert deployment["spec"]["strategy"] == {"type": "Recreate", "rollingUpdate": None}
    assert (
        deployment["spec"]["template"]["spec"]["initContainers"][0]["command"][-1]
        == "migrate"
    )


@pytest.mark.parametrize("unavailable,surge", [(0, 0), ("0%", "0%")])
def test_rolling_update_rejects_a_budget_that_cannot_progress(
    tmp_path, unavailable, surge
):
    result = render(
        tmp_path,
        {},
        database={"url": "", "existingSecret": "connection"},
        strategy={
            "type": "RollingUpdate",
            "rollingUpdate": {"maxUnavailable": unavailable, "maxSurge": surge},
        },
    )
    assert result.returncode != 0
    assert "requires non-zero" in result.stderr


def test_disruption_budget_uses_native_max_unavailable_when_selected(tmp_path):
    result = render(
        tmp_path,
        {},
        replicas=2,
        database={"url": "", "existingSecret": "connection"},
        podDisruptionBudget={
            "enabled": True,
            "minAvailable": None,
            "maxUnavailable": "50%",
        },
    )
    assert result.returncode == 0, result.stderr
    budget = next(
        item
        for item in yaml.safe_load_all(result.stdout)
        if item and item["kind"] == "PodDisruptionBudget"
    )
    assert (
        budget["spec"]["maxUnavailable"] == "50%"
        and "minAvailable" not in budget["spec"]
    )


def test_shutdown_hook_has_private_writable_signal_and_bounded_server_grace(tmp_path):
    result = render(
        tmp_path,
        {},
        terminationGracePeriodSeconds=30,
        shutdown={
            "propagationSeconds": 2,
            "drainSeconds": 10,
            "serverGraceSeconds": 5,
        },
    )
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    pod = next(o for o in objects if o["kind"] == "Deployment")["spec"]["template"][
        "spec"
    ]
    portal = pod["containers"][0]
    env = {item["name"]: item.get("value") for item in portal["env"]}
    assert pod["terminationGracePeriodSeconds"] == 30
    assert portal["lifecycle"]["preStop"]["exec"]["command"] == [
        "python",
        "-m",
        "portal.drain",
    ]
    assert (
        env["PORTAL_DRAIN_SECONDS"] == "10"
        and env["PORTAL_DRAIN_PROPAGATION_SECONDS"] == "2"
    )
    assert env["UVICORN_TIMEOUT_GRACEFUL_SHUTDOWN"] == "5"
    assert env["PORTAL_DRAIN_FILE"] == "/var/run/portal/drain"
    assert {"name": "runtime", "mountPath": "/var/run/portal"} in portal["volumeMounts"]
    assert next(volume for volume in pod["volumes"] if volume["name"] == "runtime")[
        "emptyDir"
    ] == {"medium": "Memory", "sizeLimit": "1Mi"}
    assert portal["securityContext"]["readOnlyRootFilesystem"] is True
    assert "runtime" not in [
        mount["name"] for mount in pod["initContainers"][0].get("volumeMounts", [])
    ]


@pytest.mark.parametrize("grace", [219, 220])
def test_shutdown_budget_must_fit_inside_native_pod_grace(tmp_path, grace):
    result = render(tmp_path, {}, terminationGracePeriodSeconds=grace)
    assert result.returncode != 0
    assert (
        "must exceed propagationSeconds + drainSeconds + serverGraceSeconds"
        in result.stderr
    )


def test_terminal_io_worker_budget_is_only_passed_to_the_portal(tmp_path):
    result = render(tmp_path, {"terminalIoWorkers": 7})
    assert result.returncode == 0, result.stderr
    deployment = next(
        o for o in yaml.safe_load_all(result.stdout) if o and o["kind"] == "Deployment"
    )
    pod = deployment["spec"]["template"]["spec"]
    env = {e["name"]: e.get("value") for e in pod["containers"][0]["env"]}
    assert env["PORTAL_TERMINAL_IO_WORKERS"] == "7"
    assert all(
        e["name"] != "PORTAL_TERMINAL_IO_WORKERS"
        for e in pod["initContainers"][0]["env"]
    )


@pytest.mark.parametrize("maximum", [0, 5, -1])
def test_per_user_count_limit_is_a_portal_setting(tmp_path, maximum):
    result = render(tmp_path, {"maxSandboxesPerUser": maximum})
    if maximum < 0:
        assert result.returncode != 0 and "maxSandboxesPerUser" in result.stderr
        return
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    deployment = next(o for o in objects if o["kind"] == "Deployment")
    env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    assert next(
        e["value"] for e in env if e["name"] == "PORTAL_MAX_SANDBOXES_PER_USER"
    ) == str(maximum)
    assert not any(o["kind"] == "ResourceQuota" for o in objects)


@pytest.mark.parametrize("interval", [0, 15, 120])
def test_reconciliation_interval_is_a_portal_deployment_setting(tmp_path, interval):
    result = render(tmp_path, {"reconcileIntervalSeconds": interval})
    assert result.returncode == 0, result.stderr
    deployment = next(
        o for o in yaml.safe_load_all(result.stdout) if o and o["kind"] == "Deployment"
    )
    pod = deployment["spec"]["template"]["spec"]
    env = {e["name"]: e.get("value") for e in pod["containers"][0]["env"]}
    assert env["PORTAL_RECONCILE_INTERVAL_SECONDS"] == str(interval)
    assert all(
        e["name"] != "PORTAL_RECONCILE_INTERVAL_SECONDS"
        for e in pod["initContainers"][0]["env"]
    )


def test_negative_reconciliation_interval_is_rejected(tmp_path):
    result = render(tmp_path, {"reconcileIntervalSeconds": -1})
    assert result.returncode != 0 and "reconcileIntervalSeconds" in result.stderr


@pytest.mark.parametrize("workers", [0, -1])
def test_chart_rejects_nonpositive_terminal_worker_budgets(tmp_path, workers):
    result = render(tmp_path, {"terminalIoWorkers": workers})
    assert result.returncode != 0 and "terminalIoWorkers" in result.stderr


@pytest.mark.parametrize(
    "strategy, action", [("Recreate", "migrate"), ("RollingUpdate", "check")]
)
def test_migration_command_contract_follows_the_native_strategy(
    tmp_path, strategy, action
):
    result = render(
        tmp_path,
        {},
        database={"url": "", "existingSecret": "connection"},
        strategy={"type": strategy},
    )
    assert result.returncode == 0, result.stderr
    deployment = next(
        item
        for item in yaml.safe_load_all(result.stdout)
        if item and item["kind"] == "Deployment"
    )
    command = deployment["spec"]["template"]["spec"]["initContainers"][0]["command"]
    assert command == ["python", "-m", "portal.storage", action]


def test_chart_leaves_additional_runtime_admission_to_the_platform(tmp_path):
    result = render(tmp_path, {})
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    assert not any(
        o["metadata"]["name"].endswith(("-protected-execution", "-openshell-runners"))
        for o in objects
    )


def test_admission_match_conditions_do_not_read_namespace_objects(tmp_path):
    result = render(tmp_path, {})
    assert result.returncode == 0, result.stderr
    for item in yaml.safe_load_all(result.stdout):
        if item and item["kind"] == "ValidatingAdmissionPolicy":
            for condition in item["spec"].get("matchConditions", []):
                # Kubernetes populates namespaceObject only during validation.
                assert "namespaceObject" not in condition["expression"], item[
                    "metadata"
                ]["name"]


def test_namespace_policy_edits_have_narrow_rbac_and_preserve_runtime_boundary(
    tmp_path,
):
    result = render(tmp_path, {})
    assert result.returncode == 0, result.stderr
    objects = [item for item in yaml.safe_load_all(result.stdout) if item]
    role = next(
        item
        for item in objects
        if item["kind"] == "ClusterRole"
        and item["metadata"]["name"].endswith("-bootstrap")
    )
    updates = [
        rule
        for rule in role["rules"]
        if "networkpolicies" in rule.get("resources", []) and "update" in rule["verbs"]
    ]
    assert len(updates) == 1
    assert updates[0]["resourceNames"] == ["portal-connections"]
    policy = next(
        item
        for item in objects
        if item["kind"] == "ValidatingAdmissionPolicy"
        and item["metadata"]["name"].endswith("-bootstrap")
    )
    expression = policy["spec"]["validations"][-1]["expression"]
    assert "object.spec.policyTypes == ['Egress']" in expression
    assert "!has(object.spec.ingress)" in expression
    assert "['openshell.ai/component'] == 'supervisor'" in expression
    assert (
        "'sandbox.caipe.io/namespace-uid' in object.metadata.annotations" in expression
    )
    assert (
        "== oldObject.metadata.annotations['sandbox.caipe.io/namespace-uid']"
        in expression
    )
    # Direct Agent Sandbox namespaces omit the optional integration label.
    assert (
        "(!('sandbox.caipe.io/backend' in namespaceObject.metadata.labels)"
        in expression
    )
    assert (
        "|| namespaceObject.metadata.labels['sandbox.caipe.io/backend'] == 'agentSandbox')"
        in expression
    )
    assert (
        "&& 'sandbox.caipe.io/backend' in namespaceObject.metadata.labels" in expression
    )


def test_runner_namespace_selection_preserves_enforcement_and_backend_exclusion(
    tmp_path,
):
    result = render(tmp_path, {})
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    policy = next(
        o
        for o in objects
        if o["kind"] == "ValidatingAdmissionPolicy"
        and o["metadata"]["name"].endswith("-runners")
    )
    assert policy["spec"]["failurePolicy"] == "Fail"
    assert policy["spec"]["matchConstraints"]["namespaceSelector"] == {
        "matchExpressions": [
            {
                "key": "sandbox.caipe.io/backend",
                "operator": "NotIn",
                "values": ["openShell"],
            }
        ]
    }
    binding = next(
        o
        for o in objects
        if o["kind"] == "ValidatingAdmissionPolicyBinding"
        and o["spec"]["policyName"] == policy["metadata"]["name"]
    )
    assert binding["spec"]["validationActions"] == ["Deny"]
    assert binding["spec"]["matchResources"]["namespaceSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "agent-sandbox-portal",
        "sandbox.caipe.io/tenant": "true",
        "sandbox.caipe.io/instance": "default-portal-access",
    }


def test_openshell_mounts_only_client_credentials_and_scopes_gateway_access(tmp_path):
    result = render(
        tmp_path,
        {
            "openShell": {
                "endpoint": "https://gateway:8080",
                "gatewayId": "gateway",
                "gatewayServiceAccount": "gateway",
                "sandboxServiceAccount": "protected-runner",
                "clientSecret": "gateway-client-tls",
            }
        },
    )
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    deployment = next(o for o in objects if o["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    secret = next(
        v["secret"]
        for v in pod["volumes"]
        if v.get("secret", {}).get("secretName") == "gateway-client-tls"
    )
    assert {item["key"] for item in secret["items"]} == {"ca.crt", "tls.crt", "tls.key"}
    mount = next(
        v
        for v in pod["containers"][0]["volumeMounts"]
        if v["mountPath"] == "/etc/portal-openshell"
    )
    assert mount["readOnly"] is True
    assert pod["securityContext"]["fsGroup"] == 10001
    role = next(
        o
        for o in objects
        if o["kind"] == "ClusterRole"
        and o["metadata"]["name"].endswith("-access-openshell")
    )
    assert not any("pods/exec" in r["resources"] for r in role["rules"])
    assert not any(
        o["kind"] == "ClusterRoleBinding"
        and o["roleRef"]["name"] == role["metadata"]["name"]
        for o in objects
    )
    assert not any(
        o["metadata"]["name"].endswith(("-protected-execution", "-openshell-runners"))
        for o in objects
    )


@pytest.mark.parametrize(
    "settings, expected",
    [
        ({}, ["example-runtime"]),
        ({"runtimeClass": "sandbox.example"}, ["sandbox.example"]),
        (
            {
                "runtimeClass": "kata-dev",
                "allowedRuntimeClasses": ["kata-dev", "kata-fc"],
            },
            ["kata-dev", "kata-fc"],
        ),
        (
            {
                "runtimeClass": "sandbox.a",
                "allowedRuntimeClasses": ["sandbox.a", "sandbox.b"],
            },
            ["sandbox.a", "sandbox.b"],
        ),
    ],
)
def test_portal_and_admission_use_the_same_runtime_class_list(
    tmp_path, settings, expected
):
    result = render(tmp_path, settings)
    assert result.returncode == 0, result.stderr
    objects = list(yaml.safe_load_all(result.stdout))
    deployment = next(o for o in objects if o and o["kind"] == "Deployment")
    env = {
        e["name"]: e.get("value")
        for e in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert json.loads(env["PORTAL_ALLOWED_RUNTIME_CLASSES"]) == expected
    policy = next(
        o
        for o in objects
        if o
        and o["kind"] == "ValidatingAdmissionPolicy"
        and o["metadata"]["name"].endswith("-runners")
    )
    assert (
        "object.spec.runtimeClassName in " + json.dumps(expected, separators=(",", ":"))
        in (policy["spec"]["validations"][0]["expression"])
    )


@pytest.mark.parametrize(
    "settings",
    [
        {"allowedRuntimeClasses": []},
        {"allowedRuntimeClasses": ["kata-fc"]},
        {"allowedRuntimeClasses": ["kata-dev", "kata-dev"]},
        {"allowedRuntimeClasses": ["kata-dev", "bad/name"]},
        {"allowedRuntimeClasses": "kata-dev"},
        {"runtimeClass": ""},
    ],
)
def test_chart_rejects_invalid_runtime_class_configuration(tmp_path, settings):
    result = render(tmp_path, settings)
    assert result.returncode != 0
    assert "RuntimeClasses" in result.stderr or "runtimeClass" in result.stderr


@pytest.mark.parametrize(
    "identity,expected",
    [
        (
            None,
            {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
        ),
        (
            {"runAsUser": 1000, "runAsGroup": 2000, "fsGroup": 3000},
            {"runAsUser": 1000, "runAsGroup": 2000, "fsGroup": 3000},
        ),
        (
            {"runAsUser": 1000},
            {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
        ),
    ],
)
def test_chart_supplies_the_configured_sandbox_identity(tmp_path, identity, expected):
    result = render(
        tmp_path, {} if identity is None else {"sandboxSecurityContext": identity}
    )
    assert result.returncode == 0, result.stderr
    deployment = next(
        o for o in yaml.safe_load_all(result.stdout) if o and o["kind"] == "Deployment"
    )
    pod = deployment["spec"]["template"]["spec"]
    env = {e["name"]: e.get("value") for e in pod["containers"][0]["env"]}
    assert json.loads(env["PORTAL_SANDBOX_SECURITY_CONTEXT"]) == expected
    assert pod["securityContext"]["runAsUser"] == 10001


@pytest.mark.parametrize(
    "identity",
    [
        None,
        [],
        "1000",
        *[
            {field: value}
            for field in ("runAsUser", "runAsGroup", "fsGroup")
            for value in (0, -1, True, 1.5, "1000", 2147483648)
        ],
        {"runAsNonRoot": False},
        {"seccompProfile": {"type": "Unconfined"}},
    ],
)
def test_chart_rejects_invalid_or_weakened_sandbox_identity(tmp_path, identity):
    result = render(tmp_path, {"sandboxSecurityContext": identity})
    assert result.returncode != 0
    assert "sandboxSecurityContext" in result.stderr


def test_generic_chart_has_no_workload_consumer_environment_or_secret_write_grants(
    tmp_path,
):
    result = render(tmp_path, {})
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    deployment = next(o for o in objects if o["kind"] == "Deployment")
    env = {
        e["name"]: e.get("value")
        for e in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert not {
        "PORTAL_IMAGE",
        "PORTAL_HARNESSES",
        "PORTAL_CAIPE_URL",
        "PORTAL_OMNIGENT_ENABLED",
        "PORTAL_OMNIGENT_URL",
    }.intersection(env)
    assert "PORTAL_AUTH_OMNIGENT_URL" not in env
    config = next(
        o
        for o in objects
        if o["kind"] == "ConfigMap" and o["metadata"]["name"].endswith("-profiles")
    )
    profiles = json.loads(config["data"]["profiles.json"])
    assert profiles[0]["id"] == "engineering"
    assert profiles[0]["agentSandbox"]["spec"]["podTemplate"]["spec"]["containers"][0][
        "image"
    ]
    for role in [o for o in objects if o["kind"] in {"ClusterRole", "Role"}]:
        for rule in role.get("rules", []):
            if "secrets" in rule.get("resources", []):
                assert rule["verbs"] == ["list"]


@pytest.mark.parametrize(
    "settings",
    [
        {"image": "ignored"},
        {"omnigentEnabled": True},
        {"omnigentUrl": "http://ignored"},
        {"caipeUrl": "http://ignored"},
    ],
)
def test_removed_global_workload_settings_are_rejected_by_chart(tmp_path, settings):
    result = render(tmp_path, settings)
    assert result.returncode != 0
    assert "additional propert" in result.stderr.lower()


@pytest.mark.parametrize(
    "ui",
    [
        {"unknown": True},
        {"resources": {}},
        {"resources": {"default": {"cpu": "500m"}}},
        {"resources": "unvalidated"},
    ],
)
def test_chart_rejects_unsupported_or_incomplete_profile_ui(tmp_path, ui):
    definitions = yaml.safe_load((CHART / "values.yaml").read_text())["profiles"]
    definitions[0]["ui"] = ui
    result = render(tmp_path, {}, profiles=definitions)
    assert result.returncode != 0
    assert "profiles" in result.stderr and "ui" in result.stderr


@pytest.mark.parametrize(
    "ingress_values",
    [
        {},
        {
            "className": "organisation-ingress",
            "annotations": {"example.com/timeout": "120"},
        },
    ],
)
def test_ingress_has_no_controller_specific_defaults(tmp_path, ingress_values):
    result = render(tmp_path, {}, ingress={"enabled": True, **ingress_values})
    assert result.returncode == 0, result.stderr
    ingress = next(
        o for o in yaml.safe_load_all(result.stdout) if o and o["kind"] == "Ingress"
    )
    assert ingress["spec"].get("ingressClassName") == ingress_values.get("className")
    assert ingress["metadata"]["annotations"] == ingress_values.get("annotations", {})


def test_namespace_choice_values_reach_the_portal_and_reject_an_invalid_default(
    tmp_path,
):
    configured = {
        "strategy": "perSandbox",
        "allowedStrategies": ["perSandbox", "perUser"],
        "labels": {},
        "annotations": {},
    }
    result = render(tmp_path, {}, namespace=configured)
    assert result.returncode == 0, result.stderr
    deployment = next(
        o for o in yaml.safe_load_all(result.stdout) if o and o["kind"] == "Deployment"
    )
    app = deployment["spec"]["template"]["spec"]["containers"][0]
    assert (
        json.loads(
            next(e["value"] for e in app["env"] if e["name"] == "PORTAL_NAMESPACE")
        )
        == configured
    )
    result = render(
        tmp_path, {}, namespace={**configured, "allowedStrategies": ["perUser"]}
    )
    assert result.returncode != 0 and "must include namespace.strategy" in result.stderr
    result = render(tmp_path, {}, namespace={**configured, "allowedStrategies": []})
    assert result.returncode != 0


def test_runtime_badges_can_read_only_approved_runtime_classes(tmp_path):
    result = render(
        tmp_path,
        {
            "runtimeClass": "engineering-vm",
            "allowedRuntimeClasses": ["engineering-vm", "other-vm"],
        },
    )
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    role = next(
        o
        for o in objects
        if o["kind"] == "ClusterRole" and o["metadata"]["name"].endswith("-bootstrap")
    )
    rule = next(r for r in role["rules"] if r["resources"] == ["runtimeclasses"])
    assert rule["verbs"] == ["get"]
    assert rule["resourceNames"] == ["engineering-vm", "other-vm"]


def test_native_openshell_observability_overlay_renders_audit_and_grpc_trace_export(
    tmp_path,
):
    import tomllib

    values = yaml.safe_load(
        (
            Path(__file__).parents[1] / "examples/runtime-observability.values.yaml"
        ).read_text()
    )
    values["openShell"].update(
        enabled=True, agentSandbox={"preflight": {"enabled": False}}
    )
    values["openShell"]["server"]["credentialStorage"] = {
        "existingSecret": "gateway-key"
    }
    result = render(tmp_path, {}, **values)
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    config = next(
        o
        for o in objects
        if o["kind"] == "ConfigMap" and "gateway.toml" in o.get("data", {})
    )
    gateway = tomllib.loads(config["data"]["gateway.toml"])["openshell"]["gateway"]
    assert gateway["log_level"] == "info"
    assert gateway["otlp"]["endpoint"] == "http://otel-collector.observability.svc:4317"
    assert gateway["otlp"]["ocsf"]["enabled"] is True
    assert "ocsf_log" not in gateway
    containers = [
        c
        for o in objects
        if o["kind"] in {"StatefulSet", "Deployment"}
        for c in o["spec"]["template"]["spec"]["containers"]
    ]
    native = next(
        c
        for c in containers
        if any(e["name"] == "OPENSHELL_TELEMETRY_ENABLED" for e in c.get("env", []))
    )
    env = {e["name"]: e.get("value") for e in native["env"]}
    assert env["OTEL_TRACES_SAMPLER"] == "parentbased_traceidratio"
    assert env["OTEL_TRACES_SAMPLER_ARG"] == "0.1"
    assert env["OPENSHELL_TELEMETRY_ENABLED"] == "false"
    portal = next(
        o
        for o in objects
        if o["kind"] == "Deployment" and o["metadata"]["name"] == "portal"
    )
    env = {
        e["name"]: e.get("value")
        for e in portal["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert (
        env["OTEL_EXPORTER_OTLP_ENDPOINT"]
        == "http://otel-collector.observability.svc:4318"
    )


@pytest.mark.parametrize("enabled", [False, True])
def test_namespace_baseline_network_policy_requires_operator_opt_in(tmp_path, enabled):
    result = render(tmp_path, {}, namespacePolicy={"baselineNetworkPolicy": enabled})
    assert result.returncode == 0, result.stderr
    deployment = next(
        o for o in yaml.safe_load_all(result.stdout) if o and o["kind"] == "Deployment"
    )
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    policy = json.loads(
        next(
            e["value"]
            for e in container["env"]
            if e["name"] == "PORTAL_NAMESPACE_POLICY"
        )
    )
    assert policy["baselineNetworkPolicy"] is enabled


def test_native_openshell_diagnostics_work_without_a_collector(tmp_path):
    import tomllib

    result = render(
        tmp_path,
        {},
        openShell={
            "enabled": True,
            "agentSandbox": {"preflight": {"enabled": False}},
            "server": {"credentialStorage": {"existingSecret": "gateway-key"}},
        },
    )
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    config = next(
        o
        for o in objects
        if o["kind"] == "ConfigMap" and "gateway.toml" in o.get("data", {})
    )
    gateway = tomllib.loads(config["data"]["gateway.toml"])["openshell"]["gateway"]
    assert gateway["log_level"] == "info"
    assert "otlp" not in gateway and "ocsf_log" not in gateway


def test_openshell_pvc_storage_permissions_are_scoped_and_opt_in(tmp_path):
    result = render(
        tmp_path,
        {
            "openShell": {
                "endpoint": "https://gateway:8080",
                "gatewayId": "gateway",
                "gatewayServiceAccount": "gateway",
                "sandboxServiceAccount": "protected-runner",
                "clientSecret": "gateway-client",
                "storageMode": "persistentVolumeClaim",
            }
        },
    )
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    role = next(
        o
        for o in objects
        if o["kind"] == "ClusterRole"
        and o["metadata"]["name"].endswith("-openshell-storage")
    )
    assert role["rules"] == [
        {
            "apiGroups": [""],
            "resources": ["persistentvolumeclaims"],
            "verbs": ["get", "create", "patch", "delete"],
        }
    ]
    assert not any(
        o["kind"] == "ClusterRoleBinding"
        and o["roleRef"]["name"] == role["metadata"]["name"]
        for o in objects
    )
    policy = next(
        o
        for o in objects
        if o["kind"] == "ValidatingAdmissionPolicy"
        and o["metadata"]["name"].endswith("-openshell-storage")
    )
    rules = policy["spec"]["validations"]
    assert "['sandbox.caipe.io/backend'] == 'openShell'" in rules[0]["expression"]
    assert "object.spec == oldObject.spec" in rules[1]["expression"]
    disabled = render(tmp_path, {})
    assert disabled.returncode == 0, disabled.stderr
    assert not any(
        o and o["metadata"]["name"].endswith("-openshell-storage")
        for o in yaml.safe_load_all(disabled.stdout)
    )


def test_bundled_openshell_requires_driver_attachment_approval_for_pvc_mode(tmp_path):
    settings = {
        "openShell": {
            "endpoint": "https://gateway:8080",
            "storageMode": "persistentVolumeClaim",
            "clientSecret": "gateway-client",
        }
    }
    result = render(tmp_path, settings, openShell={"enabled": True})
    assert result.returncode != 0
    assert "allowDriverConfig=true" in result.stderr
    result = render(
        tmp_path,
        settings,
        openShell={
            "enabled": True,
            "agentSandbox": {"preflight": {"enabled": False}},
            "server": {
                "credentialStorage": {"existingSecret": "gateway-key"},
                "drivers": {"kubernetes": {"allowDriverConfig": True}},
            },
        },
    )
    assert result.returncode == 0, result.stderr


def test_optional_portal_sidecar_and_service_ports(tmp_path):
    container = {
        "name": "internal-tls",
        "image": "example.invalid/proxy@sha256:" + "1" * 64,
        "ports": [{"name": "internal-tls", "containerPort": 8443}],
        "volumeMounts": [{"name": "internal-tls", "mountPath": "/tls", "readOnly": True}],
    }
    volume = {"name": "internal-tls", "secret": {"secretName": "portal-tls"}}
    port = {"name": "internal-tls", "port": 8443, "targetPort": "internal-tls"}
    result = render(tmp_path, {}, extraContainers=[container], extraVolumes=[volume], extraServicePorts=[port])
    assert result.returncode == 0, result.stderr
    objects = [o for o in yaml.safe_load_all(result.stdout) if o]
    pod = next(o for o in objects if o['kind'] == 'Deployment')['spec']['template']['spec']
    service = next(o for o in objects if o['kind'] == 'Service' and o['metadata']['name'] == 'portal')
    assert container in pod['containers']
    assert volume in pod['volumes']
    assert port in service['spec']['ports']
