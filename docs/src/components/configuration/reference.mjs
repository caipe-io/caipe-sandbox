import reference from "./reference.json" with { type: "json" };

export const sources = reference;
export const scopes = {
  profile: "Profile fields",
  deployment: "Helm chart values",
  state: "Saved state and IDs",
  environment: "Environment variables",
};
export const systems = {
  helm: "Helm",
  portal: "Portal API",
  database: "Metadata DB",
  kubernetes: "Kubernetes",
  openshell: "OpenShell",
  guest: "Inside sandbox",
};

function group(
  id,
  scope,
  label,
  match,
  owner,
  readers,
  enforcement,
  editing,
  changes,
) {
  return {
    id,
    scope,
    label,
    match,
    owner,
    readers,
    enforcement,
    editing,
    changes,
  };
}
export const groups = [
  group(
    "profile-identity",
    "profile",
    "Identity & backend",
    /^(id|title|description|agentSandbox|openShell|envoyEgress)/,
    "Profile administrator",
    ["portal", "database", "kubernetes", "openshell"],
    "The portal validates exactly one backend. Native Kubernetes/OpenShell systems validate and enforce their own supported specifications.",
    "Engineers select an offered profile at creation; the catalog is deployment-managed.",
    "Catalog edits affect new sandboxes. Existing sandboxes retain their applied snapshot.",
  ),
  group(
    "profile-acp",
    "profile",
    "ACP coding process",
    /^acp\./,
    "Profile administrator",
    ["portal", "database", "guest"],
    "The portal admits a registered private Agent Sandbox and launches the profile-owned command through the supervised ACP runner. Runtime and network controls remain independently enforced.",
    "Deployment-managed profile; callers cannot choose an executable or workspace path.",
    "Existing allocations retain their applied profile snapshot. A changed configuration requires a newly qualified connection.",
  ),
  group(
    "profile-terminal",
    "profile",
    "Terminal & helpers",
    /^(terminal|helpers)/,
    "Profile administrator",
    ["portal", "guest"],
    "The portal validates commands and runs them through the backend. Scripts and probes execute inside the sandbox; they are not immutable security controls.",
    "The UI runs helpers; it does not edit the profile's helper definitions.",
    "Saved profile commands remain attached to existing sandboxes. Tools and writable files inside the guest can change.",
  ),
  group(
    "profile-resources",
    "profile",
    "Resource defaults & bounds",
    /^ui\./,
    "Profile administrator",
    ["portal", "kubernetes", "openshell"],
    "The API checks profile bounds and platform resourcePolicy. Selected resources are written to native fields; ui.resources itself is not interpreted by Kubernetes.",
    "Engineers choose permitted sizes. Direct Agent Sandbox can resize CPU/memory only after complete suspension. OpenShell cannot resize an existing sandbox.",
    "Disk is creation-time for direct Agent Sandbox; OpenShell disk is fixed by gateway configuration.",
  ),
  group(
    "platform-catalog",
    "deployment",
    "Profile catalog",
    /^(profiles|defaultProfile)$/,
    "Platform operator",
    ["helm", "portal", "database"],
    "The portal validates profile definitions and the default profile ID at startup.",
    "Deployment/GitOps only; engineers select entries.",
    "Chart updates roll out the catalog. Existing saved configurations are not silently rewritten.",
  ),
  group(
    "platform-acp",
    "deployment",
    "ACP connections",
    /^acp\./,
    "Platform operator",
    ["helm", "portal", "database"],
    "The private data plane authenticates the service and checks the admitted caller, sandbox UID and configuration revision. TLS and network isolation require operator configuration.",
    "Register connections in deployment configuration and supply the service credential through a Kubernetes Secret.",
    "Changes apply on portal rollout; active or unconfirmed process fences are retained until confirmed drain or operator reconciliation.",
  ),
  group(
    "platform-sandbox",
    "deployment",
    "Sandbox placement & identity",
    /^settings\.(runtimeClass|allowedRuntimeClasses|namespacePrefix|runnerServiceAccount|runnerImagePullSecrets|sandboxSecurityContext|storageClass)/,
    "Platform operator",
    ["portal", "kubernetes"],
    "The renderer restricts approved runtime and protected fields; Kubernetes admission, runtime and storage enforce native settings. Ordinary Pods gain no VM boundary without Kata.",
    "Runtime, UID/GID, storage class and service-account settings are not arbitrary engineer overrides.",
    "Primarily new workloads. A catalog/deployment change does not migrate an existing workload or its volume.",
  ),
  group(
    "platform-namespace",
    "deployment",
    "Namespace & cluster network controls",
    /^(namespace\.|namespacePolicy\.)/,
    "Platform operator",
    ["portal", "kubernetes"],
    "Portal-managed namespace bootstrap, RBAC, admission and an enforcing CNI. NetworkPolicy permissions are additive; a deny-all policy cannot override another broad allow.",
    "Engineers may select permitted namespace placement. Namespace locking and Kubernetes network-policy editing are administrator controls.",
    "Bootstrap policies are create-only. Changing values is not a blanket update of existing namespace policies.",
  ),
  group(
    "platform-budget",
    "deployment",
    "Sandbox resource envelope",
    /^resourcePolicy\./,
    "Platform operator",
    ["portal", "kubernetes", "openshell"],
    "The portal validates all allocations; native runtime/Kubernetes resource fields enforce the resolved limits.",
    "Engineer selections must fit both the profile and the platform envelope.",
    "New requests are validated against current controls; reducing a limit does not resize existing sandboxes.",
  ),
  group(
    "platform-header-links",
    "deployment",
    "Portal header links",
    /^settings\.headerLinks$/,
    "Platform operator",
    ["helm", "portal"],
    "The chart and portal validate up to three title/HTTP(S) URL pairs.",
    "Deployment-managed links, shown in standalone and embedded views. An empty list hides them.",
    "Updated on portal rollout; links open in a new tab without closing terminal sessions.",
  ),
  group(
    "platform-operations",
    "deployment",
    "Portal limits & workers",
    /^settings\.(maxSandboxesPerUser|terminalIoWorkers|reconcileIntervalSeconds|operationLeaseSeconds)/,
    "Platform operator",
    ["portal", "database"],
    "API validation, shared database reservations, leases and reconciliation. These settings do not define in-guest agent permissions.",
    "Deployment-managed; not an engineer choice.",
    "The updated portal process uses these values after rollout.",
  ),
  group(
    "platform-openshell",
    "deployment",
    "OpenShell connection",
    /^settings\.openShell\./,
    "Platform operator",
    ["helm", "portal", "kubernetes", "openshell"],
    "Gateway authentication and native runtime admission. Installing a gateway and configuring the portal's connection are separate steps.",
    "Deployment-managed connection and trusted supervisor settings. Network-policy edits live with the sandbox, not here.",
    "Connection changes need a portal rollout. Do not change gateway identity or storage layout as an implicit migration of existing sandboxes.",
  ),
  group(
    "platform-auth",
    "deployment",
    "Sign-in & roles",
    /^auth\./,
    "Platform operator",
    ["helm", "portal", "database"],
    "Portal authentication, role checks and signed sessions. The workload's tool credentials are independent of portal sign-in.",
    "Operator-managed identity configuration; administrators can manage supported live access controls separately.",
    "Applied after portal rollout; existing cookies and sessions may need renewal. Store actual secrets in a Secret, not values or profiles.",
  ),
  group(
    "platform-db",
    "deployment",
    "Metadata database",
    /^database\./,
    "Platform operator",
    ["helm", "portal", "database", "kubernetes"],
    "Database connections, schema checks/migrations and native storage. SQLite requires one replica and Recreate; PostgreSQL is an externally supplied service.",
    "Deployment-managed. No database server/operator is installed for PostgreSQL.",
    "Schema changes require Recreate and a backup. Helm rollback does not reverse migrations or migrate database contents.",
  ),
  group(
    "platform-integration",
    "deployment",
    "Optional integrations",
    /^(agentSandbox\.|openShell\.|omnigent\.|kata\.)/,
    "Platform operator",
    ["helm", "kubernetes", "openshell"],
    "Optional subcharts own their native installation settings. All installation toggles default off. External installations can be reused.",
    "Deployment-managed. Subchart fields remain native to the selected integration.",
    "Integration updates follow that component's upgrade rules. Installing Kata does not automatically select it in a profile.",
  ),
  group(
    "platform-telemetry",
    "deployment",
    "Logs & tracing",
    /^observability\./,
    "Platform operator",
    ["portal"],
    "Portal instrumentation exports configured traces. JSON stdout logs need an operator-provided collector and backend.",
    "Deployment-managed; no collector is bundled.",
    "Applied to new portal processes. This does not configure every upstream component's telemetry.",
  ),
  group(
    "platform-service",
    "deployment",
    "Portal URL & ingress",
    /^(settings\.(origin|basePath|terminalUrl)|ingress\.)/,
    "Platform operator",
    ["helm", "portal", "kubernetes"],
    "Portal URL validation and the installed ingress/TLS controller. Origin/basePath must agree with routing and OIDC callbacks.",
    "Deployment-managed.",
    "Routing changes can invalidate links and require renewed sign-in. DNS, certificates and ingress controllers are operator-provided.",
  ),
  group(
    "platform-pods",
    "deployment",
    "Portal deployment & upgrades",
    /^(image\.|imagePullSecrets$|replicas$|strategy\.|podDisruptionBudget\.|topologySpreadConstraints$|nodeSelector$|affinity$|tolerations$|resources\.|terminationGracePeriodSeconds$|shutdown\.)/,
    "Platform operator",
    ["helm", "portal", "database", "kubernetes"],
    "Helm templates and Kubernetes Deployment, Pod, disruption and scheduling behavior. Resource values here size the portal itself.",
    "Deployment-managed; separate from sandbox profile resources and scheduling.",
    "Pod changes roll out the portal. Recreate migrates the schema after old writers stop; RollingUpdate only checks an unchanged PostgreSQL schema.",
  ),
  group(
    "platform-extra",
    "deployment",
    "Additional Kubernetes objects & portal sidecars",
    /^(extraObjects|extraContainers|extraVolumes|extraServicePorts)$/,
    "Platform operator",
    ["helm", "kubernetes"],
    "Kubernetes APIs and installed controllers validate supplied objects. Sidecars share the portal Pod and require operator-managed security and network controls. No Helm tpl evaluation is performed on their contents.",
    "Deployment-managed.",
    "Objects are installed with this Helm release; Pod and Service additions roll out the portal and are not copied into sandbox namespaces.",
  ),
  group(
    "state-admin",
    "state",
    "Live administrator controls",
    /^(admin\.|sandboxControl\.|namespaceControl\.)/,
    "Platform administrator",
    ["portal", "database", "kubernetes"],
    "Portal role checks control edits; access/creation restrictions apply through the portal. Saved NetworkPolicy is applied through Kubernetes and its CNI.",
    "Supported administrative actions are editable through the portal/API. Attribution and timestamps are generated.",
    "Saved in the metadata database with revision checks. These are not profile catalog keys.",
  ),
  group(
    "state-record",
    "state",
    "Sandbox identity & saved intent",
    /^record\./,
    "Portal / authorized sandbox owner",
    ["portal", "database", "kubernetes", "openshell"],
    "Database uniqueness and revision checks, operation leases and native UID checks protect association and concurrent changes.",
    "Only supported API actions change intent, title, lifecycle, grants or policies. IDs, bindings, revisions and timestamps are not arbitrary profile fields.",
    "Intent is durable. Native readiness is observed separately; deletion and terminal closure do not mean the same thing.",
  ),
  group(
    "state-lease",
    "state",
    "Operation coordination",
    /^lease\./,
    "Portal process",
    ["portal", "database"],
    "Shared metadata leases coordinate work across replicas. They do not make remote calls exactly-once.",
    "Not user-editable.",
    "Renewed during active work; expired leases allow another portal process to recover ownership.",
  ),
  group(
    "state-native",
    "state",
    "Native identity & observed status",
    /^native\./,
    "Kubernetes / OpenShell",
    ["portal", "kubernetes", "openshell"],
    "The portal compares saved bindings and native observations. Kubernetes resourceVersion and OpenShell revisions provide native concurrency checks.",
    "Read-only observations, not profile inputs.",
    "Observed on refresh/status checks. Recreating a native resource can change its UID even if the name is reused.",
  ),
  group(
    "state-correlation",
    "state",
    "Request & trace correlation",
    /^correlation\./,
    "Portal instrumentation",
    ["portal"],
    "Request/trace correlation aids investigation; it is not authorization or a guarantee that a remote mutation happened exactly once.",
    "Generated by request and tracing handling.",
    "Request correlation and operation-journal request IDs have different lifetimes. Trace IDs exist only when tracing context is available.",
  ),
  group(
    "environment",
    "environment",
    "Python process settings",
    /^(PORTAL|OTEL|WEB|UVICORN)_/,
    "Platform operator / Helm-generated wiring",
    ["helm", "portal"],
    "Settings.from_env and owning authentication, profile, storage and integration validators check configuration. These are Python defaults, not necessarily chart defaults.",
    "Advanced process configuration. Prefer the chart's supported values and Secret references when deploying with Helm.",
    "Read at process startup. Some identity/path settings are derived by Helm and should not be independently changed.",
  ),
];

const notes = {
  id: "Stable catalog identifier, distinct from a sandbox ID or Kubernetes UID. IDs must be unique in the catalog.",
  title: "Friendly profile title shown in the selection dropdown.",
  description: "Optional explanatory text shown with the profile definition.",
  "agentSandbox.spec":
    "Native Agent Sandbox specification. Currently one workload container named host and one claim named home are required. Init containers are supported within the allocation; additional workload/sidecar containers are not. The portal injects protected Pod fields, resources and claim sizing.",
  "openShell.spec":
    "Native OpenShell SandboxSpec, not a Kubernetes PodSpec. Requires template.image, command and policy.version=1. Resources map to template.resources; runtime uses template.runtime_class_name. Caller driver_config is rejected. Filesystem/process controls are creation-time; supported network edits are retained as overrides.",
  envoyEgress:
    "Reserved field only: non-null values are rejected. Envoy integration is deferred, not implemented.",
  "acp.command":
    "Profile-owned executable and argument vector launched by the supervised ACP runner inside the sandbox. Supply an executable present in the coding image; clients cannot override it.",
  "acp.workspace_root":
    "Absolute ACP workspace path inside the writable persistent home mount. The worker profile must use the same path; it is retained with the applied profile.",
  "acp.existingSecret":
    "Existing Kubernetes Secret holding the private ACP service credential. Required when connections are configured; keep its value out of chart values and sandbox workloads.",
  "acp.secretKey":
    "Key in acp.existingSecret containing the ACP service token; defaults to token.",
  "acp.connections":
    "Operator-admitted connection aliases and their owner, verified CAIPE subject, sandbox name, exact native UID and approved configuration revision. Empty disables registered connections; do not put credentials in this object.",
  "terminal.command":
    "Argument vector for a new shell, defaulting to /bin/sh -i. It opens an executable in the existing workload; it does not keep the workload alive.",
  helpers:
    "Optional list of up to 16 helper definitions, with unique IDs. Buttons execute scripts inside the sandbox. Optional status probes report tool sign-in state; scripts and probes do not automatically install tools.",
  "helpers[].id":
    "Unique helper identifier within this profile; scripts reference this ID through the portal.",
  "helpers[].title":
    "Button label. Naming a tool does not install or authenticate it.",
  "helpers[].icon":
    "Supported icon enum from the profile model. The available values are shown below.",
  "helpers[].script":
    "Shell script executed inside the sandbox with its workload identity. Keep reusable tools in the image and credentials out of script text.",
  "helpers[].status.command":
    "Argument vector for a read-only sign-in probe executed inside the workload. The tool must exist in the image. Unavailable tools and failed/ambiguous probes are not treated as signed in.",
  "helpers[].status.json_field":
    "Optional dotted path to a boolean in probe stdout JSON. A boolean determines signed-in/out status before exit-code rules; invalid or missing JSON produces unknown.",
  "helpers[].status.signed_in_exit_codes":
    "Exit codes indicating signed-in status when json_field is not configured. Default: [0]. Must not overlap signed-out exit codes.",
  "helpers[].status.signed_out_exit_codes":
    "Exit codes indicating signed-out status; must not overlap signed-in exit codes.",
  "helpers[].status.signed_out_contains":
    "Case-insensitive stdout/stderr text matches indicating signed-out status after earlier probe checks. Unrecognized results remain unknown.",
  profiles:
    "Complete offered catalog. No generated fallback catalog. Its profile-level fields are explored in the Profile fields tab.",
  defaultProfile:
    "ID of a seeded profile to preselect. Startup rejects an ID missing from the catalog.",
  "settings.headerLinks":
    "Up to three title/HTTP(S) URL pairs in the top-right bar. Docs is enabled by default. Links open in a new tab, and [] hides the links.",
  "settings.runtimeClass":
    "Default installed RuntimeClass when a profile omits its native runtime field. An empty string means the cluster default runtime, not Kata.",
  "settings.allowedRuntimeClasses":
    'Approved runtime names, including the default. null means only the named default; [""] explicitly approves ordinary cluster-default Pods. Empty default with null is rejected.',
  "settings.namespacePrefix":
    "Prefix for generated namespaces, not a full namespace name. OpenShell currently limits it to six characters for native workspace naming.",
  "settings.runnerServiceAccount":
    "Workload ServiceAccount used by the direct Agent Sandbox renderer. Automatic API-token mounting is disabled.",
  "settings.runnerImagePullSecrets":
    "Name references for sandbox image-pull Secrets, distinct from imagePullSecrets on the portal Deployment. Bootstrap supplies the supported registry Secrets.",
  "settings.storageClass":
    "StorageClass for direct Agent Sandbox home claims; empty uses the cluster default. Profiles cannot override it. OpenShell storage is gateway-owned.",
  "settings.maxSandboxesPerUser":
    "Maximum non-deleted allocations per creator across namespaces/providers, including suspended and unresolved creations. 0 disables this count limit. Chart default is 0, not the pilot's environment-specific 5.",
  "settings.terminalIoWorkers":
    "Blocking terminal-I/O workers per portal process, separate from management/database workers. This is not a terminal session count limit.",
  "settings.reconcileIntervalSeconds":
    "Periodic reconciliation of supported native Kubernetes resources against saved intent. 0 disables automatic reconciliation; unsupported integrations are not automatically repaired.",
  "settings.operationLeaseSeconds":
    "Renewable ownership interval for journaled native operations and maintenance work, coordinated through the metadata database.",
  "settings.origin":
    "Public scheme and host without a path, for example https://sandbox.example.com. Must agree with ingress and the identity provider.",
  "settings.basePath":
    "Public portal path, without a trailing slash, or empty for /. Serving at / requires independent OIDC authentication.",
  "namespace.strategy":
    "Default placement: perSandbox creates a namespace per sandbox; perUser reuses the creator's namespace. The namespace owner is its first sandbox creator; later VMs retain their own creators.",
  "namespace.allowedStrategies":
    "Choices permitted during creation. null limits choices to namespace.strategy. Reusing a shared namespace shares namespace-wide access, not only a single VM.",
  "namespace.labels":
    "Operator labels applied to new managed namespaces. Portal, Kubernetes, Pod Security and integration identity prefixes are protected.",
  "namespace.annotations":
    "Operator annotations for new namespaces; reserved ownership/identity keys cannot be supplied.",
  "namespacePolicy.labels":
    "Older namespace-label input; prefer namespace.labels. Both are deployment values, not profile fields.",
  "namespacePolicy.deleteWhenEmpty":
    "Remove only an empty managed namespace after sandboxes, Pods, Secrets and PVCs are safely cleared. Retained volumes or unrelated objects prevent deletion.",
  "namespacePolicy.podSecurityVersion":
    "Version label for Kubernetes Pod Security Admission. latest follows cluster behavior; pin a reviewed baseline if required.",
  "namespacePolicy.baselineNetworkPolicy":
    "Optional portal-created isolation policy, off by default. This is separate from OpenShell-native enforcement and operator-supplied policies.",
  "namespacePolicy.publicHttpsEgress":
    "Allows supported public HTTPS destinations in the optional baseline. Has no effect when baselineNetworkPolicy is false; it is not an OpenShell allowlist.",
  "namespacePolicy.quota":
    "Native namespace ResourceQuota hard limits. Distinct from the per-creator sandbox count and per-sandbox resourcePolicy.",
  "namespacePolicy.extraEgress":
    "Additional native egress rules for the optional portal baseline. Has no effect when that baseline is disabled.",
  "database.url":
    "SQLite URL for bundled metadata storage. Use database.existingSecret for PostgreSQL and clear this value; do not place credentials in public values.",
  "database.existingSecret":
    "Existing Kubernetes Secret containing the externally managed PostgreSQL connection URL. No PostgreSQL server/operator is bundled.",
  "database.secretKey":
    "Key inside database.existingSecret containing the URL.",
  "database.caSecret":
    "Optional database CA Secret with ca.crt; URL can reference /etc/portal-database/ca.crt for TLS verification.",
  "database.persistence.size":
    "SQLite metadata storage PVC size. This is not a sandbox's disk size.",
  "database.persistence.storageClass":
    "StorageClass for the SQLite metadata PVC, separate from settings.storageClass for sandbox home volumes.",
  "auth.mode":
    "Portal sign-in provider: independent OIDC, CAIPE hosted-app JWT verification, or optional Omnigent session validation. This does not select a sandbox backend.",
  "auth.adminEmails":
    "Operator-managed administrator seed list. SSO eligibility restrictions still apply; administrator status is not automatically mapped from groups.",
  "auth.omnigentUrl":
    "Omnigent URL used only when auth.mode is omnigent. It is unrelated to an agent tool's own sign-in.",
  "auth.existingSecret":
    "Existing Secret holding Sandbox session-signing keys and, in OIDC mode, the client secret. Store secret contents outside chart values.",
  "auth.clientSecretKey":
    "Key holding the OIDC client secret in auth.existingSecret.",
  "auth.sessionSecretKey":
    "Key holding the Sandbox signing secret: OIDC cookies or CAIPE terminal credentials. Replicas must share it; keep it separate from the CAIPE key.",
  "auth.caipe.issuer": "Expected CAIPE hosted-app JWT issuer.",
  "auth.caipe.app_id":
    "Registered CAIPE app ID; also binds JWT audience to agentic-app:<app_id>.",
  "auth.caipe.default_role":
    "Sandbox's user or viewer role for CAIPE-authenticated users; adminEmails remains operator-owned.",
  "auth.caipe.session_seconds":
    "Maximum established terminal authorization window in CAIPE mode; HTTP requests and reconnects still require current CAIPE authentication.",
  "auth.caipe.existingSecret":
    "Existing Secret containing the CAIPE hosted-app HMAC key. No signing key is stored in chart values.",
  "auth.caipe.verificationKeyKey":
    "Key inside auth.caipe.existingSecret matching CAIPE's AGENTIC_APP_TOKEN_SECRET.",
  "settings.terminalUrl":
    "Optional direct WSS base URL including the portal prefix; bypasses HTTP-only host proxies for terminal connections. Empty uses the current origin and prefix.",
  "auth.oidc.issuer":
    "OIDC discovery issuer URL, validated by the authentication provider.",
  "auth.oidc.client_id":
    "Registered OIDC application/client ID; configure a callback matching the public portal URL.",
  "auth.oidc.scopes":
    "Scopes requested at login. Include the claims required for the configured email/group eligibility rules.",
  "auth.oidc.email_claim":
    "Token/userinfo claim used for email-based portal identity and ownership.",
  "auth.oidc.groups_claim":
    "Claim read for group allowlisting and configured non-admin role mappings.",
  "auth.oidc.require_verified_email":
    "Require the provider's email verification indication when configured.",
  "auth.oidc.use_userinfo":
    "Fetch identity claims from the provider's userinfo endpoint when enabled.",
  "auth.oidc.allowed_email_domains":
    "Optional email-domain eligibility allowlist, not an outbound network policy.",
  "auth.oidc.allowed_groups":
    "Optional group eligibility allowlist evaluated during authentication.",
  "auth.oidc.role_groups":
    "Configured mappings for supported portal roles. Platform administrator seeding remains separately operator-managed.",
  "auth.oidc.default_role":
    "Fallback supported portal role for eligible users; choose explicitly in deployment values.",
  "auth.oidc.session_seconds":
    "Signed portal-session lifetime in seconds. Chart default is 3600; eight-hour dev sessions are an environment override, not the product default.",
  "settings.openShell.endpoint":
    "Gateway API address. It belongs to the deployment, not a per-profile CAIPE or ACP connection.",
  "settings.openShell.gatewayId":
    "Expected OpenShell gateway identity used in native bindings and verification.",
  "settings.openShell.gatewayServiceAccount":
    "Gateway Kubernetes ServiceAccount granted supported access to portal-managed OpenShell namespaces.",
  "settings.openShell.sandboxServiceAccount":
    "OpenShell workload ServiceAccount identity expected by access and admission wiring.",
  "settings.openShell.clientSecret":
    "Name of the existing gateway mTLS Secret: ca.crt, tls.crt and tls.key are mounted read-only at /etc/portal-openshell.",
  "settings.openShell.storageGiB":
    "Fixed disk size in gateway mode, matching gateway-native configuration. In persistentVolumeClaim mode this is only a fallback for profiles without ui.resources; it never resizes existing disks.",
  "settings.openShell.storageMode":
    "gateway uses the native fixed-size workspace. persistentVolumeClaim lets the portal provision a profile-bounded PVC and attach it through OpenShell; enable native allowDriverConfig and resource admission. Existing disks retain their attachment.",
  "settings.openShell.namespaceLabel":
    "Label used to recognize portal-managed OpenShell workspace namespaces; match gateway operator-mode settings.",
  "settings.openShell.gatewayPodSelector":
    "Native label-selector map locating the gateway Pods for supported namespace connectivity.",
  "image.repository":
    "Portal image repository. Distinct from the workload image in each profile.",
  "image.digest":
    "Required immutable portal image digest. Release tooling pins the tested image into the published chart.",
  imagePullSecrets:
    "Image-pull Secret references on portal Pods. Sandbox workload pulls use settings.runnerImagePullSecrets.",
  replicas:
    "Portal Pod count. SQLite requires exactly one; external PostgreSQL supports multiple Pods with one application worker each.",
  "strategy.type":
    "Recreate stops old portal writers before migration; RollingUpdate is PostgreSQL-only with an unchanged schema and an init-container schema check.",
  "strategy.rollingUpdate.maxUnavailable":
    "Allowed unavailable portal Pods during a schema-compatible rolling update. No effect for Recreate.",
  "strategy.rollingUpdate.maxSurge":
    "Allowed extra portal Pods during a schema-compatible rolling update. No effect for Recreate.",
  "podDisruptionBudget.enabled":
    "Create a native disruption budget only when multiple portal replicas are configured. It does not make schema migrations safe for rolling updates.",
  "podDisruptionBudget.minAvailable":
    "Minimum available portal Pods during voluntary disruptions; use either this or maxUnavailable as required by Kubernetes.",
  "podDisruptionBudget.maxUnavailable":
    "Alternative maximum unavailable portal Pods for voluntary disruptions; not supplied by default.",
  topologySpreadConstraints:
    "Native portal-Pod spread constraints. Match the actual Helm-release app label; these do not place sandbox Pods.",
  nodeSelector:
    "Native node selector for portal Pods. Sandbox placement belongs in the chosen backend's native profile fields.",
  affinity: "Native affinity for portal Pods, not workload scheduling.",
  tolerations: "Native tolerations for portal Pods, not workload scheduling.",
  terminationGracePeriodSeconds:
    "Pod termination grace must exceed propagationSeconds + drainSeconds + serverGraceSeconds.",
  "shutdown.propagationSeconds":
    "Pause after marking the portal as draining so routing/readiness changes can propagate.",
  "shutdown.drainSeconds":
    "Budget for active portal terminal connections to drain; default 180 seconds. Workload VMs and persistent volumes are separate.",
  "shutdown.serverGraceSeconds":
    "ASGI server graceful-shutdown budget after draining.",
  "ingress.enabled":
    "Create an Ingress resource using an existing operator-managed ingress controller.",
  "ingress.className": "Installed ingress controller's class name.",
  "ingress.host":
    "Public hostname; align with settings.origin, DNS and OIDC callbacks.",
  "ingress.tlsSecretName":
    "Existing TLS Secret for the host. Certificate issuance/controller installation is operator-managed.",
  "ingress.annotations":
    "Native Ingress annotations for the selected controller.",
  "observability.tracing.endpoint":
    "Optional OTLP/HTTP base endpoint for portal traces. Empty disables configured trace export; JSON stdout logging still exists.",
  "observability.tracing.sampleRatio":
    "Parent-based trace-ID ratio used for new root portal traces when export is configured. Does not control log retention.",
  "agentSandbox.enabled":
    "Optionally install the repository's Agent Sandbox chart. Both current backends need its controller/CRDs, but they may already be installed externally.",
  "omnigent.enabled":
    "Optionally install the Omnigent service chart. It is not required for the portal's independent OIDC mode or generic sandbox management.",
  "kata.enabled":
    "Optionally install Kata deployment tooling. Compatible nodes and an approved, selected RuntimeClass are still required.",
  "openShell.enabled":
    "Optionally install the native OpenShell gateway chart. Connection settings still belong under settings.openShell.",
  "openShell.workspaceResources.enabled":
    "Native chart workspace-resource toggle. Portal-managed namespace setup uses gateway Kubernetes operator mode.",
  "openShell.server.logLevel":
    "Native gateway server log level; the wrapper defaults to info.",
  "openShell.server.telemetryEnabled":
    "Native upstream gateway telemetry toggle, separate from the portal's OTLP tracing endpoint. See the pinned upstream chart for its full semantics.",
  "openShell.server.extraEnv":
    "Native gateway environment list. Defaults shown configure a parent-based trace sampler; they do not themselves select an OTLP endpoint.",
  "openShell.server.drivers.kubernetes.workspaceMode":
    "Native gateway workspace mode. The portal reference deployment uses operator-managed namespaces.",
  "openShell.server.drivers.kubernetes.operatorNamespaceLabel":
    "Native label selector for gateway operator-mode workspaces; align with settings.openShell.namespaceLabel.",
  extraContainers:
    "Optional native container objects added to the portal Pod, such as a TLS proxy. The operator supplies and secures their images and settings; names must not collide with chart-managed containers.",
  extraVolumes:
    "Optional native Kubernetes volumes added to the portal Pod for operator-provided sidecars. Do not duplicate chart-managed volume names.",
  extraServicePorts:
    "Optional native Kubernetes Service ports for portal sidecars. Restrict access and configure authentication separately; a port does not itself secure traffic.",
  extraObjects:
    "Complete native objects such as an ExternalSecret. Their controllers must already exist; this does not install Vault, cert-manager, a storage driver or an ingress controller.",
};

const envValues = {
  OTEL_SERVICE_NAME:
    "Standard service identity for portal logs and traces; chart sets caipe-sandbox-portal.",
  OTEL_SDK_DISABLED:
    "Standard SDK switch. The portal skips tracing setup when its value is true; JSON logging remains separate.",
  OTEL_EXPORTER_OTLP_ENDPOINT:
    "observability.tracing.endpoint supplies this standard OTLP base endpoint.",
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT:
    "Optional standard traces-specific endpoint recognized by portal tracing setup and the OTLP SDK; distinct from a base endpoint.",
  OTEL_RESOURCE_ATTRIBUTES:
    "Chart-generated service/image/chart/Kubernetes identity attributes for correlation, including the Pod UID.",
  OTEL_EXPORTER_OTLP_PROTOCOL:
    "Chart uses http/protobuf when portal trace export is configured.",
  OTEL_EXPORTER_OTLP_TIMEOUT:
    "Chart sets the OTLP exporter timeout to 3 seconds when export is configured.",
  OTEL_TRACES_SAMPLER:
    "Chart uses parentbased_traceidratio for portal trace export.",
  OTEL_TRACES_SAMPLER_ARG:
    "observability.tracing.sampleRatio supplies the root trace sampling ratio.",
  WEB_CONCURRENCY:
    "Chart fixes one ASGI application worker per Pod. Scale PostgreSQL-backed replicas rather than adding workers against SQLite.",
  UVICORN_TIMEOUT_GRACEFUL_SHUTDOWN:
    "shutdown.serverGraceSeconds supplies the server's native shutdown budget.",
  ACP_CONNECTIONS:
    "acp.connections encoded as JSON; contains nonsecret operator-admitted connection metadata.",
  ACP_SERVICE_TOKEN:
    "Secret reference: acp.existingSecret / acp.secretKey. The private data plane requires a distinct service token of at least 32 characters when connections are configured.",
  DATABASE_URL: "database.url / database.existingSecret",
  DATABASE_BACKEND: "Derived from database mode by Helm",
  OPERATION_LEASE_SECONDS: "settings.operationLeaseSeconds",
  TERMINAL_IO_WORKERS: "settings.terminalIoWorkers",
  RECONCILE_INTERVAL_SECONDS: "settings.reconcileIntervalSeconds",
  MAX_SANDBOXES_PER_USER: "settings.maxSandboxesPerUser",
  HEADER_LINKS: "settings.headerLinks",
  DRAIN_FILE: "Helm fixes the writable drain marker at /var/run/portal/drain",
  DRAIN_SECONDS: "shutdown.drainSeconds",
  DRAIN_PROPAGATION_SECONDS: "shutdown.propagationSeconds",
  ORIGIN: "settings.origin",
  AUTH_OMNIGENT_URL: "auth.omnigentUrl",
  NAMESPACE_PREFIX: "settings.namespacePrefix",
  NAMESPACE: "namespace",
  PROFILES:
    "Alternative JSON catalog for non-Helm processes; mutually exclusive with PORTAL_PROFILES_FILE",
  PROFILES_FILE: "Helm mounts /etc/portal-profiles/profiles.json",
  DEFAULT_PROFILE: "defaultProfile",
  OPENSHELL_ENDPOINT: "settings.openShell.endpoint",
  OPENSHELL_GATEWAY_ID: "settings.openShell.gatewayId",
  OPENSHELL_GATEWAY_SERVICE_ACCOUNT: "settings.openShell.gatewayServiceAccount",
  OPENSHELL_RUNNER_SERVICE_ACCOUNT: "settings.openShell.sandboxServiceAccount",
  OPENSHELL_STORAGE_GIB: "settings.openShell.storageGiB",
  OPENSHELL_STORAGE_MODE: "settings.openShell.storageMode",
  OPENSHELL_GATEWAY_POD_SELECTOR: "settings.openShell.gatewayPodSelector",
  OPENSHELL_NAMESPACE_LABEL: "settings.openShell.namespaceLabel",
  OPENSHELL_SUPERVISOR_RESOURCES: "settings.openShell.supervisorResources",
  PORTAL_NAMESPACE: "Derived from the Helm release namespace",
  PORTAL_SERVICE_ACCOUNT: "Derived from the Helm release name",
  NAMESPACE_ACCESS_ROLE:
    "Derived from the Helm release namespace/name; part of provider identity",
  NAMESPACE_POLICY: "namespacePolicy",
  RUNTIME_CLASS: "settings.runtimeClass",
  ALLOWED_RUNTIME_CLASSES: "settings.allowedRuntimeClasses",
  RUNNER_SERVICE_ACCOUNT: "settings.runnerServiceAccount",
  RUNNER_IMAGE_PULL_SECRETS: "settings.runnerImagePullSecrets",
  SANDBOX_SECURITY_CONTEXT: "settings.sandboxSecurityContext",
  STORAGE_CLASS: "settings.storageClass",
  RESOURCE_POLICY: "resourcePolicy",
  AUTH_MODE: "auth.mode",
  ADMIN_EMAILS: "auth.adminEmails",
  OIDC_POLICY: "auth.oidc",
  CAIPE_POLICY: "auth.caipe (issuer, app_id, default_role and session_seconds)",
  CAIPE_VERIFICATION_KEY:
    "Secret reference: auth.caipe.existingSecret / auth.caipe.verificationKeyKey",
  TERMINAL_URL: "settings.terminalUrl",
  OIDC_CLIENT_SECRET:
    "Secret reference: auth.existingSecret / auth.clientSecretKey",
  SESSION_SECRET:
    "Secret reference: auth.existingSecret / auth.sessionSecretKey",
  BASE_PATH: "settings.basePath",
  POD_UID:
    "Kubernetes downward API injects this Pod's UID for log/trace resource identity. It is not a sandbox or Linux UID.",
};

const stateNotes = {
  "record.id":
    "Portal UUID for a logical sandbox. Distinct from its friendly name, Kubernetes UID and in-guest Linux UID.",
  "record.name":
    "Generated human-friendly sandbox identifier, at most 16 characters. This is not its editable display title.",
  "record.owner":
    "Creator's email identity. Namespace sharing does not transfer lifecycle ownership.",
  "record.title":
    "Editable display name chosen by the creator, separate from the native resource name.",
  "record.provider":
    "Selected native backend, currently agentSandbox or openShell.",
  "record.provider_instance":
    "Deployment/provider instance identity used to prevent cross-instance associations.",
  "record.manifest":
    "Saved intended native manifest including accepted user choices and policy edits. Reconciliation compares supported owned fields against native state.",
  "record.requested_mode":
    "Saved requested running/suspended mode, not current readiness.",
  "record.profile_snapshot":
    "Applied profile definition, revision and resolved creation choices. It survives later catalog changes.",
  "record.scope": "Native namespace/workspace membership.",
  "record.scope_owner":
    "Namespace owner's email: the first sandbox creator. Later sandbox creators retain their own VM ownership.",
  "record.resource_usage":
    "Reserved/accounted resource quantities, not live CPU or memory measurements.",
  "record.binding.key":
    "Native resource identity bound after creation, checked before actions.",
  "record.binding.reference":
    "Serializable native name, namespace, UID and, for OpenShell, gateway/sandbox identifiers.",
  "record.revision":
    "Portal metadata revision used for optimistic concurrency. Distinct from Kubernetes resourceVersion and OpenShell policy revision.",
  "record.created_at": "Time the portal metadata allocation was first created.",
  "record.updated_at":
    "Time the saved record was last updated; it is not a workload heartbeat.",
  "record.grants":
    "Namespace-scoped view/shell grants presented with the record. Sharing applies to the namespace; it does not grant arbitrary lifecycle ownership.",
  "record.control":
    "Saved per-sandbox administrator restrictions and notice. These do not rewrite the profile.",
  "record.operation.kind":
    "Journaled create/configure/mode/delete/integration action awaiting confirmation or recovery.",
  "record.operation.request_id":
    "Portal operation UUID used for journal correlation and retry/recovery. Separate from an HTTP request ID and optional upstream replay tracking.",
  "record.operation.actor": "Email of the principal who initiated the action.",
  "record.operation.state":
    "Pending or needs-attention operation state; ambiguous results must be checked before repeating a mutation.",
  "record.operation.parameters":
    "Saved operation inputs and sanitized recovery error details; not a complete execution/audit transcript.",
  "record.deleted_at":
    "Portal retirement timestamp. Native object deletion and backing-volume reclaim follow their own completion/policy rules.",
  "lease.name": "Semantic coordination key for operation or maintenance work.",
  "lease.token":
    "UUID identifying the current lease holder, not a user authentication credential.",
  "lease.expires_at":
    "Lease deadline, renewed while the holder continues work.",
  "native.metadata.uid":
    "Kubernetes-assigned immutable object UID. Name reuse does not preserve this identity.",
  "native.metadata.resourceVersion":
    "Kubernetes concurrency token, checked for conditional writes. Do not treat it as a timestamp or profile version.",
  "native.namespace.uid":
    "Kubernetes namespace UID checked alongside managed ownership so a replacement namespace cannot be silently adopted.",
  "native.openshell.gateway_id":
    "Gateway identity observed on native OpenShell bindings.",
  "native.openshell.sandbox_id":
    "OpenShell-native sandbox identifier, distinct from the portal record UUID.",
  "native.openshell.policy_status.revision.version":
    "Native policy/configuration version read for conditional policy writes and drift checks.",
  "native.openshell.policy_status.active_version":
    "Policy version loaded by the workload. A saved policy can briefly be newer while activation completes.",
  "native.status":
    "Readiness, native errors, process/policy status and other runtime observations. The portal does not persist every transient status as desired state.",
  "correlation.request_id":
    "HTTP request correlation in portal logs/response handling. Use sandbox and operation IDs to connect multiple requests.",
  "correlation.trace_id":
    "Distributed trace correlation when available. Trace sampling and collector configuration affect whether a trace is exported.",
};

export function describe(entry, scope) {
  const path = entry.path;
  if (scope === "environment")
    return envValues[path.startsWith("PORTAL_") ? path.slice(7) : path];
  if (scope === "state") {
    if (stateNotes[path]) return stateNotes[path];
    if (path.startsWith("record.profile_snapshot.")) {
      const snapshotNotes = {
        schemaVersion:
          "Version of the portal's allocation snapshot shape, distinct from the Alembic database schema revision.",
        id: "Applied catalog profile ID, not the portal's sandbox UUID.",
        revision:
          "Content hash of the applied profile definition, not Kubernetes resourceVersion. Catalog edits produce a different revision.",
        definition:
          "Retained complete profile definition, including helpers and starting native spec.",
        namespace: "Namespace chosen when this allocation was resolved.",
        namespaceStrategy:
          "perSandbox/perUser placement selected for this allocation.",
        namespaceOwner: "Email of the namespace owner at creation.",
        namespaceConfiguration:
          "Retained namespace placement, labels and annotations selected at creation.",
        resources:
          "Resolved creation allocation in CPU millicores, memory MiB and persistent storage GiB.",
        spec: "Resolved native spec at creation. Later accepted changes live in record.manifest; this snapshot is not live readiness.",
        integration_configuration:
          "Supported integration-specific creation overrides, such as OpenShell filesystem/process configuration, when supplied.",
      };
      return snapshotNotes[path.split(".").at(-1)];
    }
    if (path.endsWith("creation_disabled"))
      return "Administrator lock preventing new sandboxes in this scope; existing sandboxes are not automatically stopped.";
    if (
      path.endsWith("sandboxes_disabled") ||
      path === "sandboxControl.disabled"
    )
      return "Administrator access restriction on the affected scope, enforced by portal access checks; this is not a native VM shutdown command.";
    if (path.endsWith("network_policy"))
      return "Saved administrator-managed namespace NetworkPolicy definition, applied with native Kubernetes concurrency and enforcement. Not an OpenShell policy.";
    if (path.endsWith("reason"))
      return "Administrator-provided explanation displayed with the restriction.";
    if (path.endsWith("updated_by") || path.endsWith("author"))
      return "Recorded administrator identity for attribution.";
    if (path.endsWith("updated_at"))
      return "Generated timestamp for the administrative edit.";
    if (path.endsWith(".title"))
      return "Administrative announcement/notice title displayed in the portal.";
    if (path.endsWith(".body"))
      return "Administrative announcement/notice text displayed in the portal.";
    return undefined;
  }
  if (notes[path]) return notes[path];
  if (scope === "profile" && path.startsWith("ui.resources.")) {
    const [, , bound, kind, field] = path.split(".");
    return `${bound === "default" ? "Starting" : bound === "minimum" ? "Smallest permitted" : "Largest permitted"} ${kind === "storage" ? "persistent disk size" : `${kind === "requests" ? "reserved" : "limit for"} ${field}`} in Kubernetes quantities. ${kind === "storage" ? "OpenShell allows disk choices with persistentVolumeClaim storage mode; gateway mode requires the fixed storageGiB." : "Requests must not exceed limits; all sizes must fit the platform envelope."}`;
  }
  if (path.startsWith("resourcePolicy.defaults."))
    return `Platform fallback ${path.includes("cpu_") ? "CPU allocation in whole millicores" : path.includes("memory_") ? "memory allocation in whole MiB" : "persistent storage allocation in whole GiB"} when the profile does not supply this resource default.`;
  if (path.startsWith("resourcePolicy."))
    return `Platform-wide ${path.endsWith(".min") ? "minimum" : "maximum"} ${path.includes("cpu_") ? "CPU in millicores" : path.includes("memory_") ? "memory in MiB" : "persistent storage in GiB"}. Profile bounds must fit this envelope.`;
  if (path.startsWith("settings.sandboxSecurityContext."))
    return "Positive non-root Linux UID/GID for direct Agent Sandbox workloads and volume access. The renderer adds runAsNonRoot and RuntimeDefault seccomp and rejects conflicting profile identities.";
  if (path.startsWith("settings.openShell.supervisorResources."))
    return "Native CPU/memory budget for OpenShell's trusted supervisor, accounted separately from agent workload resources. Supply both requests and limits; this does not resize the agent's disk.";
  if (path.startsWith("resources."))
    return "Native CPU/memory request or limit for the portal Pod and schema init container, not a sandbox allocation.";
  return undefined;
}

export function catalog(scope) {
  return sources[scope].map((entry) => {
    let section = groups.find(
      (item) => item.scope === scope && item.match.test(entry.path),
    );
    if (scope === "profile" && section?.id === "profile-identity") {
      const readers =
        entry.path === "agentSandbox.spec"
          ? ["portal", "database", "kubernetes"]
          : entry.path === "openShell.spec"
            ? ["portal", "database", "openshell"]
            : ["portal", "database"];
      section = { ...section, readers };
    }
    if (scope === "profile" && section?.id === "profile-terminal") {
      const executes =
        entry.path === "terminal.command" ||
        entry.path === "helpers[].script" ||
        entry.path === "helpers[].status.command";
      section = {
        ...section,
        readers: ["portal", "database", ...(executes ? ["guest"] : [])],
      };
    }
    return { ...entry, scope, section, summary: describe(entry, scope) };
  });
}

export function searchEntries(scope, query = "") {
  const words = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const matching = catalog(scope).filter((entry) =>
    words.every((word) =>
      `${entry.path} ${entry.summary} ${entry.section?.label}`
        .toLowerCase()
        .includes(word),
    ),
  );
  const score = (entry) =>
    words.filter((word) => entry.path.toLowerCase().includes(word)).length;
  return matching.sort((a, b) => score(b) - score(a));
}
