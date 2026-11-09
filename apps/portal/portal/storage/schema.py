"""Current relational schema; native specifications remain JSON documents."""

import sqlalchemy as sa

metadata = sa.MetaData()
leases = sa.Table(
    "portal_leases",
    metadata,
    sa.Column("name", sa.String(160), primary_key=True),
    sa.Column("token", sa.String(36), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
)
controls = sa.Table(
    "portal_controls",
    metadata,
    sa.Column("id", sa.String(16), primary_key=True),
    sa.Column("policy", sa.JSON, nullable=False),
    sa.Column("revision", sa.Integer, nullable=False),
    sa.CheckConstraint("id = 'global'", name="ck_controls_singleton"),
    sa.CheckConstraint("revision >= 1", name="ck_controls_revision"),
)
sandboxes = sa.Table(
    "sandboxes",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("owner", sa.String(254), nullable=False),
    sa.Column("name", sa.String(16), nullable=False),
    sa.Column("title", sa.String(80), nullable=False),
    sa.Column("provider", sa.String(40), nullable=False),
    sa.Column("provider_instance", sa.String(254), nullable=False),
    sa.Column("manifest", sa.JSON, nullable=False),
    sa.Column("profile_snapshot", sa.JSON(none_as_null=True)),
    sa.Column("scope", sa.String(512), nullable=False, server_default=""),
    sa.Column("scope_owner", sa.String(254), nullable=False, server_default=""),
    sa.Column("resource_usage", sa.JSON, nullable=False, server_default="{}"),
    sa.Column("control", sa.JSON, nullable=False, server_default="{}"),
    sa.Column("operation", sa.JSON(none_as_null=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
    sa.Column("requested_mode", sa.String(16), nullable=False),
    sa.Column("native_key", sa.String(512)),
    sa.Column("native_reference", sa.JSON(none_as_null=True)),
    sa.Column("revision", sa.Integer, nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("owner", "name", name="uq_sandbox_owner_name"),
    sa.UniqueConstraint(
        "provider", "provider_instance", "native_key", name="uq_sandbox_native"
    ),
    sa.CheckConstraint("requested_mode IN ('running', 'suspended')", name="ck_mode"),
)
sa.Index("ix_sandbox_scope", sandboxes.c.provider, sandboxes.c.scope)
grants = sa.Table(
    "scope_grants",
    metadata,
    sa.Column("owner", sa.String(254), primary_key=True),
    sa.Column("provider", sa.String(40), primary_key=True),
    sa.Column("provider_instance", sa.String(254), primary_key=True),
    sa.Column("scope", sa.String(512), primary_key=True),
    sa.Column("principal", sa.String(254), primary_key=True),
    sa.Column("role", sa.String(8), nullable=False),
    sa.CheckConstraint("role IN ('view', 'shell')", name="ck_scope_grant_role"),
)
sa.Index("ix_scope_grant_principal", grants.c.principal)
requests = sa.Table(
    "creation_requests",
    metadata,
    sa.Column("owner", sa.String(254), primary_key=True),
    sa.Column("request_id", sa.String(36), primary_key=True),
    sa.Column("fingerprint", sa.String(64), nullable=False),
    sa.Column(
        "sandbox_id", sa.String(36), sa.ForeignKey("sandboxes.id"), nullable=False
    ),
)

from ..integrations.caipe.schema import define_acp_bindings

acp_bindings = define_acp_bindings(metadata)
