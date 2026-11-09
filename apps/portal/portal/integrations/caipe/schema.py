"""CAIPE-owned tables participate in the portal migration history."""

import sqlalchemy as sa


def define_acp_bindings(metadata):
    acp_bindings = sa.Table(
        "acp_bindings",
        metadata,
        sa.Column("sandbox_uid", sa.String(512), primary_key=True),
        sa.Column("owner_subject", sa.String(254), nullable=False),
        sa.Column("conversation_id", sa.String(254), nullable=False),
        sa.Column("binding_id", sa.String(254), nullable=False),
        sa.Column("policy_revision", sa.String(71), nullable=False),
        sa.Column("active_run_id", sa.String(254)),
        sa.Column("process_token", sa.String(36)),
    )
    return acp_bindings
