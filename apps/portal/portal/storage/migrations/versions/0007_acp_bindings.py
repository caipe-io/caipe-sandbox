"""Retained external-agent execution bindings; no lease-expiry takeover."""

import sqlalchemy as sa
from alembic import op

revision = "0007_acp_bindings"
down_revision = "0006_scope_ownership"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "acp_bindings",
        sa.Column("sandbox_uid", sa.String(512), primary_key=True),
        sa.Column("owner_subject", sa.String(254), nullable=False),
        sa.Column("conversation_id", sa.String(254), nullable=False),
        sa.Column("binding_id", sa.String(254), nullable=False),
        sa.Column("policy_revision", sa.String(71), nullable=False),
        sa.Column("active_run_id", sa.String(254)),
        sa.Column("process_token", sa.String(36)),
    )


def downgrade():
    raise RuntimeError(
        "Restore a compatible backup rather than discarding retained ACP process fences"
    )
