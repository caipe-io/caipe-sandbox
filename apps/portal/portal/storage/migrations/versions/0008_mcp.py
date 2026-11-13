"""Persist opt-in MCP configuration without changing native sandbox specifications."""

import sqlalchemy as sa
from alembic import op

revision = "0008_mcp"
down_revision = "0007_namespace_network_policy"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "sandboxes",
        sa.Column("mcp", sa.JSON, nullable=False, server_default='{"enabled":false}'),
    )


def downgrade():
    raise RuntimeError("Restore a compatible backup before removing MCP configuration")
