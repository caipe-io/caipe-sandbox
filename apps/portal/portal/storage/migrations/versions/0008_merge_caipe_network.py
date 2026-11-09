"""Join CAIPE binding and namespace policy histories without changing either."""

revision = "0008_merge_caipe_network"
down_revision = ("0007_acp_bindings", "0007_namespace_network_policy")
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    raise RuntimeError(
        "Restore a compatible backup before separating metadata histories"
    )
