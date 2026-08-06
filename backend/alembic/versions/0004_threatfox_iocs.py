"""Add live IOC context and multi-source provenance."""

from alembic import op
import sqlalchemy as sa

revision = "0004_threatfox_iocs"
down_revision = "0003_actor_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("indicators") as batch:
        batch.add_column(sa.Column("confidence_score", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("threat_type", sa.String(120), nullable=True))
        batch.add_column(sa.Column("malware", sa.String(160), nullable=True))
        batch.add_column(sa.Column("tags", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        batch.add_column(sa.Column("reference_url", sa.String(1000), nullable=True))
        batch.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_index("ix_indicators_expires_at", "indicators", ["expires_at"])
    op.create_index("ix_indicators_is_active", "indicators", ["is_active"])

    op.create_table(
        "indicator_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("indicator_id", sa.Integer(), sa.ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_id", sa.String(160), nullable=False),
        sa.Column("reference_url", sa.String(1000), nullable=True),
        sa.Column("confidence_score", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("source_id", "external_id", name="uq_indicator_sources_external_identity"),
        sa.UniqueConstraint("indicator_id", "source_id", name="uq_indicator_sources_indicator_source"),
    )
    op.create_index("ix_indicator_sources_indicator_id", "indicator_sources", ["indicator_id"])
    op.create_index("ix_indicator_sources_source_id", "indicator_sources", ["source_id"])

    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            INSERT INTO indicator_sources (
                indicator_id, source_id, external_id, reference_url,
                first_seen, last_seen, last_synced_at, is_active
            )
            SELECT indicators.id, indicators.source_id, indicators.external_id, sources.url,
                   indicators.first_seen, indicators.last_seen, CURRENT_TIMESTAMP, TRUE
            FROM indicators JOIN sources ON sources.id = indicators.source_id
            WHERE indicators.source_id IS NOT NULL AND indicators.external_id IS NOT NULL
            """
        )
    )


def downgrade() -> None:
    op.drop_index("ix_indicator_sources_source_id", table_name="indicator_sources")
    op.drop_index("ix_indicator_sources_indicator_id", table_name="indicator_sources")
    op.drop_table("indicator_sources")
    op.drop_index("ix_indicators_is_active", table_name="indicators")
    op.drop_index("ix_indicators_expires_at", table_name="indicators")
    with op.batch_alter_table("indicators") as batch:
        batch.drop_column("is_active")
        batch.drop_column("last_synced_at")
        batch.drop_column("expires_at")
        batch.drop_column("reference_url")
        batch.drop_column("tags")
        batch.drop_column("malware")
        batch.drop_column("threat_type")
        batch.drop_column("confidence_score")
