"""Allow one actor to retain provenance from multiple intelligence sources."""

from alembic import op
import sqlalchemy as sa

revision = "0003_actor_sources"
down_revision = "0002_ingestion_and_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "actor_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.String(64), sa.ForeignKey("actors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_id", sa.String(160), nullable=False),
        sa.Column("profile_url", sa.String(1000), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("source_id", "external_id", name="uq_actor_sources_external_identity"),
        sa.UniqueConstraint("actor_id", "source_id", name="uq_actor_sources_actor_source"),
    )
    op.create_index("ix_actor_sources_actor_id", "actor_sources", ["actor_id"])
    op.create_index("ix_actor_sources_source_id", "actor_sources", ["source_id"])
    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            INSERT INTO actor_sources (actor_id, source_id, external_id, profile_url)
            SELECT actors.id, actors.source_id, actors.external_id, sources.url
            FROM actors JOIN sources ON sources.id = actors.source_id
            WHERE actors.source_id IS NOT NULL AND actors.external_id IS NOT NULL
            """
        )
    )


def downgrade() -> None:
    op.drop_index("ix_actor_sources_source_id", table_name="actor_sources")
    op.drop_index("ix_actor_sources_actor_id", table_name="actor_sources")
    op.drop_table("actor_sources")
