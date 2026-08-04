"""Add ingestion audit records and external provenance identifiers."""

from alembic import op
import sqlalchemy as sa

revision = "0002_ingestion_and_provenance"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("actors") as batch:
        batch.add_column(sa.Column("external_id", sa.String(160), nullable=True))
        batch.add_column(sa.Column("source_id", sa.Integer(), nullable=True))
        batch.create_unique_constraint("uq_actors_external_id", ["external_id"])
        batch.create_foreign_key("fk_actors_source_id", "sources", ["source_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_actors_source_id", ["source_id"])
    with op.batch_alter_table("techniques") as batch:
        batch.add_column(sa.Column("external_id", sa.String(160), nullable=True))
        batch.create_unique_constraint("uq_techniques_external_id", ["external_id"])
    with op.batch_alter_table("indicators") as batch:
        batch.add_column(sa.Column("external_id", sa.String(160), nullable=True))
        batch.create_unique_constraint("uq_indicators_external_id", ["external_id"])
    op.create_table(
        "ingestion_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("items_seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("items_written", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_ingestion_runs_source_id", "ingestion_runs", ["source_id"])


def downgrade() -> None:
    op.drop_index("ix_ingestion_runs_source_id", table_name="ingestion_runs")
    op.drop_table("ingestion_runs")
    with op.batch_alter_table("indicators") as batch:
        batch.drop_constraint("uq_indicators_external_id", type_="unique")
        batch.drop_column("external_id")
    with op.batch_alter_table("techniques") as batch:
        batch.drop_constraint("uq_techniques_external_id", type_="unique")
        batch.drop_column("external_id")
    with op.batch_alter_table("actors") as batch:
        batch.drop_index("ix_actors_source_id")
        batch.drop_constraint("fk_actors_source_id", type_="foreignkey")
        batch.drop_constraint("uq_actors_external_id", type_="unique")
        batch.drop_column("source_id")
        batch.drop_column("external_id")
