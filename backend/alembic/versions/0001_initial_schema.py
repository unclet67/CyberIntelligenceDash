"""Initial threat-intelligence schema."""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "actors",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False, unique=True),
        sa.Column("mitre_id", sa.String(32), nullable=True, unique=True),
        sa.Column("country", sa.String(80), nullable=False),
        sa.Column("sponsor", sa.String(200), nullable=False),
        sa.Column("motivation", sa.String(120), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
    )
    op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False, unique=True),
        sa.Column("url", sa.String(500), nullable=True),
    )
    op.create_table(
        "techniques",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("tactic", sa.String(120), nullable=False),
    )
    op.create_table(
        "actor_aliases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.String(64), sa.ForeignKey("actors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.UniqueConstraint("actor_id", "name"),
    )
    op.create_table(
        "actor_techniques",
        sa.Column("actor_id", sa.String(64), sa.ForeignKey("actors.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("technique_id", sa.String(32), sa.ForeignKey("techniques.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_table(
        "actor_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.String(64), sa.ForeignKey("actors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
    )
    op.create_table(
        "campaigns",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("actor_id", sa.String(64), sa.ForeignKey("actors.id", ondelete="SET NULL"), nullable=True),
        sa.Column("sector", sa.String(120), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("first_seen", sa.Date(), nullable=True),
        sa.Column("last_seen", sa.Date(), nullable=True),
    )
    op.create_table(
        "indicators",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("value", sa.String(1000), nullable=False),
        sa.Column("actor_id", sa.String(64), sa.ForeignKey("actors.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("sources.id", ondelete="SET NULL"), nullable=True),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("type", "value"),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("type", sa.String(120), nullable=False),
        sa.Column("related", sa.String(200), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("url", sa.String(1000), nullable=True),
    )
    op.create_index("ix_campaigns_actor_id", "campaigns", ["actor_id"])
    op.create_index("ix_indicators_actor_id", "indicators", ["actor_id"])
    op.create_index("ix_indicators_type", "indicators", ["type"])


def downgrade() -> None:
    op.drop_index("ix_indicators_type", table_name="indicators")
    op.drop_index("ix_indicators_actor_id", table_name="indicators")
    op.drop_index("ix_campaigns_actor_id", table_name="campaigns")
    for table in ["reports", "indicators", "campaigns", "actor_events", "actor_techniques", "actor_aliases", "techniques", "sources", "actors"]:
        op.drop_table(table)
