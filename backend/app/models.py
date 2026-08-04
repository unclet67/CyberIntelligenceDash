from datetime import date, datetime

from sqlalchemy import Column, Date, DateTime, ForeignKey, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


actor_techniques = Table(
    "actor_techniques",
    Base.metadata,
    Column("actor_id", ForeignKey("actors.id", ondelete="CASCADE"), primary_key=True),
    Column("technique_id", ForeignKey("techniques.id", ondelete="CASCADE"), primary_key=True),
)


class Actor(Base):
    __tablename__ = "actors"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    mitre_id: Mapped[str | None] = mapped_column(String(32), unique=True)
    country: Mapped[str] = mapped_column(String(80), nullable=False)
    sponsor: Mapped[str] = mapped_column(String(200), nullable=False)
    motivation: Mapped[str] = mapped_column(String(120), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(160), unique=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"), index=True)

    aliases: Mapped[list["ActorAlias"]] = relationship(back_populates="actor", cascade="all, delete-orphan")
    techniques: Mapped[list["Technique"]] = relationship(secondary=actor_techniques, back_populates="actors")
    events: Mapped[list["ActorEvent"]] = relationship(back_populates="actor", cascade="all, delete-orphan")
    campaigns: Mapped[list["Campaign"]] = relationship(back_populates="actor")
    indicators: Mapped[list["Indicator"]] = relationship(back_populates="actor")
    source: Mapped["Source | None"] = relationship(back_populates="actors")
    source_profiles: Mapped[list["ActorSource"]] = relationship(
        back_populates="actor", cascade="all, delete-orphan"
    )


class ActorAlias(Base):
    __tablename__ = "actor_aliases"
    __table_args__ = (UniqueConstraint("actor_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("actors.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    actor: Mapped[Actor] = relationship(back_populates="aliases")


class Technique(Base):
    __tablename__ = "techniques"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    tactic: Mapped[str] = mapped_column(String(120), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(160), unique=True)
    actors: Mapped[list[Actor]] = relationship(secondary=actor_techniques, back_populates="techniques")


class ActorEvent(Base):
    __tablename__ = "actor_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("actors.id", ondelete="CASCADE"), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[Actor] = relationship(back_populates="events")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("actors.id", ondelete="SET NULL"), index=True)
    sector: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    first_seen: Mapped[date | None] = mapped_column(Date)
    last_seen: Mapped[date | None] = mapped_column(Date)
    actor: Mapped[Actor | None] = relationship(back_populates="campaigns")


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    url: Mapped[str | None] = mapped_column(String(500))
    actors: Mapped[list[Actor]] = relationship(back_populates="source")
    indicators: Mapped[list["Indicator"]] = relationship(back_populates="source")
    ingestion_runs: Mapped[list["IngestionRun"]] = relationship(back_populates="source")
    actor_profiles: Mapped[list["ActorSource"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class ActorSource(Base):
    __tablename__ = "actor_sources"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_actor_sources_external_identity"),
        UniqueConstraint("actor_id", "source_id", name="uq_actor_sources_actor_source"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("actors.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    profile_url: Mapped[str | None] = mapped_column(String(1000))
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    actor: Mapped[Actor] = relationship(back_populates="source_profiles")
    source: Mapped[Source] = relationship(back_populates="actor_profiles")

    @property
    def source_name(self) -> str:
        return self.source.name


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("type", "value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(1000), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(160), unique=True)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("actors.id", ondelete="SET NULL"), index=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"))
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    actor: Mapped[Actor | None] = relationship(back_populates="indicators")
    source: Mapped[Source | None] = relationship(back_populates="indicators")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    type: Mapped[str] = mapped_column(String(120), nullable=False)
    related: Mapped[str] = mapped_column(String(200), nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False)
    url: Mapped[str | None] = mapped_column(String(1000))


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    items_seen: Mapped[int] = mapped_column(default=0, nullable=False)
    items_written: Mapped[int] = mapped_column(default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    source: Mapped[Source] = relationship(back_populates="ingestion_runs")
