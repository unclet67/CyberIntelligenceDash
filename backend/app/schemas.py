from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AliasOut(APIModel):
    name: str


class TechniqueOut(APIModel):
    id: str
    name: str
    tactic: str


class EventOut(APIModel):
    observed_at: datetime
    title: str
    detail: str


class ActorSourceOut(APIModel):
    source_name: str
    external_id: str
    profile_url: str | None
    last_synced_at: datetime | None


class ActorSummary(APIModel):
    id: str
    name: str
    mitre_id: str | None
    country: str
    sponsor: str
    motivation: str
    severity: str
    confidence: str
    external_id: str | None = None
    source_profiles: list[ActorSourceOut] = Field(default_factory=list)


class ActorDetail(ActorSummary):
    description: str
    aliases: list[AliasOut]
    techniques: list[TechniqueOut]
    events: list[EventOut]


class CampaignOut(APIModel):
    id: str
    name: str
    actor_id: str | None
    sector: str
    status: str
    first_seen: date | None
    last_seen: date | None


class IndicatorSourceOut(APIModel):
    source_name: str
    external_id: str
    reference_url: str | None
    confidence_score: int | None
    first_seen: datetime | None
    last_seen: datetime | None
    expires_at: datetime | None
    last_synced_at: datetime
    is_active: bool


class IndicatorOut(APIModel):
    id: int
    type: str
    value: str
    actor_id: str | None
    confidence: str
    confidence_score: int | None = None
    threat_type: str | None = None
    malware: str | None = None
    tags: list[str] = Field(default_factory=list)
    reference_url: str | None = None
    first_seen: datetime | None
    last_seen: datetime | None
    expires_at: datetime | None = None
    last_synced_at: datetime | None = None
    is_active: bool = True
    source_name: str | None = None
    source_profiles: list[IndicatorSourceOut] = Field(default_factory=list)


class ReportOut(APIModel):
    id: int
    title: str
    type: str
    related: str
    published_at: datetime
    format: str
    url: str | None


class IngestionRunOut(APIModel):
    id: int
    source_id: int
    started_at: datetime
    completed_at: datetime | None
    status: str
    items_seen: int
    items_written: int
    error: str | None


class DashboardBootstrap(BaseModel):
    actors: list[ActorDetail]
    campaigns: list[CampaignOut]
    indicators: list[IndicatorOut]
    techniques: list[TechniqueOut]
    reports: list[ReportOut]


class HealthOut(BaseModel):
    status: str
    database: str
