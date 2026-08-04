from datetime import date, datetime

from pydantic import BaseModel, ConfigDict


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


class ActorSummary(APIModel):
    id: str
    name: str
    mitre_id: str | None
    country: str
    sponsor: str
    motivation: str
    severity: str
    confidence: str


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


class IndicatorOut(APIModel):
    id: int
    type: str
    value: str
    actor_id: str | None
    confidence: str
    first_seen: datetime | None
    last_seen: datetime | None
    source_name: str | None = None


class ReportOut(APIModel):
    id: int
    title: str
    type: str
    related: str
    published_at: datetime
    format: str
    url: str | None


class HealthOut(BaseModel):
    status: str
    database: str
