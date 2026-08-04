from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, text
from sqlalchemy.orm import Session, selectinload

from .auth import require_api_token
from .database import get_db
from .models import Actor, Campaign, Indicator, IngestionRun, Report, Technique
from .schemas import (
    ActorDetail,
    ActorSummary,
    CampaignOut,
    DashboardBootstrap,
    HealthOut,
    IndicatorOut,
    IngestionRunOut,
    ReportOut,
    TechniqueOut,
)

router = APIRouter(prefix="/api")
data_router = APIRouter(prefix="/api", dependencies=[Depends(require_api_token)])


@router.get("/health", response_model=HealthOut)
def health(session: Session = Depends(get_db)) -> HealthOut:
    session.execute(text("SELECT 1"))
    return HealthOut(status="ok", database="reachable")


@data_router.get("/actors", response_model=list[ActorSummary])
def list_actors(
    severity: str | None = None,
    search: str | None = None,
    session: Session = Depends(get_db),
) -> list[Actor]:
    statement = select(Actor).order_by(Actor.name)
    if severity:
        statement = statement.where(Actor.severity == severity.lower())
    if search:
        statement = statement.where(Actor.name.ilike(f"%{search.strip()}%"))
    return list(session.scalars(statement))


@data_router.get("/actors/{actor_id}", response_model=ActorDetail)
def get_actor(actor_id: str, session: Session = Depends(get_db)) -> Actor:
    statement = (
        select(Actor)
        .where(Actor.id == actor_id)
        .options(selectinload(Actor.aliases), selectinload(Actor.techniques), selectinload(Actor.events))
    )
    actor = session.scalar(statement)
    if actor is None:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor


@data_router.get("/campaigns", response_model=list[CampaignOut])
def list_campaigns(
    status: str | None = None,
    actor_id: str | None = None,
    session: Session = Depends(get_db),
) -> list[Campaign]:
    statement = select(Campaign).order_by(Campaign.name)
    if status:
        statement = statement.where(Campaign.status == status.lower())
    if actor_id:
        statement = statement.where(Campaign.actor_id == actor_id)
    return list(session.scalars(statement))


def _indicator_out(item: Indicator) -> IndicatorOut:
    return IndicatorOut.model_validate(item).model_copy(
        update={"source_name": item.source.name if item.source else None}
    )


@data_router.get("/iocs", response_model=list[IndicatorOut])
def list_indicators(
    indicator_type: str | None = Query(default=None, alias="type"),
    actor_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    session: Session = Depends(get_db),
) -> list[IndicatorOut]:
    statement = select(Indicator).options(selectinload(Indicator.source)).order_by(Indicator.id.desc()).limit(limit)
    if indicator_type:
        statement = statement.where(Indicator.type == indicator_type.upper())
    if actor_id:
        statement = statement.where(Indicator.actor_id == actor_id)
    return [_indicator_out(item) for item in session.scalars(statement)]


@data_router.get("/attack/techniques", response_model=list[TechniqueOut])
def list_techniques(session: Session = Depends(get_db)) -> list[Technique]:
    return list(session.scalars(select(Technique).order_by(Technique.tactic, Technique.id)))


@data_router.get("/reports", response_model=list[ReportOut])
def list_reports(session: Session = Depends(get_db)) -> list[Report]:
    return list(session.scalars(select(Report).order_by(Report.published_at.desc())))


@data_router.get("/dashboard/bootstrap", response_model=DashboardBootstrap)
def dashboard_bootstrap(session: Session = Depends(get_db)) -> DashboardBootstrap:
    actors = list(
        session.scalars(
            select(Actor)
            .options(selectinload(Actor.aliases), selectinload(Actor.techniques), selectinload(Actor.events))
            .order_by(Actor.name)
        )
    )
    campaigns = list(session.scalars(select(Campaign).order_by(Campaign.name)))
    indicators = list(
        session.scalars(
            select(Indicator).options(selectinload(Indicator.source)).order_by(Indicator.id.desc())
        )
    )
    techniques = list(session.scalars(select(Technique).order_by(Technique.tactic, Technique.id)))
    reports = list(session.scalars(select(Report).order_by(Report.published_at.desc())))
    return DashboardBootstrap(
        actors=actors,
        campaigns=campaigns,
        indicators=[_indicator_out(item) for item in indicators],
        techniques=techniques,
        reports=reports,
    )


@data_router.get("/ingestion/runs", response_model=list[IngestionRunOut])
def list_ingestion_runs(
    limit: int = Query(default=25, ge=1, le=250),
    session: Session = Depends(get_db),
) -> list[IngestionRun]:
    statement = select(IngestionRun).order_by(IngestionRun.started_at.desc()).limit(limit)
    return list(session.scalars(statement))
