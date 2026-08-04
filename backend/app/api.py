from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, text
from sqlalchemy.orm import Session, selectinload

from .database import get_db
from .models import Actor, Campaign, Indicator, Report, Technique
from .schemas import ActorDetail, ActorSummary, CampaignOut, HealthOut, IndicatorOut, ReportOut, TechniqueOut

router = APIRouter(prefix="/api")


@router.get("/health", response_model=HealthOut)
def health(session: Session = Depends(get_db)) -> HealthOut:
    session.execute(text("SELECT 1"))
    return HealthOut(status="ok", database="reachable")


@router.get("/actors", response_model=list[ActorSummary])
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


@router.get("/actors/{actor_id}", response_model=ActorDetail)
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


@router.get("/campaigns", response_model=list[CampaignOut])
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


@router.get("/iocs", response_model=list[IndicatorOut])
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
    indicators = list(session.scalars(statement))
    return [
        IndicatorOut.model_validate(item).model_copy(update={"source_name": item.source.name if item.source else None})
        for item in indicators
    ]


@router.get("/attack/techniques", response_model=list[TechniqueOut])
def list_techniques(session: Session = Depends(get_db)) -> list[Technique]:
    return list(session.scalars(select(Technique).order_by(Technique.tactic, Technique.id)))


@router.get("/reports", response_model=list[ReportOut])
def list_reports(session: Session = Depends(get_db)) -> list[Report]:
    return list(session.scalars(select(Report).order_by(Report.published_at.desc())))
