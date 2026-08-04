from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import data_router, router
from .config import settings
from .database import Base, SessionLocal, engine
from .seed import seed_database


def create_app(*, initialize_database: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if settings.auth_required and not settings.api_auth_token:
            raise RuntimeError("API_AUTH_TOKEN must be set when AUTH_REQUIRED=true")
        if initialize_database:
            Base.metadata.create_all(bind=engine)
            if settings.seed_on_startup:
                with SessionLocal() as session:
                    seed_database(session)
        yield

    application = FastAPI(
        title=settings.app_name,
        version="0.2.0",
        description="Read-only threat-intelligence API for the ARGUS TI dashboard.",
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Authorization", "Content-Type"],
    )
    application.include_router(router)
    application.include_router(data_router)

    @application.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {"service": settings.app_name, "docs": "/docs", "health": "/api/health"}

    return application


app = create_app()
