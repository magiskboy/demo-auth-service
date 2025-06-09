from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.auth.routers import router as auth_router
from app.users.routers import router as users_router
from app.admin.routers import router as admin_router
from starlette.middleware.sessions import SessionMiddleware
from app.core import settings
from app.core.db import engine
from sqlalchemy import text
from app.core.redis import get_redis


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.execute(text('SELECT 1'))
    redis = get_redis()
    await redis.ping()

    yield

    await engine.dispose()

    
def create_app() -> FastAPI:
    app = FastAPI(
        title="OAuth",
        description="OAuth",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

    app.include_router(users_router, prefix="/api/v1/users", tags=["Users"])
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["Auth"])
    app.include_router(admin_router, prefix="/api/v1/admin", tags=["Admin"])

    @app.get('/healthz')
    async def healthz():
        return {'status': 'ok'}

    return app
