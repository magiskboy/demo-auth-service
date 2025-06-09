from fastapi import FastAPI
from app.auth.routers import router as auth_router
from app.users.routers import router as users_router
from app.admin.routers import router as admin_router



def create_app() -> FastAPI:
    app = FastAPI(
        title="OAuth",
        description="OAuth",
        version="0.1.0",
    )

    app.include_router(users_router, prefix="/api/v1/users", tags=["Users"])
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["Auth"])
    app.include_router(admin_router, prefix="/api/v1/admin", tags=["Admin"])

    @app.get('/healthz')
    async def healthz():
        return {'status': 'ok'}

    return app
