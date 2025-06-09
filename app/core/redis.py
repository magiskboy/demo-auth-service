from redis.asyncio import Redis
from app.core import settings


def get_redis(db: int = 0):
    return Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=db,
    )