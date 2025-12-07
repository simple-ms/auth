"""Background jobs for auth service maintenance."""

from datetime import datetime, timezone
from ..repository import RefreshTokenRepository
from ..database import get_db
from ..logger import logger


async def cleanup_expired_tokens() -> int:
    """
    Remove expired refresh tokens from the database.
    
    This should be run periodically (e.g., daily via cron job or background worker).
    
    Returns:
        Number of tokens removed.
    """
    async for db in get_db():
        try:
            repo = RefreshTokenRepository(db)
            count = await repo.cleanup_expired()
            logger.info(f"Cleanup job: Removed {count} expired refresh tokens")
            return count
        except Exception as e:
            logger.error(f"Cleanup job failed: {e}")
            raise
        finally:
            await db.close()


# Example usage with APScheduler (optional)
"""
from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()

# Run cleanup daily at 2 AM
scheduler.add_job(
    cleanup_expired_tokens,
    'cron',
    hour=2,
    minute=0
)

scheduler.start()
"""

# Example usage with Celery (optional)
"""
from celery import Celery

celery_app = Celery('auth_tasks')

@celery_app.task
async def cleanup_expired_tokens_task():
    return await cleanup_expired_tokens()

# Schedule in celerybeat
celery_app.conf.beat_schedule = {
    'cleanup-expired-tokens': {
        'task': 'app.jobs.cleanup_expired_tokens_task',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
    },
}
"""
