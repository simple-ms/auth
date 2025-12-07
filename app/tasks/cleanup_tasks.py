"""
Background tasks for Auth Service.
"""
from datetime import datetime, timezone
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session
from ..celery_app import celery_app
from ..models import RefreshToken
from ..settings import settings
from ..logger import logger


# Synchronous database URL for Celery tasks
SYNC_DATABASE_URL = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
sync_engine = create_engine(SYNC_DATABASE_URL)


@celery_app.task(name='app.tasks.cleanup_tasks.cleanup_expired_tokens')
def cleanup_expired_tokens():
    """
    Remove expired refresh tokens from database.
    Runs every hour via Celery Beat.
    """
    logger.info("Starting cleanup of expired refresh tokens")
    
    db = Session(sync_engine)
    try:
        now = datetime.now(timezone.utc)
        
        # Delete expired tokens
        result = db.execute(
            delete(RefreshToken).where(
                RefreshToken.expires_at < now
            )
        )
        db.commit()
        
        deleted_count = result.rowcount
        logger.info(f"Cleanup completed: {deleted_count} expired tokens removed")
        
        return {
            'task': 'cleanup_expired_tokens',
            'deleted_count': deleted_count,
            'timestamp': now.isoformat()
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error during token cleanup: {str(e)}")
        raise
    finally:
        db.close()
