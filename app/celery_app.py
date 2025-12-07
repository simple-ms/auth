"""
Celery application configuration for Auth Service.
Handles background tasks like token cleanup.
"""
from celery import Celery
from celery.schedules import crontab
from .settings import settings

# Initialize Celery app
celery_app = Celery(
    'auth-service',
    broker=f'redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/0',
    backend=f'redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/0'
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes max
    task_soft_time_limit=240,  # 4 minutes soft limit
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    task_acks_late=True,  # Acknowledge after task completion
    task_reject_on_worker_lost=True,
    task_default_queue='auth-tasks',  # Dedicated queue for auth service
    task_default_routing_key='auth-tasks',
)

# Periodic task schedule
celery_app.conf.beat_schedule = {
    'cleanup-expired-tokens': {
        'task': 'app.tasks.cleanup_tasks.cleanup_expired_tokens',
        'schedule': crontab(minute=0),  # Every hour at minute 0
    },
}

# Auto-discover tasks
celery_app.autodiscover_tasks(['app.tasks'])
